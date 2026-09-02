# ADR 0001: Storage is split between Basalt and content-addressed files

- Status: accepted
- Date: 2026-09-01
- Depends on: [docs/threat-model.md](../threat-model.md)
- Amended 2026-09-01: the content-addressing hash, left open below, is BLAKE2b-256
- Amended 2026-09-02: the key carries what ROUTING needs and not what COMPLETENESS
  needs; a per-(object, replica) back-pointer inside the payload closes the gap

## Context

Umbra has to keep two kinds of local state, and they have almost nothing in
common.

The first is **small, mutable, and constantly churning**. The operation log,
per-file metadata, the object-ID mapping, sync cursors, and the manifest that
names the vector-index segments. Individually these are tens to hundreds of
bytes. They are read on almost every operation, rewritten whenever anything
changes, and their access pattern is point lookups and short ordered range
scans. There are a lot of them and they are updated constantly.

The second is **large, immutable, and written once**. The encrypted vector index
is built in segments; a segment is produced by an indexing pass and is then
never modified. Segments are multi-megabyte. They are read whole, or not at
all, and superseded segments are deleted rather than edited.

Umbra already depends on [Basalt](https://github.com/AnshKanyadi/basalt), an LSM
storage engine, and the obvious move is to put everything in it — one store, one
durability story, one recovery path. That is the decision this ADR declines to
make for half the data.

## Decision

**Basalt holds the small mutable state.** Specifically:

| What | Why it belongs there |
|---|---|
| The operation log | Append-heavy, ordered, read by range scan |
| File metadata | Point lookups keyed by object ID, rewritten on every change |
| The object-ID mapping | The path-to-ID table from the threat model; small, mutable, read constantly |
| Sync cursors | A handful of keys, rewritten on literally every sync |
| The vector-index manifest | Names the live segments by hash; changes whenever a segment is added or retired |

This is what an LSM tree is for. Writes land in a memtable and go to disk
sequentially; keys are ordered so range scans are cheap; overwrites and deletes
are absorbed by compaction rather than paid for in place. The churn that would
be a problem for a naive on-disk structure is exactly the workload the design
targets.

**Encrypted vector index segments do not go through Basalt.** They are written
as **content-addressed files on disk** — the file's name is the hash of its
bytes — and the manifest in Basalt refers to them by that hash. Basalt stores
the reference; the filesystem stores the blob.

```
  basalt (LSM)                          segments/ (plain files)
  +--------------------------+          +---------------------------+
  | op log                   |          | <hash-a>.seg   4.1 MB     |
  | file metadata            |          | <hash-b>.seg   6.7 MB     |
  | object-ID mapping        |          | <hash-c>.seg   3.2 MB     |
  | sync cursors             |          +---------------------------+
  | index manifest ----------+--------->  (referenced by hash)
  +--------------------------+
```

## Why segments are not in the LSM

**Pushing multi-megabyte immutable blobs through compaction produces write
amplification for no benefit.**

An LSM tree earns its write pattern by rewriting data during compaction:
a value written once is copied again each time its level is merged into the
next. For small values that are frequently overwritten this is a good trade,
because compaction is also what reclaims the space of the versions the value
has replaced.

A vector index segment gets none of that benefit and pays the whole cost. It is
written once and never overwritten, so there are no superseded versions for
compaction to reclaim — the only thing compaction can do to a segment is copy it
from one level to the next, unchanged, several times over the life of the
database. A six-megabyte segment that survives four compactions has been written
twenty-four megabytes for the privilege of not changing.

The secondary costs are real too. Multi-megabyte values inflate every SST they
land in, which makes the ordered structure the LSM exists to maintain more
expensive to search for the small keys that actually need it — the metadata and
the mapping end up spread across files that are mostly blob. And reading one
segment means reading it out through the engine's iterator machinery rather than
`mmap`ing or streaming a file.

A content-addressed file has none of this. It is written once, read directly,
and deleted when the manifest stops referring to it.

## Consequences

**Two durability domains, and the ordering between them is now our problem.** A
segment file and the manifest entry naming it are not written atomically
together. The ordering rule is: **write the segment file and fsync it, then
commit the manifest entry.** A crash between the two leaves an unreferenced
segment on disk — garbage, collectable, harmless. The reverse order would leave
a manifest referring to a segment that does not exist, which is corruption. The
asymmetry is why the rule is stated here rather than left to the implementation.

**Garbage collection becomes a thing that must exist.** Unreferenced segment
files accumulate from crashes and from retired index versions, and nothing
reclaims them automatically. Basalt's compaction does not know about them. A
sweep that lists `segments/` and deletes what the manifest does not name is
required, and it must be safe against a concurrent indexing pass that has
written a segment but not yet committed its manifest entry.

**Content addressing needs a cryptographic hash, and it is now chosen.** The
segment file name is a hash of its contents, so a collision is an integrity
failure: two distinct segments claiming the same name means one silently
replaces the other. That is BLAKE2b-256 via libsodium's `crypto_generichash`,
which is also what `ContentHash` is (`include/umbra/change_event.h`). The two
uses share a function deliberately — a segment named by one hash and a file
detected by another would be two things to keep collision-free instead of one.

**The segments are encrypted before they are hashed.** Content addressing over
plaintext would make the filename a fingerprint of the contents, so anyone who
could guess a segment's plaintext could confirm it by name — the same class of
leak the threat model rules out for file paths in §3. Hash the ciphertext.

**Basalt gets the workload it was designed for**, which is the other half of the
argument. Its compaction, its bloom filters and its ordered iteration all serve
small keys with real update churn. Feeding it blobs would have made its
benchmarks meaningless as a predictor of Umbra's behaviour.

## Ordering is not completeness

*Added 2026-09-02, while designing the sync protocol.*

The key was chosen so that a range scan answers "everything from replica R after
counter C" in counter order. It does. What it cannot answer is **"and nothing
was left out"**, and the difference is the whole of this section.

**Counters are sparse per (object, replica).** A device's Lamport clock is shared
across every object and both CRDTs, so most counters do not exist for any given
object. Measured on eight files created, edited five times each, and one moved:

| Key range | Counters present | Span | Density |
|---|---|---|---|
| tree object | 11 | 147 | **7.5%** |
| text object | 17 | 124 | 13.7% |
| text object | 17 | 94 | 18.1% |

At that density a client cannot distinguish *"the relay omitted the operation at
counter 41"* from *"no operation exists at counter 41"*. Both are a hole in an
ordered sequence.

### Why that is worse than a missing message

ADR 0003's log compaction rests on a **prefix mark**: a device's claim that it
holds everything from a source at or below some counter. A relay that omits one
interior operation makes a client advance its cursor past it, and the client then
reports a mark that is false **through no fault of its own**.

> **Authenticating a report does not make it true. It makes it un-forgeable by
> the relay, which is a different property.** A device induced to believe
> something false will seal that belief honestly, and every other device will
> verify the signature and accept it.

The watermark then advances past an operation one device never received, its log
entry is dropped, and clause 5 of ADR 0003's condition absorbs the operation as a
duplicate when it finally arrives. It is lost permanently and silently. This is
the failure the sealing in ADR 0003 clause 2 does **not** cover, and noticing it
is the reason this section exists.

### The back-pointer

Every operation carries, inside its encrypted payload, the counter of the
previous operation from the same replica for the same object. The first is zero.

A client walks its cursor forward and accepts an operation only when its
back-pointer equals the cursor. A skipped operation is then unambiguous: the
arriving operation points at something the client has not reached.

**Inside the payload, not in the key**, and that is the deciding argument rather
than a detail. A dense per-object sequence number in the key would give the same
detection and would tell the relay exactly how many operations each device made
against each file — a new leak in a threat model whose central claim is that
structure is content (threat model §3). Eight bytes under the AEAD costs less.

### The chain's own safety condition

> A client holding cursor `c` for (object, replica) accepts an operation `O`
> iff `O.prev == c`, and then advances the cursor to `O.counter`. Otherwise it
> refuses to advance past `c`.

**The chain and log compaction do not interact, by construction:**

- Compaction drops `LogMove` entries from a client's in-memory tree log. It does
  not touch the cursor, which is durable and separate, and it does not touch the
  operations stored in the oplog.
- **Verification is relative to the cursor, not to zero.** A client with cursor
  `c` verifies continuity from `c` forward only; history below `c` was verified
  when it was crossed and is never re-examined. So a back-pointer naming an
  operation whose log entry has been compacted is still verifiable, because
  verification never consults log entries.

**What would break it is relay-side garbage collection, which is not
implemented.** If the relay dropped operations, the chain would have a truncated
head and a device joining later could not verify back to `prev == 0`. Such a
device could not rebuild the document from a truncated log in any case — that
needs a snapshot — so relay GC requires both a snapshot mechanism and a rule
admitting a chain start at or below a published watermark. Neither exists. **The
relay keeps everything**, and the cost of that is stated in the threat model.

### What it does not detect

**A withheld tail.** If the relay simply stops serving new operations, the client
sees nothing new, which is indistinguishable from nothing new existing. That is
*safe* rather than wrong — the cursor does not move, the mark stays truthful, and
the watermark stays low — but it is a denial of service, recorded as such in the
threat model.

## Alternatives considered

**Everything in Basalt.** One store, one recovery path, no ordering rule to get
right, no garbage collector to write. Rejected for the write amplification
above: the simplicity is real but it is bought with a cost that scales with
index size, which is the thing expected to grow.

**Everything in files, including the metadata.** No LSM dependency at all.
Rejected because the small mutable state is precisely the workload that is
miserable as files — an operation log as one file per entry is a directory with
a million entries in it, and the object-ID mapping rewritten on every change is
a whole-file rewrite per keystroke-triggered save.

**Segments as files, referenced by path rather than by hash.** Simpler naming.
Rejected because a path-named segment can be silently replaced by a different
one with the same name, and because content addressing makes a segment
identical across devices — the same index built on two machines produces the
same name, which is what will let a device recognize a segment it already has
without fetching it.
