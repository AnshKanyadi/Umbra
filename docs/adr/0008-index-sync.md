# ADR 0008: The index replicates as manifest operations plus sealed segments

- Status: accepted
- Date: 2026-09-09
- Depends on: [ADR 0001](0001-storage.md), [ADR 0005](0005-index.md),
  [ADR 0007](0007-embeddings.md), [docs/threat-model.md](../threat-model.md) §5.9

## Context

Phase 4 built the shape and said why: immutable content-addressed segments and a
manifest, because "a store built as one mutable file would have to be thrown
away to get there". This is there.

The claim being cashed is that one device can index a vault and the rest can
search it without ever running a model, while the relay in the middle learns
nothing about the notes. Two problems stand between the shape and the claim, and
only one of them is transport.

## The manifest is a CRDT, not a file

The moment two devices can both add a segment, "the manifest" is a value two
writers disagree about. A last-writer-wins file would lose an index built while
another device was offline, silently, and the symptom would be search that is
worse on one machine.

So manifest changes are **operations in the existing oplog**, under a reserved
object id beside `TreeObject()`, travelling through the same relay with the same
back-pointer chain, the same cursor and the same ordering guarantees as tree and
text operations. Nothing new transports them. The lattice is three grow-only
sets — added, tombstoned, retired — so the fold is commutative, associative and
idempotent, and there is no state a second writer can clobber because there is
no state, only operations and a function from them.

**Both devices indexing the same note** was the case the prompt asked about, and
the answer falls out of Phase 4 rather than needing new machinery: chunking is
deterministic and a segment is named by its bytes, so two devices that index the
same note produce *the same segment id*. The two `kAdd` operations are the same
operation and the lattice absorbs them. `Replication.BothDevicesIndexingOneNote
DoNotClobberEachOther` asserts one segment, one object, and each passage
returned once.

**Both devices compacting at once** works the same way, and it is why input
selection is a pure function of the manifest state rather than a walk over local
segments. Two devices with the same view choose the same inputs and build the
same segment. Two devices with *different* views can still produce overlapping
outputs; that is a duplicate-results problem, not a correctness one, and search
deduplicates by `(object, start, end)`.

## The safety condition for retirement

Stated before it was built, as the tree log's was:

> **A retirement is a fact in the log immediately and a state transition only
> when the superseding segment is present locally.** Until then the retired
> segment stays live.
>
>     live(S) iff added(S)
>               and not (retired(S -> T) and present(T) for some such T)

The failure it prevents is silent. Device A compacts S1 and S2 into T and
publishes `kAdd(T)`, `kRetire(S1 -> T)`, `kRetire(S2 -> T)`. Device B pulls the
operations — which are small — long before it pulls T, which is large. Applying
the retirements on arrival would drop S1 and S2 while B holds nothing that
replaces them, and every chunk they held would vanish from B's results until the
transfer finished. No error, just a window where the index is quietly
incomplete.

It is the same shape as the back-pointer chain: refuse to advance past something
you do not hold, rather than trusting that it will arrive. It never drops data,
because a segment stops answering only once its replacement can answer; and it
never keeps data forever, because `present(T)` becomes true as soon as T is
pulled, and pulling is driven by the manifest.

A `kRetire` therefore names its replacement. A bare "S is gone" would give a
peer no way to know when it is safe to stop using S.

**The condition lives in one function.** It was written out three times to begin
with — in `Live`, in `Index::Missing` and in `Index::Prune` — and deliberate
breakage found the cost: removing the check from one left the other two intact,
so the test that exists to prove the condition enforced passed while it was not.

## Compaction: tiering was needed, and is built

Phase 4 measured an all-or-nothing merge of a 13,838-vector index at 103 seconds
and recorded tiering as the unbuilt fix. **It blocks this phase.** Segments now
arrive from elsewhere, so every pull can trigger a compaction, and a routine
merge that rewrites the whole index would make catching up cost more than
indexing from scratch.

`PlanCompaction` takes the smallest live segment and everything within a factor
of four of it, so the large compacted segment is left alone until enough small
ones have accumulated beside it. It is a pure function of the manifest and the
live set, which is what keeps concurrent compaction convergent — the tiering and
the convergence are the same property, not two.

## Transport

The Phase 3 relay and client, extended rather than duplicated: three new
opcodes on the existing framed protocol, the existing TCP transport, the
existing connection.

**Segments travel in pieces.** A 25 MB segment does not fit an 8 MB frame, and
the obvious fix — raising `kMaxFrameBytes` — is the wrong one: that limit is
what stops a hostile relay making a client reserve memory on *any* response, and
relaxing it everywhere to accommodate one message type spends the guarantee on
all of them. Pieces at a fixed offset keep one bound, make a partial transfer
resume, and let a relay waste a client's bandwidth but not its address space.

**The relay never reassembles.** It hands back the piece stored at the requested
offset and lets the client stitch, because reassembling would mean holding a
whole segment in memory to answer one request — the allocation the chunking
exists to avoid.

## What this cost, found by running it

Three defects the unit tests did not reach and the end-to-end did:

- **Pending operations were in memory only.** A device indexed a vault, exited,
  and the next process pushed ten segments and zero operations — so the bytes
  were on the relay and nothing said they existed. They are now durable.
- **The chain check knew two payload kinds.** `FetchObject` found the
  back-pointer by trying the text and tree decoders; a manifest operation
  decoded as neither and came back as `bad-response`. The reader is now supplied
  by the caller, which keeps the sync layer from depending on the ai layer — the
  same reason the relay does not link the CRDTs.
- **Re-indexing unchanged content tombstoned itself.** Segments are content
  addressed, so re-indexing a note that has not changed produces the same
  segment id, and the object's "previous" slots are then the very slots just
  written. A second build over an unchanged vault left 19 of 20 vectors dead and
  one object where there were ten.

## Consequences

- **Search degrades honestly.** `AnswerResult::index_complete` is false while
  the manifest names segments this device does not hold, and the no-results
  message distinguishes "the vault has nothing" from "this device has not
  caught up". A partial vault presented as the whole one is the same failure as
  an ungrounded answer presented as grounded.
- **A device that has not pulled the manifest cannot know it is behind.** It
  reports a complete index because, as far as it has been told, it is. That is
  correct and it is worth stating: completeness is relative to what a device has
  been told exists.
- **A retired segment a device never replaces stays on its disk.** That device
  is not syncing, and its index being larger than necessary is the least of what
  is wrong.
- **The relay learns segment sizes, counts, growth and push timing.** Named,
  measured and not mitigated; see threat model §5.9, including the
  writing-diary adversary and why padding and batching were declined.
