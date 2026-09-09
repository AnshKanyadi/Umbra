# ADR 0005: HNSW in immutable sealed segments, with a manifest in Basalt

- Status: accepted
- Date: 2026-09-08
- Depends on: [ADR 0001](0001-storage.md), [ADR 0006](0006-chunking.md),
  [ADR 0007](0007-embeddings.md)
- Depended on by: Phase 5 (shared index sync)

## Context

A personal vault is ten to a hundred thousand vectors: small enough that an
exhaustive scan is *almost* fine and large enough that it is not. The index has
to be built here rather than linked in, because the interesting part of a vector
store is the part that decides which neighbours a node keeps, and a dependency
doing that leaves this project with behaviour nobody here can explain.

The shape matters more than the algorithm. Phase 5 syncs the index between
devices, and a store built as one mutable file would have to be thrown away to
get there.

## HNSW, not IVF

| | HNSW | IVF |
|---|---|---|
| Training | none | k-means over a sample, and retraining as the corpus drifts |
| Incremental insert | natural | degrades until retrained |
| Recall at this scale | high at modest `ef` | needs many probes to match |
| Deletes | tombstone only | tombstone only |
| Memory | vector + ~M·4 bytes per node per layer | smaller |

**IVF is rejected on training.** It needs a representative sample before it can
index anything, which a vault does not have on day one, and it needs retraining
as the corpus changes — a background job that silently degrades search when it
does not run. HNSW has no such state. Its costs are memory and build time, both
of which are measured below rather than assumed.

Neither can delete properly, so that is decided separately and identically.

## Immutable segments plus a manifest

    manifest (Basalt)          segments (files)
    -----------------          ----------------
    which segments exist  -->  <hex id>.seg    sealed, immutable
    which slots are dead
    which object is where

This is ADR 0001's shape — small authoritative records in Basalt, large
immutable blobs beside it, content-addressed — rather than a second one invented
for the index.

It also solves the problem HNSW has. **A graph edge removed from a live index
strands whatever was reachable only through it.** Every real implementation
tombstones and rebuilds; segments make that the ordinary path rather than a
special case. A tombstoned slot is still *traversed* during search, because its
edges may be the only route to its neighbours, and is filtered from the results.
Compaction is what actually reclaims it.

**Incremental by construction.** Editing one note writes a new segment holding
only that note's chunks and tombstones the slots the old ones occupied. Nothing
else is touched and nothing else is re-embedded. The cost is that segments
accumulate and search visits each one — the same bargain the oplog made, with
the same failure mode if the second half is never built, so `Compact()` exists
in this phase rather than being deferred.

**Segments hold no note text**, only `(object id, byte range)`. The text is read
from the vault when a passage is needed. A second copy would be a second thing to
keep consistent, and a citation into the live document cannot go stale the way a
cached copy can.

## Determinism, and its exact scope

Segment bytes are identical for identical **input vectors**. That required three
things:

- **The level draw is seeded from the vectors.** Textbook HNSW draws node levels
  from a random source, which makes the graph different every run and the
  segment bytes different with it.
- **Every tie breaks on node index.** Ordering only by score leaves equal-scoring
  candidates in whatever order the heap produced, which depends on the standard
  library.
- **Sealing uses a derived nonce.** A random nonce would make the sealed bytes
  differ every build. `SealDeterministic` derives it as a keyed hash of the
  plaintext and associated data — the SIV construction — so two different
  segments get different nonces and the only repeat is a byte-identical segment.
  See the note in `aead.h` for why that is safe and what it leaks.

It is **not** identical bytes for identical note text, because inference is not
reproducible across machines and does not need to be: Phase 5 copies segments
rather than rebuilding them. Chunk boundaries must be identical; vectors need
only be compatible. Conflating the two would have cost either determinism
theatre around inference or a real correctness hole.

## The bug the recall test found

The first graph pruned a full neighbour's edge list by keeping the nearest M,
while forward edges used the diversity heuristic. In a cluster of near-identical
vectors — which a real vault has, wherever a note repeats a phrase — every late
arrival was the worst neighbour of everything it pointed at and lost all of its
in-edges. Those nodes kept their out-edges and became unreachable.

It showed as recall stuck at **0.84 for every `ef` from 16 to 512**. That flatness
is the signature: a wider beam cannot reach a node nothing points at. Applying
the same heuristic to back-link pruning fixed it, and recall is now 1.0 on that
corpus and 0.999 at `ef` 32 on four thousand vectors. The cost is a slower
build — 3.4s to 8.9s for four thousand vectors — which is the right side of that
trade.

`Index.RecallAgainstBruteForce` is what caught it, and its floors are now set
where a return of the bug fails rather than passes.

## Measured

macOS 15 on Apple silicon, release build, `all-minilm` (384 dimensions) through
a local Ollama.

Recall against exhaustive search, 4000 vectors, `k` = 10:

| `ef` | recall@10 | per query |
|---|---|---|
| 10 | 0.931 | 106 µs |
| 32 | 0.999 | 214 µs |
| 64 | 1.000 | 322 µs |
| 128 | 1.000 | 468 µs |

`ef` = 64 is the default: the point where recall stops improving.

Cold index of a synthetic 3000-note vault and the eval corpus are reported in
the phase report with the full breakdown.

## Consequences

- **Search cost grows with segment count**, so compaction is not optional. It
  runs at eight segments or at twenty per cent dead, and both thresholds are
  arguable rather than derived.
- **Distances are accumulated in double.** Over 768 terms a float accumulator
  loses enough to reorder near-ties, and a ranking that changes when someone
  enables vectorisation is not a ranking.
- **A tampered or missing segment is refused at open**, not skipped. Skipping
  would silently halve someone's index.
- **The whole segment is loaded into memory.** At 384 dimensions and 30k vectors
  that is about 46 MB of vector data, which is acceptable on a laptop and would
  not be at ten times the corpus. Memory-mapping the vector section is the
  obvious next step and is not built.
