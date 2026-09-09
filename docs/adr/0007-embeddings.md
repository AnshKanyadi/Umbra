# ADR 0007: One pinned embedding model, and its version is part of the index

- Status: accepted
- Date: 2026-09-08
- Depends on: [ADR 0006](0006-chunking.md)
- Depended on by: ADR 0005 (the index), Phase 5 (shared index sync)

## Context

Two questions, and only one of them is about quality.

The quality question is which model to run on a laptop. The **correctness**
question is what happens when two devices in one vault do not run the same one.
A vector from model A and a vector from model B are numbers of the same shape
with no relationship. Cosine similarity between them is not a bad answer, it is
a meaningless one, and nothing in the arithmetic says so. Phase 5 syncs the
index; if it merges segments from two models the result is a store where
distance means nothing and search degrades in a way no test would flag.

So the version is designed into the identity now, before anything syncs,
because retrofitting it means rewriting the store.

## Vectors do not have to be bit-identical across devices

This is worth settling before the model choice, because it decides how much the
choice has to carry.

Chunking is bit-deterministic (ADR 0006) and floating-point inference is not:
the same model on two machines can differ in the last bits from SIMD width,
fused multiply-add, or thread count in a reduction. If devices had to agree on
vectors, that would be a serious constraint.

They do not, because **Phase 5 shares segments as sealed bytes rather than
recomputing them**. A segment is built once, by one device, and copied. Two
devices never independently embed the same chunk and compare results. What has
to match is the *model*, so that vectors built by one device sit in the same
space as vectors built by another -- which is what the model id is for.

So: chunk boundaries must be identical, vectors need only be compatible. Those
are different requirements and conflating them would have cost either
determinism theatre around inference or a real correctness hole.

## The model

The design is one pinned model whose identity is part of the index. Which model
is a quality question, answered by measurement in item 5 rather than by
reputation here.

**Available and measured on this machine:**

| | dims | disk | status |
|---|---|---|---|
| `all-minilm` (all-MiniLM-L6-v2) | 384 | ~46 MB | Present. 256-token window. |
| `nomic-embed-text-v1.5` | 768 | ~274 MB | **Chosen**, at a floor of 0.60. See the measurement below. |

**Wanted and not obtainable here.** `bge-small-en-v1.5` is the model this would
otherwise default to -- 384 dimensions with a 512-token window that matches the
chunk ceiling, and stronger retrieval than all-MiniLM at the same width. It is
not in the Ollama registry under a name that resolves, so it is **not** named as
the default: a default nobody in this repository can run is a claim, not a
decision. The interface takes a model name, so adopting it later is
configuration rather than a change.

The candidates that were rejected outright, with reasons:

| | dims | disk | why not |
|---|---|---|---|
| bge-base-en-v1.5 | 768 | ~110 MB | Twice the vector and roughly three times the encode time for a few points on a personal corpus. |
| e5-large-v2 | 1024 | ~330 MB | Laptop-hostile. A cold index of a few thousand notes becomes an afternoon and the store triples. |
| OpenAI text-embedding-3 | 1536 | n/a | Rejected on the threat model. Sending note text to a third party is the thing this project exists not to do. There is no configuration flag for this. |

**The tradeoff, stated plainly.** 384 dimensions is the smallest width that
still retrieves usefully. Against 768 it costs accuracy on hard queries, and it
halves the index, halves the distance arithmetic, and keeps a cold index to
minutes rather than an afternoon. For a personal vault searched by its author,
who can rephrase in two seconds, that is the right side of the trade. For a
corpus where a missed result is expensive it would not be. The measurement in
item 5 is what decides between the two available widths, and its numbers are
reported whichever way they fall.

**The 256-token window on all-MiniLM is a real mismatch** with a 1536-byte chunk
ceiling: a chunk at the ceiling will be truncated by the model, silently. That
is a point against it that the benchmark numbers alone will not show, and it is
recorded here so the decision is not made on recall@k in isolation.

A note on the asymmetry: BGE models want a query prefix (`Represent this
sentence for searching relevant passages: `) on the query side and nothing on
the document side. Getting that wrong costs real recall and produces no error,
so it belongs in the interface rather than in a caller's memory.

## The version is part of the index identity

An `EmbeddingModelId` is the tuple

    (family, version, dimension, quantisation, pooling, normalisation)

hashed to 16 bytes. It is **not** the file's hash: two people who quantise the
same weights with different tool versions produce different files and compatible
vectors, and a store that refused to merge those would be wrong in the annoying
direction. It is not the family name alone either: `bge-small-en-v1.5` at Q4 and
at Q8 are close enough to be tempting and far enough apart to be wrong.

Every segment records it. A segment whose id does not match the index's is not
loaded, and the mismatch is **reported rather than reconciled**, because the
only correct response is to re-embed the corpus and that is the user's decision
to make, not a background task's.

This also settles what happens on upgrade: a new model is a new index identity,
built alongside the old one and swapped when complete. The old segments stay
readable until the swap, so search keeps working while the rebuild runs.

## What the measurement said, and which model it chose

Measured on the ten-note eval corpus in `test/fixtures/eval` with seventeen
questions, fourteen answerable and three that the vault deliberately cannot
answer. `hit@k` counts a question correct when a **passage containing the
expected sentence** is in the top k -- not merely the right file, because the
whole argument for byte ranges is that the second is a weaker claim.

Sweeping the relevance floor:

| model | floor | hit@1 | hit@3 | MRR | refusals (3 are correct) |
|---|---|---|---|---|---|
| all-minilm | 0.10 | 12/14 | 13/14 | 0.893 | 1, of which 1 correct |
| all-minilm | **0.25** | 11/14 | 12/14 | 0.821 | 4, of which 3 correct |
| all-minilm | 0.40 | 7/14 | 7/14 | 0.500 | 8, of which 3 correct |
| nomic-embed-text | 0.25 | 11/14 | 13/14 | 0.857 | **0, of which 0 correct** |
| nomic-embed-text | 0.50 | 11/14 | 13/14 | 0.857 | **0, of which 0 correct** |
| nomic-embed-text | **0.60** | 11/14 | 13/14 | 0.857 | 3, of which 3 correct |
| nomic-embed-text | 0.70 | 8/14 | 8/14 | 0.571 | 8, of which 3 correct |

**The decisive column is the last one.** nomic-embed-text at any floor up to
0.50 answers all three questions the vault cannot answer -- the exact failure
this feature is designed to prevent -- because its scores are compressed into a
narrow band. At 0.60 it refuses all three correctly and gives up nothing:
11/14 and 13/14, the same as at 0.25.

all-minilm never reaches that. Its best refusal-correct setting (0.20-0.25)
costs a false refusal, and its best retrieval setting (0.10) answers two of the
three it should decline.

**So: `nomic-embed-text` at a floor of 0.60**, which is the opposite of what the
reputation ordering would have predicted and is the reason this was left to
measurement. The cost is real and is stated: 768 dimensions rather than 384, so
the index is 15.4x the source rather than 8.8x, and embedding runs at 28 chunks
per second rather than 37.

**The sample is small and the difference between 11/14 and 12/14 is one
question.** Seventeen questions over ten notes is enough to catch a broken
configuration and not enough to rank two working ones by a point of MRR. What it
does show clearly, because the effect is categorical rather than marginal, is
that the floor has to be tuned per model: a single default would have been
either useless or far too strict for one of these two.

## Consequences

- **Re-embedding is a first-class operation**, not a migration script. It has to
  be, because the model will change.
- **The index is not portable to a device that cannot run the model.** Stated in
  the threat model rather than discovered.
- **Nothing leaves the machine.** The model runs locally; there is no embedding
  endpoint and no key to configure. That is the point of the project and it is
  also why the model has to be small enough to actually run.
