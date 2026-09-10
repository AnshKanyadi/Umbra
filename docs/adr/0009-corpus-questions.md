# ADR 0009: Corpus questions are answered by structure, not by reading everything

- Status: accepted
- Date: 2026-09-10
- Depends on: [ADR 0005](0005-index.md), [ADR 0007](0007-embeddings.md)

## Context

Retrieval answers questions about **things in** the notes. It cannot answer
questions about the notes **as a whole**, because it never sees the whole: it
sees the k passages a search returned.

Ask it to summarize a vault and it returns six chunks and summarizes those. On a
25-note vault of algorithm notes, "summarize what is in these notes" produced a
confident paragraph about merge sort, recursion, palindromes, backtracking,
tries and two sum. The other nineteen notes — depth first search, Dijkstra,
dynamic programming, binary search — were simply absent.

**Every guard passed, and each was right to.** The citations resolved. The
passages really did support each sentence. The model honestly reported that the
passages answered the question, because a summary of six chunks *is* a true
summary of six chunks. The answer was correct about the passages and wrong about
the question, and no property of the text distinguishes those two.

Score shape cannot separate this case either. Corpus questions retrieve a flat,
low cluster — gap 0.002 to 0.027 against 0.072 and up for real hits — which is
the same signature as a near miss, for the opposite reason: everything is
equally relevant rather than equally irrelevant.

## What was rejected: a map-reduce survey over every note

The obvious answer is to read everything: one model call per note producing a
one-line summary, then reduce those in batches until one summary remains. It was
specified in full and measured before being written. The measurements killed it.

**Cost is per note, not per byte.** A 165-byte note and a 2,844-byte note each
take about 0.8s, because the time goes on decoding the one-sentence output
rather than reading the input. So:

| vault | model calls | wall clock |
|---|---|---|
| 25 notes | 26 | ~21s |
| 3,000 notes | 3,031 | **~41 minutes** |

**Batching does not help.** Ten notes in one call took 20.9s against 7.9s for
ten separate calls. Decode attends over everything in the context, so a long
prompt makes every generated token more expensive. Many small calls beat few
large ones. (Allocating a large context window is free — 4096, 8192 and 16384
answered an identical prompt in 0.40s. It is the tokens actually present that
cost, not the size of the window.)

**The reduce step destroys what the survey was for.** With a fan-in of about 100
summaries per call, 3,000 notes reduce in two levels. At depth two the output is
a summary of summaries and the specifics are gone by construction. Measured, on
100 input sentences: *"This collection of notes covers various topics in
distributed systems, specifically focusing on how they behave under failure
scenarios."* Vague, unfalsifiable, and not fixable by prompting — it is what
compressing 3,000 sentences into one paragraph means.

**And the guards do not transfer.** A survey cannot meet the citation contract
this project already states: a citation names a passage, not a file. The best a
survey can do is name notes, and after one reduce even that is gone, because
level-two claims derive from level-one sentences rather than from text. The
ANSWER / NO-ANSWER verdict is meaningless when the input is the whole vault.
Only the coverage line survives. A survey would be **less** checked than an
ordinary answer, while looking more authoritative.

Forty-one minutes to produce an unfalsifiable sentence, with fewer guarantees
than the thing it replaces, is the wrong trade.

## What was built instead

The index already holds an embedding of every chunk. The structure of a vault is
in those vectors and does not need to be read out of the notes again.

So a corpus question is answered by clustering what is already computed, and the
answer is **countable rather than narrative**: named groups, how many chunks and
notes fall in each, and example notes per group. That is a better answer to
"what is in my notes" than prose, and every guard still means something, because
a cluster is a set of real chunks with real ids.

## Consequences

- **Corpus questions are served, not declined.** Declining them would be a worse
  product; they are a reasonable thing to want.
- **The expensive path is named, never inferred.** There is no trigger to get
  wrong: the user chooses the mode, which removes the classification problem
  rather than solving it.
- **A cluster label is a guess; a cluster membership is a fact.** The counts and
  the members are exact. The name attached to a group is a model's description
  of it and is worth what such a description is worth.
- **Narrative summarization of a whole vault remains unavailable.** That is a
  real gap and it is deliberate. If it is ever built, the reduce-depth
  measurement above is the thing to argue with.
