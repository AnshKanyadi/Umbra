# ADR 0006: Markdown is chunked by structure, under a byte budget

- Status: accepted
- Date: 2026-09-08
- Depends on: [ADR 0001](0001-storage.md),
  [docs/threat-model.md](../threat-model.md)
- Depended on by: ADR 0007 (embeddings), ADR 0005 (the index)

## Context

Phase 5 shares one index between devices. That makes chunking a **correctness**
problem before it is a quality problem: if two devices split the same note
differently they produce different chunks, different vectors, and citations that
point at passages the other device does not have.

Nothing errors when that happens. The symptom is search that is quietly worse on
one machine than another, with nothing to attribute it to. It is the hardest
class of bug to notice, so the design excludes it by construction rather than
detecting it later.

The second problem is that markdown is not prose. Chunking it as if it were --
fixed windows over a character stream -- is why most local retrieval over notes
is bad. A window boundary lands in the middle of a code block, and the result
embeds as something that looks like code and compiles as nothing.

## Decision

A two-pass chunker (`src/ai/chunk.cc`): scan the document into typed blocks,
then group blocks into chunks under a byte budget, with structural rules about
what may be cut.

### The budget is in bytes, not tokens

The obvious unit is tokens, because that is what an embedding model counts. It
is the wrong unit here. **A tokenizer is part of a model**, so chunking in
tokens would make chunk boundaries a function of the model version. ADR 0007
puts the model version in the index identity; if boundaries moved with it,
changing models would not merely re-embed the corpus, it would renumber every
chunk and invalidate every stored byte range and every citation.

Bytes keep chunking independent of the model. The cost is that the budget must
be conservative enough that the worst case still fits the model's context:
1024 bytes target, 1536 ceiling, against a 512-token window. English markdown
runs about four bytes to the token; code, tables and CJK tokenize worse, and the
ceiling is set for them rather than for the average.

### What is never split

| Construct | Rule |
|---|---|
| Fenced code block | Atomic. Oversized becomes one oversized chunk. |
| Front matter | Atomic, and only recognised at offset zero. |
| Table that fits | Atomic. |
| Table that does not fit | Split at row boundaries, header carried into every piece. |

**A code block cut in half is worse than useless.** It embeds as something that
resembles code and is not, and it cites a passage that misleads whoever follows
the citation. An oversized chunk is a worse vector; a split one is a wrong
answer. So the block is kept whole and the budget loses.

**A fence inside a list item is still a fence.** The block scanner treats a run
of list items as one block, so a ```` ```sh ```` inside item three never reaches
the fence branch. That is harmless while the list fits and is exactly the above
failure once it does not. The line splitter therefore tracks fence state and
refuses to cut inside one. The boundary is judged by the state as of the
*previous* line: updating first and then deciding let a closing fence clear the
flag and permit a cut immediately before itself. `test/fixtures/chunking/
listcode.md` is the fixture that found it.

**A table fragment without its header is a grid with no column names.** When a
table exceeds the ceiling it is split at row boundaries and each piece carries
the header row *in the text it embeds but not in its byte range*, so two pieces
never cite the same bytes.

### What happens to the awkward notes

The prompt asked about two real cases.

**A note that is mostly links** -- an index, a map of content, a daily note that
is only references. Embedding it gives a vector that sits near every other list
of links, because that is what the text is: link syntax and titles with almost
no prose. It is **not** dropped: it is often the one note that names where
everything else lives. It is chunked normally, its link density is measured
(`LinkRatio`, per ten thousand so the number stays an integer), and a list chunk
above 60% is typed `kLinkList`. The measurement travels with the chunk so the
retrieval layer can decide what such a vector is worth; the chunker does not
decide for it.

**A note that is a single table** stays a single chunk if it fits, which is the
common case for a small reference table, and splits with header carry if it does
not. `onlytable.md` and `table.md` are the two fixtures.

### Citations point at bytes, not files

Every chunk carries `(object id, start, end)` into the document text as the CRDT
holds it -- not into the file on disk, which can differ by line endings. The
text that gets embedded is deliberately **not** the same as the bytes cited: it
may carry the heading path, and a table piece carries its header. A citation
that named a file but not a location would not be a citation.

### No overlap

Most RAG chunkers overlap windows so a fact split across a boundary survives in
one piece. This does not, because its boundaries are not arbitrary offsets --
they are headings, paragraph ends and block ends, the places an author already
chose. Overlap would duplicate storage and produce near-duplicate hits that then
need deduplicating at retrieval. The heading path prefix does most of what
overlap is for. This is a judgement, not a measurement, and it is the first
thing to revisit if the fixture questions in item 5 show boundary misses.

## Determinism, and how it is checked

Excluded by construction, each for a named reason:

- **No locale.** `isspace` and friends are locale-sensitive; hand-written
  classifiers over `unsigned char` replace them.
- **No plain `char` above 0x7F.** `char` is signed on x86 and unsigned on ARM,
  so `c >= 0x80` gives opposite answers on the two platforms this ships on for
  the same byte. Every byte is loaded through `Byte()`, which casts.
- **No floating point** in any boundary decision.
- **No unordered containers** in anything affecting output order.
- **No regex.** Implementations differ.
- **Fixed-width offsets.** `std::size_t` is 32 bits on some targets; offsets are
  `uint32_t` and the document ceiling is stated and enforced.
- **`.gitattributes` sets `* -text`,** so a Windows checkout cannot rewrite a
  fixture's line endings and change what is being hashed.

The check is a golden BLAKE2b digest over the boundaries and kinds of an
eleven-file fixture corpus -- over the boundaries, not the text, because hashing
the text would hide a boundary disagreement behind a match on content.

Measured, all byte-identical:

| Platform | Toolchain | `char` |
|---|---|---|
| macOS 15, arm64 | clang, libc++ | unsigned |
| Linux, x86-64 | gcc 13, libstdc++ | signed |
| Linux, x86-64 | clang 18, libstdc++ | signed |

and under `-fsigned-char` / `-funsigned-char` on one machine, and under
`LC_ALL` of `C`, `tr_TR.UTF-8` and `de_DE.UTF-8`.

**The signedness check is verified sharp.** Planting `if (s[i] < 0) return
true;` in `IsListItemStart` makes the two builds disagree on the CJK fixture
(`cc878bf9…` against `7abefddd…`). Without the plant they are identical. Two CI
jobs keep both properties guarded.

## Known limits, stated

- **Indented code blocks are not detected.** A four-space-indented run after a
  blank line is a code block in CommonMark; here it is a paragraph or part of a
  list. Distinguishing it from list continuation needs full list-context
  tracking. Fenced blocks are the overwhelmingly common form in a vault and are
  handled; this gap is real and is written down rather than papered over.
- **HTML blocks get no special treatment.** They chunk as paragraphs.
- **Link detection is syntactic**, covering `[[wikilink]]` and `[text](target)`.
  Reference-style links and bare URLs are not counted, so `link_ratio`
  understates for notes that use them.
- **The ASCII case fold** used elsewhere in the vault is not needed here;
  chunking never compares text case-insensitively.
- **No semantic chunking.** Boundaries follow the author's structure, not
  meaning. A long section about two different things is one chunk if it fits.
