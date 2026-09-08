// Splitting a markdown note into passages worth embedding.
//
// ---------------------------------------------------------------------------
// DETERMINISM IS A CORRECTNESS REQUIREMENT, NOT A NICETY
//
// Phase 5 shares one index between devices. If two devices split the same bytes
// differently they produce different chunks, different vectors, and citations
// that point at passages the other device does not have. Nothing errors. The
// symptom is search that is quietly worse on one machine than another, which is
// the hardest class of bug to notice and the hardest to attribute.
//
// So chunking is a pure function of the bytes, and everything that could make
// it depend on the machine is excluded by construction:
//
//   - NO LOCALE. `isspace` and friends are locale-sensitive and this file uses
//     hand-written classifiers over `unsigned char` instead.
//   - NO PLAIN `char` COMPARISONS ABOVE 0x7F. `char` is signed on x86 and
//     unsigned on ARM, so `c >= 0x80` is false on one and true on the other for
//     the same byte. Every byte is loaded through `Byte()`, which casts.
//   - NO FLOATING POINT anywhere in a boundary decision.
//   - NO UNORDERED CONTAINERS in anything that affects output order.
//   - NO REGEX. Implementations differ and the ones that do not are slow.
//   - FIXED WIDTH OFFSETS. `std::size_t` is 32 bits on some targets, so a
//     document that chunks one way on a 64-bit machine could overflow
//     differently on a 32-bit one. Offsets are uint32_t and the maximum
//     document size is stated and enforced.
//
// test/chunk_test.cc asserts a golden digest over the chunk boundaries of a
// fixture corpus. The CI matrix runs it on macOS/arm64 and Linux/x86-64 under
// three compilers, which is what makes "deterministic" a measurement rather
// than an intention.
//
// ---------------------------------------------------------------------------
// THE BUDGET IS IN BYTES, DELIBERATELY, AND NOT IN TOKENS
//
// The obvious unit is tokens, because that is what the embedding model counts.
// It is the wrong unit here: a tokenizer is part of a model, so chunking in
// tokens makes chunk boundaries a function of the model version. Phase 5 puts
// the model version in the index identity; if boundaries moved with it, then
// changing models would not merely re-embed the corpus, it would renumber every
// citation and invalidate every stored byte range.
//
// Bytes keep chunking independent of the model. The cost is that the budget has
// to be conservative enough that the worst case still fits the model's context.
// See kTargetBytes.
//
// ---------------------------------------------------------------------------
// WHAT IS NEVER SPLIT
//
// A fenced code block, a table, and front matter are atomic. A code block cut
// in half is worse than useless -- it embeds as something that looks like code
// but compiles as nothing, and it cites a passage that misleads whoever follows
// it. A table cut below its header row is a grid of values with no column
// names.
//
// When one of those is larger than the budget on its own it becomes an
// oversized chunk rather than being split, EXCEPT for tables, which are split
// at row boundaries with the header row carried into each piece. See
// docs/adr/0006-chunking.md.
#ifndef UMBRA_AI_CHUNK_H_
#define UMBRA_AI_CHUNK_H_

#include <cstdint>
#include <string>
#include <vector>

#include "umbra/change_event.h"

namespace umbra {
namespace ai {

// A document larger than this is refused rather than chunked. Offsets are
// uint32_t; the limit is far below the type's range so that arithmetic on a
// range can never wrap, and far above any markdown note a person writes.
constexpr uint32_t kMaxDocumentBytes = 64u * 1024 * 1024;

// The size a chunk aims for, and the size it may reach before a split is
// forced. Bytes, not tokens: see the note above.
//
// 1024 bytes of English markdown is roughly 256 tokens, and the ceiling of 1536
// is roughly 384. Both sit well inside the 512-token window of the model in
// ADR 0007, with room for the heading path that gets prefixed and for text that
// tokenizes worse than English prose -- code, tables, and CJK all do.
constexpr uint32_t kTargetBytes = 1024;
constexpr uint32_t kMaxBytes = 1536;

// Below this a chunk is merged into its neighbour rather than embedded alone. A
// heading with two words under it is not a passage.
constexpr uint32_t kMinBytes = 64;

// Closed; -Werror=switch applies.
enum class ChunkKind : uint8_t {
  // Ordinary prose, possibly several paragraphs.
  kProse,
  // A fenced code block, whole. Never split.
  kCode,
  // A table, or a piece of one. A piece carries the header row in `text` but
  // not in its byte range.
  kTable,
  // YAML or TOML front matter from the top of the file.
  kFrontMatter,
  // A list whose lines are overwhelmingly links. See link_ratio.
  kLinkList,
  // A list, or a run of list items.
  kList,
  // A blockquote, including the callout forms.
  kQuote,
};

const char* ChunkKindName(ChunkKind k);

struct Chunk {
  // WHERE THE CITATION POINTS. A half-open byte range into the document's text
  // as the CRDT holds it -- not into the file on disk, which may differ by line
  // endings, and not into `text`, which may have a heading path prefixed.
  ObjectId object;
  uint32_t start = 0;
  uint32_t end = 0;

  // WHAT GETS EMBEDDED, which is deliberately not the same as the bytes cited.
  // A chunk taken from deep in a document is much easier to retrieve when it
  // carries the headings above it, and a table fragment is meaningless without
  // its header row. Both are prefixed here and neither is inside [start, end).
  std::string text;

  // The headings above this chunk, outermost first, joined with " > ". Empty
  // for a chunk before the first heading.
  std::string heading_path;

  ChunkKind kind = ChunkKind::kProse;

  // Per ten thousand, so this stays an integer: a link-dominated note is a real
  // thing in a vault and this is how the retrieval layer knows to expect one.
  // See the note on link_ratio in the .cc.
  uint32_t link_ratio = 0;

  // Index of this chunk within its document, from zero. Part of a chunk's
  // identity along with the object id.
  uint32_t ordinal = 0;

  uint32_t bytes() const { return end - start; }
};

// Closed; -Werror=switch applies.
enum class ChunkStatus : uint8_t {
  kOk,
  // Larger than kMaxDocumentBytes.
  kTooLarge,
  // Not valid UTF-8. Refused rather than split at a byte that is halfway
  // through a code point.
  kNotUtf8,
};

const char* ChunkStatusName(ChunkStatus s);

struct ChunkOptions {
  uint32_t target_bytes = kTargetBytes;
  uint32_t max_bytes = kMaxBytes;
  uint32_t min_bytes = kMinBytes;
  // Prefix each chunk's embedded text with the headings above it.
  bool prefix_heading_path = true;
};

// Split one document. Deterministic: the same bytes and the same options give
// byte-identical output on every platform.
ChunkStatus ChunkMarkdown(const ObjectId& object, const std::string& text,
                          const ChunkOptions& options, std::vector<Chunk>* out);

// The same with default options.
ChunkStatus ChunkMarkdown(const ObjectId& object, const std::string& text,
                          std::vector<Chunk>* out);

// A digest over the chunk BOUNDARIES and kinds of a document -- not over the
// text, which is already known to both sides. Two devices that agree on this
// agree on how the document was split. Exists so a determinism test can compare
// one value instead of a vector, and so Phase 5 can put it in a manifest.
std::string ChunkingDigest(const std::vector<Chunk>& chunks);

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_CHUNK_H_
