// An immutable, sealed, content-addressed index segment.
//
// ---------------------------------------------------------------------------
// THE SHAPE IS BUILT NOW BECAUSE RETROFITTING IT MEANS REWRITING THE STORE
//
// Nothing syncs in this phase. The segment-plus-manifest shape exists anyway,
// because ADR 0001 already decided what a syncable artefact looks like -- a
// manifest in Basalt naming content-addressed files on disk -- and a store
// built as one mutable file would have to be thrown away to get there.
//
// Immutable also solves the problem a mutable graph has: HNSW cannot delete. An
// edge removed from a live graph strands whatever was reachable only through
// it, so real implementations tombstone and rebuild. Segments make that the
// normal path rather than a special case: a delete is a tombstone in the
// manifest, and compaction is a rebuild that drops them.
//
// ---------------------------------------------------------------------------
// WHAT A SEGMENT DOES NOT CONTAIN
//
// Note text. A chunk is stored as (object id, byte range) and the passage is
// read back from the vault when it is needed. Two reasons, and the second is
// the important one:
//
//   - the text is already in the vault, and a second copy is a second thing to
//     keep consistent;
//   - a citation that points into the live document cannot go stale in the way
//     a cached copy can. If the note changed, the citation is wrong in a way
//     the reader can SEE, rather than quietly serving text the vault no longer
//     holds.
//
// It still holds vectors, which encode a great deal about the text, so a
// segment is sealed rather than left as plaintext.
//
// ---------------------------------------------------------------------------
// SEALING WITH A DERIVED NONCE, AND WHY THAT IS SAFE HERE
//
// Segment bytes must be reproducible: item 5 asks for the same input to produce
// the same segment, byte for byte. A random nonce would make the sealed bytes
// different every build, so the nonce is derived from a hash of the plaintext.
//
// Reusing a nonce under one key is normally catastrophic. It is safe in this
// specific shape because the nonce is a collision-resistant hash of the
// plaintext: two different segments get different nonces, and the only way to
// get the same nonce twice is to seal identical bytes, which produces a segment
// that is identical anyway and is already recognisable as such because segments
// are content-addressed.
//
// What it leaks: that two segments are byte-identical. Content addressing leaks
// that regardless. Recorded rather than glossed.
#ifndef UMBRA_AI_SEGMENT_H_
#define UMBRA_AI_SEGMENT_H_

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "umbra/ai/chunk.h"
#include "umbra/ai/embed.h"
#include "umbra/crypto/keys.h"

namespace umbra {
namespace ai {

// Where a stored vector came from. Everything a citation needs and nothing
// more: no text, and no path -- a path is a property of the tree at a moment,
// and the tree is what resolves an object id to one.
struct SegmentEntry {
  ObjectId object;
  uint32_t start = 0;
  uint32_t end = 0;
  uint32_t ordinal = 0;
  ChunkKind kind = ChunkKind::kProse;
  uint32_t link_ratio = 0;
  // Kept because it is short, useful for ranking and display, and would
  // otherwise require reading the whole document back to reconstruct.
  std::string heading_path;
};

// Names a file on disk. The hash of the SEALED bytes, so the name is a check on
// what was actually read.
struct SegmentId {
  std::array<uint8_t, 32> bytes{};
  bool operator==(const SegmentId& o) const { return bytes == o.bytes; }
  bool operator!=(const SegmentId& o) const { return !(*this == o); }
  bool operator<(const SegmentId& o) const { return bytes < o.bytes; }
  std::string Hex() const;
  std::string Short() const;
};

// Closed; -Werror=switch applies.
enum class SegmentStatus : uint8_t {
  kOk,
  // Not a segment, or a version this build does not know.
  kBadFormat,
  // Truncated, or a section that runs past the end. A segment that arrived from
  // elsewhere is not trusted to be well formed.
  kTruncated,
  // The AEAD refused it: wrong key, wrong epoch, or tampering.
  kAuthFailed,
  // Built by a different embedding model. Reported, never reconciled: the only
  // correct response is to re-embed and that is the user's decision.
  kModelMismatch,
  // More vectors or bytes than the format allows.
  kTooLarge,
};

const char* SegmentStatusName(SegmentStatus s);

// A segment held in memory, ready to search.
class Segment {
 public:
  ~Segment();

  // Build from chunks and their vectors. `chunks` and `vectors` must be the
  // same length; every vector must be unit length and of `model`'s dimension.
  static SegmentStatus Build(const EmbeddingModelId& model, uint32_t dimension,
                             const std::vector<SegmentEntry>& entries,
                             const std::vector<Vector>& vectors,
                             std::string* plaintext);

  // Seal built bytes for storage. The id is the hash of the result.
  static SegmentStatus Seal(const VaultKeys& keys, Epoch epoch,
                            const std::string& plaintext, std::string* sealed,
                            SegmentId* id);

  // Open sealed bytes. `expect` is the index's model; a segment built by a
  // different one is refused with kModelMismatch rather than loaded.
  static SegmentStatus Open(const VaultKeys& keys, const std::string& sealed,
                            const EmbeddingModelId& expect,
                            std::unique_ptr<Segment>* out);

  // Nearest `k`, skipping slots marked in `tombstones` (which may be empty).
  // Tombstoned nodes are still traversed; see the note in hnsw.h.
  std::vector<Neighbour> Search(const Vector& query, uint32_t k, uint32_t ef,
                                const std::vector<bool>& tombstones) const;

  // Exhaustive, for measuring the graph against.
  std::vector<Neighbour> BruteForce(const Vector& query, uint32_t k,
                                    const std::vector<bool>& tombstones) const;

  uint32_t count() const;
  uint32_t dimension() const;
  const EmbeddingModelId& model() const;
  const SegmentEntry& entry(uint32_t slot) const;
  const float* vector(uint32_t slot) const;

 private:
  Segment();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_SEGMENT_H_
