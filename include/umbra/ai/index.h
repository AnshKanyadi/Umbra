// The vector index: a manifest in Basalt naming sealed segments on disk.
//
// ---------------------------------------------------------------------------
// THE SHAPE, AND WHY IT IS THIS ONE
//
// ADR 0001 already decided what a syncable artefact looks like in this project:
// small authoritative records in Basalt, large immutable blobs beside it,
// content-addressed. The index follows that rather than inventing a second
// shape, because Phase 5 has to move segments between devices and a store built
// as one mutable file would have to be thrown away to get there.
//
//   manifest (Basalt)          segments (files)
//   -----------------          ----------------
//   which segments exist  -->  <hex id>.seg   sealed, immutable
//   which slots are dead
//   which object is where
//
// ---------------------------------------------------------------------------
// INCREMENTAL, BECAUSE REINDEXING A VAULT TO EDIT ONE NOTE IS NOT AN OPTION
//
// Editing a note writes a NEW segment holding only that note's chunks, and
// tombstones the slots its previous chunks occupied. Nothing else is touched
// and nothing else is re-embedded. The cost is that segments accumulate, and
// search has to visit each one, which is what compaction is for.
//
// This is the same bargain the oplog made, and it has the same failure mode if
// the second half is never built: a store that only grows. So Compact() exists
// in this phase rather than being left for later.
//
// ---------------------------------------------------------------------------
// DELETES ARE TOMBSTONES BECAUSE HNSW CANNOT DO BETTER
//
// A graph edge removed from a live index strands whatever was only reachable
// through it. Every real implementation tombstones and rebuilds; segments make
// that the ordinary path. A tombstoned slot is still TRAVERSED during search --
// its edges may be the only route to its neighbours -- and is filtered out of
// the results. Compaction is what actually reclaims it.
#ifndef UMBRA_AI_INDEX_H_
#define UMBRA_AI_INDEX_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "umbra/ai/chunk.h"
#include "umbra/ai/embed.h"
#include "umbra/ai/manifest.h"
#include "umbra/ai/segment.h"
#include "umbra/crypto/keys.h"

namespace umbra {
namespace ai {

// Closed; -Werror=switch applies.
enum class IndexStatus : uint8_t {
  kOk,
  // The manifest could not be opened or written.
  kStoreFailed,
  // A segment file named by the manifest is missing, unreadable, or fails its
  // own integrity check.
  kSegmentLost,
  // A segment was built by a different embedding model. Reported, never
  // reconciled; see embed.h.
  kModelMismatch,
  // The caller passed something inconsistent: mismatched lengths, a vector of
  // the wrong width.
  kBadArgument,
};

const char* IndexStatusName(IndexStatus s);

// One hit, with everything a citation needs.
struct SearchHit {
  ObjectId object;
  uint32_t start = 0;
  uint32_t end = 0;
  uint32_t ordinal = 0;
  ChunkKind kind = ChunkKind::kProse;
  uint32_t link_ratio = 0;
  std::string heading_path;
  float score = 0.0f;
  SegmentId segment;
  uint32_t slot = 0;
};

struct IndexStats {
  uint32_t segments = 0;
  uint32_t vectors = 0;  // live plus tombstoned
  uint32_t tombstoned = 0;
  uint64_t segment_bytes = 0;
  uint32_t objects = 0;
};

class Index {
 public:
  ~Index();

  // Opens or creates an index under `dir`. `model` is the identity every
  // segment must match; a segment that does not is refused at open and the
  // caller is told rather than having it silently skipped.
  //
  // `replica` is the id this device signs its manifest operations with -- the
  // same id the oplog and the CRDTs use, because one device has one identity.
  // It is required rather than optional: an index that cannot say who changed
  // it cannot replicate, and an overload that quietly invented one would be a
  // way to build an index that looks replicable and is not.
  static IndexStatus Open(const std::string& dir, const VaultKeys* keys,
                          Epoch epoch, const EmbeddingModelId& model,
                          uint32_t dimension, const ReplicaId& replica,
                          std::unique_ptr<Index>* out);

  // Replace everything indexed for `object` with these chunks and vectors.
  // Writes one new segment and tombstones the object's previous slots. Passing
  // no chunks is how a deleted note is removed.
  IndexStatus PutObject(const ObjectId& object,
                        const std::vector<Chunk>& chunks,
                        const std::vector<Vector>& vectors);

  // Remove an object entirely. Equivalent to PutObject with nothing.
  IndexStatus RemoveObject(const ObjectId& object);

  // Nearest `k` across every segment. `ef` is the per-segment beam.
  IndexStatus Search(const Vector& query, uint32_t k, uint32_t ef,
                     std::vector<SearchHit>* out) const;

  // Exhaustive search over every live vector. What recall is measured against,
  // and slow by design.
  IndexStatus BruteForce(const Vector& query, uint32_t k,
                         std::vector<SearchHit>* out) const;

  // Merge segments and drop tombstoned slots. Returns how many segments were
  // read and how many vectors were reclaimed.
  //
  // `min_segments` is the number below which it does nothing, so an idle vault
  // does not rewrite its index; `max_dead_ratio` is the fraction of dead slots
  // above which a segment is worth rewriting on its own.
  IndexStatus Compact(uint32_t min_segments, uint32_t max_dead_ratio_percent,
                      uint32_t* merged, uint32_t* reclaimed);

  IndexStats Stats() const;

  // ------------------------------------------------------------ replication
  //
  // The index is not the thing that talks to a relay -- that is the client, and
  // this layer must not learn about sockets. What it exposes instead is the two
  // halves replication needs: the operations it produced, and a door for
  // operations that arrived.

  // Manifest operations this device generated and has not yet handed out, in
  // the order it made them. Cleared by TakePending.
  std::vector<ManifestOp> TakePending();

  // Apply a manifest operation that arrived from another device. Segment bytes
  // are NOT required to be present: the fold records what exists and the safety
  // condition decides what is live. See manifest.h.
  ManifestApply ApplyManifestOp(const ManifestOp& op);

  // Adopt a segment whose bytes arrived from elsewhere. Verifies the content
  // hash and the model before anything is written, so a corrupted or foreign
  // segment is refused at the door rather than discovered during a search.
  IndexStatus AdoptSegment(const std::string& sealed);

  // Segments the manifest names that this device does not hold. What a puller
  // asks the relay for.
  std::vector<SegmentId> Missing() const;

  // Segments this device holds that the manifest says are retired but which are
  // still live because their replacement has not arrived. Exists so a client
  // can explain why its index is larger than the manifest implies.
  std::vector<SegmentId> AwaitingReplacement() const;

  // THE HONEST ANSWER TO "IS THIS INDEX COMPLETE". False when the manifest
  // names segments this device does not have, which is exactly the state a
  // device is in after pulling operations but before pulling bytes. Search
  // still works; it is simply searching less than the vault holds, and a caller
  // that reports results as complete while this is false is lying.
  bool Complete() const;

  const ManifestDoc& manifest() const;

  // Every segment id the manifest names, in a stable order. Exists so a test
  // can assert byte-for-byte reproducibility of the files themselves.
  std::vector<SegmentId> SegmentIds() const;

 private:
  Index();
  // Drop segments whose retirement has become safe. See the safety condition in
  // manifest.h: safe means the superseding segment is present here.
  void Prune();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_INDEX_H_
