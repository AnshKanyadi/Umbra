// The index manifest as a CRDT, so two devices can index at the same time.
//
// ---------------------------------------------------------------------------
// WHY THE MANIFEST HAS TO BE A CRDT AND NOT A FILE
//
// Phase 4's manifest was local state in Basalt: a device wrote it, a device
// read it, and nobody else existed. This phase makes segments travel, and the
// moment two devices can both add one, "the manifest" is a value two writers
// disagree about. A last-writer-wins file would lose an index built while
// another device was offline, silently, and the symptom would be search that is
// worse on one machine.
//
// So manifest changes are OPERATIONS in the existing oplog, under a reserved
// object id, travelling through the same relay with the same back-pointer chain
// and the same cursor as tree and text operations. Nothing new transports them.
//
// ---------------------------------------------------------------------------
// THE LATTICE
//
// Three grow-only sets:
//
//   added      (segment id) -> what it holds
//   tombstoned (segment id, slot)
//   retired    (segment id) -> the segment that supersedes it
//
// Union is commutative, associative and idempotent, so the fold of a set of
// operations does not depend on the order they arrive in and re-delivery costs
// nothing. There is no state a second writer can clobber, because there is no
// state -- only operations, and a function from them.
//
// ---------------------------------------------------------------------------
// THE SAFETY CONDITION FOR RETIREMENT, STATED BEFORE IT WAS BUILT
//
// Compaction produces a new segment and retires the ones it merged. On one
// device that is safe by construction: the new segment is written before the
// old ones are removed. Across devices it is not, and the failure is silent.
//
// Device A compacts S1 and S2 into T and publishes kAdd(T), kRetire(S1 -> T),
// kRetire(S2 -> T). Device B pulls the operations -- which are small -- long
// before it pulls T, which is large. If B applied the retirements on arrival it
// would drop S1 and S2 from its live set while holding nothing that replaces
// them, and every chunk they held would vanish from B's search results until
// the transfer finished. No error, just a window where the index is quietly
// incomplete.
//
//     A RETIREMENT IS A FACT IN THE LOG IMMEDIATELY AND A STATE TRANSITION
//     ONLY WHEN THE SUPERSEDING SEGMENT IS PRESENT LOCALLY. Until then the
//     retired segment stays live.
//
// Which gives, precisely:
//
//     live(S) iff added(S)
//               and not (retired(S -> T) and present(T) for some such T)
//
// and the corollary that a device never needs to know whether its peers have
// caught up. It is the same shape as the back-pointer chain in ADR 0001: refuse
// to advance past something you do not hold, rather than trusting that it will
// arrive.
//
// The condition is safe in both directions:
//
//   - it never drops data, because a segment is only stopped from answering
//     once its replacement can answer;
//   - it never keeps data forever, because `present(T)` becomes true as soon as
//     the segment is pulled, and pulling is driven by the manifest itself.
//
// The cost is that a device which never pulls T keeps S1 and S2 on disk. That
// is a device that is not syncing, and its index being larger than necessary is
// the least of what is wrong.
//
// ---------------------------------------------------------------------------
// CONCURRENT COMPACTION
//
// Compaction input selection is a PURE FUNCTION of the manifest state. Two
// devices that see the same manifest choose the same inputs, and because
// segment building is deterministic (ADR 0005) they produce the same content
// addressed id -- so the two kAdd operations are the same operation and the
// lattice absorbs them. Concurrent compaction of the same view is idempotent
// rather than conflicting.
//
// Two devices with DIFFERENT views can still choose different inputs and
// produce overlapping outputs. That is a duplicate-results problem, not a
// correctness one, and it is handled where it shows: search deduplicates by
// (object, start, end) so a chunk held twice is returned once.
#ifndef UMBRA_AI_MANIFEST_H_
#define UMBRA_AI_MANIFEST_H_

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "umbra/ai/embed.h"
#include "umbra/ai/segment.h"
#include "umbra/crdt/op_id.h"

namespace umbra {
namespace ai {

// The reserved object the manifest's operations live under, alongside
// TreeObject(). Manifest operations are pushed, fetched, chained and cursored
// exactly as tree operations are.
ObjectId IndexObject();

// Closed; -Werror=switch applies.
enum class ManifestOpKind : uint8_t {
  // A segment exists and holds `count` vectors.
  kAdd = 1,
  // One slot in a segment is dead. Grow-only: a tombstone is never lifted.
  kTombstone = 2,
  // A segment has been superseded by another. See the safety condition above:
  // this does not take effect until the superseding segment is present.
  kRetire = 3,
};

const char* ManifestOpKindName(ManifestOpKind k);

struct ManifestOp {
  OpId id;
  ManifestOpKind kind = ManifestOpKind::kAdd;

  SegmentId segment;
  // kAdd only.
  uint32_t count = 0;
  uint64_t bytes = 0;
  EmbeddingModelId model;
  // kTombstone only.
  uint32_t slot = 0;
  // kRetire only: the segment that replaces this one.
  SegmentId superseded_by;

  // The back-pointer, exactly as in op.h: the counter of the previous manifest
  // operation from this replica, or 0 for its first.
  uint64_t prev = 0;
};

std::string EncodeManifestOp(const ManifestOp& op);
bool DecodeManifestOp(const std::string& in, ManifestOp* out);

// What a folded manifest says about one segment.
struct SegmentState {
  SegmentId id;
  uint32_t count = 0;
  uint64_t bytes = 0;
  EmbeddingModelId model;
  std::set<uint32_t> dead;
  // Empty when nothing has retired it.
  std::vector<SegmentId> superseded_by;
  // Which replica added it, for reporting and for the "who indexed" question.
  ReplicaId added_by;
  OpId added_at;
};

// Closed; -Werror=switch applies.
enum class ManifestApply : uint8_t {
  kApplied,
  // Seen before. Normal: the relay may resend and a peer may deliver twice.
  kDuplicate,
  // Structurally impossible, or a kAdd for a segment already added with
  // different contents.
  kMalformed,
  // The operation names an embedding model this index does not use. Reported,
  // never merged; see embed.h.
  kModelMismatch,
};

const char* ManifestApplyName(ManifestApply a);

// The fold. Holds no segment bytes: it is the answer to "which segments should
// this device have, and which of their slots are live".
class ManifestDoc {
 public:
  explicit ManifestDoc(const EmbeddingModelId& model);

  ManifestApply Apply(const ManifestOp& op);

  // Which segments this device should be holding, in id order. A device pulls
  // whatever is in here that it does not have.
  std::vector<SegmentId> Wanted() const;

  // THE SAFETY CONDITION, EVALUATED. `present` answers whether a segment's
  // bytes are on this device. A retired segment stays live until whatever
  // supersedes it is present.
  //
  // Passing a predicate rather than a set keeps this a pure function of the
  // operations plus what the caller can see, which is what makes it testable
  // without a store.
  template <typename Present>
  std::vector<SegmentId> Live(const Present& present) const {
    std::vector<SegmentId> out;
    for (const std::pair<const SegmentId, SegmentState>& kv : segments_) {
      if (!present(kv.first)) continue;
      bool replaced = false;
      for (const SegmentId& by : kv.second.superseded_by) {
        if (present(by)) {
          replaced = true;
          break;
        }
      }
      if (!replaced) out.push_back(kv.first);
    }
    return out;
  }

  // Segments that a retirement is waiting on: retired, still live because the
  // replacement has not arrived. Exists so a client can say why its index is
  // larger than the manifest implies, rather than leaving it a mystery.
  template <typename Present>
  std::vector<SegmentId> AwaitingReplacement(const Present& present) const {
    std::vector<SegmentId> out;
    for (const std::pair<const SegmentId, SegmentState>& kv : segments_) {
      if (kv.second.superseded_by.empty()) continue;
      if (!present(kv.first)) continue;
      bool replaced = false;
      for (const SegmentId& by : kv.second.superseded_by) {
        if (present(by)) replaced = true;
      }
      if (!replaced) out.push_back(kv.first);
    }
    return out;
  }

  const SegmentState* Get(const SegmentId& id) const;
  const std::map<SegmentId, SegmentState>& segments() const {
    return segments_;
  }
  const EmbeddingModelId& model() const { return model_; }

  // How many operations this fold has absorbed, and how many were refused for a
  // model mismatch. Reported rather than counted silently, because a device
  // refusing everything should be able to say so.
  uint64_t applied() const { return applied_; }
  uint64_t refused_model() const { return refused_model_; }

 private:
  EmbeddingModelId model_;
  std::map<SegmentId, SegmentState> segments_;
  std::set<OpId> seen_;
  uint64_t applied_ = 0;
  uint64_t refused_model_ = 0;
};

// Which segments to compact, as a pure function of the manifest and what is
// present. Two devices with the same view choose the same inputs and therefore
// build the same segment; see the note on concurrent compaction above.
//
// Tiered by size: small segments merge with small segments. `tier_ratio` is how
// much larger a segment may be than the smallest before it is left out of the
// round, which is what keeps a routine merge from rewriting the whole index.
struct CompactionPlan {
  std::vector<SegmentId> inputs;
  uint32_t live_vectors = 0;
  uint32_t dead_vectors = 0;
  const char* reason = "nothing to do";
};

CompactionPlan PlanCompaction(const ManifestDoc& manifest,
                              const std::vector<SegmentId>& live,
                              uint32_t min_segments,
                              uint32_t max_dead_ratio_percent,
                              uint32_t tier_ratio);

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_MANIFEST_H_
