#include "umbra/ai/manifest.h"

#include <algorithm>
#include <cstring>

namespace umbra {
namespace ai {
namespace {

constexpr uint8_t kEncodingVersion = 1;

void PutU32(std::string* out, uint32_t v) {
  for (int i = 3; i >= 0; --i) {
    out->push_back(static_cast<char>((v >> (i * 8)) & 0xFF));
  }
}

void PutU64(std::string* out, uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<char>((v >> (i * 8)) & 0xFF));
  }
}

class Reader {
 public:
  explicit Reader(const std::string& s) : s_(s) {}
  bool U8(uint8_t* v) {
    if (at_ + 1 > s_.size()) return false;
    *v = static_cast<uint8_t>(s_[at_++]);
    return true;
  }
  bool U32(uint32_t* v) {
    if (at_ + 4 > s_.size()) return false;
    uint32_t x = 0;
    for (int i = 0; i < 4; ++i) {
      x = (x << 8) | static_cast<uint8_t>(s_[at_ + static_cast<std::size_t>(i)]);
    }
    at_ += 4;
    *v = x;
    return true;
  }
  bool U64(uint64_t* v) {
    if (at_ + 8 > s_.size()) return false;
    uint64_t x = 0;
    for (int i = 0; i < 8; ++i) {
      x = (x << 8) | static_cast<uint8_t>(s_[at_ + static_cast<std::size_t>(i)]);
    }
    at_ += 8;
    *v = x;
    return true;
  }
  bool Bytes(void* p, std::size_t n) {
    if (at_ + n > s_.size()) return false;
    std::memcpy(p, s_.data() + at_, n);
    at_ += n;
    return true;
  }
  bool Done() const { return at_ == s_.size(); }

 private:
  const std::string& s_;
  std::size_t at_ = 0;
};

}  // namespace

ObjectId IndexObject() {
  ObjectId id;
  // Reserved(3), alongside TreeRoot, TreeTrash and TreeObject. Kept as a
  // literal rather than calling tree.cc's private helper, so the ai layer does
  // not reach into the crdt layer's internals for one byte.
  id.bytes[15] = 3;
  return id;
}

const char* ManifestOpKindName(ManifestOpKind k) {
  switch (k) {
    case ManifestOpKind::kAdd:
      return "add";
    case ManifestOpKind::kTombstone:
      return "tombstone";
    case ManifestOpKind::kRetire:
      return "retire";
  }
  return "unknown";
}

const char* ManifestApplyName(ManifestApply a) {
  switch (a) {
    case ManifestApply::kApplied:
      return "applied";
    case ManifestApply::kDuplicate:
      return "duplicate";
    case ManifestApply::kMalformed:
      return "malformed";
    case ManifestApply::kModelMismatch:
      return "model-mismatch";
  }
  return "unknown";
}

std::string EncodeManifestOp(const ManifestOp& op) {
  std::string out;
  out.push_back(static_cast<char>(kEncodingVersion));
  out.push_back(static_cast<char>(op.kind));
  PutU64(&out, op.id.counter);
  out.append(reinterpret_cast<const char*>(op.id.replica.bytes.data()),
             op.id.replica.bytes.size());
  PutU64(&out, op.prev);
  out.append(reinterpret_cast<const char*>(op.segment.bytes.data()),
             op.segment.bytes.size());
  PutU32(&out, op.count);
  PutU64(&out, op.bytes);
  out.append(reinterpret_cast<const char*>(op.model.bytes.data()),
             op.model.bytes.size());
  PutU32(&out, op.slot);
  out.append(reinterpret_cast<const char*>(op.superseded_by.bytes.data()),
             op.superseded_by.bytes.size());
  return out;
}

bool DecodeManifestOp(const std::string& in, ManifestOp* out) {
  Reader r(in);
  uint8_t version = 0;
  if (!r.U8(&version) || version != kEncodingVersion) return false;
  uint8_t kind = 0;
  if (!r.U8(&kind)) return false;
  if (kind < static_cast<uint8_t>(ManifestOpKind::kAdd) ||
      kind > static_cast<uint8_t>(ManifestOpKind::kRetire)) {
    return false;
  }
  out->kind = static_cast<ManifestOpKind>(kind);
  if (!r.U64(&out->id.counter)) return false;
  if (!r.Bytes(out->id.replica.bytes.data(), out->id.replica.bytes.size())) {
    return false;
  }
  if (!r.U64(&out->prev)) return false;
  // The same rule op.cc enforces: a back-pointer must name an EARLIER
  // operation, so a chain cannot point at itself or forward.
  if (out->prev >= out->id.counter) return false;
  if (!r.Bytes(out->segment.bytes.data(), out->segment.bytes.size())) {
    return false;
  }
  if (!r.U32(&out->count)) return false;
  if (!r.U64(&out->bytes)) return false;
  if (!r.Bytes(out->model.bytes.data(), out->model.bytes.size())) return false;
  if (!r.U32(&out->slot)) return false;
  if (!r.Bytes(out->superseded_by.bytes.data(),
               out->superseded_by.bytes.size())) {
    return false;
  }
  return r.Done();
}

ManifestDoc::ManifestDoc(const EmbeddingModelId& model) : model_(model) {}

ManifestApply ManifestDoc::Apply(const ManifestOp& op) {
  if (op.id.counter == 0) return ManifestApply::kMalformed;
  if (!seen_.insert(op.id).second) return ManifestApply::kDuplicate;

  switch (op.kind) {
    case ManifestOpKind::kAdd: {
      if (op.count == 0) {
        seen_.erase(op.id);
        return ManifestApply::kMalformed;
      }
      // REFUSED, NOT MERGED. A segment built by another model holds vectors in
      // a space this one cannot compare against, and mixing them produces a
      // store where distance means nothing with no error anywhere. The
      // operation is counted so a device can say why its index looks empty.
      if (op.model != model_) {
        ++refused_model_;
        ++applied_;
        return ManifestApply::kModelMismatch;
      }
      const std::map<SegmentId, SegmentState>::iterator it =
          segments_.find(op.segment);
      if (it != segments_.end()) {
        // A SECOND kAdd FOR ONE SEGMENT IS NORMAL AND MUST AGREE. Segments are
        // content addressed, so two devices that build the same one really did
        // build the same bytes; disagreement about the count means one of them
        // is lying or the id has collided, and neither should be absorbed
        // quietly.
        if (it->second.count != op.count) {
          return ManifestApply::kMalformed;
        }
        // Keep the earliest add, so `added_by` is stable across devices rather
        // than depending on delivery order.
        if (op.id < it->second.added_at) {
          it->second.added_at = op.id;
          it->second.added_by = op.id.replica;
        }
        ++applied_;
        return ManifestApply::kApplied;
      }
      SegmentState s;
      s.id = op.segment;
      s.count = op.count;
      s.bytes = op.bytes;
      s.model = op.model;
      s.added_at = op.id;
      s.added_by = op.id.replica;
      segments_[op.segment] = s;
      ++applied_;
      return ManifestApply::kApplied;
    }
    case ManifestOpKind::kTombstone: {
      // A TOMBSTONE MAY ARRIVE BEFORE THE SEGMENT IT NAMES. Operations are
      // small and segments are large, so out of order is the common case, not
      // the exception. The entry is created empty and filled in when the kAdd
      // lands; dropping it would lose a deletion.
      SegmentState& s = segments_[op.segment];
      s.id = op.segment;
      s.dead.insert(op.slot);
      ++applied_;
      return ManifestApply::kApplied;
    }
    case ManifestOpKind::kRetire: {
      SegmentState& s = segments_[op.segment];
      s.id = op.segment;
      bool already = false;
      for (const SegmentId& by : s.superseded_by) {
        if (by == op.superseded_by) already = true;
      }
      if (!already) s.superseded_by.push_back(op.superseded_by);
      // Sorted, so the fold does not depend on arrival order. Two devices with
      // the same operations must produce byte-identical state or the
      // convergence claim is only about the parts anyone happened to compare.
      std::sort(s.superseded_by.begin(), s.superseded_by.end());
      ++applied_;
      return ManifestApply::kApplied;
    }
  }
  return ManifestApply::kMalformed;
}

std::vector<SegmentId> ManifestDoc::Wanted() const {
  std::vector<SegmentId> out;
  for (const std::pair<const SegmentId, SegmentState>& kv : segments_) {
    // A segment known only from a tombstone has no count yet: its kAdd has not
    // arrived. Asking for it would be asking for something nobody has said
    // exists.
    if (kv.second.count == 0) continue;
    out.push_back(kv.first);
  }
  return out;
}

const SegmentState* ManifestDoc::Get(const SegmentId& id) const {
  const std::map<SegmentId, SegmentState>::const_iterator it =
      segments_.find(id);
  return it == segments_.end() ? nullptr : &it->second;
}

CompactionPlan PlanCompaction(const ManifestDoc& manifest,
                              const std::vector<SegmentId>& live,
                              uint32_t min_segments,
                              uint32_t max_dead_ratio_percent,
                              uint32_t tier_ratio) {
  CompactionPlan plan;
  if (live.size() < 2) return plan;

  // A PURE FUNCTION OF THE MANIFEST AND THE LIVE SET, with no clock, no random
  // choice and no local preference. Two devices with the same view must select
  // the same inputs, because that is what makes their outputs the same segment
  // and concurrent compaction idempotent rather than conflicting.
  struct Entry {
    SegmentId id;
    uint32_t count = 0;
    uint32_t dead = 0;
  };
  std::vector<Entry> entries;
  for (const SegmentId& id : live) {
    const SegmentState* s = manifest.Get(id);
    if (s == nullptr || s->count == 0) continue;
    Entry e;
    e.id = id;
    e.count = s->count;
    e.dead = static_cast<uint32_t>(s->dead.size());
    entries.push_back(e);
  }
  if (entries.size() < 2) return plan;

  // Ordered by size then by id: size is what tiering is about, and the id
  // breaks ties so the order is total rather than whatever sort happened to do.
  std::sort(entries.begin(), entries.end(),
            [](const Entry& a, const Entry& b) {
              if (a.count != b.count) return a.count < b.count;
              return a.id < b.id;
            });

  // TIERED, WHICH IS WHAT KEEPS A ROUTINE MERGE FROM REWRITING THE INDEX.
  // Phase 4 measured an all-or-nothing compaction of a 13,838-vector index at
  // 103 seconds, which is fine once a week and absurd after every note. The
  // round takes the smallest segment and everything within tier_ratio of it, so
  // the large compacted segment is left alone until enough small ones have
  // accumulated beside it.
  const uint64_t smallest = entries.front().count;
  const uint64_t ceiling = smallest * tier_ratio;
  uint32_t live_vectors = 0;
  uint32_t dead_vectors = 0;
  for (const Entry& e : entries) {
    if (static_cast<uint64_t>(e.count) > ceiling && !plan.inputs.empty()) break;
    plan.inputs.push_back(e.id);
    live_vectors += e.count - e.dead;
    dead_vectors += e.dead;
  }

  if (plan.inputs.size() < 2) {
    plan.inputs.clear();
    return plan;
  }

  const uint32_t total = live_vectors + dead_vectors;
  const uint32_t dead_pct =
      total == 0 ? 0
                 : static_cast<uint32_t>(
                       (static_cast<uint64_t>(dead_vectors) * 100) / total);
  const bool many = plan.inputs.size() >= min_segments;
  const bool wasteful = dead_pct >= max_dead_ratio_percent;
  if (!many && !wasteful) {
    plan.inputs.clear();
    return plan;
  }
  plan.live_vectors = live_vectors;
  plan.dead_vectors = dead_vectors;
  plan.reason = many ? "segment count" : "dead ratio";
  return plan;
}

}  // namespace ai
}  // namespace umbra
