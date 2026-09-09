#include "umbra/sync/client.h"

#include <algorithm>
#include <cstring>

#include "check.h"
#include "umbra/crypto/aead.h"

namespace umbra {
namespace sync {
namespace {

relay::Id16 ToRelay(const ObjectId& o) {
  relay::Id16 r;
  r.bytes = o.bytes;
  return r;
}

relay::Id16 ToRelay(const ReplicaId& o) {
  relay::Id16 r;
  r.bytes = o.bytes;
  return r;
}

}  // namespace

const char* SyncStatusName(SyncStatus s) {
  switch (s) {
    case SyncStatus::kOk:
      return "ok";
    case SyncStatus::kUnreachable:
      return "unreachable";
    case SyncStatus::kBadResponse:
      return "bad-response";
    case SyncStatus::kChainBroken:
      return "chain-broken";
    case SyncStatus::kOutOfOrder:
      return "out-of-order";
    case SyncStatus::kAuthFailed:
      return "auth-failed";
    case SyncStatus::kBadReport:
      return "bad-report";
    case SyncStatus::kLocalError:
      return "local-error";
  }
  return "unknown";
}

Client::Client(const relay::VaultId& vault, const ReplicaId& self,
               VaultKeys* keys, OpLog* log, Transport* transport)
    : vault_(vault),
      self_(self),
      keys_(keys),
      log_(log),
      transport_(transport) {}

SyncStatus Client::LoadCursor(const ObjectId& object, const ReplicaId& source,
                              uint64_t* out) const {
  const std::pair<ObjectId, ReplicaId> k(object, source);
  const std::map<std::pair<ObjectId, ReplicaId>, uint64_t>::const_iterator it =
      cursor_cache_.find(k);
  if (it != cursor_cache_.end()) {
    *out = it->second;
    return SyncStatus::kOk;
  }
  uint64_t v = 0;
  if (!log_->GetCursor(object, source, &v)) v = 0;
  cursor_cache_[k] = v;
  *out = v;
  return SyncStatus::kOk;
}

SyncStatus Client::StoreCursor(const ObjectId& object, const ReplicaId& source,
                               uint64_t value) {
  if (!log_->SetCursor(object, source, value)) return SyncStatus::kLocalError;
  cursor_cache_[std::pair<ObjectId, ReplicaId>(object, source)] = value;
  return SyncStatus::kOk;
}

uint64_t Client::Cursor(const ObjectId& object, const ReplicaId& source) const {
  uint64_t v = 0;
  (void)LoadCursor(object, source, &v);
  return v;
}

SyncStatus Client::PushObject(const ObjectId& object, std::size_t* pushed) {
  // Everything this device produced for the object. The relay stores a repeated
  // blob once, so re-pushing after a crash is free and correct.
  std::vector<StoredBlob> mine;
  if (log_->ReadStoredFrom(object, self_, 0, &mine) != LogStatus::kOk) {
    return SyncStatus::kLocalError;
  }
  *pushed = 0;
  // In windows, so a large backlog does not become one enormous frame. The
  // relay has its own cap; neither side trusts the other's.
  for (std::size_t i = 0; i < mine.size(); i += kFetchWindow) {
    relay::PushRequest req;
    req.vault = vault_;
    const std::size_t end = std::min(mine.size(), i + kFetchWindow);
    for (std::size_t k = i; k < end; ++k) {
      relay::Blob b;
      b.object = ToRelay(object);
      b.replica = ToRelay(mine[k].id.replica);
      b.counter = mine[k].id.counter;
      b.epoch = mine[k].epoch;
      b.payload = mine[k].sealed;
      req.blobs.push_back(b);
    }
    if (!transport_->Push(req)) return SyncStatus::kUnreachable;
    *pushed += end - i;
  }
  return SyncStatus::kOk;
}

SyncStatus Client::FetchObject(
    const ObjectId& object, const ReplicaId& source,
    const std::function<bool(const OpPayload&)>& apply, FetchStats* stats) {
  // The two payload kinds this layer knows. A payload that decodes as neither
  // is refused, which is what it was before this became a parameter.
  const auto builtin = [](const OpPayload& p, uint64_t* prev) {
    Op text_op;
    TreeOp tree_op;
    if (DecodeOp(p, &text_op)) {
      *prev = text_op.prev;
      return true;
    }
    if (DecodeTreeOp(p, &tree_op)) {
      *prev = tree_op.prev;
      return true;
    }
    return false;
  };
  return FetchObjectWith(object, source, builtin, apply, stats);
}

SyncStatus Client::FetchObjectWith(
    const ObjectId& object, const ReplicaId& source,
    const std::function<bool(const OpPayload&, uint64_t*)>& back_pointer,
    const std::function<bool(const OpPayload&)>& apply, FetchStats* stats) {
  uint64_t cursor = 0;
  (void)LoadCursor(object, source, &cursor);
  stats->cursor_before = cursor;
  stats->cursor_after = cursor;

  for (;;) {
    relay::FetchRequest req;
    req.vault = vault_;
    req.object = ToRelay(object);
    req.replica = ToRelay(source);
    req.after = cursor;
    req.limit = kFetchWindow;
    relay::BlobsResponse resp;
    if (!transport_->Fetch(req, &resp)) return SyncStatus::kUnreachable;
    ++stats->windows;
    if (resp.blobs.empty()) break;

    uint64_t last_counter = cursor;
    for (const relay::Blob& b : resp.blobs) {
      ++stats->fetched;
      // ORDER IS CHECKED, NOT TRUSTED. The relay is hostile; that its key
      // layout would produce ascending counters is a fact about an honest one.
      if (b.counter <= last_counter) return SyncStatus::kOutOfOrder;
      last_counter = b.counter;

      SecretKey k;
      if (keys_->ContentKey(b.epoch, &k) != CryptoStatus::kOk) {
        return SyncStatus::kAuthFailed;
      }
      SealContext ctx;
      ctx.object = object;
      ctx.op.counter = b.counter;
      ctx.op.replica = source;
      ctx.epoch = b.epoch;
      OpPayload payload;
      if (::umbra::Open(k, ctx, b.payload, &payload.bytes) !=
          CryptoStatus::kOk) {
        return SyncStatus::kAuthFailed;
      }

      // THE CHAIN. Both operation kinds carry a back-pointer; which decoder
      // applies is the caller's business, so the pointer is read here from
      // whichever decodes. A payload that decodes as neither is refused.
      uint64_t prev = 0;
      if (!back_pointer(payload, &prev)) return SyncStatus::kBadResponse;
      if (prev != cursor) {
        // The relay skipped something. The cursor stays where it is, nothing
        // after this point is applied, and the caller is told. Anything already
        // applied in this window was verified and stays.
        return SyncStatus::kChainBroken;
      }

      // PERSISTED BEFORE THE CURSOR MOVES, and the order is the whole point.
      //
      // A cursor that advanced on APPLY rather than on PERSIST would claim this
      // device holds an operation that a crash would take with it: the document
      // is rebuilt from the log, the log would not have it, and the prefix mark
      // this device reports would then be a lie in the dangerous direction.
      // Found by asserting the shipped cursor against the harness's definition
      // of a prefix mark; they disagreed.
      StoredBlob stored;
      stored.id.replica = source;
      stored.id.counter = b.counter;
      stored.epoch = b.epoch;
      stored.sealed = b.payload;
      if (log_->AppendStored(object, {stored}) != LogStatus::kOk) {
        return SyncStatus::kLocalError;
      }
      if (!apply(payload)) return SyncStatus::kLocalError;
      ++stats->applied;
      cursor = b.counter;
      // WRITTEN PER OPERATION, not per window. A client that dies here resumes
      // from exactly this point; one that wrote per window would re-apply the
      // window, which is harmless for a CRDT but would leave the cursor behind
      // the log and make the prefix mark a lie in the safe direction only by
      // luck.
      if (StoreCursor(object, source, cursor) != SyncStatus::kOk) {
        return SyncStatus::kLocalError;
      }
      stats->cursor_after = cursor;
    }
    if (!resp.more) break;
  }
  return SyncStatus::kOk;
}

SyncStatus Client::PublishEnvelope(const std::array<uint8_t, 32>& tag,
                                   const std::string& body) {
  relay::PutEnvelopeRequest req;
  req.vault = vault_;
  req.envelope.tag = tag;
  req.envelope.body = body;
  if (!transport_->PutEnvelope(req)) return SyncStatus::kUnreachable;
  return SyncStatus::kOk;
}

SyncStatus Client::CollectEnvelopes(std::vector<relay::Envelope>* out) {
  relay::GetEnvelopesRequest req;
  req.vault = vault_;
  relay::EnvelopesResponse resp;
  if (!transport_->GetEnvelopes(req, &resp)) return SyncStatus::kUnreachable;
  out->swap(resp.envelopes);
  return SyncStatus::kOk;
}

SyncStatus Client::PushSegment(const std::array<uint8_t, 32>& id,
                               const std::string& sealed) {
  if (sealed.empty()) return SyncStatus::kLocalError;
  if (sealed.size() > relay::kMaxSegmentBytes) return SyncStatus::kLocalError;
  const uint64_t total = static_cast<uint64_t>(sealed.size());
  for (uint64_t off = 0; off < total; off += relay::kSegmentChunkBytes) {
    const uint64_t take =
        std::min<uint64_t>(relay::kSegmentChunkBytes, total - off);
    relay::PutSegmentRequest req;
    req.vault = vault_;
    req.segment = id;
    req.offset = off;
    req.total = total;
    req.chunk.assign(sealed, static_cast<std::size_t>(off),
                     static_cast<std::size_t>(take));
    if (!transport_->PutSegment(req)) return SyncStatus::kUnreachable;
  }
  return SyncStatus::kOk;
}

SyncStatus Client::PullSegment(const std::array<uint8_t, 32>& id,
                               std::string* sealed) {
  sealed->clear();
  // NOTHING PARTIAL SURVIVES A FAILURE. Every early return below left whatever
  // pieces had arrived in the caller's buffer, so a caller that logged the
  // status instead of branching on it held a truncated segment that looked like
  // a segment. The content hash catches it later, which is the wrong place: an
  // out parameter on a failed call should be empty, not nearly right.
  //
  // A guard rather than a clear before each return, because there are six
  // returns and the seventh is the one somebody forgets.
  class Guard {
   public:
    explicit Guard(std::string* s) : s_(s) {}
    ~Guard() {
      if (!ok_) s_->clear();
    }
    void Keep() { ok_ = true; }

   private:
    std::string* s_;
    bool ok_ = false;
  } guard(sealed);

  uint64_t total = 0;
  uint64_t want = 0;
  // A BOUND ON ROUNDS, NOT ONLY ON BYTES. A relay that answers every request
  // with an empty chunk at the offset asked for would otherwise spin here
  // forever; the loop refuses to make more requests than a correct transfer
  // could possibly need.
  const uint64_t max_rounds =
      (relay::kMaxSegmentBytes / relay::kSegmentChunkBytes) + 8;
  for (uint64_t round = 0; round < max_rounds; ++round) {
    relay::GetSegmentRequest req;
    req.vault = vault_;
    req.segment = id;
    req.offset = want;
    relay::SegmentResponse resp;
    if (!transport_->GetSegment(req, &resp)) return SyncStatus::kUnreachable;
    if (!resp.found) return SyncStatus::kBadResponse;
    if (total == 0) {
      total = resp.total;
      if (total == 0 || total > relay::kMaxSegmentBytes) {
        return SyncStatus::kBadResponse;
      }
      sealed->reserve(static_cast<std::size_t>(total));
    } else if (resp.total != total) {
      // THE SEGMENT CHANGED SIZE MID TRANSFER. A segment is content addressed
      // and therefore immutable, so this is a relay saying something that
      // cannot be true.
      return SyncStatus::kBadResponse;
    }
    if (resp.offset != want) {
      // A hole, or a piece from somewhere else. Either way the client cannot
      // stitch a segment it was not given contiguously.
      return SyncStatus::kBadResponse;
    }
    if (resp.chunk.empty()) return SyncStatus::kBadResponse;
    sealed->append(resp.chunk);
    want += static_cast<uint64_t>(resp.chunk.size());
    if (want >= total) break;
  }
  if (sealed->size() != total) return SyncStatus::kBadResponse;
  guard.Keep();
  return SyncStatus::kOk;
}

SyncStatus Client::ListSegments(std::vector<std::array<uint8_t, 32>>* ids,
                                std::vector<uint64_t>* sizes) {
  ids->clear();
  if (sizes != nullptr) sizes->clear();
  std::array<uint8_t, 32> after{};
  for (;;) {
    relay::ListSegmentsRequest req;
    req.vault = vault_;
    req.after = after;
    req.limit = relay::kMaxSegmentsListed;
    relay::SegmentListResponse resp;
    if (!transport_->ListSegments(req, &resp)) return SyncStatus::kUnreachable;
    if (resp.segments.empty()) break;
    for (const relay::SegmentEntryWire& e : resp.segments) {
      ids->push_back(e.segment);
      if (sizes != nullptr) sizes->push_back(e.bytes);
    }
    after = resp.segments.back().segment;
    if (resp.segments.size() < relay::kMaxSegmentsListed) break;
  }
  return SyncStatus::kOk;
}

SyncStatus Client::PublishReport(uint64_t clock,
                                 const std::vector<ObjectId>& objects,
                                 const ReplicaId& tree_object_source_hint) {
  (void)tree_object_source_hint;
  DeviceReport rep;
  rep.device = self_;
  rep.clock = clock;
  // THE MARKS COME FROM THE CURSORS, which is what makes them a claim this
  // device can honestly make: a cursor moved only across a verified chain.
  for (const ObjectId& object : objects) {
    std::vector<ReplicaId> sources;
    if (!log_->SourcesFor(object, &sources)) continue;
    for (const ReplicaId& s : sources) {
      uint64_t c = 0;
      (void)LoadCursor(object, s, &c);
      // A device holds all of its own operations without fetching them.
      if (s == self_) {
        uint64_t own = 0;
        if (log_->HighestFrom(object, self_, &own) && own > c) c = own;
      }
      if (c == 0) continue;  // omitted on the wire; see the watermark
      uint64_t& mark = rep.have[s];
      if (c > mark) mark = c;
    }
  }
  std::string sealed;
  if (SealDeviceReport(*keys_, keys_->current(), rep, &sealed) !=
      CryptoStatus::kOk) {
    return SyncStatus::kLocalError;
  }
  relay::PutReportRequest req;
  req.vault = vault_;
  req.report.device = ToRelay(self_);
  req.report.epoch = keys_->current();
  req.report.sealed = sealed;
  if (!transport_->PutReport(req)) return SyncStatus::kUnreachable;
  return SyncStatus::kOk;
}

SyncStatus Client::CollectReports(const std::vector<ReplicaId>& enrolled,
                                  uint64_t* watermark, std::size_t* refused) {
  relay::GetReportsRequest req;
  req.vault = vault_;
  relay::ReportsResponse resp;
  if (!transport_->GetReports(req, &resp)) return SyncStatus::kUnreachable;

  *refused = 0;
  std::vector<DeviceReport> reports;
  for (const relay::SealedReport& s : resp.reports) {
    ReplicaId claimed;
    claimed.bytes = s.device.bytes;
    DeviceReport r;
    // A REPORT THAT DOES NOT OPEN IS DROPPED, NOT FATAL. A relay that stores
    // one bad report must not be able to stop the vault reasoning about
    // compaction at all; dropping it lowers the watermark, which is the safe
    // direction.
    if (OpenDeviceReport(*keys_, s.epoch, claimed, s.sealed, &r) !=
        CryptoStatus::kOk) {
      ++*refused;
      continue;
    }
    reports.push_back(r);
    last_reports_[r.device] = r;
  }
  *watermark = CompactionWatermark(enrolled, reports);
  return SyncStatus::kOk;
}

bool Client::RelayLooksStale(const std::vector<ReplicaId>& enrolled,
                             std::string* why) {
  for (const ReplicaId& d : enrolled) {
    // Never our own report. This device does not fetch from itself, so its
    // cursor for itself is always zero and comparing the two would report every
    // relay as stale.
    if (d == self_) continue;
    const std::map<ReplicaId, DeviceReport>::const_iterator it =
        last_reports_.find(d);
    if (it == last_reports_.end()) continue;
    const std::map<ReplicaId, uint64_t>& have = it->second.have;
    const std::map<ReplicaId, uint64_t>::const_iterator own = have.find(d);
    if (own == have.end()) continue;
    // The device says it has produced up to `own->second`. If our cursor for it
    // is behind, the relay is not serving us what it has been given.
    uint64_t ours = 0;
    (void)LoadCursor(TreeObject(), d, &ours);
    if (own->second > ours) {
      *why = "device " + d.Short() + " reports producing up to " +
             std::to_string(own->second) +
             " but the relay has served us only " + std::to_string(ours);
      return true;
    }
  }
  return false;
}

}  // namespace sync
}  // namespace umbra
