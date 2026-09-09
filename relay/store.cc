#include "store.h"

#include <sys/stat.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <mutex>

#include "basalt/caps.h"
#include "basalt/db.h"
#include "basalt/posix_env.h"
#include "basalt/slice.h"

namespace umbra {
namespace relay {
namespace {

void PutBe64(uint64_t v, std::string* out) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
  }
}

uint64_t GetBe64(const char* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<unsigned char>(p[i]);
  return v;
}

// `vault || object || replica || counter(BE)`. Big-endian so byte order and
// numeric order agree and a fetch is one range scan; ADR 0001 makes the same
// argument for the client's own log.
constexpr char kBlobPrefix = 'b';
constexpr char kReportPrefix = 'r';
// Enrolment envelopes. A separate prefix so a listing of one never sees the
// other, and so a relay operator reading its own disk sees two opaque
// key spaces rather than one it might be tempted to interpret.
constexpr char kEnvelopePrefix = 'e';

// Sealed index segments. 'g' holds the pieces, keyed by offset so a transfer
// can resume; 'G' holds the total size, which is what says a segment is
// complete. Separate prefixes because a listing of one must never see the
// other.
constexpr char kSegmentPiecePrefix = 'g';
constexpr char kSegmentSizePrefix = 'G';

std::string BlobKey(const VaultId& v, const ObjectId& o, const ReplicaId& r,
                    uint64_t counter) {
  std::string k(1, kBlobPrefix);
  k.append(reinterpret_cast<const char*>(v.bytes.data()), v.bytes.size());
  k.append(reinterpret_cast<const char*>(o.bytes.data()), o.bytes.size());
  k.append(reinterpret_cast<const char*>(r.bytes.data()), r.bytes.size());
  PutBe64(counter, &k);
  return k;
}

std::string ReportKey(const VaultId& v, const ReplicaId& device) {
  std::string k(1, kReportPrefix);
  k.append(reinterpret_cast<const char*>(v.bytes.data()), v.bytes.size());
  k.append(reinterpret_cast<const char*>(device.bytes.data()),
           device.bytes.size());
  return k;
}

std::string SegmentPieceKey(const VaultId& v,
                            const std::array<uint8_t, 32>& seg,
                            uint64_t offset) {
  std::string k(1, kSegmentPiecePrefix);
  k.append(reinterpret_cast<const char*>(v.bytes.data()), v.bytes.size());
  k.append(reinterpret_cast<const char*>(seg.data()), seg.size());
  PutBe64(offset, &k);
  return k;
}

std::string SegmentSizeKey(const VaultId& v,
                           const std::array<uint8_t, 32>& seg) {
  std::string k(1, kSegmentSizePrefix);
  k.append(reinterpret_cast<const char*>(v.bytes.data()), v.bytes.size());
  k.append(reinterpret_cast<const char*>(seg.data()), seg.size());
  return k;
}

std::string EnvelopeKey(const VaultId& v, const std::array<uint8_t, 32>& tag) {
  std::string k(1, kEnvelopePrefix);
  k.append(reinterpret_cast<const char*>(v.bytes.data()), v.bytes.size());
  k.append(reinterpret_cast<const char*>(tag.data()), tag.size());
  return k;
}

// The stored value: epoch then payload. The relay does not look inside the
// payload; the epoch is copied through because a reader needs it.
std::string BlobValue(uint32_t epoch, const std::string& payload) {
  std::string v;
  for (int i = 0; i < 4; ++i) {
    v.push_back(static_cast<char>((epoch >> (8 * i)) & 0xFF));
  }
  v += payload;
  return v;
}

bool SplitBlobValue(const std::string& v, uint32_t* epoch,
                    std::string* payload) {
  if (v.size() < 4) return false;
  *epoch = 0;
  for (int i = 0; i < 4; ++i) {
    *epoch |= static_cast<uint32_t>(
                  static_cast<unsigned char>(v[static_cast<std::size_t>(i)]))
              << (8 * i);
  }
  payload->assign(v, 4, v.size() - 4);
  return true;
}

bool MakeDirs(const std::string& path) {
  std::string acc;
  std::size_t i = 0;
  while (i <= path.size()) {
    if (i == path.size() || path[i] == '/') {
      if (!acc.empty() && ::mkdir(acc.c_str(), 0700) != 0 && errno != EEXIST) {
        return false;
      }
    }
    if (i < path.size()) acc.push_back(path[i]);
    ++i;
  }
  return true;
}

}  // namespace

const char* StoreStatusName(StoreStatus s) {
  switch (s) {
    case StoreStatus::kOk:
      return "ok";
    case StoreStatus::kOpenFailed:
      return "open-failed";
    case StoreStatus::kWriteFailed:
      return "write-failed";
    case StoreStatus::kReadFailed:
      return "read-failed";
    case StoreStatus::kBadRequest:
      return "bad-request";
  }
  return "unknown";
}

struct Store::Impl {
  std::unique_ptr<basalt::Env> env;
  std::unique_ptr<basalt::DB> db;
  // ONE CALLER AT A TIME, BECAUSE THAT IS THE CONTRACT.
  //
  // The server runs a detached thread per connection (server.cc:153) and every
  // one of them lands here on a single DB. Basalt promises exactly this much
  // concurrency, in its own words: "TSan observed no data race across two
  // authored interleaving patterns (concurrent MemTable Add and Get; concurrent
  // DB Write and Sync across a flush); this is not a proof of race-freedom"
  // (third_party/basalt/src/concurrency_claim.h). Two concurrent Syncs are not
  // in that claim, and Basalt does not merely leave them undefined -- it
  // enforces the precondition with a SingleCaller guard that ABORTS.
  //
  // Which is what happened the first time two devices synced at once against a
  // relay on a real network: the process died on
  // single_caller.h:29 CHECK failed: !held_->exchange(true), the clients
  // reported an ordinary empty round, and the vault silently stopped
  // replicating. Localhost never showed it because no test had ever run two
  // clients against one relay at the same time.
  //
  // A reader-writer lock would be the tempting refinement. It would be a claim
  // Basalt has not made: concurrent readers against a flush that replaces the
  // memtable underneath them is not one of the two authored patterns. Serialise
  // everything until that sentence changes.
  mutable std::mutex mu;
};

Store::Store() : impl_(new Impl()) {}

Store::~Store() {
  if (impl_ && impl_->db) (void)impl_->db->Close();
}

StoreStatus Store::Open(const std::string& dir, std::unique_ptr<Store>* out) {
  if (!MakeDirs(dir)) return StoreStatus::kOpenFailed;
  std::unique_ptr<Store> s(new Store());
  s->impl_->env = basalt::NewPosixEnv();
  const basalt::wal::Caps caps;
  const basalt::Status st =
      basalt::DB::Open(s->impl_->env.get(), dir, caps, &s->impl_->db);
  if (!st.ok()) return StoreStatus::kOpenFailed;
  *out = std::move(s);
  return StoreStatus::kOk;
}

StoreStatus Store::Push(const PushRequest& req) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  if (req.blobs.empty()) return StoreStatus::kOk;
  basalt::WriteBatch batch;
  std::vector<std::string> keys;
  std::vector<std::string> values;
  keys.reserve(req.blobs.size());
  values.reserve(req.blobs.size());
  for (const Blob& b : req.blobs) {
    keys.push_back(BlobKey(req.vault, b.object, b.replica, b.counter));
    values.push_back(BlobValue(b.epoch, b.payload));
  }
  for (std::size_t i = 0; i < keys.size(); ++i) {
    // IDEMPOTENT BY CONSTRUCTION: a Set at the same key with the same bytes is
    // the same store. A client that crashed mid-push simply pushes again.
    batch.Set(basalt::Slice(keys[i]), basalt::Slice(values[i]));
  }
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

StoreStatus Store::Fetch(const FetchRequest& req, BlobsResponse* out) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  const uint32_t limit =
      req.limit == 0 ? kMaxFetchBlobs : std::min(req.limit, kMaxFetchBlobs);
  // `after` is exclusive. UINT64_MAX would overflow to zero and fetch
  // everything, so it is refused rather than wrapped.
  if (req.after == UINT64_MAX) return StoreStatus::kBadRequest;
  const std::string lo =
      BlobKey(req.vault, req.object, req.replica, req.after + 1);
  std::string hi = BlobKey(req.vault, req.object, req.replica, UINT64_MAX);
  hi.push_back('\0');

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  uint32_t n = 0;
  for (bool ok = it->First(); ok; ok = it->Next()) {
    if (n == limit) {
      out->more = true;
      break;
    }
    Blob b;
    b.object = req.object;
    b.replica = req.replica;
    const std::string key = it->Key().ToString();
    if (key.size() != 1 + 16 + 16 + 16 + 8) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    b.counter = GetBe64(key.data() + 1 + 16 + 16 + 16);
    if (!SplitBlobValue(it->Value().ToString(), &b.epoch, &b.payload)) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    out->blobs.push_back(b);
    ++n;
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? StoreStatus::kOk : StoreStatus::kReadFailed;
}

StoreStatus Store::PutReport(const PutReportRequest& req) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  basalt::WriteBatch batch;
  const std::string key = ReportKey(req.vault, req.report.device);
  const std::string value = BlobValue(req.report.epoch, req.report.sealed);
  batch.Set(basalt::Slice(key), basalt::Slice(value));
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

StoreStatus Store::PutEnvelope(const PutEnvelopeRequest& req) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  basalt::WriteBatch batch;
  const std::string key = EnvelopeKey(req.vault, req.envelope.tag);
  batch.Set(basalt::Slice(key), basalt::Slice(req.envelope.body));
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

StoreStatus Store::GetEnvelopes(const GetEnvelopesRequest& req,
                                EnvelopesResponse* out) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  std::array<uint8_t, 32> lo_tag{};
  std::array<uint8_t, 32> hi_tag{};
  hi_tag.fill(0xFF);
  const std::string lo = EnvelopeKey(req.vault, lo_tag);
  std::string hi = EnvelopeKey(req.vault, hi_tag);
  hi.push_back('\0');

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  for (bool ok = it->First(); ok; ok = it->Next()) {
    if (out->envelopes.size() >= kMaxEnvelopes) break;
    const std::string key = it->Key().ToString();
    if (key.size() != 1 + 16 + 32) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    Envelope e;
    std::memcpy(e.tag.data(), key.data() + 1 + 16, e.tag.size());
    e.body = it->Value().ToString();
    out->envelopes.push_back(e);
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? StoreStatus::kOk : StoreStatus::kReadFailed;
}

StoreStatus Store::PutSegment(const PutSegmentRequest& req) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  basalt::WriteBatch batch;
  const std::string piece = SegmentPieceKey(req.vault, req.segment, req.offset);
  batch.Set(basalt::Slice(piece), basalt::Slice(req.chunk));
  // THE SIZE RECORD IS WHAT SAYS A SEGMENT IS COMPLETE. Written on every piece
  // rather than only the last, so a transfer that is interrupted still leaves
  // the relay able to say how much it is missing, and a reader can tell a
  // partial segment from a finished one by comparing what it has against it.
  std::string total;
  PutBe64(req.total, &total);
  const std::string size_key = SegmentSizeKey(req.vault, req.segment);
  batch.Set(basalt::Slice(size_key), basalt::Slice(total));
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

StoreStatus Store::GetSegment(const GetSegmentRequest& req,
                              SegmentResponse* out) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  out->found = false;
  out->offset = req.offset;
  out->total = 0;
  out->chunk.clear();

  const std::string size_key = SegmentSizeKey(req.vault, req.segment);
  std::string total;
  if (!impl_->db->Get(basalt::Slice(size_key), &total).ok()) {
    return StoreStatus::kOk;  // not found is not an error
  }
  if (total.size() != 8) return StoreStatus::kReadFailed;
  uint64_t size = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    size = (size << 8) | static_cast<uint8_t>(total[i]);
  }
  out->total = size;
  out->found = true;
  if (req.offset >= size) return StoreStatus::kOk;  // a legitimate end

  // THE RELAY DOES NOT REASSEMBLE. It hands back the piece stored at or after
  // the requested offset and lets the client stitch, because reassembling would
  // mean holding a whole segment in memory to answer one request -- which is
  // exactly the allocation the chunking exists to avoid.
  const std::string lo = SegmentPieceKey(req.vault, req.segment, req.offset);
  std::string hi = SegmentPieceKey(req.vault, req.segment, UINT64_MAX);
  hi.push_back('\0');
  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  if (it->First()) {
    const std::string k = it->Key().ToString();
    if (k.size() != 1 + 16 + 32 + 8) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    uint64_t at = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      at = (at << 8) |
           static_cast<uint8_t>(k[1 + 16 + 32 + static_cast<std::size_t>(i)]);
    }
    out->offset = at;
    out->chunk = it->Value().ToString();
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? StoreStatus::kOk : StoreStatus::kReadFailed;
}

StoreStatus Store::ListSegments(const ListSegmentsRequest& req,
                                SegmentListResponse* out) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  std::array<uint8_t, 32> hi_seg{};
  hi_seg.fill(0xFF);
  std::string lo = SegmentSizeKey(req.vault, req.after);
  // Exclusive: paging asks for what comes AFTER the last id seen.
  lo.push_back('\0');
  std::string hi = SegmentSizeKey(req.vault, hi_seg);
  hi.push_back('\0');

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  const uint32_t limit = (req.limit == 0 || req.limit > kMaxSegmentsListed)
                             ? kMaxSegmentsListed
                             : req.limit;
  for (bool ok = it->First(); ok; ok = it->Next()) {
    if (out->segments.size() >= limit) break;
    const std::string k = it->Key().ToString();
    if (k.size() != 1 + 16 + 32) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    const std::string v = it->Value().ToString();
    if (v.size() != 8) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    SegmentEntryWire e;
    std::memcpy(e.segment.data(), k.data() + 1 + 16, e.segment.size());
    uint64_t size = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      size = (size << 8) | static_cast<uint8_t>(v[i]);
    }
    e.bytes = size;
    out->segments.push_back(e);
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? StoreStatus::kOk : StoreStatus::kReadFailed;
}

StoreStatus Store::GetReports(const GetReportsRequest& req,
                              ReportsResponse* out) {
  const std::lock_guard<std::mutex> held(impl_->mu);
  ReplicaId lo_dev;
  ReplicaId hi_dev;
  for (std::size_t i = 0; i < hi_dev.bytes.size(); ++i) hi_dev.bytes[i] = 0xFF;
  const std::string lo = ReportKey(req.vault, lo_dev);
  std::string hi = ReportKey(req.vault, hi_dev);
  hi.push_back('\0');

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  for (bool ok = it->First(); ok; ok = it->Next()) {
    const std::string key = it->Key().ToString();
    if (key.size() != 1 + 16 + 16) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    SealedReport s;
    std::memcpy(s.device.bytes.data(), key.data() + 1 + 16,
                s.device.bytes.size());
    if (!SplitBlobValue(it->Value().ToString(), &s.epoch, &s.sealed)) {
      (void)it->Close();
      return StoreStatus::kReadFailed;
    }
    out->reports.push_back(s);
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? StoreStatus::kOk : StoreStatus::kReadFailed;
}

StoreStatus Store::Sync() {
  const std::lock_guard<std::mutex> held(impl_->mu);
  basalt::wal::SeqNum w = 0;
  const basalt::Status s = impl_->db->Sync(&w);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

std::size_t Store::BlobCount() const {
  const std::lock_guard<std::mutex> held(impl_->mu);
  basalt::IterOptions o;
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  std::size_t n = 0;
  for (bool ok = it->First(); ok; ok = it->Next()) {
    if (!it->Key().empty() && it->Key().ToString()[0] == kBlobPrefix) ++n;
  }
  (void)it->Close();
  return n;
}

std::string HandleRequest(Store* store, const std::string& body) {
  Op op;
  if (!PeekOp(body, &op)) return EncodeError("unknown opcode");
  switch (op) {
    case Op::kPush: {
      PushRequest req;
      if (!DecodePush(body, &req)) return EncodeError("malformed push");
      if (store->Push(req) != StoreStatus::kOk)
        return EncodeError("write failed");
      // SYNCED BEFORE OK. A relay that acknowledged a push it had not made
      // durable would be lying in exactly the way a client cannot check.
      if (store->Sync() != StoreStatus::kOk) return EncodeError("sync failed");
      return EncodeOk();
    }
    case Op::kFetch: {
      FetchRequest req;
      if (!DecodeFetch(body, &req)) return EncodeError("malformed fetch");
      BlobsResponse resp;
      if (store->Fetch(req, &resp) != StoreStatus::kOk) {
        return EncodeError("read failed");
      }
      return EncodeBlobs(resp);
    }
    case Op::kPutReport: {
      PutReportRequest req;
      if (!DecodePutReport(body, &req)) return EncodeError("malformed report");
      if (store->PutReport(req) != StoreStatus::kOk) {
        return EncodeError("write failed");
      }
      if (store->Sync() != StoreStatus::kOk) return EncodeError("sync failed");
      return EncodeOk();
    }
    case Op::kPutEnvelope: {
      PutEnvelopeRequest req;
      if (!DecodePutEnvelope(body, &req))
        return EncodeError("malformed envelope");
      if (store->PutEnvelope(req) != StoreStatus::kOk) {
        return EncodeError("cannot store the envelope");
      }
      if (store->Sync() != StoreStatus::kOk) {
        return EncodeError("cannot sync the envelope");
      }
      return EncodeOk();
    }
    case Op::kGetEnvelopes: {
      GetEnvelopesRequest req;
      if (!DecodeGetEnvelopes(body, &req))
        return EncodeError("malformed get-envelopes");
      EnvelopesResponse resp;
      if (store->GetEnvelopes(req, &resp) != StoreStatus::kOk) {
        return EncodeError("cannot read envelopes");
      }
      return EncodeEnvelopes(resp);
    }
    case Op::kPutSegment: {
      PutSegmentRequest req;
      if (!DecodePutSegment(body, &req))
        return EncodeError("malformed put-segment");
      if (store->PutSegment(req) != StoreStatus::kOk) {
        return EncodeError("cannot store the segment");
      }
      if (store->Sync() != StoreStatus::kOk) {
        return EncodeError("cannot sync the segment");
      }
      return EncodeOk();
    }
    case Op::kGetSegment: {
      GetSegmentRequest req;
      if (!DecodeGetSegment(body, &req))
        return EncodeError("malformed get-segment");
      SegmentResponse resp;
      if (store->GetSegment(req, &resp) != StoreStatus::kOk) {
        return EncodeError("cannot read the segment");
      }
      return EncodeSegment(resp);
    }
    case Op::kListSegments: {
      ListSegmentsRequest req;
      if (!DecodeListSegments(body, &req))
        return EncodeError("malformed list-segments");
      SegmentListResponse resp;
      if (store->ListSegments(req, &resp) != StoreStatus::kOk) {
        return EncodeError("cannot list segments");
      }
      return EncodeSegmentList(resp);
    }
    case Op::kGetReports: {
      GetReportsRequest req;
      if (!DecodeGetReports(body, &req))
        return EncodeError("malformed request");
      ReportsResponse resp;
      if (store->GetReports(req, &resp) != StoreStatus::kOk) {
        return EncodeError("read failed");
      }
      return EncodeReports(resp);
    }
    // A client never sends these. Refused rather than ignored, because a peer
    // sending them is either broken or probing.
    case Op::kOk:
    case Op::kBlobs:
    case Op::kReports:
    case Op::kEnvelopes:
    case Op::kSegment:
    case Op::kSegmentList:
    case Op::kError:
      return EncodeError("not a request");
  }
  return EncodeError("unknown opcode");
}

}  // namespace relay
}  // namespace umbra
