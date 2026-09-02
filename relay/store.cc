#include "store.h"

#include <sys/stat.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

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
  basalt::WriteBatch batch;
  const std::string key = ReportKey(req.vault, req.report.device);
  const std::string value = BlobValue(req.report.epoch, req.report.sealed);
  batch.Set(basalt::Slice(key), basalt::Slice(value));
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

StoreStatus Store::PutEnvelope(const PutEnvelopeRequest& req) {
  basalt::WriteBatch batch;
  const std::string key = EnvelopeKey(req.vault, req.envelope.tag);
  batch.Set(basalt::Slice(key), basalt::Slice(req.envelope.body));
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

StoreStatus Store::GetEnvelopes(const GetEnvelopesRequest& req,
                                EnvelopesResponse* out) {
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

StoreStatus Store::GetReports(const GetReportsRequest& req,
                              ReportsResponse* out) {
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
  basalt::wal::SeqNum w = 0;
  const basalt::Status s = impl_->db->Sync(&w);
  return s.ok() ? StoreStatus::kOk : StoreStatus::kWriteFailed;
}

std::size_t Store::BlobCount() const {
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
    case Op::kError:
      return EncodeError("not a request");
  }
  return EncodeError("unknown opcode");
}

}  // namespace relay
}  // namespace umbra
