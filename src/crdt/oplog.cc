#include "umbra/crdt/oplog.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstring>

#include "basalt/caps.h"
#include "basalt/db.h"
#include "basalt/posix_env.h"
#include "basalt/slice.h"
#include "check.h"

namespace umbra {
namespace {

void PutBe64(uint64_t v, std::string* out) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
  }
}

uint64_t GetBe64(const char* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v = (v << 8) | static_cast<unsigned char>(p[i]);
  }
  return v;
}

}  // namespace

const char* LogStatusName(LogStatus s) {
  switch (s) {
    case LogStatus::kOk:
      return "ok";
    case LogStatus::kOpenFailed:
      return "open-failed";
    case LogStatus::kWriteFailed:
      return "write-failed";
    case LogStatus::kReadFailed:
      return "read-failed";
    case LogStatus::kCorrupt:
      return "corrupt";
    case LogStatus::kNotClosed:
      return "not-causally-closed";
  }
  return "unknown";
}

std::string MakeOpLogKey(const ObjectId& object, const ReplicaId& replica,
                         uint64_t counter) {
  std::string k;
  k.reserve(kOpLogKeyBytes);
  k.append(reinterpret_cast<const char*>(object.bytes.data()),
           object.bytes.size());
  k.append(reinterpret_cast<const char*>(replica.bytes.data()),
           replica.bytes.size());
  PutBe64(counter, &k);
  return k;
}

bool ParseOpLogKey(const std::string& key, ObjectId* object, ReplicaId* replica,
                   uint64_t* counter) {
  if (key.size() != kOpLogKeyBytes) return false;
  std::memcpy(object->bytes.data(), key.data(), object->bytes.size());
  std::memcpy(replica->bytes.data(), key.data() + 16, replica->bytes.size());
  *counter = GetBe64(key.data() + 32);
  return true;
}

struct OpLog::Impl {
  std::unique_ptr<basalt::Env> env;
  std::unique_ptr<basalt::DB> db;
};

OpLog::OpLog() : impl_(new Impl()) {}
OpLog::~OpLog() {
  if (impl_ && impl_->db) {
    // Close does not sync, deliberately, in basalt. Anything that had to
    // survive was synced by the caller at the point it was published.
    (void)impl_->db->Close();
  }
}

namespace {

// basalt opens an existing directory; it does not create one. Creating it here
// rather than making every caller do it, because "the directory did not exist"
// is not a distinction anyone opening a vault cares about.
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

LogStatus OpLog::Open(const std::string& dir, std::unique_ptr<OpLog>* out) {
  if (!MakeDirs(dir)) return LogStatus::kOpenFailed;
  std::unique_ptr<OpLog> log(new OpLog());
  log->impl_->env = basalt::NewPosixEnv();
  const basalt::wal::Caps caps;
  const basalt::Status s =
      basalt::DB::Open(log->impl_->env.get(), dir, caps, &log->impl_->db);
  if (!s.ok()) return LogStatus::kOpenFailed;
  *out = std::move(log);
  return LogStatus::kOk;
}

LogStatus OpLog::Append(const ObjectId& object, const std::vector<Op>& ops) {
  if (ops.empty()) return LogStatus::kOk;
  // ONE BATCH. Basalt applies a WriteBatch atomically, which is what makes the
  // log causally closed at every point a reader could observe it: either all of
  // these operations are there or none are, so a crash cannot leave a child
  // without its parent.
  basalt::WriteBatch batch;
  for (const Op& op : ops) {
    const std::string key = MakeOpLogKey(object, op.id.replica, op.id.counter);
    const OpPayload payload = EncodeOp(op);
    batch.Set(basalt::Slice(key), basalt::Slice(payload.bytes));
  }
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? LogStatus::kOk : LogStatus::kWriteFailed;
}

LogStatus OpLog::ReadObject(const ObjectId& object,
                            std::vector<Op>* out) const {
  // The object id is the key prefix, so the whole object is one bounded range.
  const std::string lo = MakeOpLogKey(object, ReplicaId{}, 0);
  ReplicaId max_replica;
  for (std::size_t i = 0; i < max_replica.bytes.size(); ++i) {
    max_replica.bytes[i] = 0xFF;
  }
  const std::string hi = MakeOpLogKey(object, max_replica, UINT64_MAX);

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  // Upper is exclusive and the highest legal key must be included, so the bound
  // is one byte past it rather than equal to it.
  std::string hi_exclusive = hi;
  hi_exclusive.push_back('\0');
  o.upper = basalt::Bound::At(basalt::Slice(hi_exclusive));

  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  for (bool ok = it->First(); ok; ok = it->Next()) {
    OpPayload p;
    p.bytes = it->Value().ToString();
    Op op;
    if (!DecodeOp(p, &op)) {
      (void)it->Close();
      return LogStatus::kCorrupt;
    }
    out->push_back(op);
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? LogStatus::kOk : LogStatus::kReadFailed;
}

LogStatus OpLog::ReadFrom(const ObjectId& object, const ReplicaId& replica,
                          uint64_t after, std::vector<Op>* out) const {
  const std::string lo = MakeOpLogKey(object, replica, after + 1);
  const std::string hi = MakeOpLogKey(object, replica, UINT64_MAX);
  std::string hi_exclusive = hi;
  hi_exclusive.push_back('\0');

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi_exclusive));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  for (bool ok = it->First(); ok; ok = it->Next()) {
    OpPayload p;
    p.bytes = it->Value().ToString();
    Op op;
    if (!DecodeOp(p, &op)) {
      (void)it->Close();
      return LogStatus::kCorrupt;
    }
    out->push_back(op);
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? LogStatus::kOk : LogStatus::kReadFailed;
}

LogStatus OpLog::Replay(const ObjectId& object, TextDoc* doc,
                        std::map<ReplicaId, uint64_t>* high_water) const {
  std::vector<Op> ops;
  const LogStatus s = ReadObject(object, &ops);
  if (s != LogStatus::kOk) return s;

  // The scan is in (replica, counter) order, which is not apply order: an
  // operation from replica B may name a parent from replica A that sorts after
  // it. So replay buffers and drains rather than assuming an order the key
  // layout was never chosen to provide.
  std::vector<Op> pending;
  pending.swap(ops);
  bool progress = true;
  while (progress && !pending.empty()) {
    progress = false;
    std::vector<Op> still;
    for (const Op& op : pending) {
      const ApplyResult r = doc->Apply(op);
      switch (r) {
        case ApplyResult::kApplied:
        case ApplyResult::kDuplicate:
          progress = true;
          break;
        case ApplyResult::kNotReady:
          still.push_back(op);
          break;
        case ApplyResult::kMalformed:
          return LogStatus::kCorrupt;
      }
      if (r == ApplyResult::kApplied || r == ApplyResult::kDuplicate) {
        const OpId last = LastId(op);
        uint64_t& hw = (*high_water)[last.replica];
        if (last.counter > hw) hw = last.counter;
      }
    }
    pending.swap(still);
  }
  // Anything still buffered names something the log does not contain.
  return pending.empty() ? LogStatus::kOk : LogStatus::kNotClosed;
}

LogStatus OpLog::Sync() {
  basalt::wal::SeqNum watermark = 0;
  const basalt::Status s = impl_->db->Sync(&watermark);
  return s.ok() ? LogStatus::kOk : LogStatus::kWriteFailed;
}

}  // namespace umbra
