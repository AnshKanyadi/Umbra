#include "umbra/crdt/oplog.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstring>

#include "basalt/caps.h"
#include "basalt/db.h"
#include "basalt/posix_env.h"
#include "basalt/slice.h"
#include "check.h"
#include "umbra/crypto/aead.h"

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
  const VaultKeys* keys = nullptr;  // not owned; null means store plaintext
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

namespace {

void PutEnvelope(Epoch e, std::string* out) {
  for (int i = 0; i < 4; ++i) {
    out->push_back(static_cast<char>((e >> (8 * i)) & 0xFF));
  }
}

bool GetEnvelope(const std::string& s, Epoch* e) {
  if (s.size() < kEnvelopeBytes) return false;
  *e = 0;
  for (int i = 0; i < 4; ++i) {
    *e |= static_cast<Epoch>(
              static_cast<unsigned char>(s[static_cast<std::size_t>(i)]))
          << (8 * i);
  }
  return true;
}

}  // namespace

LogStatus OpLog::OpenEncrypted(const std::string& dir, const VaultKeys* keys,
                               std::unique_ptr<OpLog>* out) {
  const LogStatus s = Open(dir, out);
  if (s != LogStatus::kOk) return s;
  (*out)->impl_->keys = keys;
  return LogStatus::kOk;
}

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

LogStatus OpLog::AppendRaw(const ObjectId& object,
                           const std::vector<LoggedOp>& ops) {
  if (ops.empty()) return LogStatus::kOk;
  // ONE BATCH. Basalt applies a WriteBatch atomically, which is what makes the
  // log causally closed at every point a reader could observe it: either all of
  // these operations are there or none are, so a crash cannot leave a child
  // without its parent.
  basalt::WriteBatch batch;
  // Values are built up front and kept alive for the whole batch: basalt::Slice
  // does not own its bytes, so a temporary here would be a dangling read.
  std::vector<std::string> keys_held;
  std::vector<std::string> values_held;
  keys_held.reserve(ops.size());
  values_held.reserve(ops.size());
  for (const LoggedOp& op : ops) {
    keys_held.push_back(MakeOpLogKey(object, op.id.replica, op.id.counter));
    if (impl_->keys == nullptr) {
      values_held.push_back(op.payload.bytes);
    } else {
      // THE ONE PLACE ENCRYPTION HAPPENS. Above this line the system deals in
      // OpPayload; below it, in ciphertext. No CRDT code is on either side of
      // it.
      const Epoch e = impl_->keys->current();
      SecretKey k;
      if (impl_->keys->ContentKey(e, &k) != CryptoStatus::kOk) {
        return LogStatus::kWriteFailed;
      }
      SealContext ctx;
      ctx.object = object;
      ctx.op = op.id;
      ctx.epoch = e;
      std::string value;
      PutEnvelope(e, &value);
      value += Seal(k, ctx, op.payload.bytes);
      values_held.push_back(value);
    }
  }
  for (std::size_t i = 0; i < ops.size(); ++i) {
    batch.Set(basalt::Slice(keys_held[i]), basalt::Slice(values_held[i]));
  }
  basalt::wal::SeqNum seq = 0;
  const basalt::Status s = impl_->db->Write(batch, &seq);
  return s.ok() ? LogStatus::kOk : LogStatus::kWriteFailed;
}

// THE ONE READ PATH, and it is one on purpose.
//
// Before encryption there were three readers -- ReadRaw, ReadObject and
// ReadFrom -- each with its own iterator. Adding decryption to ReadRaw left the
// other two returning ciphertext to a decoder, which is how
// RelayView.TheVaultRoundTripsThroughAnEncryptedLog failed. The payload
// boundary held on the WRITE side, where there was already a single AppendRaw;
// it did not hold on the read side, because nobody had made the reads go
// through one place. They do now.
LogStatus OpLog::ReadBounded(const ObjectId& object, const std::string& lo,
                             const std::string& hi_exclusive,
                             std::vector<LoggedOp>* out) const {
  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi_exclusive));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  for (bool ok = it->First(); ok; ok = it->Next()) {
    LoggedOp lop;
    ObjectId obj;
    if (!ParseOpLogKey(it->Key().ToString(), &obj, &lop.id.replica,
                       &lop.id.counter)) {
      (void)it->Close();
      return LogStatus::kCorrupt;
    }
    const std::string stored = it->Value().ToString();
    if (impl_->keys == nullptr) {
      lop.payload.bytes = stored;
    } else {
      Epoch e = 0;
      if (!GetEnvelope(stored, &e)) {
        (void)it->Close();
        return LogStatus::kCorrupt;
      }
      SecretKey k;
      if (impl_->keys->ContentKey(e, &k) != CryptoStatus::kOk) {
        // A payload from an epoch this device does not hold. That is what a
        // removed device sees, and it is a legitimate outcome rather than
        // corruption -- but this log belongs to a device that should have the
        // key, so it is reported rather than skipped.
        (void)it->Close();
        return LogStatus::kCorrupt;
      }
      SealContext ctx;
      ctx.object = obj;
      ctx.op = lop.id;
      ctx.epoch = e;
      // Qualified: OpLog::Open is in scope here and would be found first.
      if (::umbra::Open(k, ctx, stored.substr(kEnvelopeBytes),
                        &lop.payload.bytes) != CryptoStatus::kOk) {
        (void)it->Close();
        return LogStatus::kCorrupt;
      }
    }
    out->push_back(lop);
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  (void)object;
  return err.ok() ? LogStatus::kOk : LogStatus::kReadFailed;
}

LogStatus OpLog::ReadRaw(const ObjectId& object,
                         std::vector<LoggedOp>* out) const {
  const std::string lo = MakeOpLogKey(object, ReplicaId{}, 0);
  ReplicaId max_replica;
  for (std::size_t i = 0; i < max_replica.bytes.size(); ++i) {
    max_replica.bytes[i] = 0xFF;
  }
  std::string hi = MakeOpLogKey(object, max_replica, UINT64_MAX);
  hi.push_back('\0');
  return ReadBounded(object, lo, hi, out);
}

LogStatus OpLog::AppendTree(const std::vector<TreeOp>& ops) {
  std::vector<LoggedOp> raw;
  raw.reserve(ops.size());
  for (const TreeOp& op : ops) {
    LoggedOp l;
    l.id = op.id;
    l.payload = EncodeTreeOp(op);
    raw.push_back(l);
  }
  return AppendRaw(TreeObject(), raw);
}

LogStatus OpLog::ReadTree(std::vector<TreeOp>* out) const {
  std::vector<LoggedOp> raw;
  const LogStatus s = ReadRaw(TreeObject(), &raw);
  if (s != LogStatus::kOk) return s;
  for (const LoggedOp& l : raw) {
    TreeOp op;
    if (!DecodeTreeOp(l.payload, &op)) return LogStatus::kCorrupt;
    out->push_back(op);
  }
  return LogStatus::kOk;
}

LogStatus OpLog::ReplayTree(TreeDoc* tree,
                            std::map<ReplicaId, uint64_t>* high_water) const {
  std::vector<TreeOp> ops;
  const LogStatus s = ReadTree(&ops);
  if (s != LogStatus::kOk) return s;
  for (const TreeOp& op : ops) {
    const TreeApply r = tree->Apply(op);
    if (r == TreeApply::kMalformed) return LogStatus::kCorrupt;
    uint64_t& hw = (*high_water)[op.id.replica];
    if (op.id.counter > hw) hw = op.id.counter;
  }
  return LogStatus::kOk;
}

LogStatus OpLog::Append(const ObjectId& object, const std::vector<Op>& ops) {
  if (ops.empty()) return LogStatus::kOk;
  std::vector<LoggedOp> raw;
  raw.reserve(ops.size());
  for (const Op& op : ops) {
    LoggedOp l;
    l.id = op.id;
    l.payload = EncodeOp(op);
    raw.push_back(l);
  }
  return AppendRaw(object, raw);
}

LogStatus OpLog::ReadObject(const ObjectId& object,
                            std::vector<Op>* out) const {
  std::vector<LoggedOp> raw;
  const LogStatus s = ReadRaw(object, &raw);
  if (s != LogStatus::kOk) return s;
  for (const LoggedOp& l : raw) {
    Op op;
    if (!DecodeOp(l.payload, &op)) return LogStatus::kCorrupt;
    out->push_back(op);
  }
  return LogStatus::kOk;
}

LogStatus OpLog::ReadFrom(const ObjectId& object, const ReplicaId& replica,
                          uint64_t after, std::vector<Op>* out) const {
  const std::string lo = MakeOpLogKey(object, replica, after + 1);
  std::string hi = MakeOpLogKey(object, replica, UINT64_MAX);
  hi.push_back('\0');
  std::vector<LoggedOp> raw;
  const LogStatus s = ReadBounded(object, lo, hi, &raw);
  if (s != LogStatus::kOk) return s;
  for (const LoggedOp& l : raw) {
    Op op;
    if (!DecodeOp(l.payload, &op)) return LogStatus::kCorrupt;
    out->push_back(op);
  }
  return LogStatus::kOk;
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

namespace {

// Cursors live under a different first byte from operations, so the two key
// spaces cannot overlap however the ids fall.
std::string CursorKey(const ObjectId& object, const ReplicaId& source) {
  std::string k(1, 'c');
  k.append(reinterpret_cast<const char*>(object.bytes.data()),
           object.bytes.size());
  k.append(reinterpret_cast<const char*>(source.bytes.data()),
           source.bytes.size());
  return k;
}

}  // namespace

LogStatus OpLog::ReadStoredFrom(const ObjectId& object,
                                const ReplicaId& replica, uint64_t after,
                                std::vector<StoredBlob>* out) const {
  if (after == UINT64_MAX) return LogStatus::kReadFailed;
  const std::string lo = MakeOpLogKey(object, replica, after + 1);
  std::string hi = MakeOpLogKey(object, replica, UINT64_MAX);
  hi.push_back('\0');

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  for (bool ok = it->First(); ok; ok = it->Next()) {
    StoredBlob b;
    ObjectId obj;
    if (!ParseOpLogKey(it->Key().ToString(), &obj, &b.id.replica,
                       &b.id.counter)) {
      (void)it->Close();
      return LogStatus::kCorrupt;
    }
    const std::string stored = it->Value().ToString();
    if (impl_->keys == nullptr) {
      b.epoch = 0;
      b.sealed = stored;
    } else {
      if (!GetEnvelope(stored, &b.epoch)) {
        (void)it->Close();
        return LogStatus::kCorrupt;
      }
      b.sealed = stored.substr(kEnvelopeBytes);
    }
    out->push_back(b);
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok() ? LogStatus::kOk : LogStatus::kReadFailed;
}

bool OpLog::SourcesFor(const ObjectId& object,
                       std::vector<ReplicaId>* out) const {
  const std::string lo = MakeOpLogKey(object, ReplicaId{}, 0);
  ReplicaId max_replica;
  for (std::size_t i = 0; i < max_replica.bytes.size(); ++i) {
    max_replica.bytes[i] = 0xFF;
  }
  std::string hi = MakeOpLogKey(object, max_replica, UINT64_MAX);
  hi.push_back('\0');

  basalt::IterOptions o;
  o.lower = basalt::Bound::At(basalt::Slice(lo));
  o.upper = basalt::Bound::At(basalt::Slice(hi));
  std::unique_ptr<basalt::Iterator> it = impl_->db->NewIter(o);
  ReplicaId last;
  bool have_last = false;
  for (bool ok = it->First(); ok; ok = it->Next()) {
    ObjectId obj;
    ReplicaId rep;
    uint64_t counter = 0;
    if (!ParseOpLogKey(it->Key().ToString(), &obj, &rep, &counter)) continue;
    if (!have_last || !(rep == last)) {
      out->push_back(rep);
      last = rep;
      have_last = true;
    }
  }
  const basalt::Status err = it->Error();
  (void)it->Close();
  return err.ok();
}

bool OpLog::HighestFrom(const ObjectId& object, const ReplicaId& replica,
                        uint64_t* out) const {
  std::vector<StoredBlob> blobs;
  if (ReadStoredFrom(object, replica, 0, &blobs) != LogStatus::kOk)
    return false;
  if (blobs.empty()) return false;
  *out = blobs.back().id.counter;
  return true;
}

bool OpLog::GetCursor(const ObjectId& object, const ReplicaId& source,
                      uint64_t* out) const {
  std::string value;
  // The key must outlive the Slice: basalt::Slice does not own its bytes, so a
  // temporary here would be a dangling read.
  const std::string key = CursorKey(object, source);
  const basalt::Status s = impl_->db->Get(basalt::Slice(key), &value);
  if (!s.ok() || value.size() != 8) return false;
  *out = 0;
  for (int i = 0; i < 8; ++i) {
    *out |= static_cast<uint64_t>(
                static_cast<unsigned char>(value[static_cast<std::size_t>(i)]))
            << (8 * i);
  }
  return true;
}

bool OpLog::SetCursor(const ObjectId& object, const ReplicaId& source,
                      uint64_t value) {
  std::string v;
  for (int i = 0; i < 8; ++i) {
    v.push_back(static_cast<char>((value >> (8 * i)) & 0xFF));
  }
  basalt::WriteBatch batch;
  const std::string key = CursorKey(object, source);
  batch.Set(basalt::Slice(key), basalt::Slice(v));
  basalt::wal::SeqNum seq = 0;
  return impl_->db->Write(batch, &seq).ok();
}

LogStatus OpLog::Sync() {
  basalt::wal::SeqNum watermark = 0;
  const basalt::Status s = impl_->db->Sync(&watermark);
  return s.ok() ? LogStatus::kOk : LogStatus::kWriteFailed;
}

}  // namespace umbra
