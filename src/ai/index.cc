#include "umbra/ai/index.h"

#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <set>

#include "basalt/db.h"
#include "basalt/posix_env.h"
#include "basalt/slice.h"
#include "keyspace.h"

namespace umbra {
namespace ai {
namespace {

// HOW MUCH LARGER A SEGMENT MAY BE than the smallest in a round and still be
// merged with it. Four is the usual starting point for a tiered store: small
// enough that the big compacted segment is left alone until several of its own
// size have accumulated, large enough that a round makes real progress.
constexpr uint32_t kTierRatio = 4;

// Key spaces in the manifest. One byte each, so a scan over one never sees
// another, and a person reading the store with a hex dump can tell them apart.
constexpr char kSegmentPrefix = 's';    // 's' || segment id   -> count, bytes
constexpr char kTombstonePrefix = 't';  // 't' || seg || slot  -> empty
constexpr char kObjectPrefix = 'o';     // 'o' || object || seg || slot -> empty
constexpr char kMetaPrefix = 'm';       // 'm' || name         -> value
// 'p' || counter(8 BE) -> the encoded operation. PENDING OPERATIONS OUTLIVE THE
// PROCESS THAT MADE THEM. They were in memory only to begin with, and the
// end-to-end run showed exactly what that costs: a device indexed a vault,
// exited, and the next process published ten segments and zero operations --
// so the segments were on the relay and nothing said they existed.
constexpr char kPendingPrefix = 'p';
// 'a' || segment id -> empty. A SEGMENT THIS DEVICE HAS ANNOUNCED, either
// because it made the kAdd or because it adopted the segment from a peer that
// had. Without it a device cannot tell "everyone knows about this segment" from
// "I have it and nobody has been told", and the two look identical on disk.
//
// The 24 MB transfer found the difference: an index built before manifest
// operations existed pushed its segments and published nothing, so the peer
// learned of no segments and called itself complete.
constexpr char kAnnouncedPrefix = 'a';

void PutU32(std::string* out, uint32_t v) {
  out->push_back(static_cast<char>((v >> 24) & 0xFF));
  out->push_back(static_cast<char>((v >> 16) & 0xFF));
  out->push_back(static_cast<char>((v >> 8) & 0xFF));
  out->push_back(static_cast<char>(v & 0xFF));
}

uint32_t GetU32(const char* p) {
  return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24) |
         (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8) |
         static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
}

// 'w' || replica(16) || counter(8) -> encoded operation. A MANIFEST OPERATION
// FROM A PEER THAT THE DISK CANNOT RE-DERIVE.
//
// The fold is rebuilt at Open from what is on disk, which is right for
// everything this device HOLDS and silently wrong for everything it has only
// been TOLD ABOUT. A kAdd for a segment whose bytes have not arrived leaves no
// trace anywhere: kill a puller partway and it comes back having forgotten that
// the other segments exist, while its cursor says it already consumed those
// operations. It then reports a complete index. Measured: killed at 1662 of
// 2000 segments, it restarted, applied nothing, fetched nothing, and said
// "complete: yes" while missing 339.
//
// So the operations that the disk cannot reconstruct are journalled here and
// replayed at Open. The mirror of the 'p' prefix, which holds what this device
// produced and has not yet published.
constexpr char kWantedPrefix = 'w';

std::string WantedKey(const OpId& id) {
  std::string k(1, kWantedPrefix);
  k.append(reinterpret_cast<const char*>(id.replica.bytes.data()),
           id.replica.bytes.size());
  for (int i = 7; i >= 0; --i) {
    k.push_back(static_cast<char>((id.counter >> (i * 8)) & 0xFF));
  }
  return k;
}

// The last counter this device PUBLISHED, which anchors the back-pointer
// chain. Kept apart from the counter high-water mark because reopening an
// index advances that mark without publishing anything.
std::string PublishedKey() { return std::string(1, kMetaPrefix) + "published"; }

std::string Counter8(uint64_t v) {
  std::string out;
  for (int i = 7; i >= 0; --i) {
    out.push_back(static_cast<char>((v >> (i * 8)) & 0xFF));
  }
  return out;
}

bool ReadCounter8(const std::string& v, uint64_t* out) {
  if (v.size() != 8) return false;
  uint64_t n = 0;
  for (std::size_t i = 0; i < 8; ++i) n = (n << 8) | static_cast<uint8_t>(v[i]);
  *out = n;
  return true;
}

std::string AnnouncedKey(const SegmentId& id) {
  std::string k(1, kAnnouncedPrefix);
  k.append(reinterpret_cast<const char*>(id.bytes.data()), id.bytes.size());
  return k;
}

std::string SegmentKey(const SegmentId& id) {
  std::string k(1, kSegmentPrefix);
  k.append(reinterpret_cast<const char*>(id.bytes.data()), id.bytes.size());
  return k;
}

std::string TombstoneKey(const SegmentId& id, uint32_t slot) {
  std::string k(1, kTombstonePrefix);
  k.append(reinterpret_cast<const char*>(id.bytes.data()), id.bytes.size());
  PutU32(&k, slot);
  return k;
}

std::string ObjectKey(const ObjectId& object, const SegmentId& seg,
                      uint32_t slot) {
  std::string k(1, kObjectPrefix);
  k.append(reinterpret_cast<const char*>(object.bytes.data()),
           object.bytes.size());
  k.append(reinterpret_cast<const char*>(seg.bytes.data()), seg.bytes.size());
  PutU32(&k, slot);
  return k;
}

bool MakeDirs(const std::string& path) {
  if (path.empty()) return false;
  std::string built;
  std::size_t i = 0;
  if (path[0] == '/') {
    built = "/";
    i = 1;
  }
  while (i < path.size()) {
    std::size_t j = path.find('/', i);
    if (j == std::string::npos) j = path.size();
    built += path.substr(i, j - i);
    if (::mkdir(built.c_str(), 0700) != 0 && errno != EEXIST) return false;
    built += "/";
    i = j + 1;
  }
  return true;
}

bool ReadWholeFile(const std::string& path, std::string* out) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) return false;
  out->clear();
  char buf[65536];
  std::size_t n = 0;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out->append(buf, n);
  const bool ok = std::ferror(f) == 0;
  std::fclose(f);
  return ok;
}

// TEMP AND RENAME, because a segment is named by the hash of its contents and a
// half-written file under that name is a lie the manifest would then believe.
bool WriteFileAtomically(const std::string& path, const std::string& body) {
  const std::string tmp = path + ".tmp";
  std::FILE* f = std::fopen(tmp.c_str(), "wb");
  if (f == nullptr) return false;
  const bool wrote = std::fwrite(body.data(), 1, body.size(), f) == body.size();
  const bool flushed = std::fflush(f) == 0;
  const int fd = ::fileno(f);
  const bool synced = (fd >= 0) && (::fsync(fd) == 0);
  std::fclose(f);
  if (!wrote || !flushed || !synced) {
    ::unlink(tmp.c_str());
    return false;
  }
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    return false;
  }
  return true;
}

struct Loaded {
  SegmentId id;
  std::unique_ptr<Segment> segment;
  // One bit per slot. Read from the manifest at open and kept in memory,
  // because search consults it for every candidate.
  std::vector<bool> dead;
  uint32_t dead_count = 0;
  uint64_t bytes = 0;
};

bool NearerHit(const SearchHit& a, const SearchHit& b) {
  if (a.score != b.score) return a.score > b.score;
  // A TOTAL ORDER ACROSS SEGMENTS. Two hits with equal scores in different
  // segments would otherwise be ordered by whichever segment happened to be
  // visited first, which depends on manifest iteration and would make results
  // depend on insertion history rather than on the query.
  if (a.segment != b.segment) return a.segment < b.segment;
  return a.slot < b.slot;
}

}  // namespace

const char* IndexStatusName(IndexStatus s) {
  switch (s) {
    case IndexStatus::kOk:
      return "ok";
    case IndexStatus::kStoreFailed:
      return "store-failed";
    case IndexStatus::kSegmentLost:
      return "segment-lost";
    case IndexStatus::kModelMismatch:
      return "model-mismatch";
    case IndexStatus::kBadArgument:
      return "bad-argument";
  }
  return "unknown";
}

struct Index::Impl {
  std::string dir;
  std::string segment_dir;
  const VaultKeys* keys = nullptr;
  Epoch epoch = 0;
  EmbeddingModelId model;
  uint32_t dimension = 0;
  ReplicaId replica;
  std::unique_ptr<basalt::Env> env;
  std::unique_ptr<basalt::DB> db;
  // Ordered so that iteration, and therefore search order and tie-breaking, is
  // a function of the ids rather than of insertion history.
  std::map<SegmentId, Loaded> segments;

  // The replicated half. `manifest` is the fold of every operation this device
  // has seen, its own included; `pending` is what it has produced and not yet
  // handed to a client to publish.
  std::unique_ptr<ManifestDoc> manifest;
  std::vector<ManifestOp> pending;
  // This replica's manifest counter and the back-pointer to its previous
  // operation, exactly as the text and tree logs keep them.
  uint64_t counter = 0;
  uint64_t prev = 0;

  std::string PathFor(const SegmentId& id) const {
    return segment_dir + "/" + id.Hex() + ".seg";
  }

  bool Present(const SegmentId& id) const { return segments.count(id) != 0; }

  // Every manifest operation this device makes goes through here, so the
  // counter and the chain cannot be advanced in one place and forgotten in
  // another.
  ManifestOp Make(ManifestOpKind kind) {
    ManifestOp op;
    op.kind = kind;
    op.id.replica = replica;
    op.id.counter = ++counter;
    op.prev = prev;
    prev = op.id.counter;
    return op;
  }

  void Emit(const ManifestOp& op) {
    (void)manifest->Apply(op);
    pending.push_back(op);
    if (op.kind == ManifestOpKind::kAdd) MarkAnnounced(op.segment);
    const std::string key =
        std::string(1, kPendingPrefix) + Counter8(op.id.counter);
    const std::string value = EncodeManifestOp(op);
    basalt::WriteBatch batch;
    batch.Set(basalt::Slice(key), basalt::Slice(value));
    // AND THE CHAIN HEAD, IN THE SAME BATCH. A puller verifies that each
    // operation's back-pointer names the one before it, starting from zero, so
    // the value this device must remember across a restart is the counter of
    // the last operation it PUBLISHED. That is not the same number as the
    // counter high-water mark below: reopening an index burns counters
    // reconstructing the local fold, and a chain anchored to a burnt counter
    // points at an operation no peer has ever seen. Same batch as the operation
    // because a chain head that outlives its operation, or the reverse, is a
    // chain nobody can follow.
    const std::string head_key = PublishedKey();
    const std::string head = Counter8(op.id.counter);
    batch.Set(basalt::Slice(head_key), basalt::Slice(head));
    basalt::wal::SeqNum seq = 0;
    (void)db->Write(batch, &seq);
  }

  // Journal an operation the disk cannot re-derive, and forget the ones it can.
  void RememberWanted(const ManifestOp& op) {
    const std::string key = WantedKey(op.id);
    const std::string value = EncodeManifestOp(op);
    basalt::WriteBatch batch;
    batch.Set(basalt::Slice(key), basalt::Slice(value));
    basalt::wal::SeqNum seq = 0;
    if (!db->Write(batch, &seq).ok()) return;
    // SYNCED, BECAUSE THE CURSOR THAT CONSUMED THIS OPERATION IS ALREADY
    // DURABLE. The client persists its cursor per operation
    // (src/sync/client.cc:216) and will never hand this one over again, so a
    // journal entry lost to a crash is an operation lost for good.
    basalt::wal::SeqNum watermark = 0;
    (void)db->Sync(&watermark);
  }

  void ForgetWanted(const std::vector<OpId>& ids) {
    if (ids.empty()) return;
    basalt::WriteBatch batch;
    std::vector<std::string> keys;
    keys.reserve(ids.size());
    for (const OpId& id : ids) keys.push_back(WantedKey(id));
    for (const std::string& k : keys) batch.Delete(basalt::Slice(k));
    basalt::wal::SeqNum seq = 0;
    (void)db->Write(batch, &seq);
  }

  void MarkAnnounced(const SegmentId& id) {
    const std::string key = AnnouncedKey(id);
    basalt::WriteBatch batch;
    batch.Set(basalt::Slice(key), basalt::Slice(""));
    basalt::wal::SeqNum seq = 0;
    (void)db->Write(batch, &seq);
  }

  bool Announced(const SegmentId& id) const {
    const std::string key = AnnouncedKey(id);
    std::string held;
    return db->Get(basalt::Slice(key), &held).ok();
  }

  // THE PUBLISHED COUNTER IS PERSISTED, so a restart continues the sequence
  // rather than reissuing ids another device has already seen. The oplog is
  // keyed by (object, replica, counter), so a reissued counter is a lost write
  // and not a conflict -- the same defect Vault::ApplyTreeOp had.
  void SaveCounter() {
    const std::string value = Counter8(counter);
    const std::string key = std::string(1, kMetaPrefix) + "counter";
    basalt::WriteBatch batch;
    batch.Set(basalt::Slice(key), basalt::Slice(value));
    basalt::wal::SeqNum seq = 0;
    if (!db->Write(batch, &seq).ok()) return;
    basalt::wal::SeqNum watermark = 0;
    (void)db->Sync(&watermark);
  }
};

Index::Index() : impl_(new Impl) {}
Index::~Index() = default;

IndexStatus Index::Open(const std::string& dir, const VaultKeys* keys,
                        Epoch epoch, const EmbeddingModelId& model,
                        uint32_t dimension, const ReplicaId& replica,
                        std::unique_ptr<Index>* out) {
  if (keys == nullptr || dimension == 0) return IndexStatus::kBadArgument;
  std::unique_ptr<Index> idx(new Index);
  Impl& im = *idx->impl_;
  im.dir = dir;
  im.segment_dir = dir + "/segments";
  im.keys = keys;
  im.epoch = epoch;
  im.model = model;
  im.dimension = dimension;
  im.replica = replica;
  im.manifest.reset(new ManifestDoc(model));
  if (!MakeDirs(im.segment_dir)) return IndexStatus::kStoreFailed;
  // Basalt opens a directory that already exists; it does not create one.
  if (!MakeDirs(dir + "/manifest")) return IndexStatus::kStoreFailed;

  im.env = basalt::NewPosixEnv();
  const basalt::wal::Caps caps;
  if (!basalt::DB::Open(im.env.get(), dir + "/manifest", caps, &im.db).ok()) {
    return IndexStatus::kStoreFailed;
  }

  // THE MODEL IS RECORDED IN THE MANIFEST ON FIRST OPEN and checked on every
  // one after. Refusing here, once, is the whole reason the identity exists:
  // the alternative is a store that quietly mixes two vector spaces.
  {
    const std::string key = std::string(1, kMetaPrefix) + "model";
    std::string held;
    const basalt::Slice k(key);
    if (im.db->Get(k, &held).ok()) {
      if (held.size() != model.bytes.size() ||
          std::memcmp(held.data(), model.bytes.data(), held.size()) != 0) {
        return IndexStatus::kModelMismatch;
      }
    } else {
      basalt::WriteBatch batch;
      const std::string value(reinterpret_cast<const char*>(model.bytes.data()),
                              model.bytes.size());
      batch.Set(basalt::Slice(key), basalt::Slice(value));
      basalt::wal::SeqNum seq = 0;
      if (!im.db->Write(batch, &seq).ok()) return IndexStatus::kStoreFailed;
      // SYNCED, because this is the record that decides whether the store will
      // ever accept a different model. Without it, an index created and closed
      // without anything being added forgot its own identity, and the next
      // open adopted whatever model it was given -- which is precisely the
      // silent mixing of two vector spaces the identity exists to prevent.
      basalt::wal::SeqNum watermark = 0;
      if (!im.db->Sync(&watermark).ok()) return IndexStatus::kStoreFailed;
    }
  }

  // Load every segment the manifest names, then apply the tombstones.
  {
    const std::string lo(1, kSegmentPrefix);
    const std::string hi = PrefixUpperBound(lo);
    basalt::IterOptions o;
    o.lower = basalt::Bound::At(basalt::Slice(lo));
    o.upper = basalt::Bound::At(basalt::Slice(hi));
    std::unique_ptr<basalt::Iterator> it = im.db->NewIter(o);
    for (bool ok = it->First(); ok; ok = it->Next()) {
      const std::string k = it->Key().ToString();
      if (k.size() != 1 + 32) {
        (void)it->Close();
        return IndexStatus::kStoreFailed;
      }
      Loaded loaded;
      std::memcpy(loaded.id.bytes.data(), k.data() + 1, loaded.id.bytes.size());
      std::string sealed;
      if (!ReadWholeFile(im.PathFor(loaded.id), &sealed)) {
        (void)it->Close();
        return IndexStatus::kSegmentLost;
      }
      const SegmentStatus ss =
          Segment::Open(*keys, sealed, model, &loaded.segment);
      if (ss == SegmentStatus::kModelMismatch) {
        (void)it->Close();
        return IndexStatus::kModelMismatch;
      }
      if (ss != SegmentStatus::kOk) {
        (void)it->Close();
        return IndexStatus::kSegmentLost;
      }
      loaded.bytes = sealed.size();
      loaded.dead.assign(loaded.segment->count(), false);
      im.segments[loaded.id] = std::move(loaded);
    }
    const basalt::Status err = it->Error();
    (void)it->Close();
    if (!err.ok()) return IndexStatus::kStoreFailed;
  }
  {
    const std::string lo(1, kTombstonePrefix);
    const std::string hi = PrefixUpperBound(lo);
    basalt::IterOptions o;
    o.lower = basalt::Bound::At(basalt::Slice(lo));
    o.upper = basalt::Bound::At(basalt::Slice(hi));
    std::unique_ptr<basalt::Iterator> it = im.db->NewIter(o);
    for (bool ok = it->First(); ok; ok = it->Next()) {
      const std::string k = it->Key().ToString();
      if (k.size() != 1 + 32 + 4) continue;
      SegmentId id;
      std::memcpy(id.bytes.data(), k.data() + 1, id.bytes.size());
      const uint32_t slot = GetU32(k.data() + 1 + 32);
      const std::map<SegmentId, Loaded>::iterator f = im.segments.find(id);
      if (f == im.segments.end()) continue;  // segment already compacted away
      if (slot >= f->second.dead.size()) continue;
      if (!f->second.dead[slot]) {
        f->second.dead[slot] = true;
        ++f->second.dead_count;
      }
    }
    const basalt::Status err = it->Error();
    (void)it->Close();
    if (!err.ok()) return IndexStatus::kStoreFailed;
  }

  // THE MANIFEST FOLD IS REBUILT FROM WHAT IS ON DISK, not persisted as a
  // second copy. The local store already records which segments exist and which
  // slots are dead; deriving the fold from it means there is one source of
  // truth on this device and no way for the two to disagree after a crash.
  //
  // Operations that arrived from peers were applied to the store as they came,
  // so replaying them is not needed either. What IS lost across a restart is
  // this device's manifest counter, which is recovered below.
  for (const std::pair<const SegmentId, Loaded>& kv : im.segments) {
    ManifestOp add;
    add.kind = ManifestOpKind::kAdd;
    add.id.replica = replica;
    // Counter zero would be refused as malformed, and these are not real
    // operations -- they are the fold of operations already published. The
    // sequence is local and never leaves this device.
    add.id.counter = ++im.counter;
    add.prev = im.counter - 1;
    add.segment = kv.first;
    add.count = kv.second.segment->count();
    add.bytes = kv.second.bytes;
    add.model = model;
    (void)im.manifest->Apply(add);
    for (uint32_t slot = 0; slot < kv.second.dead.size(); ++slot) {
      if (!kv.second.dead[slot]) continue;
      ManifestOp t;
      t.kind = ManifestOpKind::kTombstone;
      t.id.replica = replica;
      t.id.counter = ++im.counter;
      t.prev = im.counter - 1;
      t.segment = kv.first;
      t.slot = slot;
      (void)im.manifest->Apply(t);
    }
  }
  // AND THE OPERATIONS THE DISK COULD NOT SAY AGAIN ARE REPLAYED. See
  // kWantedPrefix: the fold above knows only what this device HOLDS, so
  // without this a puller that died partway came back having forgotten that
  // the segments it had not reached yet exist -- and its cursor, which is
  // durable and per operation, would never offer them again.
  {
    std::vector<ManifestOp> replay;
    const std::string lo(1, kWantedPrefix);
    const std::string hi(1, kWantedPrefix + 1);
    basalt::IterOptions o;
    o.lower = basalt::Bound::At(basalt::Slice(lo));
    o.upper = basalt::Bound::At(basalt::Slice(hi));
    std::unique_ptr<basalt::Iterator> it = im.db->NewIter(o);
    for (bool ok = it->First(); ok; ok = it->Next()) {
      ManifestOp op;
      if (!DecodeManifestOp(it->Value().ToString(), &op)) continue;
      replay.push_back(op);
    }
    const basalt::Status err = it->Error();
    (void)it->Close();
    if (!err.ok()) return IndexStatus::kStoreFailed;
    for (const ManifestOp& op : replay) (void)im.manifest->Apply(op);

    // What the disk can now derive on its own goes: a kAdd or a tombstone for a
    // segment that has since arrived is rebuilt from the segment record and the
    // tombstone keys. A retirement is derivable from nothing and stays.
    std::vector<OpId> done;
    for (const ManifestOp& op : replay) {
      if (op.kind == ManifestOpKind::kRetire) continue;
      if (!im.Present(op.segment)) continue;
      done.push_back(op.id);
    }
    im.ForgetWanted(done);
  }

  // A SEGMENT NOBODY HAS BEEN TOLD ABOUT IS ANNOUNCED NOW.
  //
  // The fold above is reconstructed for local use and says nothing about what
  // the vault knows. A segment that is present and unannounced is one this
  // device holds and has never published -- an index built before manifest
  // operations existed, or one whose pending operations were taken and lost
  // before they reached a relay. Either way the peers cannot know it exists,
  // and the only device that can tell them is this one.
  //
  // THE COUNTER AND THE CHAIN HEAD ARE RECOVERED FROM THE STORE, not restarted,
  // and they are two different numbers.
  //
  // The counter is a high-water mark for issuing ids: a device that reissued
  // one after a restart would produce two manifest operations with a single id,
  // and the oplog is keyed by (object, replica, counter), so the second would
  // overwrite the first. That is the defect Vault::ApplyTreeOp had, and it is
  // worth not making twice. The fold above burns counters for the same reason
  // -- its reconstructed operations must not collide with published ones.
  //
  // The chain head is what a puller verifies against, and it must name an
  // operation that actually reached a relay. Anchoring the chain to the counter
  // instead cost a whole afternoon: with two real devices the puller reported
  // chain-broken and applied nothing, because the first operation this device
  // published pointed back at a counter burnt reconstructing a local fold.
  {
    const std::string counter_key = std::string(1, kMetaPrefix) + "counter";
    const std::string head_key = PublishedKey();
    std::string held;
    uint64_t stored = 0;
    if (im.db->Get(basalt::Slice(counter_key), &held).ok() &&
        ReadCounter8(held, &stored) && stored > im.counter) {
      im.counter = stored;
    }
    uint64_t published = 0;
    if (im.db->Get(basalt::Slice(head_key), &held).ok()) {
      (void)ReadCounter8(held, &published);
    }
    im.prev = published;
  }
  for (const std::pair<const SegmentId, Loaded>& kv : im.segments) {
    if (im.Announced(kv.first)) continue;
    ManifestOp add = im.Make(ManifestOpKind::kAdd);
    add.segment = kv.first;
    add.count = kv.second.segment->count();
    add.bytes = kv.second.bytes;
    add.model = model;
    im.Emit(add);
    for (uint32_t slot = 0; slot < kv.second.dead.size(); ++slot) {
      if (!kv.second.dead[slot]) continue;
      ManifestOp t = im.Make(ManifestOpKind::kTombstone);
      t.segment = kv.first;
      t.slot = slot;
      im.Emit(t);
    }
  }
  im.SaveCounter();

  *out = std::move(idx);
  return IndexStatus::kOk;
}

IndexStatus Index::PutObject(const ObjectId& object,
                             const std::vector<Chunk>& chunks,
                             const std::vector<Vector>& vectors) {
  Impl& im = *impl_;
  if (chunks.size() != vectors.size()) return IndexStatus::kBadArgument;
  for (const Vector& v : vectors) {
    if (v.size() != im.dimension) return IndexStatus::kBadArgument;
  }

  // Find the object's existing slots first. They are tombstoned in the SAME
  // write as the new segment is added, so a crash between the two cannot leave
  // a vault with both the old and the new chunks of one note answering queries.
  std::vector<std::pair<SegmentId, uint32_t>> previous;
  {
    std::string lo(1, kObjectPrefix);
    lo.append(reinterpret_cast<const char*>(object.bytes.data()),
              object.bytes.size());
    const std::string hi = PrefixUpperBound(lo);
    basalt::IterOptions o;
    o.lower = basalt::Bound::At(basalt::Slice(lo));
    if (!hi.empty()) o.upper = basalt::Bound::At(basalt::Slice(hi));
    std::unique_ptr<basalt::Iterator> it = im.db->NewIter(o);
    for (bool ok = it->First(); ok; ok = it->Next()) {
      const std::string k = it->Key().ToString();
      if (k.size() != 1 + 16 + 32 + 4) continue;
      SegmentId seg;
      std::memcpy(seg.bytes.data(), k.data() + 1 + 16, seg.bytes.size());
      previous.push_back({seg, GetU32(k.data() + 1 + 16 + 32)});
    }
    const basalt::Status err = it->Error();
    (void)it->Close();
    if (!err.ok()) return IndexStatus::kStoreFailed;
  }

  basalt::WriteBatch batch;
  // Declared BEFORE anything that adds to the batch. Every key and value handed
  // to a Slice has to outlive the Write, and the first version scoped the
  // segment key and its value to the if-block below -- they were destroyed
  // before Write ran, so the batch stored a segment entry from freed memory.
  std::deque<std::string> keep_alive;
  SegmentId new_id;
  std::string sealed;
  bool have_new = false;

  if (!chunks.empty()) {
    std::vector<SegmentEntry> entries;
    entries.reserve(chunks.size());
    for (const Chunk& c : chunks) {
      SegmentEntry e;
      e.object = c.object;
      e.start = c.start;
      e.end = c.end;
      e.ordinal = c.ordinal;
      e.kind = c.kind;
      e.link_ratio = c.link_ratio;
      e.heading_path = c.heading_path;
      entries.push_back(e);
    }
    std::string plaintext;
    if (Segment::Build(im.model, im.dimension, entries, vectors, &plaintext) !=
        SegmentStatus::kOk) {
      return IndexStatus::kBadArgument;
    }
    if (Segment::Seal(*im.keys, im.epoch, plaintext, &sealed, &new_id) !=
        SegmentStatus::kOk) {
      return IndexStatus::kStoreFailed;
    }
    // THE FILE LANDS BEFORE THE MANIFEST NAMES IT. The other order leaves a
    // manifest entry pointing at a file that does not exist, which is
    // indistinguishable from a lost segment; this order can leave an unnamed
    // file, which is garbage rather than corruption.
    if (!WriteFileAtomically(im.PathFor(new_id), sealed)) {
      return IndexStatus::kStoreFailed;
    }
    keep_alive.push_back(std::string());
    std::string& value = keep_alive.back();
    PutU32(&value, static_cast<uint32_t>(chunks.size()));
    PutU32(&value, static_cast<uint32_t>(sealed.size()));
    keep_alive.push_back(SegmentKey(new_id));
    batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(value));
    have_new = true;
  }

  // A DEQUE, NOT A VECTOR, for the same reason: basalt::Slice does not own its
  // bytes, and a vector's push_back reallocates, which moves every string
  // already in it and leaves every Slice built from one pointing at freed
  // memory. The batch then writes and deletes whatever those addresses now
  // hold. A deque never invalidates references to elements already in it.
  // NOT THE SEGMENT WE JUST WROTE. Segments are content addressed, so
  // re-indexing a note that has not changed produces the SAME segment id -- and
  // the object's "previous" slots are then the very slots this call just added.
  // Tombstoning them kills the note it was re-indexing: a second build over an
  // unchanged vault left 19 of 20 vectors dead and one object where there were
  // ten, which is what the end-to-end run found.
  if (have_new) {
    previous.erase(
        std::remove_if(previous.begin(), previous.end(),
                       [&new_id](const std::pair<SegmentId, uint32_t>& p) {
                         return p.first == new_id;
                       }),
        previous.end());
  }

  for (const std::pair<SegmentId, uint32_t>& p : previous) {
    keep_alive.push_back(TombstoneKey(p.first, p.second));
    batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(""));
    keep_alive.push_back(ObjectKey(object, p.first, p.second));
    batch.Delete(basalt::Slice(keep_alive.back()));
  }
  if (have_new) {
    for (uint32_t i = 0; i < static_cast<uint32_t>(chunks.size()); ++i) {
      keep_alive.push_back(ObjectKey(object, new_id, i));
      batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(""));
    }
  }

  basalt::wal::SeqNum seq = 0;
  if (!im.db->Write(batch, &seq).ok()) return IndexStatus::kStoreFailed;
  basalt::wal::SeqNum watermark = 0;
  if (!im.db->Sync(&watermark).ok()) return IndexStatus::kStoreFailed;

  // THE MANIFEST OPERATIONS ARE MADE AFTER THE WRITE IS DURABLE. A device that
  // published "segment X exists" and then failed to write X would be telling
  // its peers to fetch something nobody has.
  if (have_new) {
    ManifestOp add = im.Make(ManifestOpKind::kAdd);
    add.segment = new_id;
    add.count = static_cast<uint32_t>(chunks.size());
    add.bytes = sealed.size();
    add.model = im.model;
    im.Emit(add);
  }
  for (const std::pair<SegmentId, uint32_t>& p : previous) {
    ManifestOp t = im.Make(ManifestOpKind::kTombstone);
    t.segment = p.first;
    t.slot = p.second;
    im.Emit(t);
  }
  im.SaveCounter();

  // Reflect it in memory only after it is durable, so an in-memory index never
  // claims something the manifest does not.
  for (const std::pair<SegmentId, uint32_t>& p : previous) {
    const std::map<SegmentId, Loaded>::iterator f = im.segments.find(p.first);
    if (f == im.segments.end()) continue;
    if (p.second < f->second.dead.size() && !f->second.dead[p.second]) {
      f->second.dead[p.second] = true;
      ++f->second.dead_count;
    }
  }
  if (have_new) {
    Loaded loaded;
    loaded.id = new_id;
    if (Segment::Open(*im.keys, sealed, im.model, &loaded.segment) !=
        SegmentStatus::kOk) {
      return IndexStatus::kSegmentLost;
    }
    loaded.bytes = sealed.size();
    loaded.dead.assign(loaded.segment->count(), false);
    im.segments[new_id] = std::move(loaded);
  }
  return IndexStatus::kOk;
}

IndexStatus Index::RemoveObject(const ObjectId& object) {
  return PutObject(object, {}, {});
}

IndexStatus Index::Search(const Vector& query, uint32_t k, uint32_t ef,
                          std::vector<SearchHit>* out) const {
  out->clear();
  if (query.size() != impl_->dimension) return IndexStatus::kBadArgument;
  if (k == 0) return IndexStatus::kOk;

  std::vector<SearchHit> all;
  for (const std::pair<const SegmentId, Loaded>& kv : impl_->segments) {
    const Loaded& l = kv.second;
    // EVERY SLOT DEAD MEANS NOTHING TO FIND. Skipping the segment entirely is
    // not merely faster: searching it would traverse a graph whose every result
    // is filtered out, which is the worst case for the beam.
    if (l.dead_count >= l.segment->count()) continue;
    const std::vector<Neighbour> found =
        l.segment->Search(query, k, ef, l.dead);
    for (const Neighbour& n : found) {
      const SegmentEntry& e = l.segment->entry(n.id);
      SearchHit h;
      h.object = e.object;
      h.start = e.start;
      h.end = e.end;
      h.ordinal = e.ordinal;
      h.kind = e.kind;
      h.link_ratio = e.link_ratio;
      h.heading_path = e.heading_path;
      h.score = n.score;
      h.segment = kv.first;
      h.slot = n.id;
      all.push_back(h);
    }
  }
  std::sort(all.begin(), all.end(), NearerHit);
  if (all.size() > k) all.resize(k);
  out->swap(all);
  return IndexStatus::kOk;
}

IndexStatus Index::BruteForce(const Vector& query, uint32_t k,
                              std::vector<SearchHit>* out) const {
  out->clear();
  if (query.size() != impl_->dimension) return IndexStatus::kBadArgument;
  std::vector<SearchHit> all;
  for (const std::pair<const SegmentId, Loaded>& kv : impl_->segments) {
    const Loaded& l = kv.second;
    const std::vector<Neighbour> found =
        l.segment->BruteForce(query, l.segment->count(), l.dead);
    for (const Neighbour& n : found) {
      const SegmentEntry& e = l.segment->entry(n.id);
      SearchHit h;
      h.object = e.object;
      h.start = e.start;
      h.end = e.end;
      h.ordinal = e.ordinal;
      h.kind = e.kind;
      h.link_ratio = e.link_ratio;
      h.heading_path = e.heading_path;
      h.score = n.score;
      h.segment = kv.first;
      h.slot = n.id;
      all.push_back(h);
    }
  }
  std::sort(all.begin(), all.end(), NearerHit);
  if (all.size() > k) all.resize(k);
  out->swap(all);
  return IndexStatus::kOk;
}

IndexStatus Index::Compact(uint32_t min_segments,
                           uint32_t max_dead_ratio_percent, uint32_t* merged,
                           uint32_t* reclaimed) {
  Impl& im = *impl_;
  if (merged != nullptr) *merged = 0;
  if (reclaimed != nullptr) *reclaimed = 0;

  // WHAT IS WORTH REWRITING, AS A PURE FUNCTION OF THE MANIFEST.
  //
  // Phase 4 chose inputs by walking the local segment map, which was fine when
  // one device existed. It is not fine now: two devices choosing inputs by
  // local iteration can pick different sets, produce different outputs, and
  // leave the index holding both. PlanCompaction takes the manifest and the
  // live set and nothing else, so two devices with the same view choose the
  // same inputs -- and because building a segment is deterministic (ADR 0005)
  // they then produce the same content-addressed id, which the lattice absorbs
  // as one operation rather than two.
  //
  // It is also TIERED. Phase 4 measured an all-or-nothing merge of a
  // 13,838-vector index at 103 seconds and recorded tiering as the unbuilt fix;
  // segments now arrive from elsewhere, so a routine merge that rewrites the
  // whole index would make every pull expensive. See manifest.h.
  const auto present = [&im](const SegmentId& id) { return im.Present(id); };
  const std::vector<SegmentId> live = im.manifest->Live(present);
  const CompactionPlan plan = PlanCompaction(
      *im.manifest, live, min_segments, max_dead_ratio_percent, kTierRatio);
  const std::vector<SegmentId> chosen = plan.inputs;
  if (chosen.size() < 2) return IndexStatus::kOk;

  // Gather the live vectors, in a fixed order: by segment id, then slot. The
  // output is therefore a function of the input rather than of iteration.
  std::vector<SegmentEntry> entries;
  std::vector<Vector> vectors;
  uint32_t dropped = 0;
  for (const SegmentId& id : chosen) {
    const Loaded& l = im.segments[id];
    for (uint32_t slot = 0; slot < l.segment->count(); ++slot) {
      if (slot < l.dead.size() && l.dead[slot]) {
        ++dropped;
        continue;
      }
      entries.push_back(l.segment->entry(slot));
      const float* v = l.segment->vector(slot);
      vectors.push_back(Vector(v, v + im.dimension));
    }
  }

  basalt::WriteBatch batch;
  // See the note in PutObject: a vector here dangles every Slice it has already
  // handed to the batch.
  std::deque<std::string> keep_alive;
  SegmentId new_id;
  std::string sealed;
  const bool have_new = !entries.empty();

  if (have_new) {
    std::string plaintext;
    if (Segment::Build(im.model, im.dimension, entries, vectors, &plaintext) !=
        SegmentStatus::kOk) {
      return IndexStatus::kBadArgument;
    }
    if (Segment::Seal(*im.keys, im.epoch, plaintext, &sealed, &new_id) !=
        SegmentStatus::kOk) {
      return IndexStatus::kStoreFailed;
    }
    // A COMPACTION THAT PRODUCES AN EXISTING SEGMENT IS A NO-OP, not a bug: the
    // segment is content-addressed, so rebuilding the same live set gives the
    // same id. Rewriting the manifest in that case would churn for nothing.
    //
    // AND IF THAT EXISTING SEGMENT CARRIES TOMBSTONES, ADOPTING IT DESTROYS THE
    // INDEX. This guard used to require chosen.size() == 1, which let the
    // dangerous case straight through. Found by following docs/USING.md on a
    // real vault: build, compact, build, compact left an index reporting three
    // vectors, all dead, zero objects, and a search that answered nothing.
    //
    // The sequence: the rebuild re-adds each note as its own segment and
    // tombstones the copies inside the compacted one -- correctly, they are
    // superseded. Compacting again gathers exactly the live vectors, which are
    // byte-for-byte what the first compaction produced, so Seal returns THE
    // SAME ID. Its slots are all tombstoned, and tombstones are grow-only by
    // design, so the resurrected segment comes back dead.
    //
    // Refusing is the fix, not clearing the tombstones: on a second device the
    // same id names the same bytes in the same slots, so a tombstone on it is
    // that device saying the vector is deleted. Dropping it here would resolve
    // a lattice by forgetting half of it. Refusing leaves the index exactly as
    // it was -- larger than it needs to be, and correct.
    const std::map<SegmentId, Loaded>::const_iterator existing =
        im.segments.find(new_id);
    if (existing != im.segments.end() &&
        (existing->second.dead_count > 0 ||
         std::find(chosen.begin(), chosen.end(), new_id) != chosen.end())) {
      return IndexStatus::kOk;
    }
    if (!WriteFileAtomically(im.PathFor(new_id), sealed)) {
      return IndexStatus::kStoreFailed;
    }
    keep_alive.push_back(std::string());
    std::string& value = keep_alive.back();
    PutU32(&value, static_cast<uint32_t>(entries.size()));
    PutU32(&value, static_cast<uint32_t>(sealed.size()));
    keep_alive.push_back(SegmentKey(new_id));
    batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(value));
    for (uint32_t i = 0; i < static_cast<uint32_t>(entries.size()); ++i) {
      keep_alive.push_back(ObjectKey(entries[i].object, new_id, i));
      batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(""));
    }
  }

  // Remove the old segments, their tombstones, and their object entries.
  for (const SegmentId& id : chosen) {
    if (have_new && id == new_id) continue;
    keep_alive.push_back(SegmentKey(id));
    batch.Delete(basalt::Slice(keep_alive.back()));
    const Loaded& l = im.segments[id];
    for (uint32_t slot = 0; slot < l.segment->count(); ++slot) {
      keep_alive.push_back(TombstoneKey(id, slot));
      batch.Delete(basalt::Slice(keep_alive.back()));
      keep_alive.push_back(ObjectKey(l.segment->entry(slot).object, id, slot));
      batch.Delete(basalt::Slice(keep_alive.back()));
    }
  }

  basalt::wal::SeqNum seq = 0;
  if (!im.db->Write(batch, &seq).ok()) return IndexStatus::kStoreFailed;
  basalt::wal::SeqNum watermark = 0;
  if (!im.db->Sync(&watermark).ok()) return IndexStatus::kStoreFailed;

  // THE RETIREMENT NAMES ITS REPLACEMENT, which is what lets a peer apply the
  // safety condition: it can hold the fact that S is retired while keeping S
  // live until it has T. A bare "S is gone" would give a peer no way to know
  // when it is safe to stop using S. See manifest.h.
  if (have_new) {
    ManifestOp add = im.Make(ManifestOpKind::kAdd);
    add.segment = new_id;
    add.count = static_cast<uint32_t>(entries.size());
    add.bytes = sealed.size();
    add.model = im.model;
    im.Emit(add);
  }
  for (const SegmentId& id : chosen) {
    if (have_new && id == new_id) continue;
    ManifestOp r = im.Make(ManifestOpKind::kRetire);
    r.segment = id;
    r.superseded_by = new_id;
    im.Emit(r);
  }
  im.SaveCounter();

  // THE FILES GO LAST. If the process dies between the manifest write and
  // these unlinks the store is correct and carrying garbage; the other order
  // would leave the manifest naming files that are gone, which is corruption.
  for (const SegmentId& id : chosen) {
    if (have_new && id == new_id) continue;
    im.segments.erase(id);
    ::unlink(im.PathFor(id).c_str());
  }
  if (have_new && im.segments.count(new_id) == 0) {
    Loaded loaded;
    loaded.id = new_id;
    if (Segment::Open(*im.keys, sealed, im.model, &loaded.segment) !=
        SegmentStatus::kOk) {
      return IndexStatus::kSegmentLost;
    }
    loaded.bytes = sealed.size();
    loaded.dead.assign(loaded.segment->count(), false);
    im.segments[new_id] = std::move(loaded);
  }

  if (merged != nullptr) *merged = static_cast<uint32_t>(chosen.size());
  if (reclaimed != nullptr) *reclaimed = dropped;
  return IndexStatus::kOk;
}

std::vector<ManifestOp> Index::TakePending() {
  Impl& im = *impl_;
  // FROM THE STORE, NOT FROM MEMORY. What this device has produced and not yet
  // published has to survive the process that produced it, or a device that
  // indexes and exits publishes nothing.
  std::vector<ManifestOp> out;
  std::vector<std::string> keys;
  {
    const std::string lo(1, kPendingPrefix);
    const std::string hi = PrefixUpperBound(lo);
    basalt::IterOptions o;
    o.lower = basalt::Bound::At(basalt::Slice(lo));
    if (!hi.empty()) o.upper = basalt::Bound::At(basalt::Slice(hi));
    std::unique_ptr<basalt::Iterator> it = im.db->NewIter(o);
    for (bool ok = it->First(); ok; ok = it->Next()) {
      ManifestOp op;
      if (DecodeManifestOp(it->Value().ToString(), &op)) {
        out.push_back(op);
        keys.push_back(it->Key().ToString());
      }
    }
    (void)it->Close();
  }
  im.pending.clear();
  if (keys.empty()) return out;

  // TAKEN MEANS TAKEN. Publishing is idempotent -- the relay stores a blob
  // under (object, replica, counter) and a repeat is the same blob -- so the
  // risk of clearing here is a lost publish rather than a duplicate one, and
  // the caller is about to write them into the oplog, which is durable.
  basalt::WriteBatch batch;
  std::deque<std::string> keep_alive;
  for (const std::string& k : keys) {
    keep_alive.push_back(k);
    batch.Delete(basalt::Slice(keep_alive.back()));
  }
  basalt::wal::SeqNum seq = 0;
  if (im.db->Write(batch, &seq).ok()) {
    basalt::wal::SeqNum watermark = 0;
    (void)im.db->Sync(&watermark);
  }
  return out;
}

ManifestApply Index::ApplyManifestOp(const ManifestOp& op) {
  Impl& im = *impl_;
  const ManifestApply a = im.manifest->Apply(op);
  if (a != ManifestApply::kApplied) return a;

  // A TOMBSTONE FROM A PEER APPLIES TO BYTES THIS DEVICE MAY ALREADY HOLD, so
  // it has to reach the loaded segment as well as the fold. Without this a
  // deletion made on another device would be recorded and not obeyed: the
  // manifest would say the slot is dead and search would keep returning it.
  if (op.kind == ManifestOpKind::kTombstone) {
    const std::map<SegmentId, Loaded>::iterator it =
        im.segments.find(op.segment);
    if (it != im.segments.end() && op.slot < it->second.dead.size() &&
        !it->second.dead[op.slot]) {
      it->second.dead[op.slot] = true;
      ++it->second.dead_count;
      basalt::WriteBatch batch;
      const std::string key = TombstoneKey(op.segment, op.slot);
      batch.Set(basalt::Slice(key), basalt::Slice(""));
      basalt::wal::SeqNum seq = 0;
      if (im.db->Write(batch, &seq).ok()) {
        basalt::wal::SeqNum watermark = 0;
        (void)im.db->Sync(&watermark);
      }
    }
  }

  // A RETIREMENT DOES NOT DROP ANYTHING HERE. The safety condition in
  // manifest.h says a retired segment stays live until its replacement is
  // present, and `Live` evaluates that on every search. Dropping the bytes at
  // this point is what would open the window where the index is quietly
  // incomplete; they are dropped by Compact, which knows the replacement is in
  // hand because it just wrote it, or by Prune once the replacement arrives.

  // JOURNALLED IF THE DISK CANNOT SAY IT AGAIN. See kWantedPrefix. An operation
  // about a segment this device holds is re-derivable from the segment file and
  // its tombstone keys; one about a segment it does not hold, and every
  // retirement, is not.
  if (!im.Present(op.segment) || op.kind == ManifestOpKind::kRetire) {
    im.RememberWanted(op);
  }
  return a;
}

IndexStatus Index::AdoptSegment(const std::string& sealed) {
  Impl& im = *impl_;
  if (sealed.empty()) return IndexStatus::kBadArgument;

  // THE HASH IS CHECKED BEFORE ANYTHING IS WRITTEN. A segment arrives from a
  // relay that is not trusted, over a link that is not trusted, and the name it
  // will be stored under is derived from its bytes -- so a segment whose
  // contents do not match its name must never reach the disk, or the store
  // would hold a file that lies about what it is.
  SegmentId id;
  crypto_generichash(id.bytes.data(), id.bytes.size(),
                     reinterpret_cast<const unsigned char*>(sealed.data()),
                     sealed.size(), nullptr, 0);

  if (im.segments.count(id) != 0) return IndexStatus::kOk;  // already held

  Loaded loaded;
  loaded.id = id;
  const SegmentStatus ss =
      Segment::Open(*im.keys, sealed, im.model, &loaded.segment);
  if (ss == SegmentStatus::kModelMismatch) return IndexStatus::kModelMismatch;
  if (ss != SegmentStatus::kOk) return IndexStatus::kSegmentLost;

  if (loaded.segment->dimension() != im.dimension) {
    return IndexStatus::kModelMismatch;
  }
  if (!WriteFileAtomically(im.PathFor(id), sealed)) {
    return IndexStatus::kStoreFailed;
  }
  loaded.bytes = sealed.size();
  loaded.dead.assign(loaded.segment->count(), false);

  // Tombstones the manifest already knows about apply to a segment the moment
  // it arrives. They routinely precede it: operations are small and segments
  // are not.
  const SegmentState* state = im.manifest->Get(id);
  if (state != nullptr) {
    for (uint32_t slot : state->dead) {
      if (slot < loaded.dead.size() && !loaded.dead[slot]) {
        loaded.dead[slot] = true;
        ++loaded.dead_count;
      }
    }
  }

  basalt::WriteBatch batch;
  std::deque<std::string> keep_alive;
  keep_alive.push_back(std::string());
  std::string& value = keep_alive.back();
  PutU32(&value, loaded.segment->count());
  PutU32(&value, static_cast<uint32_t>(sealed.size()));
  keep_alive.push_back(SegmentKey(id));
  batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(value));
  // ADOPTED MEANS SOMEBODY ELSE ANNOUNCED IT, and the marker goes in the SAME
  // batch as the segment record. Written after the sync instead, it was not
  // durable, so a restart re-announced every segment this device had ever
  // adopted -- harmless in the lattice and noise on the relay.
  keep_alive.push_back(AnnouncedKey(id));
  batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(""));
  for (uint32_t i = 0; i < loaded.segment->count(); ++i) {
    keep_alive.push_back(ObjectKey(loaded.segment->entry(i).object, id, i));
    batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(""));
    if (i < loaded.dead.size() && loaded.dead[i]) {
      keep_alive.push_back(TombstoneKey(id, i));
      batch.Set(basalt::Slice(keep_alive.back()), basalt::Slice(""));
    }
  }
  basalt::wal::SeqNum seq = 0;
  if (!im.db->Write(batch, &seq).ok()) return IndexStatus::kStoreFailed;
  basalt::wal::SeqNum watermark = 0;
  if (!im.db->Sync(&watermark).ok()) return IndexStatus::kStoreFailed;

  im.segments[id] = std::move(loaded);

  // ADOPTING A SEGMENT CAN SATISFY A RETIREMENT THAT WAS WAITING. This is where
  // the safety condition's second half pays off: the retired segment has been
  // answering queries all along and stops now, at the moment its replacement
  // can answer instead.
  Prune();
  return IndexStatus::kOk;
}

// Drop segments whose retirement has become safe: retired, and the segment that
// supersedes them is present. Called after anything that changes what is
// present.
void Index::Prune() {
  Impl& im = *impl_;
  const std::vector<SegmentId> drop = im.manifest->Droppable(
      [&im](const SegmentId& id) { return im.Present(id); });
  if (drop.empty()) return;

  basalt::WriteBatch batch;
  std::deque<std::string> keep_alive;
  for (const SegmentId& id : drop) {
    const Loaded& l = im.segments[id];
    keep_alive.push_back(SegmentKey(id));
    batch.Delete(basalt::Slice(keep_alive.back()));
    for (uint32_t slot = 0; slot < l.segment->count(); ++slot) {
      keep_alive.push_back(TombstoneKey(id, slot));
      batch.Delete(basalt::Slice(keep_alive.back()));
      keep_alive.push_back(ObjectKey(l.segment->entry(slot).object, id, slot));
      batch.Delete(basalt::Slice(keep_alive.back()));
    }
  }
  basalt::wal::SeqNum seq = 0;
  if (!im.db->Write(batch, &seq).ok()) return;
  basalt::wal::SeqNum watermark = 0;
  (void)im.db->Sync(&watermark);
  for (const SegmentId& id : drop) {
    im.segments.erase(id);
    ::unlink(im.PathFor(id).c_str());
  }
}

std::vector<SegmentId> Index::Missing() const {
  const Impl& im = *impl_;
  return im.manifest->MissingFrom(
      [&im](const SegmentId& id) { return im.Present(id); });
}

std::vector<SegmentId> Index::MissingInFetchOrder() const {
  const Impl& im = *impl_;
  std::vector<SegmentId> first;
  std::vector<SegmentId> last;
  for (const SegmentId& id : Missing()) {
    const SegmentState* st = im.manifest->Get(id);
    if (st != nullptr && !st->superseded_by.empty()) {
      last.push_back(id);
    } else {
      first.push_back(id);
    }
  }
  first.insert(first.end(), last.begin(), last.end());
  return first;
}

bool Index::Wants(const SegmentId& id) const {
  const Impl& im = *impl_;
  if (im.Present(id)) return false;
  const SegmentState* st = im.manifest->Get(id);
  if (st == nullptr) return false;
  // Superseded by something already held is not wanted, which is the whole
  // point of re-asking: the replacement may have landed since the list was
  // taken.
  for (const SegmentId& by : st->superseded_by) {
    if (im.Present(by)) return false;
  }
  return true;
}

std::vector<SegmentId> Index::AwaitingReplacement() const {
  const Impl& im = *impl_;
  const auto present = [&im](const SegmentId& id) { return im.Present(id); };
  return im.manifest->AwaitingReplacement(present);
}

bool Index::Complete() const { return Missing().empty(); }

const ManifestDoc& Index::manifest() const { return *impl_->manifest; }

IndexStats Index::Stats() const {
  IndexStats st;
  std::set<std::string> objects;
  for (const std::pair<const SegmentId, Loaded>& kv : impl_->segments) {
    ++st.segments;
    st.vectors += kv.second.segment->count();
    st.tombstoned += kv.second.dead_count;
    st.segment_bytes += kv.second.bytes;
    for (uint32_t slot = 0; slot < kv.second.segment->count(); ++slot) {
      if (slot < kv.second.dead.size() && kv.second.dead[slot]) continue;
      const ObjectId& o = kv.second.segment->entry(slot).object;
      objects.insert(std::string(reinterpret_cast<const char*>(o.bytes.data()),
                                 o.bytes.size()));
    }
  }
  st.objects = static_cast<uint32_t>(objects.size());
  return st;
}

std::vector<SegmentId> Index::SegmentIds() const {
  std::vector<SegmentId> out;
  out.reserve(impl_->segments.size());
  for (const std::pair<const SegmentId, Loaded>& kv : impl_->segments) {
    out.push_back(kv.first);
  }
  return out;
}

}  // namespace ai
}  // namespace umbra
