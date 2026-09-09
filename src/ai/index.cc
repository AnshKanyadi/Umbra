#include "umbra/ai/index.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

#include "basalt/db.h"
#include "basalt/posix_env.h"
#include "basalt/slice.h"

namespace umbra {
namespace ai {
namespace {

// Key spaces in the manifest. One byte each, so a scan over one never sees
// another, and a person reading the store with a hex dump can tell them apart.
constexpr char kSegmentPrefix = 's';    // 's' || segment id   -> count, bytes
constexpr char kTombstonePrefix = 't';  // 't' || seg || slot  -> empty
constexpr char kObjectPrefix = 'o';     // 'o' || object || seg || slot -> empty
constexpr char kMetaPrefix = 'm';       // 'm' || name         -> value

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
  std::unique_ptr<basalt::Env> env;
  std::unique_ptr<basalt::DB> db;
  // Ordered so that iteration, and therefore search order and tie-breaking, is
  // a function of the ids rather than of insertion history.
  std::map<SegmentId, Loaded> segments;

  std::string PathFor(const SegmentId& id) const {
    return segment_dir + "/" + id.Hex() + ".seg";
  }
};

Index::Index() : impl_(new Impl) {}
Index::~Index() = default;

IndexStatus Index::Open(const std::string& dir, const VaultKeys* keys,
                        Epoch epoch, const EmbeddingModelId& model,
                        uint32_t dimension, std::unique_ptr<Index>* out) {
  if (keys == nullptr || dimension == 0) return IndexStatus::kBadArgument;
  std::unique_ptr<Index> idx(new Index);
  Impl& im = *idx->impl_;
  im.dir = dir;
  im.segment_dir = dir + "/segments";
  im.keys = keys;
  im.epoch = epoch;
  im.model = model;
  im.dimension = dimension;
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
    }
  }

  // Load every segment the manifest names, then apply the tombstones.
  {
    const std::string lo(1, kSegmentPrefix);
    const std::string hi(1, kSegmentPrefix + 1);
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
    const std::string hi(1, kTombstonePrefix + 1);
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
    std::string hi = lo;
    hi.push_back('\xff');
    basalt::IterOptions o;
    o.lower = basalt::Bound::At(basalt::Slice(lo));
    o.upper = basalt::Bound::At(basalt::Slice(hi));
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
    std::string value;
    PutU32(&value, static_cast<uint32_t>(chunks.size()));
    PutU32(&value, static_cast<uint32_t>(sealed.size()));
    const std::string skey = SegmentKey(new_id);
    batch.Set(basalt::Slice(skey), basalt::Slice(value));
    have_new = true;
  }

  std::vector<std::string> keep_alive;
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

  // WHAT IS WORTH REWRITING. Either there are enough segments that search is
  // paying to visit them all, or some segment is mostly dead and is carrying
  // its own weight for nothing. Neither test alone is enough: a vault with two
  // segments where one is 90% tombstoned should still be compacted, and a vault
  // with forty clean segments should be merged even though nothing is dead.
  std::vector<SegmentId> chosen;
  const bool too_many = im.segments.size() >= min_segments && min_segments > 0;
  for (const std::pair<const SegmentId, Loaded>& kv : im.segments) {
    const Loaded& l = kv.second;
    const uint32_t total = l.segment->count();
    const uint32_t dead_pct =
        (total == 0) ? 0
                     : static_cast<uint32_t>(
                           (static_cast<uint64_t>(l.dead_count) * 100) / total);
    if (too_many || dead_pct >= max_dead_ratio_percent)
      chosen.push_back(kv.first);
  }
  if (chosen.size() < 2) {
    // Merging one segment into one segment is still worth doing when it is
    // mostly dead, but not when it is clean.
    if (chosen.size() == 1) {
      const Loaded& l = im.segments[chosen[0]];
      if (l.dead_count == 0) return IndexStatus::kOk;
    } else {
      return IndexStatus::kOk;
    }
  }

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
  std::vector<std::string> keep_alive;
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
    if (im.segments.count(new_id) != 0 && chosen.size() == 1 &&
        chosen[0] == new_id) {
      return IndexStatus::kOk;
    }
    if (!WriteFileAtomically(im.PathFor(new_id), sealed)) {
      return IndexStatus::kStoreFailed;
    }
    std::string value;
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
