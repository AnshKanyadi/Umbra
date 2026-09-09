#include "umbra/ai/segment.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>

#include "hnsw.h"
#include "umbra/crypto/aead.h"

namespace umbra {
namespace ai {
namespace {

// "UMBSEG" and a format version. A file that does not start with this is not
// refused politely -- it is refused before anything else is read.
constexpr char kMagic[6] = {'U', 'M', 'B', 'S', 'E', 'G'};
constexpr uint32_t kFormatVersion = 1;

// Bounds every decoder checks before it reserves anything. A segment may have
// arrived from another device (Phase 5) and is not trusted to be honest about
// its own sizes.
constexpr uint32_t kMaxVectors = 4u * 1000 * 1000;
constexpr uint32_t kMaxDimension = 8192;
constexpr uint32_t kMaxHeadingBytes = 4096;

void PutU32(std::string* out, uint32_t v) {
  out->push_back(static_cast<char>((v >> 24) & 0xFF));
  out->push_back(static_cast<char>((v >> 16) & 0xFF));
  out->push_back(static_cast<char>((v >> 8) & 0xFF));
  out->push_back(static_cast<char>(v & 0xFF));
}

// FLOATS GO OUT AS THEIR BIT PATTERN, BIG ENDIAN. Writing the raw bytes of a
// float array would make the file endian-dependent, so a segment written on a
// big-endian machine would be read as noise on a little-endian one. Nobody
// ships big-endian laptops today; the file format outlives that assumption.
void PutF32(std::string* out, float f) {
  uint32_t bits = 0;
  static_assert(sizeof(bits) == sizeof(f), "float is not 32 bits");
  std::memcpy(&bits, &f, sizeof(bits));
  PutU32(out, bits);
}

class Reader {
 public:
  Reader(const std::string& s) : s_(s) {}
  bool U32(uint32_t* v) {
    if (at_ + 4 > s_.size()) return false;
    *v = (static_cast<uint32_t>(static_cast<uint8_t>(s_[at_])) << 24) |
         (static_cast<uint32_t>(static_cast<uint8_t>(s_[at_ + 1])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(s_[at_ + 2])) << 8) |
         static_cast<uint32_t>(static_cast<uint8_t>(s_[at_ + 3]));
    at_ += 4;
    return true;
  }
  bool U8(uint8_t* v) {
    if (at_ + 1 > s_.size()) return false;
    *v = static_cast<uint8_t>(s_[at_++]);
    return true;
  }
  bool F32(float* f) {
    uint32_t bits = 0;
    if (!U32(&bits)) return false;
    std::memcpy(f, &bits, sizeof(*f));
    return true;
  }
  bool Bytes(void* p, std::size_t n) {
    if (at_ + n > s_.size()) return false;
    std::memcpy(p, s_.data() + at_, n);
    at_ += n;
    return true;
  }
  bool Str(std::string* out, uint32_t cap) {
    uint32_t n = 0;
    if (!U32(&n)) return false;
    if (n > cap || at_ + n > s_.size()) return false;
    out->assign(s_, at_, n);
    at_ += n;
    return true;
  }
  bool Done() const { return at_ == s_.size(); }
  std::size_t at() const { return at_; }

 private:
  const std::string& s_;
  std::size_t at_ = 0;
};

}  // namespace

std::string SegmentId::Hex() const {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::string SegmentId::Short() const { return Hex().substr(0, 12); }

const char* SegmentStatusName(SegmentStatus s) {
  switch (s) {
    case SegmentStatus::kOk:
      return "ok";
    case SegmentStatus::kBadFormat:
      return "bad-format";
    case SegmentStatus::kTruncated:
      return "truncated";
    case SegmentStatus::kAuthFailed:
      return "auth-failed";
    case SegmentStatus::kModelMismatch:
      return "model-mismatch";
    case SegmentStatus::kTooLarge:
      return "too-large";
  }
  return "unknown";
}

struct Segment::Impl {
  EmbeddingModelId model;
  uint32_t dimension = 0;
  uint32_t count = 0;
  HnswParams params;
  uint32_t entry_node = 0;
  std::vector<float> vectors;
  std::vector<uint8_t> levels;
  std::vector<uint32_t> adjacency;
  std::vector<SegmentEntry> entries;
  std::unique_ptr<HnswGraph> graph;
};

Segment::Segment() : impl_(new Impl) {}
Segment::~Segment() = default;

SegmentStatus Segment::Build(const EmbeddingModelId& model, uint32_t dimension,
                             const std::vector<SegmentEntry>& entries,
                             const std::vector<Vector>& vectors,
                             std::string* plaintext) {
  if (entries.size() != vectors.size()) return SegmentStatus::kBadFormat;
  if (entries.empty()) return SegmentStatus::kBadFormat;
  if (entries.size() > kMaxVectors) return SegmentStatus::kTooLarge;
  if (dimension == 0 || dimension > kMaxDimension) {
    return SegmentStatus::kTooLarge;
  }
  const uint32_t count = static_cast<uint32_t>(entries.size());
  for (const Vector& v : vectors) {
    if (v.size() != dimension) return SegmentStatus::kBadFormat;
  }
  for (const SegmentEntry& e : entries) {
    if (e.heading_path.size() > kMaxHeadingBytes) {
      return SegmentStatus::kTooLarge;
    }
  }

  // Flatten first: the graph reads the same layout the file stores, so there is
  // one copy of the vectors and no chance of the two disagreeing.
  std::vector<float> flat;
  flat.reserve(static_cast<std::size_t>(count) * dimension);
  for (const Vector& v : vectors) flat.insert(flat.end(), v.begin(), v.end());

  const HnswParams params;
  const HnswGraph graph =
      HnswGraph::Build(flat.data(), count, dimension, params);

  std::string out;
  out.append(kMagic, sizeof(kMagic));
  PutU32(&out, kFormatVersion);
  out.append(reinterpret_cast<const char*>(model.bytes.data()),
             model.bytes.size());
  PutU32(&out, dimension);
  PutU32(&out, count);
  PutU32(&out, params.m);
  PutU32(&out, params.ef_construction);
  PutU32(&out, params.max_level);
  PutU32(&out, graph.entry());

  for (float f : flat) PutF32(&out, f);
  for (uint8_t l : graph.levels()) out.push_back(static_cast<char>(l));
  PutU32(&out, static_cast<uint32_t>(graph.adjacency().size()));
  for (uint32_t a : graph.adjacency()) PutU32(&out, a);

  for (const SegmentEntry& e : entries) {
    out.append(reinterpret_cast<const char*>(e.object.bytes.data()),
               e.object.bytes.size());
    PutU32(&out, e.start);
    PutU32(&out, e.end);
    PutU32(&out, e.ordinal);
    out.push_back(static_cast<char>(e.kind));
    PutU32(&out, e.link_ratio);
    PutU32(&out, static_cast<uint32_t>(e.heading_path.size()));
    out.append(e.heading_path);
  }
  plaintext->swap(out);
  return SegmentStatus::kOk;
}

SegmentStatus Segment::Seal(const VaultKeys& keys, Epoch epoch,
                            const std::string& plaintext, std::string* sealed,
                            SegmentId* id) {
  SecretKey key;
  if (keys.ContentKey(epoch, &key) != CryptoStatus::kOk) {
    return SegmentStatus::kAuthFailed;
  }
  // The nonce comes from the plaintext. See the header for why that is safe
  // here and what it leaks.
  std::array<uint8_t, 32> digest{};
  crypto_generichash(digest.data(), digest.size(),
                     reinterpret_cast<const unsigned char*>(plaintext.data()),
                     plaintext.size(), nullptr, 0);

  SealContext ctx;
  ctx.epoch = epoch;
  // The AEAD's associated data binds the segment to its own content hash, so a
  // sealed segment cannot be presented as a different one.
  std::memcpy(ctx.object.bytes.data(), digest.data(), ctx.object.bytes.size());
  ctx.op.counter = 0;

  const std::string body = SealDeterministic(key, ctx, plaintext);
  if (body.empty()) return SegmentStatus::kAuthFailed;

  std::string out;
  out.append(kMagic, sizeof(kMagic));
  PutU32(&out, kFormatVersion);
  PutU32(&out, epoch);
  out.append(reinterpret_cast<const char*>(digest.data()), digest.size());
  PutU32(&out, static_cast<uint32_t>(body.size()));
  out.append(body);

  crypto_generichash(id->bytes.data(), id->bytes.size(),
                     reinterpret_cast<const unsigned char*>(out.data()),
                     out.size(), nullptr, 0);
  sealed->swap(out);
  return SegmentStatus::kOk;
}

SegmentStatus Segment::Open(const VaultKeys& keys, const std::string& sealed,
                            const EmbeddingModelId& expect,
                            std::unique_ptr<Segment>* out) {
  Reader outer(sealed);
  char magic[sizeof(kMagic)];
  if (!outer.Bytes(magic, sizeof(magic))) return SegmentStatus::kTruncated;
  if (std::memcmp(magic, kMagic, sizeof(kMagic)) != 0) {
    return SegmentStatus::kBadFormat;
  }
  uint32_t version = 0;
  if (!outer.U32(&version)) return SegmentStatus::kTruncated;
  if (version != kFormatVersion) return SegmentStatus::kBadFormat;
  uint32_t epoch = 0;
  if (!outer.U32(&epoch)) return SegmentStatus::kTruncated;
  std::array<uint8_t, 32> digest{};
  if (!outer.Bytes(digest.data(), digest.size())) {
    return SegmentStatus::kTruncated;
  }
  uint32_t body_len = 0;
  if (!outer.U32(&body_len)) return SegmentStatus::kTruncated;
  if (body_len > sealed.size() - outer.at()) return SegmentStatus::kTruncated;
  const std::string body(sealed, outer.at(), body_len);

  SecretKey key;
  if (keys.ContentKey(epoch, &key) != CryptoStatus::kOk) {
    return SegmentStatus::kAuthFailed;
  }
  SealContext ctx;
  ctx.epoch = epoch;
  std::memcpy(ctx.object.bytes.data(), digest.data(), ctx.object.bytes.size());
  ctx.op.counter = 0;
  std::string plain;
  if (::umbra::Open(key, ctx, body, &plain) != CryptoStatus::kOk) {
    return SegmentStatus::kAuthFailed;
  }
  // THE DIGEST IN THE HEADER IS CHECKED AGAINST THE PLAINTEXT. The AEAD already
  // proves the body was not altered, but the digest is also the nonce and the
  // associated data, so a header that disagrees with its own body would be a
  // segment whose identity does not match its contents.
  std::array<uint8_t, 32> actual{};
  crypto_generichash(actual.data(), actual.size(),
                     reinterpret_cast<const unsigned char*>(plain.data()),
                     plain.size(), nullptr, 0);
  if (actual != digest) return SegmentStatus::kAuthFailed;

  std::unique_ptr<Segment> seg(new Segment);
  Impl& im = *seg->impl_;
  Reader r(plain);
  char m2[sizeof(kMagic)];
  if (!r.Bytes(m2, sizeof(m2))) return SegmentStatus::kTruncated;
  if (std::memcmp(m2, kMagic, sizeof(kMagic)) != 0) {
    return SegmentStatus::kBadFormat;
  }
  uint32_t v2 = 0;
  if (!r.U32(&v2) || v2 != kFormatVersion) return SegmentStatus::kBadFormat;
  if (!r.Bytes(im.model.bytes.data(), im.model.bytes.size())) {
    return SegmentStatus::kTruncated;
  }
  // REPORTED, NEVER RECONCILED. Vectors from two models are not comparable and
  // the only correct response is to re-embed, which is the user's decision.
  if (im.model != expect) return SegmentStatus::kModelMismatch;

  if (!r.U32(&im.dimension) || !r.U32(&im.count)) {
    return SegmentStatus::kTruncated;
  }
  if (im.dimension == 0 || im.dimension > kMaxDimension || im.count == 0 ||
      im.count > kMaxVectors) {
    return SegmentStatus::kTooLarge;
  }
  if (!r.U32(&im.params.m) || !r.U32(&im.params.ef_construction) ||
      !r.U32(&im.params.max_level) || !r.U32(&im.entry_node)) {
    return SegmentStatus::kTruncated;
  }
  if (im.params.m == 0 || im.params.m > 256 || im.params.max_level == 0 ||
      im.params.max_level > 64 || im.entry_node >= im.count) {
    return SegmentStatus::kBadFormat;
  }

  const std::size_t floats = static_cast<std::size_t>(im.count) * im.dimension;
  im.vectors.resize(floats);
  for (std::size_t i = 0; i < floats; ++i) {
    if (!r.F32(&im.vectors[i])) return SegmentStatus::kTruncated;
  }
  im.levels.resize(im.count);
  for (uint32_t i = 0; i < im.count; ++i) {
    if (!r.U8(&im.levels[i])) return SegmentStatus::kTruncated;
    if (im.levels[i] >= im.params.max_level) return SegmentStatus::kBadFormat;
  }
  uint32_t adj = 0;
  if (!r.U32(&adj)) return SegmentStatus::kTruncated;
  // The adjacency length is implied by the levels, so a file that disagrees is
  // malformed rather than merely surprising.
  uint32_t expect_adj = 0;
  for (uint32_t i = 0; i < im.count; ++i) {
    expect_adj += HnswGraph::SlotsFor(im.levels[i], im.params);
  }
  if (adj != expect_adj) return SegmentStatus::kBadFormat;
  im.adjacency.resize(adj);
  for (uint32_t i = 0; i < adj; ++i) {
    if (!r.U32(&im.adjacency[i])) return SegmentStatus::kTruncated;
    if (im.adjacency[i] != UINT32_MAX && im.adjacency[i] >= im.count) {
      // An edge pointing outside the segment would read past the vectors.
      return SegmentStatus::kBadFormat;
    }
  }

  im.entries.resize(im.count);
  for (uint32_t i = 0; i < im.count; ++i) {
    SegmentEntry& e = im.entries[i];
    if (!r.Bytes(e.object.bytes.data(), e.object.bytes.size())) {
      return SegmentStatus::kTruncated;
    }
    uint8_t kind = 0;
    if (!r.U32(&e.start) || !r.U32(&e.end) || !r.U32(&e.ordinal) ||
        !r.U8(&kind) || !r.U32(&e.link_ratio)) {
      return SegmentStatus::kTruncated;
    }
    if (e.end <= e.start) return SegmentStatus::kBadFormat;
    if (kind > static_cast<uint8_t>(ChunkKind::kQuote)) {
      return SegmentStatus::kBadFormat;
    }
    e.kind = static_cast<ChunkKind>(kind);
    if (!r.Str(&e.heading_path, kMaxHeadingBytes)) {
      return SegmentStatus::kTruncated;
    }
  }
  if (!r.Done()) return SegmentStatus::kBadFormat;

  im.graph.reset(new HnswGraph(
      HnswGraph::FromParts(im.vectors.data(), im.count, im.dimension,
                           im.entry_node, im.levels, im.adjacency, im.params)));
  *out = std::move(seg);
  return SegmentStatus::kOk;
}

std::vector<Neighbour> Segment::Search(
    const Vector& query, uint32_t k, uint32_t ef,
    const std::vector<bool>& tombstones) const {
  if (query.size() != impl_->dimension) return {};
  HnswGraph::Scratch scratch;
  return impl_->graph->Search(query.data(), k, ef,
                              tombstones.empty() ? nullptr : &tombstones,
                              &scratch);
}

std::vector<Neighbour> Segment::BruteForce(
    const Vector& query, uint32_t k,
    const std::vector<bool>& tombstones) const {
  if (query.size() != impl_->dimension) return {};
  return impl_->graph->BruteForce(query.data(), k,
                                  tombstones.empty() ? nullptr : &tombstones);
}

uint32_t Segment::count() const { return impl_->count; }
uint32_t Segment::dimension() const { return impl_->dimension; }
const EmbeddingModelId& Segment::model() const { return impl_->model; }
const SegmentEntry& Segment::entry(uint32_t slot) const {
  return impl_->entries[slot];
}
const float* Segment::vector(uint32_t slot) const {
  return impl_->vectors.data() +
         (static_cast<std::size_t>(slot) * impl_->dimension);
}

}  // namespace ai
}  // namespace umbra
