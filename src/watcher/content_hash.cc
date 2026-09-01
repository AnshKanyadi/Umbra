#include <algorithm>

#include "umbra/change_event.h"

namespace umbra {
namespace {

// FNV-1a-64. See the warning on ContentHash in the public header: this is a
// change detector, not a cryptographic hash, and it is deliberately simple so
// that nobody mistakes it for one.
constexpr uint64_t kFnvPrime = 0x100000001b3ULL;

uint64_t Fnv1a(const unsigned char* p, std::size_t n, uint64_t basis) {
  uint64_t h = basis;
  for (std::size_t i = 0; i < n; ++i) {
    h ^= static_cast<uint64_t>(p[i]);
    h *= kFnvPrime;
  }
  return h;
}

void PutBe64(uint64_t v, uint8_t* out) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<uint8_t>((v >> (56 - (8 * i))) & 0xff);
  }
}

std::string ToHexBytes(const uint8_t* p, std::size_t n) {
  std::string s;
  s.reserve(n * 2);
  static const char kHex[] = "0123456789abcdef";
  for (std::size_t i = 0; i < n; ++i) {
    s.push_back(kHex[p[i] >> 4]);
    s.push_back(kHex[p[i] & 0x0f]);
  }
  return s;
}

}  // namespace

ContentHash HashBytes(const void* data, std::size_t len) {
  const unsigned char* p = static_cast<const unsigned char*>(data);
  // Four different offset bases. The lanes are correlated -- they walk the same
  // bytes with the same prime -- so this fills 32 bytes without claiming 256
  // bits of strength. The length is folded into each basis so that appending
  // zero bytes cannot be a no-op.
  const uint64_t l = static_cast<uint64_t>(len);
  ContentHash h;
  PutBe64(Fnv1a(p, len, 0xcbf29ce484222325ULL ^ l), h.bytes.data());
  PutBe64(Fnv1a(p, len, 0x9e3779b97f4a7c15ULL ^ l), &h.bytes[8]);
  PutBe64(Fnv1a(p, len, 0xff51afd7ed558ccdULL ^ l), &h.bytes[16]);
  PutBe64(Fnv1a(p, len, 0xc4ceb9fe1a85ec53ULL ^ l), &h.bytes[24]);
  return h;
}

bool ContentHash::IsZero() const {
  return std::all_of(bytes.begin(), bytes.end(),
                     [](uint8_t b) { return b == 0; });
}

std::string ContentHash::ToHex() const {
  return ToHexBytes(bytes.data(), bytes.size());
}

std::string ObjectId::ToHex() const {
  return ToHexBytes(bytes.data(), bytes.size());
}

const char* ChangeKindName(ChangeKind k) {
  switch (k) {
    case ChangeKind::kCreated:
      return "created";
    case ChangeKind::kModified:
      return "modified";
    case ChangeKind::kDeleted:
      return "deleted";
    case ChangeKind::kMoved:
      return "moved";
  }
  return "unknown";
}

}  // namespace umbra
