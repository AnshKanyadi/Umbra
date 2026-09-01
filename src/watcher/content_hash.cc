#include <sodium.h>

#include <mutex>

#include "check.h"
#include "umbra/change_event.h"

namespace umbra {
namespace {

// sodium_init IS CALLED ONCE, AND ITS FAILURE IS FATAL.
//
// libsodium requires it before any other call. It is idempotent and documented
// as thread-safe from 1.0.11 onward, but call_once costs nothing and makes the
// ordering a property of the code rather than of libsodium's version.
//
// A failure here means the library could not initialise its runtime state --
// on the platforms this builds for, that is the entropy source being
// unavailable. Continuing would mean hashing with an uninitialised library, so
// the process aborts. This is the one place in the watcher that can abort, and
// it is deliberate: there is no Status a caller could usefully act on.
void EnsureSodium() {
  static std::once_flag once;
  std::call_once(once, [] {
    if (::sodium_init() < 0) {
      UMBRA_DIE(
          "sodium_init failed; refusing to hash with an uninitialised "
          "libsodium");
    }
  });
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
  EnsureSodium();
  ContentHash h;
  // Unkeyed BLAKE2b-256. crypto_generichash is libsodium's name for BLAKE2b;
  // 32 bytes is crypto_generichash_BYTES, which the header asserts against
  // ContentHash's size.
  static_assert(sizeof(h.bytes) == crypto_generichash_BYTES,
                "ContentHash is not the size crypto_generichash produces");
  //
  // NO KEY. A keyed hash would make the digest unreproducible by anything that
  // does not hold the key, and the digest has to be reproducible: ADR 0001 makes
  // the segment store content-addressed, so the same bytes must name the same
  // blob on every device. Confidentiality of the content comes from encrypting
  // it, not from keying its name.
  const int rc = ::crypto_generichash(
      h.bytes.data(), h.bytes.size(), static_cast<const unsigned char*>(data),
      static_cast<unsigned long long>(len), nullptr, 0);
  UMBRA_CHECK(rc == 0, "crypto_generichash failed on a valid-sized request");
  return h;
}

bool ContentHash::IsZero() const {
  // sodium_is_zero rather than a loop: it is constant-time. Nothing here is
  // secret today, but the sentinel comparison lives next to real digests and a
  // timing-variable comparison on a digest is the kind of thing that becomes
  // wrong later without anybody editing it.
  EnsureSodium();
  return ::sodium_is_zero(bytes.data(), bytes.size()) == 1;
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
