#include "umbra/crypto/aead.h"

#include <sodium.h>

#include "check.h"

namespace umbra {
namespace {

void PutU32(uint32_t v, std::string* out) {
  for (int i = 0; i < 4; ++i) {
    out->push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
  }
}

void PutU64(uint64_t v, std::string* out) {
  for (int i = 0; i < 8; ++i) {
    out->push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
  }
}

}  // namespace

std::string SealContext::Bytes() const {
  // Fixed width and fixed order. A length-prefixed or delimited encoding would
  // be equivalent here only because every field is fixed size; writing it this
  // way means adding a variable-length field later cannot silently make two
  // different contexts produce the same bytes.
  std::string s;
  s.reserve(1 + 16 + 8 + 16 + 4);
  s.push_back('U');  // a version tag, so the binding can change deliberately
  s.append(reinterpret_cast<const char*>(object.bytes.data()),
           object.bytes.size());
  PutU64(op.counter, &s);
  s.append(reinterpret_cast<const char*>(op.replica.bytes.data()),
           op.replica.bytes.size());
  PutU32(epoch, &s);
  return s;
}

std::string Seal(const SecretKey& key, const SealContext& ctx,
                 const std::string& plaintext) {
  UMBRA_CHECK(::sodium_init() >= 0, "sodium_init failed");
  const std::string aad = ctx.Bytes();
  std::string out;
  out.resize(kNonceBytes + plaintext.size() + kMacBytes);
  unsigned char* nonce = reinterpret_cast<unsigned char*>(&out[0]);
  ::randombytes_buf(nonce, kNonceBytes);

  unsigned long long clen = 0;
  const int rc = ::crypto_aead_xchacha20poly1305_ietf_encrypt(
      reinterpret_cast<unsigned char*>(&out[0]) + kNonceBytes, &clen,
      reinterpret_cast<const unsigned char*>(plaintext.data()),
      static_cast<unsigned long long>(plaintext.size()),
      reinterpret_cast<const unsigned char*>(aad.data()),
      static_cast<unsigned long long>(aad.size()), nullptr, nonce, key.data());
  UMBRA_CHECK(rc == 0, "xchacha20poly1305 encryption failed");
  out.resize(kNonceBytes + static_cast<std::size_t>(clen));
  return out;
}

std::string SealDeterministic(const SecretKey& key, const SealContext& ctx,
                              const std::string& plaintext) {
  UMBRA_CHECK(::sodium_init() >= 0, "sodium_init failed");
  const std::string aad = ctx.Bytes();
  std::string out;
  out.resize(kNonceBytes + plaintext.size() + kMacBytes);

  // A KEYED hash, not a plain one. An unkeyed digest would also be unique per
  // plaintext, but keying it means an observer who guesses the plaintext cannot
  // confirm the guess by recomputing the nonce.
  crypto_generichash_state st;
  ::crypto_generichash_init(&st, key.data(), SecretKey::size(), kNonceBytes);
  ::crypto_generichash_update(
      &st, reinterpret_cast<const unsigned char*>(aad.data()), aad.size());
  ::crypto_generichash_update(
      &st, reinterpret_cast<const unsigned char*>(plaintext.data()),
      plaintext.size());
  ::crypto_generichash_final(&st, reinterpret_cast<unsigned char*>(&out[0]),
                             kNonceBytes);

  unsigned long long clen = 0;
  const int rc = ::crypto_aead_xchacha20poly1305_ietf_encrypt(
      reinterpret_cast<unsigned char*>(&out[0]) + kNonceBytes, &clen,
      reinterpret_cast<const unsigned char*>(plaintext.data()),
      static_cast<unsigned long long>(plaintext.size()),
      reinterpret_cast<const unsigned char*>(aad.data()),
      static_cast<unsigned long long>(aad.size()), nullptr,
      reinterpret_cast<const unsigned char*>(&out[0]), key.data());
  UMBRA_CHECK(rc == 0, "deterministic seal failed");
  out.resize(kNonceBytes + static_cast<std::size_t>(clen));
  return out;
}

CryptoStatus Open(const SecretKey& key, const SealContext& ctx,
                  const std::string& sealed, std::string* plaintext) {
  UMBRA_CHECK(::sodium_init() >= 0, "sodium_init failed");
  if (sealed.size() < kNonceBytes + kMacBytes) return CryptoStatus::kAuthFailed;
  const std::string aad = ctx.Bytes();
  const unsigned char* nonce =
      reinterpret_cast<const unsigned char*>(sealed.data());
  const std::size_t clen = sealed.size() - kNonceBytes;

  plaintext->resize(clen);  // never larger than the ciphertext
  unsigned long long mlen = 0;
  const int rc = ::crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext->empty() ? nullptr
                         : reinterpret_cast<unsigned char*>(&(*plaintext)[0]),
      &mlen, nullptr,
      reinterpret_cast<const unsigned char*>(sealed.data()) + kNonceBytes,
      static_cast<unsigned long long>(clen),
      reinterpret_cast<const unsigned char*>(aad.data()),
      static_cast<unsigned long long>(aad.size()), nonce, key.data());
  if (rc != 0) {
    // NOTHING IS WRITTEN OUT ON FAILURE. libsodium leaves the buffer
    // unspecified, and handing a caller unauthenticated bytes is how a
    // "decrypt then check" bug starts.
    plaintext->clear();
    return CryptoStatus::kAuthFailed;
  }
  plaintext->resize(static_cast<std::size_t>(mlen));
  return CryptoStatus::kOk;
}

}  // namespace umbra
