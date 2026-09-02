#include "umbra/crypto/keys.h"

#include <sodium.h>

#include <cstring>

#include "check.h"
#include "umbra/crypto/aead.h"

namespace umbra {
namespace {

void EnsureSodium() { UMBRA_CHECK(::sodium_init() >= 0, "sodium_init failed"); }

// crypto_kdf contexts are exactly 8 bytes. Named constants rather than string
// literals at call sites so a typo is a compile error rather than a silently
// different key.
constexpr char kCtxEpochWrap[] = "umbEpoch";
constexpr char kCtxContent[] = "umbCont1";

}  // namespace

const char* CryptoStatusName(CryptoStatus s) {
  switch (s) {
    case CryptoStatus::kOk:
      return "ok";
    case CryptoStatus::kOutOfMemory:
      return "out-of-memory";
    case CryptoStatus::kBadInput:
      return "bad-input";
    case CryptoStatus::kAuthFailed:
      return "auth-failed";
    case CryptoStatus::kUnknownEpoch:
      return "unknown-epoch";
  }
  return "unknown";
}

SecretKey::SecretKey() { EnsureSodium(); }

SecretKey::~SecretKey() {
  // sodium_memzero, not a loop: the compiler is entitled to remove a loop that
  // writes to memory nothing reads afterwards, and does.
  ::sodium_memzero(bytes_.data(), bytes_.size());
}

SecretKey::SecretKey(const SecretKey& o) : bytes_(o.bytes_) {}

SecretKey& SecretKey::operator=(const SecretKey& o) {
  if (this != &o) {
    ::sodium_memzero(bytes_.data(), bytes_.size());
    bytes_ = o.bytes_;
  }
  return *this;
}

bool SecretKey::Equals(const SecretKey& o) const {
  return ::sodium_memcmp(bytes_.data(), o.bytes_.data(), bytes_.size()) == 0;
}

Argon2idParams Argon2idParams::Default() {
  Argon2idParams p;
  p.opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
  p.memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
  return p;
}

std::array<uint8_t, kSaltBytes> NewSalt() {
  EnsureSodium();
  std::array<uint8_t, kSaltBytes> salt{};
  ::randombytes_buf(salt.data(), salt.size());
  return salt;
}

CryptoStatus DeriveRootKey(const std::string& passphrase,
                           const std::array<uint8_t, kSaltBytes>& salt,
                           const Argon2idParams& params, SecretKey* out) {
  EnsureSodium();
  if (passphrase.empty()) return CryptoStatus::kBadInput;
  static_assert(kSaltBytes == crypto_pwhash_SALTBYTES,
                "salt length must be what Argon2id expects");
  const int rc = ::crypto_pwhash(
      out->data(), SecretKey::size(), passphrase.data(),
      static_cast<unsigned long long>(passphrase.size()), salt.data(),
      params.opslimit, params.memlimit, crypto_pwhash_ALG_ARGON2ID13);
  // The only documented failure is running out of memory, which is a real
  // outcome at 256 MiB and not a programming error.
  return rc == 0 ? CryptoStatus::kOk : CryptoStatus::kOutOfMemory;
}

SecretKey DeriveSubkey(const SecretKey& parent, uint64_t subkey_id,
                       const char* context) {
  EnsureSodium();
  UMBRA_CHECK(std::strlen(context) == crypto_kdf_CONTEXTBYTES,
              "a crypto_kdf context must be exactly 8 bytes");
  SecretKey out;
  const int rc = ::crypto_kdf_derive_from_key(
      out.data(), SecretKey::size(), subkey_id, context, parent.data());
  UMBRA_CHECK(rc == 0, "crypto_kdf_derive_from_key failed");
  return out;
}

ReplicaId DeviceKeyPair::Replica() const {
  // HASHED, NOT TRUNCATED. A replica id travels to the relay on every
  // operation; truncating the public key would hand the relay half of it for
  // free. A hash reveals nothing about the input, and the derivation means a
  // device has one identity rather than two that could drift apart.
  const ContentHash h = HashBytes(public_key.data(), public_key.size());
  ReplicaId r;
  for (std::size_t i = 0; i < r.bytes.size(); ++i) r.bytes[i] = h.bytes[i];
  return r;
}

DeviceKeyPair NewDeviceKeyPair() {
  EnsureSodium();
  DeviceKeyPair kp;
  static_assert(kPublicKeyBytes == crypto_box_PUBLICKEYBYTES,
                "public key length must match crypto_box");
  static_assert(kSecretKeyBytes == crypto_box_SECRETKEYBYTES,
                "secret key length must match crypto_box");
  const int rc =
      ::crypto_box_keypair(kp.public_key.data(), kp.secret_key.data());
  UMBRA_CHECK(rc == 0, "crypto_box_keypair failed");
  return kp;
}

VaultKeys::VaultKeys() = default;

CryptoStatus VaultKeys::Create(const std::string& passphrase,
                               const std::array<uint8_t, kSaltBytes>& salt,
                               const Argon2idParams& params, VaultKeys* out) {
  EnsureSodium();
  const CryptoStatus s = DeriveRootKey(passphrase, salt, params, &out->root_);
  if (s != CryptoStatus::kOk) return s;
  SecretKey e0;
  ::randombytes_buf(e0.data(), SecretKey::size());
  out->epochs_[0] = e0;
  out->current_ = 0;
  return CryptoStatus::kOk;
}

Epoch VaultKeys::Rotate() {
  EnsureSodium();
  SecretKey next;
  // RANDOM, NOT DERIVED. See the note at the top of keys.h: a derived epoch key
  // would be computable by a removed device, which knows the root.
  ::randombytes_buf(next.data(), SecretKey::size());
  ++current_;
  epochs_[current_] = next;
  return current_;
}

CryptoStatus VaultKeys::ContentKey(Epoch e, SecretKey* out) const {
  const std::map<Epoch, SecretKey>::const_iterator it = epochs_.find(e);
  if (it == epochs_.end()) return CryptoStatus::kUnknownEpoch;
  *out = DeriveSubkey(it->second, 1, kCtxContent);
  return CryptoStatus::kOk;
}

std::string VaultKeys::SealEpochToDevice(
    Epoch epoch, const std::array<uint8_t, kPublicKeyBytes>& device_public,
    CryptoStatus* status) const {
  EnsureSodium();
  const std::map<Epoch, SecretKey>::const_iterator it = epochs_.find(epoch);
  if (it == epochs_.end()) {
    *status = CryptoStatus::kUnknownEpoch;
    return std::string();
  }
  // An ANONYMOUS sealed box: the ciphertext carries an ephemeral public key and
  // says nothing about who produced it. A relay watching enrolment learns that
  // a device was enrolled, which the threat model already admits it learns from
  // the device count, and not which device did the enrolling.
  std::string out;
  out.resize(SecretKey::size() + crypto_box_SEALBYTES);
  const int rc = ::crypto_box_seal(reinterpret_cast<unsigned char*>(&out[0]),
                                   it->second.data(), SecretKey::size(),
                                   device_public.data());
  UMBRA_CHECK(rc == 0, "crypto_box_seal failed");
  *status = CryptoStatus::kOk;
  return out;
}

CryptoStatus VaultKeys::AcceptSealedEpoch(Epoch epoch,
                                          const std::string& sealed,
                                          const DeviceKeyPair& me) {
  EnsureSodium();
  if (sealed.size() != SecretKey::size() + crypto_box_SEALBYTES) {
    return CryptoStatus::kAuthFailed;
  }
  SecretKey k;
  const int rc = ::crypto_box_seal_open(
      k.data(), reinterpret_cast<const unsigned char*>(sealed.data()),
      static_cast<unsigned long long>(sealed.size()), me.public_key.data(),
      me.secret_key.data());
  if (rc != 0) return CryptoStatus::kAuthFailed;
  epochs_[epoch] = k;
  if (epoch > current_) current_ = epoch;
  return CryptoStatus::kOk;
}

std::string VaultKeys::WrapEpochToRoot(Epoch epoch,
                                       CryptoStatus* status) const {
  const std::map<Epoch, SecretKey>::const_iterator it = epochs_.find(epoch);
  if (it == epochs_.end()) {
    *status = CryptoStatus::kUnknownEpoch;
    return std::string();
  }
  const SecretKey wrap = DeriveSubkey(root_, epoch, kCtxEpochWrap);
  SealContext ctx;
  ctx.epoch = epoch;  // object and op stay zero: this is not an operation
  const std::string plain(reinterpret_cast<const char*>(it->second.data()),
                          SecretKey::size());
  *status = CryptoStatus::kOk;
  return Seal(wrap, ctx, plain);
}

CryptoStatus VaultKeys::RecoverFromPassphrase(
    const std::string& passphrase, const std::array<uint8_t, kSaltBytes>& salt,
    const Argon2idParams& params,
    const std::map<Epoch, std::string>& root_wrapped, VaultKeys* out) {
  const CryptoStatus s = DeriveRootKey(passphrase, salt, params, &out->root_);
  if (s != CryptoStatus::kOk) return s;
  out->epochs_.clear();
  out->current_ = 0;
  for (const std::map<Epoch, std::string>::value_type& kv : root_wrapped) {
    const SecretKey wrap = DeriveSubkey(out->root_, kv.first, kCtxEpochWrap);
    SealContext ctx;
    ctx.epoch = kv.first;
    std::string plain;
    const CryptoStatus o = Open(wrap, ctx, kv.second, &plain);
    // A WRONG PASSPHRASE FAILS HERE, not at the root derivation: Argon2id will
    // happily produce a key from any passphrase, and the first thing that can
    // tell a right one from a wrong one is an authentication tag.
    if (o != CryptoStatus::kOk) return o;
    if (plain.size() != SecretKey::size()) return CryptoStatus::kAuthFailed;
    SecretKey k;
    std::memcpy(k.data(), plain.data(), SecretKey::size());
    ::sodium_memzero(&plain[0], plain.size());
    out->epochs_[kv.first] = k;
    if (kv.first > out->current_) out->current_ = kv.first;
  }
  return CryptoStatus::kOk;
}

}  // namespace umbra
