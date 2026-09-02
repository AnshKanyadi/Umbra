// The key hierarchy, per docs/threat-model.md section 4.
//
//     passphrase
//         |  Argon2id  (salt is public, stored with the vault)
//         v
//     root key ------------------------------------------.
//         |                                              |
//         | KDF                                          | wraps
//         v                                              v
//     epoch-wrap key                              device keypairs (X25519)
//         |  wraps                                       |  wrap
//         v                                              v
//     epoch key E(n) --KDF--> content key, metadata key  E(n)
//
// ---------------------------------------------------------------------------
// WHY EPOCH KEYS ARE RANDOM AND NOT DERIVED FROM THE ROOT
//
// The obvious design derives every key from the root by KDF. It cannot work
// here, and the reason is revocation. A removed device knows the root key --
// it had to, to read anything -- so if future keys were KDF(root, epoch) it
// could compute them and revocation would protect nothing.
//
// So an epoch key is RANDOM, generated at rotation, and stored twice:
//
//   1. sealed to each ENROLLED device's public key, which is how devices get
//      it and how a removed device stops getting it, and
//   2. encrypted under a key derived from the root, which is what makes
//      "the passphrase alone recovers a vault with no surviving device" true
//      (threat model section 4).
//
// Both wraps live beside the ciphertext they unlock. Neither is a secret the
// relay could use: (1) needs a device private key, (2) needs the passphrase.
//
// The honest consequence, already stated in the threat model: a removed device
// that ALSO knows the passphrase can derive everything, forever. The passphrase
// is the single point of failure in both directions and rotation does not
// change that.
#ifndef UMBRA_CRYPTO_KEYS_H_
#define UMBRA_CRYPTO_KEYS_H_

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "umbra/crdt/op_id.h"

namespace umbra {

// Closed; -Werror=switch applies.
enum class CryptoStatus : uint8_t {
  kOk,
  // Argon2id could not allocate its memory. Not a programming error: the
  // parameters below deliberately ask for a quarter of a gigabyte, and a
  // constrained device may not have it.
  kOutOfMemory,
  // A passphrase that is empty, or a salt of the wrong length.
  kBadInput,
  // Authentication failed. The ciphertext, the key, the nonce or the
  // associated data is not the one that was used to seal it -- and which of
  // those is deliberately not distinguished, because telling an attacker which
  // part they got right is an oracle.
  kAuthFailed,
  // No key for the epoch a ciphertext names. Either the device was enrolled
  // after that epoch, or it has been removed from it.
  kUnknownEpoch,
};

const char* CryptoStatusName(CryptoStatus s);

constexpr std::size_t kKeyBytes = 32;
constexpr std::size_t kSaltBytes = 16;
constexpr std::size_t kPublicKeyBytes = 32;
constexpr std::size_t kSecretKeyBytes = 32;

// A 32-byte secret. Zeroed on destruction with sodium_memzero, which the
// compiler is not permitted to optimise away the way a plain loop can be.
class SecretKey {
 public:
  SecretKey();
  ~SecretKey();
  SecretKey(const SecretKey& o);
  SecretKey& operator=(const SecretKey& o);

  uint8_t* data() { return bytes_.data(); }
  const uint8_t* data() const { return bytes_.data(); }
  static constexpr std::size_t size() { return kKeyBytes; }

  // Constant-time. A key comparison that short-circuits leaks how much of a
  // guess was right.
  bool Equals(const SecretKey& o) const;

 private:
  std::array<uint8_t, kKeyBytes> bytes_{};
};

// THE ARGON2id PARAMETERS, AND WHY THESE.
//
//   opslimit = crypto_pwhash_OPSLIMIT_MODERATE   (3)
//   memlimit = crypto_pwhash_MEMLIMIT_MODERATE   (256 MiB)
//   alg      = crypto_pwhash_ALG_ARGON2ID13
//
// The memory parameter is the one that matters. Argon2id's resistance to a GPU
// or ASIC attacker comes from forcing each guess to hold a large working set,
// and 256 MiB per guess is expensive to parallelise on hardware that has tens
// of gigabytes total.
//
// INTERACTIVE (64 MiB) was rejected: it is tuned for a login prompt where the
// user is waiting and the thing behind it is a session, not a key that decrypts
// every note the user has ever written.
//
// SENSITIVE (1 GiB) was rejected for a reason that is about the product rather
// than the cryptography: a phone cannot reliably allocate a gigabyte, and a
// vault that fails to unlock on the device the user carries is a vault they
// stop using. 256 MiB is the largest figure that is comfortable on the smallest
// device this is meant to run on.
//
// Argon2id rather than Argon2i or Argon2d: it is the hybrid the RFC recommends
// for password hashing, resisting both side-channel and time-memory tradeoff
// attacks, and it is what libsodium's own default names.
//
// THE SALT IS PUBLIC and 16 bytes of randomness stored beside the vault. It is
// not a secret; it exists so that two vaults with the same passphrase do not
// have the same root key, and so a precomputed table cannot cover both.
struct Argon2idParams {
  unsigned long long opslimit;
  std::size_t memlimit;
  static Argon2idParams Default();
};

// Derive the root key. Slow by construction -- that is the whole point -- so
// it belongs on an unlock path and nowhere else.
CryptoStatus DeriveRootKey(const std::string& passphrase,
                           const std::array<uint8_t, kSaltBytes>& salt,
                           const Argon2idParams& params, SecretKey* out);

std::array<uint8_t, kSaltBytes> NewSalt();

// Subkey derivation, BLAKE2b via crypto_kdf. `context` is 8 bytes and
// namespaces the derivation so that two different uses of one parent key cannot
// collide.
SecretKey DeriveSubkey(const SecretKey& parent, uint64_t subkey_id,
                       const char* context);

// A device's identity. The public half is what other devices seal to; the
// secret half never leaves the device.
struct DeviceKeyPair {
  std::array<uint8_t, kPublicKeyBytes> public_key{};
  SecretKey secret_key;

  // The replica id this device uses in operation timestamps: the first 16
  // bytes of a hash of the public key.
  //
  // DERIVED, NOT RANDOM, so a device has ONE identity rather than two that
  // could disagree -- and hashed rather than truncated so that the replica id
  // reveals nothing about the public key to a relay that only sees the former.
  ReplicaId Replica() const;
};

DeviceKeyPair NewDeviceKeyPair();

// One rotation generation. Every payload records the epoch it was sealed
// under, so a device that joined at epoch 3 can still read epoch 1 if it was
// given the key, and cannot read epoch 4 if it was removed before it.
using Epoch = uint32_t;

// What a device holds after enrolment: the epoch keys it has been given.
class VaultKeys {
 public:
  VaultKeys();

  // Create a brand new vault from a passphrase. Generates epoch 0.
  static CryptoStatus Create(const std::string& passphrase,
                             const std::array<uint8_t, kSaltBytes>& salt,
                             const Argon2idParams& params, VaultKeys* out);

  // Recover from the passphrase alone, given the wraps the relay holds. This
  // is the path that must work when every device is gone.
  static CryptoStatus RecoverFromPassphrase(
      const std::string& passphrase,
      const std::array<uint8_t, kSaltBytes>& salt,
      const Argon2idParams& params,
      const std::map<Epoch, std::string>& root_wrapped, VaultKeys* out);

  // Rotation. Generates a new epoch key, makes it current, and returns the new
  // epoch. Old epochs stay readable; only WRITES move forward, which is exactly
  // the guarantee the threat model claims and no more.
  Epoch Rotate();

  // Wrap the current epoch key for a device being enrolled. Anonymous sealed
  // box: only the holder of the matching secret key can open it, and the
  // ciphertext does not say who sealed it.
  std::string SealEpochToDevice(
      Epoch epoch, const std::array<uint8_t, kPublicKeyBytes>& device_public,
      CryptoStatus* status) const;

  // The other side of enrolment.
  CryptoStatus AcceptSealedEpoch(Epoch epoch, const std::string& sealed,
                                 const DeviceKeyPair& me);

  // Wrap an epoch key under the root key, for passphrase-only recovery.
  std::string WrapEpochToRoot(Epoch epoch, CryptoStatus* status) const;

  Epoch current() const { return current_; }
  bool HasEpoch(Epoch e) const { return epochs_.count(e) != 0; }
  // The key an AEAD should use for payloads in this epoch.
  CryptoStatus ContentKey(Epoch e, SecretKey* out) const;

  const SecretKey& root() const { return root_; }

 private:
  SecretKey root_;
  std::map<Epoch, SecretKey> epochs_;
  Epoch current_ = 0;
};

}  // namespace umbra

#endif  // UMBRA_CRYPTO_KEYS_H_
