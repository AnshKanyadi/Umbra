// Authenticated encryption for everything that reaches the relay.
//
// XChaCha20-Poly1305-IETF, via libsodium.
//
// WHY XChaCha AND NOT ChaCha20-Poly1305: the nonce is 24 bytes rather than 12,
// so it can be drawn at random with no birthday concern and no counter to keep.
// A counter would have to survive crashes and never repeat across devices, and
// a repeated nonce with the same key is catastrophic for this construction --
// it leaks the XOR of two plaintexts and the authentication key. A 192-bit
// random nonce removes the bookkeeping and with it that class of bug.
//
// ---------------------------------------------------------------------------
// THE ASSOCIATED DATA IS THE POINT, NOT AN EXTRA
//
// Every sealed payload is bound to WHERE IT LIVES: the object id, the replica,
// the counter and the epoch. Those are the oplog key plus the key generation
// (see oplog.h), and they are authenticated but not encrypted, because the
// relay must be able to route and order by them without reading anything.
//
// Binding them means a hostile relay cannot take the ciphertext stored at one
// key and serve it at another. Without the binding it could: the payload would
// decrypt perfectly, and a device would apply operation 7 from replica A where
// operation 9 from replica B belonged. That is a real attack on a store-and-
// forward relay that is assumed hostile, and it costs nothing to close.
#ifndef UMBRA_CRYPTO_AEAD_H_
#define UMBRA_CRYPTO_AEAD_H_

#include <cstdint>
#include <string>

#include "umbra/change_event.h"
#include "umbra/crdt/op_id.h"
#include "umbra/crypto/keys.h"

namespace umbra {

// The nonce is prepended to the ciphertext, so a sealed payload is
// self-contained apart from its key and its associated data.
constexpr std::size_t kNonceBytes = 24;
constexpr std::size_t kMacBytes = 16;

// What a payload is bound to. Everything here is visible to the relay by
// design; see the threat model's table of what it learns.
struct SealContext {
  ObjectId object;
  OpId op;
  Epoch epoch = 0;

  // The exact bytes fed to the AEAD as associated data. Deterministic and
  // canonical, because the two sides must build the same string or every open
  // fails.
  std::string Bytes() const;
};

// Seals `plaintext`. The result is nonce || ciphertext || tag, so it is
// kNonceBytes + kMacBytes longer than the plaintext.
//
// THE LENGTH IS NOT HIDDEN. Threat model section 5.1 admits that ciphertext
// sizes leak approximate plaintext sizes and says padding was declined; this is
// where that shows up, and CryptoRelay.CiphertextLengthTracksPlaintextLength
// asserts it rather than leaving it as prose.
std::string Seal(const SecretKey& key, const SealContext& ctx,
                 const std::string& plaintext);

// Opens. Returns kAuthFailed for a wrong key, a wrong context, a truncated
// input or a tampered one, and does not distinguish between them.
CryptoStatus Open(const SecretKey& key, const SealContext& ctx,
                  const std::string& sealed, std::string* plaintext);

}  // namespace umbra

#endif  // UMBRA_CRYPTO_AEAD_H_
