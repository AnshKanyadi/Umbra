// Device enrolment and revocation.
//
// ---------------------------------------------------------------------------
// THE PROBLEM A SEALED BOX DOES NOT SOLVE
//
// keys.h seals an epoch key to a joining device with an anonymous sealed box,
// and says so plainly: "the ciphertext does not say who sealed it". Anyone can
// seal to a public key. A relay that wants into the vault can therefore answer
// a joining device's request with its OWN grant, sealed to that device's real
// public key, and the device cannot tell the difference -- it decrypts, it
// works, and the device is now enrolled in the attacker's vault while the user
// believes it joined theirs.
//
// Confidentiality was never the missing half. AUTHENTICITY is.
//
// ---------------------------------------------------------------------------
// WHAT THE USER DOES, AND WHY IT IS ONE COMPARISON
//
// Both devices display the same six digits. The user checks they match.
//
//   joining device            enrolling device
//   ---------------           ----------------
//   umbra_sync --enrol        umbra_sync --approve 4f2a91
//     pairing code            pairing code
//        418 073                 418 073
//
// The code is the first 20 bits of BLAKE2b("umbra enrol sas" || the two public
// keys, sorted), rendered as six digits. Both devices know both public keys
// only if no one substituted one, so the codes agree only if no one did. An
// attacker must commit to a key before it can see the code it will produce, and
// cannot search for a collision after the fact because the honest device has
// already displayed the honest code.
//
// Six digits is 20 bits: one guess in a million. THAT IS A DELIBERATE CEILING,
// not a target -- it is the number a person will actually compare. It holds
// because the attack is online and one-shot: the attacker gets exactly one
// try per enrolment, in front of a user who is looking at two screens. It
// would NOT hold if the code could be attacked offline, which is why the code
// authenticates keys already exchanged rather than being a secret to derive a
// key from.
//
// If the user does not compare, this reduces to trust-on-first-use through the
// relay and the relay can enrol itself. That is stated in the threat model
// rather than hidden behind a default.
//
// ---------------------------------------------------------------------------
// WHAT A REVOKED DEVICE KEEPS
//
// Everything it already had. Revocation rotates the epoch key and seals the new
// one to the devices that remain; it does not and cannot reach into a removed
// device and erase what it holds. A revoked device keeps:
//
//   - every file in its vault folder, in plaintext, on its own disk
//   - every operation in its local log
//   - every epoch key it was ever given, so it can still read anything on the
//     relay that was sealed under those epochs
//
// It cannot read anything written after the rotation. That is the whole of the
// guarantee and the user-facing strings say exactly that much.
#ifndef UMBRA_SYNC_ENROLL_H_
#define UMBRA_SYNC_ENROLL_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "umbra/crdt/op_id.h"
#include "umbra/crypto/keys.h"

namespace umbra {
namespace sync {

// What a joining device publishes: its public key, and nothing else. It has no
// vault material yet, so there is nothing here to protect.
struct EnrollRequest {
  std::array<uint8_t, kPublicKeyBytes> device_public{};
};

// What an enrolling device publishes in reply, addressed to one public key.
// salt and vault are NOT secret -- the relay sees the vault id on every request
// and an Argon2id salt is public by construction -- so only the epoch key is
// sealed.
struct EnrollGrant {
  std::array<uint8_t, kPublicKeyBytes> to{};
  std::array<uint8_t, kPublicKeyBytes> from{};
  Epoch epoch = 0;
  std::array<uint8_t, kSaltBytes> salt{};
  std::array<uint8_t, 16> vault{};
  std::string sealed_epoch;
};

std::string EncodeEnrollRequest(const EnrollRequest& r);
bool DecodeEnrollRequest(const std::string& in, EnrollRequest* out);
std::string EncodeEnrollGrant(const EnrollGrant& g);
bool DecodeEnrollGrant(const std::string& in, EnrollGrant* out);

// The six digits both devices display. Order-independent: the two keys are
// sorted before hashing so each side computes the same value without either
// having to know which of them is joining.
std::string PairingCode(const std::array<uint8_t, kPublicKeyBytes>& a,
                        const std::array<uint8_t, kPublicKeyBytes>& b);

// The short form a user reads off a screen to name a device. Six hex
// characters of the replica id -- enough to pick one device out of a household,
// not enough to be an identity.
std::string DeviceLabel(const ReplicaId& r);

}  // namespace sync
}  // namespace umbra

#endif  // UMBRA_SYNC_ENROLL_H_
