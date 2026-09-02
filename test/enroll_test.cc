// Device enrolment and revocation.
//
// These tests exist because Phase 2 built the confidentiality half and said so
// in its own comment: an anonymous sealed box "does not say who sealed it".
// The tests below are about the other half.
#include "umbra/sync/enroll.h"

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "umbra/crypto/aead.h"
#include "umbra/crypto/keys.h"

namespace umbra {
namespace sync {
namespace {

Argon2idParams Fast() {
  // The tests are about enrolment, not about Argon2id. The production
  // parameters are asserted in crypto_test.cc; here they would add nine
  // seconds per case for nothing.
  Argon2idParams p = Argon2idParams::Default();
  p.opslimit = 1;
  p.memlimit = 8u * 1024 * 1024;
  return p;
}

std::array<uint8_t, kSaltBytes> SaltFromSeed(uint8_t seed) {
  std::array<uint8_t, kSaltBytes> s{};
  s.fill(seed);
  return s;
}

}  // namespace

TEST(Enrollment, ThePairingCodeIsSixDigitsAndOrderIndependent) {
  const DeviceKeyPair a = NewDeviceKeyPair();
  const DeviceKeyPair b = NewDeviceKeyPair();
  const std::string one = PairingCode(a.public_key, b.public_key);
  const std::string two = PairingCode(b.public_key, a.public_key);
  EXPECT_EQ(one, two) << "each side must compute the same code without "
                         "knowing which of them is joining";
  ASSERT_EQ(one.size(), 7u);
  EXPECT_EQ(one[3], ' ');
  for (std::size_t i = 0; i < one.size(); ++i) {
    if (i == 3) continue;
    EXPECT_GE(one[i], '0');
    EXPECT_LE(one[i], '9');
  }
}

// THE ATTACK THE CODE EXISTS FOR.
//
// A relay cannot open a sealed box, but it does not need to: it can seal its
// OWN epoch key to the joining device's real public key and serve that instead.
// The joining device decrypts it successfully -- there is nothing wrong with
// the ciphertext -- and is now enrolled in the relay's vault.
//
// The test asserts both halves: that the forged grant really does open, so the
// attack is real and not hand-waved, and that the pairing code the joining
// device would display differs from the one the true enroller displays.
TEST(Enrollment, ARelayCanForgeAGrantAndTheCodeIsWhatCatchesIt) {
  const std::array<uint8_t, kSaltBytes> salt = SaltFromSeed(1);
  VaultKeys owner;
  ASSERT_EQ(VaultKeys::Create("the owner's passphrase", salt, Fast(), &owner),
            CryptoStatus::kOk);
  VaultKeys attacker;
  ASSERT_EQ(VaultKeys::Create("the relay's own passphrase", SaltFromSeed(2),
                              Fast(), &attacker),
            CryptoStatus::kOk);

  const DeviceKeyPair enroller = NewDeviceKeyPair();
  const DeviceKeyPair joiner = NewDeviceKeyPair();
  const DeviceKeyPair relay = NewDeviceKeyPair();

  // The forged grant is sealed to the joiner's REAL public key, so it opens.
  CryptoStatus st = CryptoStatus::kOk;
  const std::string forged =
      attacker.SealEpochToDevice(attacker.current(), joiner.public_key, &st);
  ASSERT_EQ(st, CryptoStatus::kOk);
  VaultKeys fooled;
  ASSERT_EQ(VaultKeys::Create("the owner's passphrase", salt, Fast(), &fooled),
            CryptoStatus::kOk);
  EXPECT_EQ(fooled.AcceptSealedEpoch(attacker.current(), forged, joiner),
            CryptoStatus::kOk)
      << "the forged grant must actually open, or this test proves nothing";

  // What the user compares.
  const std::string honest =
      PairingCode(enroller.public_key, joiner.public_key);
  const std::string forged_code =
      PairingCode(relay.public_key, joiner.public_key);
  EXPECT_NE(honest, forged_code)
      << "the relay substituted a key and the code did not change";
}

// The honest path, end to end, including that the joining device can read a
// payload the enrolling device sealed under the epoch key it was given.
TEST(Enrollment, AnEnrolledDeviceReadsWhatTheVaultWrote) {
  const std::array<uint8_t, kSaltBytes> salt = SaltFromSeed(3);
  VaultKeys owner;
  ASSERT_EQ(VaultKeys::Create("passphrase", salt, Fast(), &owner),
            CryptoStatus::kOk);
  const DeviceKeyPair joiner = NewDeviceKeyPair();

  EnrollRequest req;
  req.device_public = joiner.public_key;
  const std::string wire_req = EncodeEnrollRequest(req);
  EnrollRequest back;
  ASSERT_TRUE(DecodeEnrollRequest(wire_req, &back));
  EXPECT_EQ(back.device_public, joiner.public_key);

  CryptoStatus st = CryptoStatus::kOk;
  EnrollGrant g;
  g.to = joiner.public_key;
  g.epoch = owner.current();
  g.salt = salt;
  g.vault.fill(0x5A);
  g.sealed_epoch = owner.SealEpochToDevice(g.epoch, g.to, &st);
  ASSERT_EQ(st, CryptoStatus::kOk);
  const std::string wire_grant = EncodeEnrollGrant(g);
  EnrollGrant got;
  ASSERT_TRUE(DecodeEnrollGrant(wire_grant, &got));
  EXPECT_EQ(got.epoch, g.epoch);
  EXPECT_EQ(got.salt, salt);
  EXPECT_EQ(got.sealed_epoch, g.sealed_epoch);

  VaultKeys mine;
  ASSERT_EQ(VaultKeys::Create("passphrase", got.salt, Fast(), &mine),
            CryptoStatus::kOk);
  ASSERT_EQ(mine.AcceptSealedEpoch(got.epoch, got.sealed_epoch, joiner),
            CryptoStatus::kOk);

  SealContext ctx;
  ctx.epoch = owner.current();
  ctx.op.counter = 7;
  SecretKey k_owner;
  SecretKey k_joiner;
  ASSERT_EQ(owner.ContentKey(ctx.epoch, &k_owner), CryptoStatus::kOk);
  ASSERT_EQ(mine.ContentKey(ctx.epoch, &k_joiner), CryptoStatus::kOk);
  const std::string sealed = Seal(k_owner, ctx, "a note the vault holds");
  std::string opened;
  EXPECT_EQ(::umbra::Open(k_joiner, ctx, sealed, &opened), CryptoStatus::kOk);
  EXPECT_EQ(opened, "a note the vault holds");
}

// WHAT REVOCATION DOES AND WHAT IT DOES NOT.
//
// It moves writes forward. It does not reach backwards, and the test asserts
// the second half as loudly as the first so that no user-facing string can
// quietly grow into a claim the code does not make.
TEST(Revocation, ARemovedDeviceLosesTheFutureAndKeepsThePast) {
  const std::array<uint8_t, kSaltBytes> salt = SaltFromSeed(4);
  VaultKeys owner;
  ASSERT_EQ(VaultKeys::Create("passphrase", salt, Fast(), &owner),
            CryptoStatus::kOk);
  const DeviceKeyPair removed = NewDeviceKeyPair();
  const DeviceKeyPair kept = NewDeviceKeyPair();

  const Epoch before = owner.current();
  CryptoStatus st = CryptoStatus::kOk;
  VaultKeys removed_keys;
  ASSERT_EQ(VaultKeys::Create("passphrase", salt, Fast(), &removed_keys),
            CryptoStatus::kOk);
  ASSERT_EQ(
      removed_keys.AcceptSealedEpoch(
          before, owner.SealEpochToDevice(before, removed.public_key, &st),
          removed),
      CryptoStatus::kOk);
  ASSERT_EQ(st, CryptoStatus::kOk);

  SealContext old_ctx;
  old_ctx.epoch = before;
  old_ctx.op.counter = 1;
  SecretKey k_before;
  ASSERT_EQ(owner.ContentKey(before, &k_before), CryptoStatus::kOk);
  const std::string old_note =
      Seal(k_before, old_ctx, "written before removal");

  // The revocation: a new epoch, sealed only to the devices that remain.
  const Epoch after = owner.Rotate();
  ASSERT_GT(after, before);
  VaultKeys kept_keys;
  ASSERT_EQ(VaultKeys::Create("passphrase", salt, Fast(), &kept_keys),
            CryptoStatus::kOk);
  ASSERT_EQ(
      kept_keys.AcceptSealedEpoch(
          after, owner.SealEpochToDevice(after, kept.public_key, &st), kept),
      CryptoStatus::kOk);

  SealContext new_ctx;
  new_ctx.epoch = after;
  new_ctx.op.counter = 2;
  SecretKey k_after;
  ASSERT_EQ(owner.ContentKey(after, &k_after), CryptoStatus::kOk);
  const std::string new_note = Seal(k_after, new_ctx, "written after removal");

  // The future is closed.
  EXPECT_FALSE(removed_keys.HasEpoch(after));
  SecretKey unused;
  EXPECT_EQ(removed_keys.ContentKey(after, &unused),
            CryptoStatus::kUnknownEpoch)
      << "a removed device must not hold the epoch it was removed from";

  // The past is NOT. This is the honest half.
  SecretKey still_has;
  ASSERT_EQ(removed_keys.ContentKey(before, &still_has), CryptoStatus::kOk);
  std::string readable;
  EXPECT_EQ(::umbra::Open(still_has, old_ctx, old_note, &readable),
            CryptoStatus::kOk);
  EXPECT_EQ(readable, "written before removal")
      << "revocation does not un-read what a device already had";

  // And the device that stayed reads the new writes.
  SecretKey kept_key;
  ASSERT_EQ(kept_keys.ContentKey(after, &kept_key), CryptoStatus::kOk);
  std::string fresh;
  EXPECT_EQ(::umbra::Open(kept_key, new_ctx, new_note, &fresh),
            CryptoStatus::kOk);
  EXPECT_EQ(fresh, "written after removal");
}

}  // namespace sync
}  // namespace umbra
