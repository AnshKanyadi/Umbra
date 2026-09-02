// The key hierarchy, the AEAD, and what a relay actually holds.
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <sodium.h>

#include "scan.h"
#include "umbra/crdt/oplog.h"
#include "umbra/crdt/tree.h"
#include "umbra/crdt/vault.h"
#include "umbra/crypto/aead.h"
#include "umbra/crypto/keys.h"

namespace umbra {
namespace {

class TempDir {
 public:
  TempDir() {
    const char* tmp = ::getenv("TMPDIR");
    std::string base = tmp != nullptr && tmp[0] != '\0' ? tmp : "/tmp";
    if (!base.empty() && base.back() == '/') base.pop_back();
    std::string tpl = base + "/umbra-crypto-test-XXXXXX";
    std::vector<char> buf(tpl.begin(), tpl.end());
    buf.push_back('\0');
    const char* made = ::mkdtemp(buf.data());
    EXPECT_NE(made, nullptr) << ::strerror(errno);
    if (made != nullptr) path_ = made;
  }
  ~TempDir() {
    if (path_.empty()) return;
    std::vector<std::string> files;
    std::vector<std::string> dirs;
    WalkSubtree(path_, path_, [&](const std::string& p, const FileState& st) {
      if (st.is_dir) {
        dirs.push_back(p);
      } else {
        files.push_back(p);
      }
    });
    for (const std::string& f : files) ::unlink(f.c_str());
    for (std::vector<std::string>::reverse_iterator it = dirs.rbegin();
         it != dirs.rend(); ++it) {
      ::rmdir(it->c_str());
    }
    ::rmdir(path_.c_str());
  }
  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

// Argon2id at the shipped parameters takes 256 MiB and a noticeable fraction of
// a second, which is the entire point of it and exactly wrong for a test that
// runs a hundred times under three sanitizers. Tests that are about the
// HIERARCHY use these; the test that is about the PARAMETERS asserts the real
// ones are what the header says.
Argon2idParams FastParams() {
  Argon2idParams p;
  p.opslimit = crypto_pwhash_OPSLIMIT_MIN;
  p.memlimit = crypto_pwhash_MEMLIMIT_MIN;
  return p;
}

std::array<uint8_t, kSaltBytes> FixedSalt(uint8_t b) {
  std::array<uint8_t, kSaltBytes> s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(b + i);
  return s;
}

bool Contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

// ------------------------------------------------------------- parameters

TEST(Argon2id, TheShippedParametersAreTheOnesDocumented) {
  // The header argues for MODERATE and says why INTERACTIVE and SENSITIVE were
  // rejected. This asserts the code agrees with the argument, so that lowering
  // them is a test failure rather than a quiet change.
  const Argon2idParams p = Argon2idParams::Default();
  EXPECT_EQ(p.opslimit, crypto_pwhash_OPSLIMIT_MODERATE);
  EXPECT_EQ(p.memlimit, crypto_pwhash_MEMLIMIT_MODERATE);
  EXPECT_EQ(p.memlimit, 268435456u) << "256 MiB";
}

TEST(Argon2id, IsDeterministicAndDependsOnTheSalt) {
  SecretKey a;
  SecretKey b;
  SecretKey c;
  ASSERT_EQ(DeriveRootKey("correct horse", FixedSalt(1), FastParams(), &a),
            CryptoStatus::kOk);
  ASSERT_EQ(DeriveRootKey("correct horse", FixedSalt(1), FastParams(), &b),
            CryptoStatus::kOk);
  EXPECT_TRUE(a.Equals(b)) << "the same inputs gave different keys";

  ASSERT_EQ(DeriveRootKey("correct horse", FixedSalt(2), FastParams(), &c),
            CryptoStatus::kOk);
  EXPECT_FALSE(a.Equals(c)) << "the salt did not change the key";

  SecretKey d;
  ASSERT_EQ(DeriveRootKey("correct horsf", FixedSalt(1), FastParams(), &d),
            CryptoStatus::kOk);
  EXPECT_FALSE(a.Equals(d)) << "a one-character change gave the same key";

  SecretKey e;
  EXPECT_EQ(DeriveRootKey("", FixedSalt(1), FastParams(), &e),
            CryptoStatus::kBadInput);
}

TEST(Kdf, SubkeysAreDistinctPerContextAndIndex) {
  SecretKey root;
  ASSERT_EQ(DeriveRootKey("pass", FixedSalt(1), FastParams(), &root),
            CryptoStatus::kOk);
  const SecretKey a = DeriveSubkey(root, 1, "umbCont1");
  const SecretKey b = DeriveSubkey(root, 2, "umbCont1");
  const SecretKey c = DeriveSubkey(root, 1, "umbEpoch");
  EXPECT_FALSE(a.Equals(b)) << "the subkey index did not matter";
  EXPECT_FALSE(a.Equals(c)) << "the context did not matter";
}

// ---------------------------------------------------------------- devices

TEST(Device, IdentityIsDerivedFromThePublicKeyAndHidesIt) {
  const DeviceKeyPair a = NewDeviceKeyPair();
  const DeviceKeyPair b = NewDeviceKeyPair();
  EXPECT_FALSE(a.Replica() == b.Replica());
  // Deterministic: one device, one identity.
  EXPECT_TRUE(a.Replica() == a.Replica());
  // HASHED, NOT TRUNCATED. The replica id travels to the relay on every
  // operation; it must not hand over a prefix of the public key.
  const std::string pub(reinterpret_cast<const char*>(a.public_key.data()),
                        a.public_key.size());
  const std::string rep(reinterpret_cast<const char*>(a.Replica().bytes.data()),
                        a.Replica().bytes.size());
  EXPECT_FALSE(Contains(pub, rep)) << "the replica id is a slice of the key";
}

TEST(Enrollment, ADeviceGetsTheEpochKeyAndAStrangerDoesNot) {
  VaultKeys vault;
  ASSERT_EQ(VaultKeys::Create("pass", FixedSalt(1), FastParams(), &vault),
            CryptoStatus::kOk);
  const DeviceKeyPair mine = NewDeviceKeyPair();
  const DeviceKeyPair theirs = NewDeviceKeyPair();

  CryptoStatus st = CryptoStatus::kOk;
  const std::string sealed =
      vault.SealEpochToDevice(vault.current(), mine.public_key, &st);
  ASSERT_EQ(st, CryptoStatus::kOk);

  VaultKeys enrolled;
  EXPECT_EQ(enrolled.AcceptSealedEpoch(vault.current(), sealed, mine),
            CryptoStatus::kOk);
  SecretKey k1;
  SecretKey k2;
  ASSERT_EQ(vault.ContentKey(vault.current(), &k1), CryptoStatus::kOk);
  ASSERT_EQ(enrolled.ContentKey(vault.current(), &k2), CryptoStatus::kOk);
  EXPECT_TRUE(k1.Equals(k2)) << "enrolment produced a different content key";

  VaultKeys stranger;
  EXPECT_EQ(stranger.AcceptSealedEpoch(vault.current(), sealed, theirs),
            CryptoStatus::kAuthFailed);
}

// THE REVOCATION PROPERTY, exactly as docs/threat-model.md section 6 states it:
// rotation makes FUTURE writes unreadable to a removed device, and does nothing
// about what it already has.
TEST(Rotation, RemovesFutureReadsAndLeavesPastOnesAlone) {
  VaultKeys vault;
  ASSERT_EQ(VaultKeys::Create("pass", FixedSalt(1), FastParams(), &vault),
            CryptoStatus::kOk);
  const DeviceKeyPair removed = NewDeviceKeyPair();

  CryptoStatus st = CryptoStatus::kOk;
  VaultKeys device;
  ASSERT_EQ(
      device.AcceptSealedEpoch(
          0, vault.SealEpochToDevice(0, removed.public_key, &st), removed),
      CryptoStatus::kOk);

  SealContext ctx;
  ctx.epoch = 0;
  SecretKey k0;
  ASSERT_EQ(vault.ContentKey(0, &k0), CryptoStatus::kOk);
  const std::string old_ciphertext = Seal(k0, ctx, "written before removal");

  // Remove the device: rotate, and do NOT seal the new epoch to it.
  const Epoch e1 = vault.Rotate();
  EXPECT_EQ(e1, 1u);
  SecretKey k1;
  ASSERT_EQ(vault.ContentKey(e1, &k1), CryptoStatus::kOk);
  SealContext ctx1;
  ctx1.epoch = e1;
  const std::string new_ciphertext = Seal(k1, ctx1, "written after removal");

  // The removed device can still read what it already had a key for. That is
  // not a bug; it is the stated limit.
  SecretKey dk0;
  ASSERT_EQ(device.ContentKey(0, &dk0), CryptoStatus::kOk);
  std::string plain;
  EXPECT_EQ(Open(dk0, ctx, old_ciphertext, &plain), CryptoStatus::kOk);
  EXPECT_EQ(plain, "written before removal");

  // And it cannot read anything written afterwards, because it has no key for
  // the new epoch and cannot derive one -- the epoch key is random, not derived
  // from the root it knows.
  SecretKey dk1;
  EXPECT_EQ(device.ContentKey(e1, &dk1), CryptoStatus::kUnknownEpoch);
}

TEST(Recovery, ThePassphraseAloneRecoversAVaultWithNoDevices) {
  VaultKeys vault;
  ASSERT_EQ(VaultKeys::Create("a long passphrase", FixedSalt(3), FastParams(),
                              &vault),
            CryptoStatus::kOk);
  vault.Rotate();
  vault.Rotate();

  std::map<Epoch, std::string> wrapped;
  for (Epoch e = 0; e <= vault.current(); ++e) {
    CryptoStatus st = CryptoStatus::kOk;
    wrapped[e] = vault.WrapEpochToRoot(e, &st);
    ASSERT_EQ(st, CryptoStatus::kOk);
  }

  // Every device is gone. Only the passphrase and what the relay holds remain.
  VaultKeys recovered;
  ASSERT_EQ(VaultKeys::RecoverFromPassphrase("a long passphrase", FixedSalt(3),
                                             FastParams(), wrapped, &recovered),
            CryptoStatus::kOk);
  EXPECT_EQ(recovered.current(), vault.current());
  for (Epoch e = 0; e <= vault.current(); ++e) {
    SecretKey a;
    SecretKey b;
    ASSERT_EQ(vault.ContentKey(e, &a), CryptoStatus::kOk);
    ASSERT_EQ(recovered.ContentKey(e, &b), CryptoStatus::kOk);
    EXPECT_TRUE(a.Equals(b)) << "epoch " << e << " did not recover";
  }

  // A WRONG PASSPHRASE FAILS AT THE AUTHENTICATION TAG, not at the derivation:
  // Argon2id produces a key from any input, and the first thing that can tell
  // right from wrong is the AEAD.
  VaultKeys wrong;
  EXPECT_EQ(VaultKeys::RecoverFromPassphrase("a long passphrasf", FixedSalt(3),
                                             FastParams(), wrapped, &wrong),
            CryptoStatus::kAuthFailed);
}

// ------------------------------------------------------------------- aead

TEST(Aead, RoundTripsAndRefusesEverythingElse) {
  SecretKey k;
  ::randombytes_buf(k.data(), SecretKey::size());
  SealContext ctx;
  ctx.object.bytes[0] = 7;
  ctx.op = OpId{42, ReplicaIdFromSeed(1)};
  ctx.epoch = 3;

  const std::string msg = "# a note\n\nwith a body";
  const std::string sealed = Seal(k, ctx, msg);
  std::string out;
  ASSERT_EQ(Open(k, ctx, sealed, &out), CryptoStatus::kOk);
  EXPECT_EQ(out, msg);

  SecretKey other;
  ::randombytes_buf(other.data(), SecretKey::size());
  EXPECT_EQ(Open(other, ctx, sealed, &out), CryptoStatus::kAuthFailed);
  EXPECT_TRUE(out.empty()) << "a failed open handed back bytes";

  // THE ASSOCIATED DATA BINDING. Each field is the difference between a
  // ciphertext being at the right place and the wrong one.
  SealContext moved = ctx;
  moved.op.counter = 43;
  EXPECT_EQ(Open(k, moved, sealed, &out), CryptoStatus::kAuthFailed)
      << "a ciphertext opened under a different counter";
  moved = ctx;
  moved.object.bytes[0] = 8;
  EXPECT_EQ(Open(k, moved, sealed, &out), CryptoStatus::kAuthFailed)
      << "a ciphertext opened under a different object";
  moved = ctx;
  moved.op.replica = ReplicaIdFromSeed(2);
  EXPECT_EQ(Open(k, moved, sealed, &out), CryptoStatus::kAuthFailed)
      << "a ciphertext opened under a different replica";
  moved = ctx;
  moved.epoch = 4;
  EXPECT_EQ(Open(k, moved, sealed, &out), CryptoStatus::kAuthFailed)
      << "a ciphertext opened under a different epoch";

  // Tampering, one bit at a time over the whole thing.
  for (std::size_t i = 0; i < sealed.size(); ++i) {
    std::string bad = sealed;
    bad[i] = static_cast<char>(bad[i] ^ 0x01);
    EXPECT_EQ(Open(k, ctx, bad, &out), CryptoStatus::kAuthFailed)
        << "a flipped bit at offset " << i << " went unnoticed";
  }
  for (std::size_t cut = 0; cut < sealed.size(); ++cut) {
    EXPECT_EQ(Open(k, ctx, sealed.substr(0, cut), &out),
              CryptoStatus::kAuthFailed);
  }
}

TEST(Aead, TheSamePlaintextSealsDifferentlyEachTime) {
  SecretKey k;
  ::randombytes_buf(k.data(), SecretKey::size());
  SealContext ctx;
  const std::string msg = "identical";
  const std::string a = Seal(k, ctx, msg);
  const std::string b = Seal(k, ctx, msg);
  EXPECT_NE(a, b)
      << "the nonce is not random; two identical notes are linkable";
  EXPECT_EQ(a.size(), b.size());
}

// OBJECT IDS ARE OPAQUE, which threat model section 3 requires: an id derived
// from the path would let a relay confirm a guessed filename by computing its
// id, which is the same leak as storing the name.
TEST(ObjectIdentity, IsNotDerivedFromThePath) {
  Vault a(ReplicaIdFromSeed(1));
  Vault b(ReplicaIdFromSeed(2));
  ChangeEvent e;
  e.kind = ChangeKind::kCreated;
  e.path = "notes/identical.md";
  const ChangeOutcome ca = a.ApplyChange(e, "same bytes");
  const ChangeOutcome cb = b.ApplyChange(e, "same bytes");
  ASSERT_EQ(ca.status, VaultOutcome::kOk);
  ASSERT_EQ(cb.status, VaultOutcome::kOk);
  EXPECT_FALSE(ca.object == cb.object)
      << "two vaults gave the same path the same id, so the id is a function "
         "of the path";

  // And the same vault gives two different paths different ids, so the id is
  // not a constant either.
  ChangeEvent e2 = e;
  e2.path = "notes/other.md";
  const ChangeOutcome c2 = a.ApplyChange(e2, "x");
  ASSERT_EQ(c2.status, VaultOutcome::kOk);
  EXPECT_FALSE(ca.object == c2.object);

  // The id must not contain the name as a substring, which a naive "hash the
  // path but keep a prefix" scheme would.
  const std::string idbytes(
      reinterpret_cast<const char*>(ca.object.bytes.data()),
      ca.object.bytes.size());
  EXPECT_FALSE(Contains(idbytes, "identical"));
  EXPECT_FALSE(Contains(idbytes, "notes"));
}

// ------------------------------------------------- WHAT THE RELAY HOLDS
//
// This is the test the threat model owes. It is written over the ACTUAL BYTES
// that reach storage -- obtained by reopening the same log WITHOUT keys, which
// is precisely a relay's view -- and not over an assertion that the code calls
// an encryption function somewhere.
//
// Everything asserted absent here is something threat model section 3 puts
// inside the confidentiality boundary. Everything asserted PRESENT is something
// section 5 already concedes the relay learns, and is asserted so that the
// concession is checked rather than merely written down: if a future change
// stopped leaking it, this test should be updated deliberately, and if a future
// change started leaking something new, the absence assertions catch it.
class RelayView : public ::testing::Test {
 protected:
  // Distinctive enough that a substring search over a few kilobytes of
  // ciphertext cannot match them by accident.
  const std::string kSecretBody = "SECRET-BODY-xyzzy-plugh-2718281828";
  const std::string kSecretName = "SECRET-NAME-quux-frobnitz.md";
  const std::string kSecretDir = "SECRET-DIR-grault";

  void Build() {
    ASSERT_EQ(VaultKeys::Create("relay test passphrase", FixedSalt(9),
                                FastParams(), &keys_),
              CryptoStatus::kOk);
    db_ = dir_.path() + "/db";
    std::unique_ptr<OpLog> log;
    ASSERT_EQ(OpLog::OpenEncrypted(db_, &keys_, &log), LogStatus::kOk);

    Vault v(ReplicaIdFromSeed(11));
    ChangeEvent e;
    e.kind = ChangeKind::kCreated;
    e.path = kSecretDir + "/" + kSecretName;
    const ChangeOutcome c = v.ApplyChange(e, kSecretBody);
    ASSERT_EQ(c.status, VaultOutcome::kOk);
    ASSERT_FALSE(c.ops.empty());
    ASSERT_FALSE(c.tree_ops.empty());
    object_ = c.object;

    ASSERT_EQ(log->Append(c.object, c.ops), LogStatus::kOk);
    ASSERT_EQ(log->AppendTree(c.tree_ops), LogStatus::kOk);
    ASSERT_EQ(log->Sync(), LogStatus::kOk);
    plaintext_ops_ = c.ops.size() + c.tree_ops.size();
  }

  // Exactly what a relay would have: the stored keys and the stored values,
  // read back by something that holds no key material at all.
  void ReadAsRelay(std::vector<LoggedOp>* text, std::vector<LoggedOp>* tree) {
    std::unique_ptr<OpLog> relay;
    ASSERT_EQ(OpLog::Open(db_, &relay), LogStatus::kOk);
    ASSERT_EQ(relay->ReadRaw(object_, text), LogStatus::kOk);
    ASSERT_EQ(relay->ReadRaw(TreeObject(), tree), LogStatus::kOk);
  }

  TempDir dir_;
  std::string db_;
  VaultKeys keys_;
  ObjectId object_;
  std::size_t plaintext_ops_ = 0;
};

TEST_F(RelayView, HoldsNoFileContentAndNoFileName) {
  Build();
  if (::testing::Test::HasFatalFailure()) return;
  std::vector<LoggedOp> text;
  std::vector<LoggedOp> tree;
  ReadAsRelay(&text, &tree);
  if (::testing::Test::HasFatalFailure()) return;
  ASSERT_FALSE(text.empty());
  ASSERT_FALSE(tree.empty());

  std::string everything;
  for (const LoggedOp& l : text) {
    everything += MakeOpLogKey(object_, l.id.replica, l.id.counter);
    everything += l.payload.bytes;
  }
  for (const LoggedOp& l : tree) {
    everything += MakeOpLogKey(TreeObject(), l.id.replica, l.id.counter);
    everything += l.payload.bytes;
  }

  // THE CONTENT OF THE FILE IS NOT THERE.
  EXPECT_FALSE(Contains(everything, kSecretBody))
      << "the relay holds the note's text";
  // NOR IS ITS NAME. The name lives inside a tree operation's payload, so this
  // is the assertion that encrypting payloads is what keeps names off the
  // relay -- threat model section 3.
  EXPECT_FALSE(Contains(everything, kSecretName))
      << "the relay holds the file name";
  EXPECT_FALSE(Contains(everything, kSecretDir))
      << "the relay holds the directory name";
  // Not even a fragment. A substring long enough to be recognisable is enough
  // to confirm a guess.
  EXPECT_FALSE(Contains(everything, kSecretBody.substr(0, 12)));
  EXPECT_FALSE(Contains(everything, kSecretName.substr(0, 12)));
  // And no plaintext operation structure: the encoding version byte of a tree
  // operation followed by its shape would be recognisable if payloads were
  // stored in the clear.
  for (const LoggedOp& l : tree) {
    TreeOp decoded;
    EXPECT_FALSE(DecodeTreeOp(l.payload, &decoded))
        << "a stored tree payload decoded without a key";
  }
  for (const LoggedOp& l : text) {
    Op decoded;
    EXPECT_FALSE(DecodeOp(l.payload, &decoded))
        << "a stored text payload decoded without a key";
  }
}

TEST_F(RelayView, HoldsExactlyWhatTheThreatModelSaysItDoes) {
  Build();
  if (::testing::Test::HasFatalFailure()) return;
  std::vector<LoggedOp> text;
  std::vector<LoggedOp> tree;
  ReadAsRelay(&text, &tree);
  if (::testing::Test::HasFatalFailure()) return;

  // 1. OBJECT IDS ARE VISIBLE, in the key. Conceded by section 3: they are
  // opaque and unrelated to the path, and the relay addresses blobs by them.
  const std::string key =
      MakeOpLogKey(object_, text[0].id.replica, text[0].id.counter);
  const std::string obj(reinterpret_cast<const char*>(object_.bytes.data()),
                        object_.bytes.size());
  EXPECT_TRUE(Contains(key, obj)) << "the relay cannot address the object";

  // 2. THE REPLICA ID IS VISIBLE, which is how section 5.3's device count
  // leaks. It must be the DERIVED identity and not anything about the key.
  // 3. THE COUNTER IS VISIBLE, which is what makes a sync cursor possible
  // without decryption -- the reason ADR 0002 kept it out of the payload.
  ObjectId parsed_obj;
  ReplicaId parsed_rep;
  uint64_t parsed_counter = 0;
  ASSERT_TRUE(ParseOpLogKey(key, &parsed_obj, &parsed_rep, &parsed_counter));
  EXPECT_EQ(parsed_obj, object_);
  EXPECT_GT(parsed_counter, 0u);

  // 4. THE NUMBER OF OPERATIONS IS VISIBLE. Section 5.5: which objects change
  // together, and how often, is admitted.
  EXPECT_EQ(text.size() + tree.size(), plaintext_ops_);

  // 5. THE EPOCH IS VISIBLE, four bytes in the clear at the front of every
  // value, because a reader must know which key generation sealed it. A relay
  // can therefore count rotations.
  for (const LoggedOp& l : text) {
    ASSERT_GE(l.payload.bytes.size(), kEnvelopeBytes);
    EXPECT_EQ(static_cast<unsigned char>(l.payload.bytes[0]), 0u)
        << "epoch 0 was expected in the envelope";
  }
}

TEST_F(RelayView, CiphertextLengthTracksPlaintextLength) {
  // SECTION 5.1, ASSERTED RATHER THAN ADMITTED IN PROSE. Padding was declined,
  // so a note's approximate size is visible. This test exists so that the leak
  // is a documented, checked property: if padding is ever added, this test
  // fails and someone updates the threat model deliberately.
  SecretKey k;
  ::randombytes_buf(k.data(), SecretKey::size());
  SealContext ctx;
  const std::string small = Seal(k, ctx, std::string(10, 'x'));
  const std::string large = Seal(k, ctx, std::string(10000, 'x'));
  EXPECT_EQ(small.size(), 10u + kNonceBytes + kMacBytes);
  EXPECT_EQ(large.size(), 10000u + kNonceBytes + kMacBytes);
  EXPECT_LT(small.size(), large.size())
      << "sizes are hidden, which would be good news and a documentation bug";
}

TEST_F(RelayView, CannotMoveACiphertextToADifferentKey) {
  // A hostile relay serving the value stored at one key under another. The
  // associated data binding is what stops it; without it the payload would
  // decrypt perfectly at the wrong position.
  Build();
  if (::testing::Test::HasFatalFailure()) return;
  std::vector<LoggedOp> text;
  std::vector<LoggedOp> tree;
  ReadAsRelay(&text, &tree);
  if (::testing::Test::HasFatalFailure()) return;
  ASSERT_FALSE(text.empty());

  SecretKey k;
  ASSERT_EQ(keys_.ContentKey(0, &k), CryptoStatus::kOk);
  const std::string sealed = text[0].payload.bytes.substr(kEnvelopeBytes);

  SealContext right;
  right.object = object_;
  right.op = text[0].id;
  right.epoch = 0;
  std::string out;
  ASSERT_EQ(Open(k, right, sealed, &out), CryptoStatus::kOk)
      << "the honest read does not work, so the attack test proves nothing";

  SealContext elsewhere = right;
  elsewhere.op.counter += 1;
  EXPECT_EQ(Open(k, elsewhere, sealed, &out), CryptoStatus::kAuthFailed);
  elsewhere = right;
  elsewhere.object = TreeObject();
  EXPECT_EQ(Open(k, elsewhere, sealed, &out), CryptoStatus::kAuthFailed);
}

TEST_F(RelayView, TheVaultRoundTripsThroughAnEncryptedLog) {
  // The encryption is not merely present; the system still works with it on.
  Build();
  if (::testing::Test::HasFatalFailure()) return;
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::OpenEncrypted(db_, &keys_, &log), LogStatus::kOk);

  TextDoc doc;
  std::map<ReplicaId, uint64_t> high;
  ASSERT_EQ(log->Replay(object_, &doc, &high), LogStatus::kOk);
  EXPECT_EQ(doc.Text(), kSecretBody);

  TreeDoc tree;
  std::map<ReplicaId, uint64_t> thigh;
  ASSERT_EQ(log->ReplayTree(&tree, &thigh), LogStatus::kOk);
  std::string path;
  ASSERT_TRUE(tree.PathOf(object_, &path));
  EXPECT_EQ(path, kSecretDir + "/" + kSecretName);
}

}  // namespace
}  // namespace umbra
