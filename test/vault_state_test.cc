// Where a device identity lives, and the rules about making one.
//
// The device key is the only plaintext secret in a vault's state, and it used
// to sit inside the vault folder -- the sort of folder iCloud or Obsidian Sync
// watches. Copying a vault therefore copied the identity, which is how two
// "devices" in an earlier end-to-end test turned out to be one machine wearing
// one key twice. It lives outside the vault now, and the rules that keep it
// honest are asserted here rather than described in a comment.
#include "vault_state.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <string>

#include <gtest/gtest.h>

namespace umbra {
namespace {

class TempDir {
 public:
  TempDir() {
    char tmpl[] = "/tmp/umbra_state_XXXXXX";
    const char* made = ::mkdtemp(tmpl);
    path_ = made != nullptr ? made : "";
  }
  ~TempDir() {
    if (path_.empty()) return;
    (void)::unlink((path_ + "/device").c_str());
    (void)::rmdir(path_.c_str());
  }
  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

TEST(VaultState, TheStateDirectoryIsKeyedByTheVaultPath) {
  const std::string a = cmdstate::StateDirFor("/tmp/vault-one", "");
  const std::string b = cmdstate::StateDirFor("/tmp/vault-two", "");
  EXPECT_NE(a, b) << "two vaults would share one device identity";
  EXPECT_EQ(a, cmdstate::StateDirFor("/tmp/vault-one", ""))
      << "the same vault resolved to two identities across calls";
}

// AN EXPLICIT --state-dir IS TAKEN VERBATIM, and that is what makes a moved
// vault recoverable: the default name is a hash of the vault's path, so after a
// rename the old key sits under the old hash. Keying the override too would
// promise a recovery that cannot work.
TEST(VaultState, AnExplicitStateDirIsUsedAsGiven) {
  EXPECT_EQ(cmdstate::StateDirFor("/tmp/vault-one", "/somewhere/else"),
            "/somewhere/else");
  EXPECT_EQ(cmdstate::StateDirFor("/tmp/vault-two", "/somewhere/else"),
            "/somewhere/else");
}

TEST(VaultState, AMissingIdentityIsReportedRatherThanInvented) {
  TempDir dir;
  ASSERT_FALSE(dir.path().empty());
  DeviceKeyPair d;
  EXPECT_EQ(cmdstate::LoadDeviceKeys(dir.path(), &d),
            cmdstate::DeviceKeyStatus::kMissing);

  // RequireDeviceKeys must not create one. A fresh identity is indistinguishable
  // from a stranger to every other device in the vault, so guessing is worse
  // than failing.
  EXPECT_FALSE(
      cmdstate::RequireDeviceKeys("/tmp/no-such-vault", dir.path(), &d))
      << "an identity was invented for a machine that has none";
  EXPECT_EQ(cmdstate::LoadDeviceKeys(dir.path(), &d),
            cmdstate::DeviceKeyStatus::kMissing)
      << "RequireDeviceKeys wrote a key it was not allowed to write";
}

TEST(VaultState, ACreatedIdentityIsStableAndPrivate) {
  TempDir dir;
  ASSERT_FALSE(dir.path().empty());
  DeviceKeyPair made;
  ASSERT_TRUE(cmdstate::CreateDeviceKeys(dir.path(), &made));

  DeviceKeyPair loaded;
  ASSERT_EQ(cmdstate::LoadDeviceKeys(dir.path(), &loaded),
            cmdstate::DeviceKeyStatus::kOk);
  EXPECT_EQ(made.Replica(), loaded.Replica())
      << "the identity changed between writing and reading it";

  // Reloading must not reissue: a device that changed identity on restart would
  // be a new device to every peer.
  DeviceKeyPair again;
  ASSERT_EQ(cmdstate::LoadDeviceKeys(dir.path(), &again),
            cmdstate::DeviceKeyStatus::kOk);
  EXPECT_EQ(made.Replica(), again.Replica());

  struct stat st;
  ASSERT_EQ(::stat((dir.path() + "/device").c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600)
      << "a private key was written world- or group-readable";
}

}  // namespace
}  // namespace umbra
