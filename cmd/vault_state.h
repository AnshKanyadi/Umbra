// The on-disk state that makes a folder a vault, and the keys that open it.
//
// WHY THIS IS SHARED RATHER THAN COPIED. umbra_ai used to derive its own keys
// from a passphrase constant in the source with a fixed salt, because it began
// life as a benchmark driver with no vault to read keys from. That made every
// index it wrote openable by anyone holding the binary -- the opposite of the
// project's claim -- and it stayed true the moment the driver was pointed at
// real notes. One copy of this code, used by both binaries, is what stops the
// two drifting apart again.
//
// Everything here reads and writes `<vault>/.umbra/`. Where that directory
// should live is a separate question; see docs/USING.md.
#ifndef UMBRA_CMD_VAULT_STATE_H_
#define UMBRA_CMD_VAULT_STATE_H_

#include <cstdint>
#include <map>
#include <string>

#include "umbra/crypto/keys.h"

namespace umbra {
namespace cmdstate {

// Plain file helpers, shared so the two binaries cannot disagree about what
// writing a key file means. WriteWholeFile is atomic via rename.
bool ReadWholeFile(const std::string& path, std::string* out);
bool WriteWholeFile(const std::string& path, const std::string& body);
bool MakeDirs(const std::string& path);

// `<vault>/.umbra/salt`, created on first use and then VAULT-WIDE: the
// enrolment grant carries it (sync/enroll.h:81, which notes an Argon2id salt is
// public by construction), so every device in a vault derives the same root and
// computes the same vault id. A joining device is told the id anyway, because
// it needs one before it has been granted anything.
std::array<uint8_t, kSaltBytes> LoadOrCreateSalt(const std::string& dir);

// `<vault>/.umbra/epochs`: epoch(4 BE) || length(4 BE) || wrapped, repeated.
//
// THE EPOCH KEYS ARE RANDOM AND MUST BE KEPT. keys.h explains why they are not
// derived from the root: a removed device knows the root, so a derived future
// key would still be computable by it and revocation would mean nothing. The
// consequence is that they have to be stored, and the storage is the
// wrap-under-root that keys.h already provides -- which is also what makes
// passphrase-only recovery work when every device is gone.
bool LoadEpochWraps(const std::string& dir, std::map<Epoch, std::string>* out);
bool SaveEpochWraps(const std::string& dir,
                    const std::map<Epoch, std::string>& wraps);
bool SaveEpochWrap(const std::string& dir, const VaultKeys& keys, Epoch e);

// ---------------------------------------------------------------- identity
//
// THE DEVICE KEY DOES NOT LIVE IN THE VAULT, AND IT IS THE ONLY FILE THAT MOVED.
//
// `.umbra/` holds four things and exactly one of them is a plaintext secret:
// `salt` is public by construction, `epochs` is wrapped under a root only the
// passphrase derives, `log/` is sealed, and `device` is a raw X25519 private
// key. A vault folder is the sort of thing iCloud or Obsidian Sync watches, so
// that one file is a leak path for the material the whole design protects --
// and copying a vault clones the identity, which is how two "devices" in an
// earlier end-to-end test turned out to be one.
//
// Salt and epoch wraps stay in the vault deliberately. They are what makes
// passphrase-only recovery work when every device is gone, and a user who backs
// up the vault folder must not silently stop backing up their ability to
// recover it.
//
// FUTURE WORK, BEHIND THIS SAME SEAM: the macOS Keychain is the right home for
// a private key and would make the identity survive a vault rename, which this
// scheme does not. It is platform-specific and a real dependency, so it belongs
// as another implementation of StateDirFor/LoadDeviceKeys rather than instead
// of them.

// Where this machine keeps its state for one vault: a directory named for the
// vault's resolved path, under a root that is per-user rather than per-vault.
//
// An explicit override is that directory itself, taken verbatim, because that
// is what lets a moved vault be pointed back at the identity it already had.
// The default keying is what keeps one identity per vault.
std::string StateDirFor(const std::string& vault,
                        const std::string& override_dir);

enum class DeviceKeyStatus : uint8_t {
  kOk,
  kMissing,     // this machine has no identity for this vault
  kUnreadable,  // it has one and it is the wrong size or unopenable
};

DeviceKeyStatus LoadDeviceKeys(const std::string& state_dir,
                               DeviceKeyPair* out);

// Mints one. Only two callers may: creating a vault and joining one. Everything
// else must fail instead, because a fresh identity is indistinguishable from a
// stranger to every other device in the vault.
bool CreateDeviceKeys(const std::string& state_dir, DeviceKeyPair* out);

// Moves a pre-existing `<vault>/.umbra/device` to the state directory, once.
// Not minting: it preserves the identity a vault already had, and takes the
// secret out of the synced folder, which is the point. Returns true if it moved
// one, and prints what it did.
bool AdoptLegacyDeviceKey(const std::string& vault,
                          const std::string& state_dir);

// Loads the identity, adopting a legacy one if that is what is there. On a miss
// it prints the explanation below and returns false. It never mints.
bool RequireDeviceKeys(const std::string& vault, const std::string& state_dir,
                       DeviceKeyPair* out);

// What a user sees when this machine has no identity for this vault. It has to
// carry its weight: the reflex on reading it is that the vault is broken.
void ExplainMissingIdentity(const std::string& vault,
                            const std::string& state_dir);

// The passphrase, from a file, the environment, or a prompt with echo off.
// Never from an argument vector: that is visible in `ps` and in shell history.
bool ReadPassphraseFromFile(const std::string& path, std::string* out);
bool PromptForPassphrase(const std::string& label, std::string* out);

// The three in the documented order: --pass-file, then UMBRA_PASSPHRASE, then a
// prompt. Prints its own diagnosis and returns false if none of them yield one.
bool ResolvePassphrase(const std::string& pass_file, std::string* out);

// Open an existing vault's keys. Fails, rather than creating anything, when the
// folder is not a vault yet -- a caller that wanted to make one should say so.
enum class OpenVaultStatus : uint8_t {
  kOk,
  kNotAVault,  // no .umbra/epochs: nothing has created this vault
  kWrongPassphrase,
};

OpenVaultStatus OpenVaultKeys(const std::string& dir, const std::string& pass,
                              VaultKeys* out);

const char* OpenVaultStatusName(OpenVaultStatus s);

}  // namespace cmdstate
}  // namespace umbra

#endif  // UMBRA_CMD_VAULT_STATE_H_
