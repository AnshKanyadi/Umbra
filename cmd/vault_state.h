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

// `<vault>/.umbra/salt`, created on first use. The salt is per device, not per
// vault: two devices deriving different roots is fine and expected, because
// epoch keys travel by enrolment sealed to a device key rather than by being
// derived from a shared root. Only the vault id is derived from the root, and a
// joining device is told that rather than computing it.
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

// `<vault>/.umbra/device`, mode 0600. This device's identity, which is not
// where its index happens to live.
DeviceKeyPair LoadOrCreateDeviceKeys(const std::string& dir);

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
