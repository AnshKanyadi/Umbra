#include "vault_state.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sodium.h>
#include <iostream>

namespace umbra {
namespace cmdstate {
namespace {
class EchoOff {
 public:
  explicit EchoOff(int fd) : fd_(fd) {
    if (::tcgetattr(fd_, &saved_) != 0) return;
    ok_ = true;
    struct termios quiet = saved_;
    quiet.c_lflag = static_cast<tcflag_t>(quiet.c_lflag & ~ECHO);
    (void)::tcsetattr(fd_, TCSAFLUSH, &quiet);
  }
  ~EchoOff() {
    if (ok_) (void)::tcsetattr(fd_, TCSAFLUSH, &saved_);
  }
  EchoOff(const EchoOff&) = delete;
  EchoOff& operator=(const EchoOff&) = delete;

 private:
  int fd_;
  bool ok_ = false;
  struct termios saved_{};
};
}  // namespace

bool ReadWholeFile(const std::string& path, std::string* out) {
  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) return false;
  out->clear();
  char buf[65536];
  for (;;) {
    const ssize_t r = ::read(fd, buf, sizeof(buf));
    if (r == 0) break;
    if (r < 0) {
      ::close(fd);
      return false;
    }
    out->append(buf, static_cast<std::size_t>(r));
  }
  ::close(fd);
  return true;
}

bool MakeDirs(const std::string& path) {
  std::string acc;
  std::size_t i = 0;
  while (i <= path.size()) {
    if (i == path.size() || path[i] == '/') {
      if (!acc.empty() && ::mkdir(acc.c_str(), 0755) != 0 && errno != EEXIST) {
        return false;
      }
    }
    if (i < path.size()) acc.push_back(path[i]);
    ++i;
  }
  return true;
}

bool WriteWholeFile(const std::string& path, const std::string& body) {
  const std::size_t slash = path.rfind('/');
  if (slash != std::string::npos && !MakeDirs(path.substr(0, slash))) {
    return false;
  }
  // Write to a temp file and rename, so a reader never sees a half-written
  // note -- the same discipline the watcher expects of an editor.
  const std::string tmp = path + ".umbra-tmp";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return false;
  std::size_t sent = 0;
  while (sent < body.size()) {
    const ssize_t w = ::write(fd, body.data() + sent, body.size() - sent);
    if (w < 0) {
      ::close(fd);
      return false;
    }
    sent += static_cast<std::size_t>(w);
  }
  ::close(fd);
  return ::rename(tmp.c_str(), path.c_str()) == 0;
}

std::array<uint8_t, kSaltBytes> LoadOrCreateSalt(const std::string& dir) {
  const std::string path = dir + "/.umbra/salt";
  std::string existing;
  std::array<uint8_t, kSaltBytes> salt{};
  if (ReadWholeFile(path, &existing) && existing.size() == kSaltBytes) {
    std::memcpy(salt.data(), existing.data(), kSaltBytes);
    return salt;
  }
  salt = NewSalt();
  (void)MakeDirs(dir + "/.umbra");
  (void)WriteWholeFile(
      path,
      std::string(reinterpret_cast<const char*>(salt.data()), kSaltBytes));
  return salt;
}

bool LoadEpochWraps(const std::string& dir, std::map<Epoch, std::string>* out) {
  std::string bytes;
  if (!ReadWholeFile(dir + "/.umbra/epochs", &bytes)) return false;
  std::size_t off = 0;
  while (off + 8 <= bytes.size()) {
    uint32_t e = 0;
    uint32_t n = 0;
    for (int i = 0; i < 4; ++i)
      e = (e << 8) | static_cast<uint8_t>(bytes[off + i]);
    for (int i = 0; i < 4; ++i)
      n = (n << 8) | static_cast<uint8_t>(bytes[off + 4 + i]);
    off += 8;
    if (n > bytes.size() - off) return false;
    (*out)[e] = bytes.substr(off, n);
    off += n;
  }
  return off == bytes.size() && !out->empty();
}

bool SaveEpochWraps(const std::string& dir,
                    const std::map<Epoch, std::string>& wraps) {
  std::string bytes;
  for (const std::pair<const Epoch, std::string>& kv : wraps) {
    for (int i = 3; i >= 0; --i)
      bytes.push_back(static_cast<char>((kv.first >> (i * 8)) & 0xFF));
    const uint32_t n = static_cast<uint32_t>(kv.second.size());
    for (int i = 3; i >= 0; --i)
      bytes.push_back(static_cast<char>((n >> (i * 8)) & 0xFF));
    bytes.append(kv.second);
  }
  return WriteWholeFile(dir + "/.umbra/epochs", bytes);
}

bool SaveEpochWrap(const std::string& dir, const VaultKeys& keys, Epoch e) {
  std::map<Epoch, std::string> wraps;
  (void)LoadEpochWraps(dir, &wraps);
  CryptoStatus st = CryptoStatus::kOk;
  const std::string w = keys.WrapEpochToRoot(e, &st);
  if (st != CryptoStatus::kOk) {
    std::fprintf(stderr, "cannot wrap the epoch key\n");
    return false;
  }
  wraps[e] = w;
  if (!SaveEpochWraps(dir, wraps)) {
    std::fprintf(stderr, "cannot write the epoch keys\n");
    return false;
  }
  return true;
}

namespace {

std::string DefaultStateRoot() {
  const char* home = std::getenv("HOME");
  const std::string h = (home != nullptr && *home != '\0') ? home : ".";
#if defined(__APPLE__)
  return h + "/Library/Application Support/Umbra";
#else
  const char* xdg = std::getenv("XDG_STATE_HOME");
  if (xdg != nullptr && *xdg != '\0') return std::string(xdg) + "/umbra";
  return h + "/.local/state/umbra";
#endif
}

// The vault's resolved path, so a symlink and its target are one vault rather
// than two identities. A path that does not resolve is used as given: the
// caller is about to fail on it for a better reason than this.
std::string ResolvedPath(const std::string& path) {
  char buf[4096];
  if (::realpath(path.c_str(), buf) != nullptr) return std::string(buf);
  return path;
}

std::string DeviceKeyPath(const std::string& state_dir) {
  return state_dir + "/device";
}

}  // namespace

std::string StateDirFor(const std::string& vault,
                        const std::string& override_dir) {
  // AN EXPLICIT --state-dir IS THE DIRECTORY ITSELF, not a root to key under.
  //
  // It was a root at first, and that made the recovery this scheme promises
  // impossible: the per-vault name is a hash of the vault's path, so after a
  // rename the old identity sits under the OLD hash and no root override finds
  // it. Taking the path verbatim is what lets someone who moved a vault point
  // at the identity it already had.
  //
  // The one-identity-per-vault invariant is kept by the DEFAULT keying. Pointing
  // two vaults at one directory on purpose is now possible, and is a choice
  // rather than an accident -- one physical device holding one identity across
  // two vaults is coherent, unlike two devices sharing one.
  if (!override_dir.empty()) return override_dir;
  const std::string root = DefaultStateRoot();
  const std::string resolved = ResolvedPath(vault);
  uint8_t digest[16];
  crypto_generichash(digest, sizeof(digest),
                     reinterpret_cast<const unsigned char*>(resolved.data()),
                     resolved.size(), nullptr, 0);
  std::string hex;
  for (unsigned char b : digest) {
    static const char* kHex = "0123456789abcdef";
    hex.push_back(kHex[b >> 4]);
    hex.push_back(kHex[b & 0x0F]);
  }
  return root + "/devices/" + hex;
}

DeviceKeyStatus LoadDeviceKeys(const std::string& state_dir,
                               DeviceKeyPair* out) {
  std::string bytes;
  if (!ReadWholeFile(DeviceKeyPath(state_dir), &bytes)) {
    return DeviceKeyStatus::kMissing;
  }
  if (bytes.size() != kPublicKeyBytes + SecretKey::size()) {
    return DeviceKeyStatus::kUnreadable;
  }
  std::memcpy(out->public_key.data(), bytes.data(), kPublicKeyBytes);
  std::memcpy(out->secret_key.data(), bytes.data() + kPublicKeyBytes,
              SecretKey::size());
  return DeviceKeyStatus::kOk;
}

namespace {

bool WriteDeviceKey(const std::string& state_dir, const DeviceKeyPair& d) {
  if (!MakeDirs(state_dir)) return false;
  std::string bytes;
  bytes.append(reinterpret_cast<const char*>(d.public_key.data()),
               kPublicKeyBytes);
  bytes.append(reinterpret_cast<const char*>(d.secret_key.data()),
               SecretKey::size());
  const std::string path = DeviceKeyPath(state_dir);
  if (!WriteWholeFile(path, bytes)) return false;
  // The secret half of a device identity. Not 0644.
  return ::chmod(path.c_str(), 0600) == 0;
}

}  // namespace

bool CreateDeviceKeys(const std::string& state_dir, DeviceKeyPair* out) {
  *out = NewDeviceKeyPair();
  if (!WriteDeviceKey(state_dir, *out)) {
    std::fprintf(stderr, "cannot write the device key under %s\n",
                 state_dir.c_str());
    return false;
  }
  return true;
}

bool AdoptLegacyDeviceKey(const std::string& vault,
                          const std::string& state_dir) {
  const std::string legacy = vault + "/.umbra/device";
  std::string bytes;
  if (!ReadWholeFile(legacy, &bytes)) return false;
  if (bytes.size() != kPublicKeyBytes + SecretKey::size()) return false;

  DeviceKeyPair d;
  std::memcpy(d.public_key.data(), bytes.data(), kPublicKeyBytes);
  std::memcpy(d.secret_key.data(), bytes.data() + kPublicKeyBytes,
              SecretKey::size());
  if (!WriteDeviceKey(state_dir, d)) {
    std::fprintf(stderr,
                 "found a device key in the vault but cannot write it to %s. "
                 "Leaving it where it is.\n",
                 state_dir.c_str());
    return false;
  }
  // COPIED FIRST, THEN REMOVED. The other order loses the identity if the write
  // fails, and the identity is the thing that cannot be regenerated.
  if (::unlink(legacy.c_str()) != 0) {
    std::fprintf(stderr,
                 "moved this device's key to %s but could not remove the copy "
                 "at %s -- delete it by hand; a private key in a synced folder "
                 "is what this move exists to avoid.\n",
                 state_dir.c_str(), legacy.c_str());
    return true;
  }
  std::printf(
      "moved this device's key out of the vault, to\n"
      "  %s\n"
      "A vault folder is often synced, and that file is the one plaintext "
      "secret in it.\n",
      state_dir.c_str());
  return true;
}

void ExplainMissingIdentity(const std::string& vault,
                            const std::string& state_dir) {
  std::fprintf(
      stderr,
      "no device identity on this machine for the vault at\n"
      "  %s\n"
      "\n"
      "NOTHING IS LOST AND THE VAULT IS NOT DAMAGED. Its notes, its keys and\n"
      "its history are exactly where they were, and your passphrase still\n"
      "decrypts all of it. What is missing is only this machine's membership\n"
      "of the vault -- a private key, held outside the vault folder on\n"
      "purpose, because that folder is often synced and a copied key would\n"
      "make two machines into one device.\n"
      "\n"
      "Umbra will not act on the vault from this machine until it has one.\n"
      "That is a refusal to guess rather than a failure: everything Umbra\n"
      "writes is signed by this identity, and inventing a new one would sign\n"
      "as a device the vault has never admitted. No other device would trust\n"
      "it and this one could not read what it had been sent.\n"
      "\n"
      "The key belongs here:\n"
      "  %s\n"
      "and that directory has none. Most often the vault was moved or renamed\n"
      "since it was enrolled, or this is a new machine, or the state\n"
      "directory was not carried over.\n"
      "\n"
      "IF YOU MOVED OR RENAMED THE VAULT and still have the old state\n"
      "directory, point at it and nothing needs re-enrolling:\n"
      "  --state-dir PATH\n"
      "\n"
      "OTHERWISE enrol this machine from a device already in the vault:\n"
      "  umbra_sync --dir %s --pass-file FILE --enrol --vault VAULT_ID\n"
      "and approve it there. Enrolling makes a new identity, which is the\n"
      "one command allowed to.\n",
      vault.c_str(), state_dir.c_str(), vault.c_str());
}

bool RequireDeviceKeys(const std::string& vault, const std::string& state_dir,
                       DeviceKeyPair* out) {
  DeviceKeyStatus st = LoadDeviceKeys(state_dir, out);
  if (st == DeviceKeyStatus::kMissing &&
      AdoptLegacyDeviceKey(vault, state_dir)) {
    st = LoadDeviceKeys(state_dir, out);
  }
  if (st == DeviceKeyStatus::kOk) return true;
  if (st == DeviceKeyStatus::kUnreadable) {
    std::fprintf(stderr,
                 "the device key at %s/device is not a device key. Refusing to "
                 "replace it: if it is the only copy, a new one is a new "
                 "device and this one can no longer read what it was sent.\n",
                 state_dir.c_str());
    return false;
  }
  ExplainMissingIdentity(vault, state_dir);
  return false;
}

bool ReadPassphraseFromFile(const std::string& path, std::string* out) {
  std::string bytes;
  if (!ReadWholeFile(path, &bytes)) {
    std::fprintf(stderr, "cannot read the passphrase file %s\n", path.c_str());
    return false;
  }
  const std::string::size_type nl = bytes.find('\n');
  *out = (nl == std::string::npos) ? bytes : bytes.substr(0, nl);
  if (!out->empty() && out->back() == '\r') out->pop_back();
  if (out->empty()) {
    std::fprintf(stderr, "the passphrase file %s is empty\n", path.c_str());
    return false;
  }
  return true;
}

bool PromptForPassphrase(const std::string& label, std::string* out) {
  if (::isatty(STDIN_FILENO) == 0) {
    std::fprintf(stderr,
                 "no terminal to prompt on. Use --pass-file PATH or set "
                 "UMBRA_PASSPHRASE.\n");
    return false;
  }
  std::fprintf(stderr, "%s", label.c_str());
  std::fflush(stderr);
  std::string line;
  {
    EchoOff quiet(STDIN_FILENO);
    if (!std::getline(std::cin, line)) {
      std::fprintf(stderr, "\n");
      return false;
    }
  }
  std::fprintf(stderr, "\n");
  if (!line.empty() && line.back() == '\r') line.pop_back();
  if (line.empty()) {
    std::fprintf(stderr, "empty passphrase\n");
    return false;
  }
  out->swap(line);
  return true;
}

bool ResolvePassphrase(const std::string& pass_file, std::string* out) {
  if (!pass_file.empty()) return ReadPassphraseFromFile(pass_file, out);
  const char* from_env = std::getenv("UMBRA_PASSPHRASE");
  if (from_env != nullptr && *from_env != '\0') {
    *out = from_env;
    return true;
  }
  return PromptForPassphrase("vault passphrase: ", out);
}

OpenVaultStatus OpenVaultKeys(const std::string& dir, const std::string& pass,
                              VaultKeys* out) {
  // The salt is read, not created: creating one here would silently derive a
  // different root and report a wrong passphrase for a vault that is simply not
  // there yet.
  std::string salt_bytes;
  std::array<uint8_t, kSaltBytes> salt{};
  if (!ReadWholeFile(dir + "/.umbra/salt", &salt_bytes) ||
      salt_bytes.size() != kSaltBytes) {
    return OpenVaultStatus::kNotAVault;
  }
  std::memcpy(salt.data(), salt_bytes.data(), kSaltBytes);

  std::map<Epoch, std::string> wrapped;
  if (!LoadEpochWraps(dir, &wrapped)) return OpenVaultStatus::kNotAVault;
  if (VaultKeys::RecoverFromPassphrase(pass, salt, Argon2idParams::Default(),
                                       wrapped, out) != CryptoStatus::kOk) {
    return OpenVaultStatus::kWrongPassphrase;
  }
  return OpenVaultStatus::kOk;
}

const char* OpenVaultStatusName(OpenVaultStatus s) {
  switch (s) {
    case OpenVaultStatus::kOk:
      return "ok";
    case OpenVaultStatus::kNotAVault:
      return "not-a-vault";
    case OpenVaultStatus::kWrongPassphrase:
      return "wrong-passphrase";
  }
  return "unknown";
}

}  // namespace cmdstate
}  // namespace umbra
