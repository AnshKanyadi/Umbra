#include "vault_state.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
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

DeviceKeyPair LoadOrCreateDeviceKeys(const std::string& dir) {
  const std::string path = dir + "/.umbra/device";
  std::string existing;
  DeviceKeyPair d;
  if (ReadWholeFile(path, &existing) &&
      existing.size() == kPublicKeyBytes + SecretKey::size()) {
    std::memcpy(d.public_key.data(), existing.data(), kPublicKeyBytes);
    std::memcpy(d.secret_key.data(), existing.data() + kPublicKeyBytes,
                SecretKey::size());
    return d;
  }
  d = NewDeviceKeyPair();
  (void)MakeDirs(dir + "/.umbra");
  std::string bytes;
  bytes.append(reinterpret_cast<const char*>(d.public_key.data()),
               kPublicKeyBytes);
  bytes.append(reinterpret_cast<const char*>(d.secret_key.data()),
               SecretKey::size());
  (void)WriteWholeFile(path, bytes);
  // The secret half of a device identity. Not 0644.
  (void)::chmod(path.c_str(), 0600);
  return d;
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
