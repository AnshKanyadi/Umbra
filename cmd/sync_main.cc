// A vault client.
//
//     umbra_sync --dir ~/notes --relay 127.0.0.1:9000 --pass-file ~/.umbra-pass --once
//
// Scans a folder of markdown files, turns what changed into operations, pushes
// them to a relay, pulls what other devices pushed, and writes the merged result
// back to the folder. One shot by default; --watch loops.
//
// The passphrase on the command line is fine for a test harness and wrong for a
// person -- it lands in shell history and in ps output. A real client reads it
// from a prompt or a keychain; this is a tool for driving the system end to end,
// and saying so is better than pretending otherwise.
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "scan.h"
#include "umbra/crdt/oplog.h"
#include "umbra/crdt/tree.h"
#include "umbra/crdt/vault.h"
#include "umbra/sync/client.h"
#include "umbra/sync/enroll.h"
#include "vault_state.h"

namespace {

// The vault state helpers now live in one place, shared with umbra_ai so the
// two cannot derive different keys for the same vault. See cmd/vault_state.h.
using ::umbra::cmdstate::LoadEpochWraps;
using ::umbra::cmdstate::LoadOrCreateSalt;
using ::umbra::cmdstate::MakeDirs;
using ::umbra::cmdstate::PromptForPassphrase;
using ::umbra::cmdstate::ReadPassphraseFromFile;
using ::umbra::cmdstate::ReadWholeFile;
using ::umbra::cmdstate::SaveEpochWrap;
using ::umbra::cmdstate::SaveEpochWraps;
using ::umbra::cmdstate::WriteWholeFile;

using namespace umbra;

// Every .md file under the vault, vault-relative.
void ListVault(const std::string& root, std::vector<std::string>* out) {
  WalkSubtree(root, std::string(),
              [&](const std::string& rel, const FileState& st) {
                if (st.is_dir || rel.empty()) return;
                if (rel.compare(0, 7, ".umbra/") == 0) return;  // our own state
                if (!IsVaultFile(rel)) return;
                out->push_back(rel);
              });
}

// A stable replica id for a vault directory, so restarting the client does not
// look like a new device.
// Rebuild a vault from everything the log holds.
//
// OUT OF ORDER IS NORMAL, NOT AN ERROR. The oplog is keyed by
// object||replica||counter, so iteration is grouped by replica: every operation
// from A, then every operation from B. An insert of B's whose parent is a later
// operation of A's therefore arrives before its parent and comes back
// kNotReady, which text_doc.h says the caller must hold and retry. A loop that
// drops those replays a DIFFERENT document than the one in memory, and the
// client then "corrects" the file on disk to match -- which is how a line came
// to appear twice and why both devices produced new operations every round
// without ever settling.
//
// So: keep passing over the pending set until a pass applies nothing.
void RebuildFromLog(OpLog* log, Vault* v) {
  std::vector<TreeOp> tree_ops;
  (void)log->ReadTree(&tree_ops);
  // The move operation is order-independent by construction (undo, do, redo),
  // so the tree needs no retry pass. See docs/adr/0003-tree.md.
  for (const TreeOp& op : tree_ops) (void)v->ApplyTreeOp(op);

  for (const std::pair<std::string, ObjectId>& kv : v->tree().Listing()) {
    if (v->tree().IsDir(kv.second)) continue;
    std::vector<Op> pending;
    if (log->ReadObject(kv.second, &pending) != LogStatus::kOk) continue;
    for (;;) {
      std::vector<Op> again;
      std::size_t applied = 0;
      for (const Op& op : pending) {
        const ApplyResult r = v->ApplyOp(kv.second, op);
        if (r == ApplyResult::kApplied || r == ApplyResult::kDuplicate) {
          ++applied;
        } else if (r == ApplyResult::kNotReady) {
          again.push_back(op);
        }
      }
      if (again.empty() || applied == 0) break;
      pending.swap(again);
    }
  }
}

// READING THE PASSPHRASE.
//
// It used to come from --pass, which puts the key to the whole vault in the
// shell history, in `ps` output for every other user on the machine, and in any
// shell tracing that happens to be on. That is a security defect in a security
// product, and the fact that it was convenient for driving tests is not a
// reason to ship it.
//
// Three sources, in the order a person would expect:
//
//   --pass-file PATH   read it from a file, first line, newline stripped
//   UMBRA_PASSPHRASE   read it from the environment
//   (neither)          prompt on the terminal with echo off
//
// A file is the one that scripts should use: it has an owner and a mode, unlike
// an argument vector. The environment variable is there because containers and
// service managers have no other sane channel; it is still visible to anything
// that can read /proc/<pid>/environ on Linux, so it is documented as the weaker
// option rather than presented as equivalent.
//
// THE PROMPT TURNS ECHO OFF AND PUTS IT BACK, including when it is interrupted.
// A prompt that leaves a terminal with echo disabled after a Ctrl-C is a bug
// people remember.

// Restores the terminal on the way out however the scope is left.

// What the user asked this run to do.
enum class Mode { kSync, kCreate, kEnrol, kApprove, kRevoke };

// Epoch keys, each wrapped under the root. The file is a sequence of
// epoch(4 BE) || length(4 BE) || wrapped.

// WHO THIS DEVICE HAS LET IN, kept locally.
//
// The obvious place to look is the relay: every grant envelope names the device
// it was sealed to. But the relay controls that list. It can hide a grant, and
// worse, it can REPLAY one -- so a revocation that reads its device list from
// the relay can be made to seal the new epoch key to the very device the user
// just removed. The list has to come from somewhere the relay cannot write.
//
// This device approved these devices, so this device knows. The file is a
// sequence of 32-byte public keys.
std::vector<std::array<uint8_t, kPublicKeyBytes>> LoadRoster(
    const std::string& dir) {
  std::vector<std::array<uint8_t, kPublicKeyBytes>> out;
  std::string bytes;
  if (!ReadWholeFile(dir + "/.umbra/enrolled", &bytes)) return out;
  for (std::size_t off = 0; off + kPublicKeyBytes <= bytes.size();
       off += kPublicKeyBytes) {
    std::array<uint8_t, kPublicKeyBytes> k{};
    std::memcpy(k.data(), bytes.data() + off, kPublicKeyBytes);
    out.push_back(k);
  }
  return out;
}

bool SaveRoster(const std::string& dir,
                const std::vector<std::array<uint8_t, kPublicKeyBytes>>& r) {
  std::string bytes;
  for (const std::array<uint8_t, kPublicKeyBytes>& k : r) {
    bytes.append(reinterpret_cast<const char*>(k.data()), k.size());
  }
  return WriteWholeFile(dir + "/.umbra/enrolled", bytes);
}

// The tag an envelope is filed under. A request is filed under the joining
// device's public key; a grant under the same key with the high bit of the
// first byte flipped, so the two never collide and the relay still sees only
// opaque bytes.
std::array<uint8_t, 32> RequestTag(
    const std::array<uint8_t, kPublicKeyBytes>& pub) {
  std::array<uint8_t, 32> t{};
  std::memcpy(t.data(), pub.data(), 32);
  return t;
}

std::array<uint8_t, 32> GrantTag(
    const std::array<uint8_t, kPublicKeyBytes>& pub) {
  std::array<uint8_t, 32> t = RequestTag(pub);
  t[0] = static_cast<uint8_t>(t[0] ^ 0x80);
  return t;
}

double SecondsSince(const std::chrono::steady_clock::time_point& t) {
  return std::chrono::duration_cast<std::chrono::duration<double>>(
             std::chrono::steady_clock::now() - t)
      .count();
}

void Usage() {
  std::fprintf(
      stderr,
      "umbra_sync --dir PATH --relay HOST:PORT [--pass-file PATH]\n"
      "           [--create | --enrol | --approve DEVICE | --revoke DEVICE]\n"
      "           [--vault HEX] [--code NNNNNN] [--once | --watch]\n"
      "           [--state-dir PATH]\n"
      "           [--interval SECONDS] [-v]\n"
      "\n"
      "  --create   start a new vault in this folder\n"
      "  --enrol    ask an existing device to let this one in, then\n"
      "             --enrol --code NNNNNN once it has answered\n"
      "  --approve  let a device in, after comparing its pairing code\n"
      "  --revoke   rotate the vault key away from a device\n"
      "\n"
      "Enrolment is two steps and one comparison. On the joining device\n"
      "run --enrol; it prints a six digit code. On a device already in\n"
      "the vault run --approve DEVICE --code NNNNNN with the digits the\n"
      "joining device showed. If they do not match, something is between\n"
      "you and the relay: do not approve.\n"
      "\n"
      "The passphrase comes from --pass-file PATH, or the environment\n"
      "variable UMBRA_PASSPHRASE, or a prompt with echo off. It is never\n"
      "taken from the command line: an argument vector is visible in shell\n"
      "history and in ps.\n");
}

}  // namespace

int main(int argc, char** argv) {
  std::string dir;
  std::string relay = "127.0.0.1:9000";
  // Taken verbatim when given: this is the directory holding this machine's
  // key for this vault, which is how a moved vault is pointed back at its own.
  std::string state_dir_override;
  std::string pass;
  Mode mode = Mode::kSync;
  std::string target;
  std::string typed_code;
  std::string vault_hex;
  std::string pass_file;
  bool watch = false;
  int interval = 2;
  bool verbose = false;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    const char* next = (i + 1 < argc) ? argv[i + 1] : nullptr;
    if (a == "--dir" && next) {
      dir = next;
      ++i;
    } else if (a == "--state-dir" && next) {
      state_dir_override = next;
      ++i;
    } else if (a == "--relay" && next) {
      relay = next;
      ++i;
    } else if (a == "--pass-file" && next) {
      pass_file = next;
      ++i;
    } else if (a == "--pass" && next) {
      std::fprintf(stderr,
                   "--pass is gone. It put the vault passphrase in your shell "
                   "history and in ps output.\nUse --pass-file PATH, set "
                   "UMBRA_PASSPHRASE, or let it prompt.\n");
      return 2;
    } else if (a == "--create") {
      mode = Mode::kCreate;
    } else if (a == "--enrol" || a == "--enroll") {
      mode = Mode::kEnrol;
    } else if (a == "--approve" && next) {
      mode = Mode::kApprove;
      target = next;
      ++i;
    } else if (a == "--vault" && next) {
      vault_hex = next;
      ++i;
    } else if (a == "--code" && next) {
      typed_code = next;
      ++i;
    } else if (a == "--revoke" && next) {
      mode = Mode::kRevoke;
      target = next;
      ++i;
    } else if (a == "--interval" && next) {
      interval = std::atoi(next);
      ++i;
    } else if (a == "--watch") {
      watch = true;
    } else if (a == "--once") {
      watch = false;
    } else if (a == "-v") {
      verbose = true;
    } else {
      Usage();
      return 2;
    }
  }
  if (dir.empty()) {
    Usage();
    return 2;
  }
  // File, then environment, then prompt. See the note above
  // ReadPassphraseFromFile for why --pass is no longer among them.
  if (!pass_file.empty()) {
    if (!ReadPassphraseFromFile(pass_file, &pass)) return 1;
  } else {
    const char* from_env = std::getenv("UMBRA_PASSPHRASE");
    if (from_env != nullptr && *from_env != '\0') {
      pass = from_env;
    } else if (!PromptForPassphrase("vault passphrase: ", &pass)) {
      return 1;
    }
  }

  const std::size_t colon = relay.rfind(':');
  if (colon == std::string::npos) {
    Usage();
    return 2;
  }
  const std::string host = relay.substr(0, colon);
  const uint16_t port =
      static_cast<uint16_t>(std::atoi(relay.c_str() + colon + 1));

  std::string root;
  if (RealPath(dir, &root) != ReadOutcome::kOk) {
    std::fprintf(stderr, "no such directory: %s\n", dir.c_str());
    return 1;
  }

  const auto key_start = std::chrono::steady_clock::now();
  VaultKeys keys;
  const std::array<uint8_t, kSaltBytes> salt = LoadOrCreateSalt(root);

  // THE EPOCH KEYS ARE RANDOM AND MUST BE KEPT. keys.h explains why they are
  // not derived from the root: a removed device knows the root, so a derived
  // future key would still be computable by it and revocation would mean
  // nothing. The consequence is that they have to be stored, and the storage
  // is the wrap-under-root that keys.h already provides -- which is also what
  // makes passphrase-only recovery work when every device is gone.
  std::map<Epoch, std::string> wrapped;
  const bool have_vault = LoadEpochWraps(root, &wrapped);
  if (have_vault) {
    if (VaultKeys::RecoverFromPassphrase(pass, salt, Argon2idParams::Default(),
                                         wrapped, &keys) != CryptoStatus::kOk) {
      std::fprintf(stderr, "cannot open this vault with that passphrase\n");
      return 1;
    }
  } else if (mode == Mode::kCreate) {
    if (VaultKeys::Create(pass, salt, Argon2idParams::Default(), &keys) !=
        CryptoStatus::kOk) {
      std::fprintf(stderr, "cannot derive the root key (out of memory?)\n");
      return 1;
    }
    if (!SaveEpochWrap(root, keys, keys.current())) return 1;
  } else if (mode == Mode::kEnrol) {
    // A joining device has no epoch key yet. It needs the root to check the
    // passphrase and to wrap what it is given, and nothing else until a grant
    // arrives.
    if (VaultKeys::Create(pass, salt, Argon2idParams::Default(), &keys) !=
        CryptoStatus::kOk) {
      std::fprintf(stderr, "cannot derive the root key (out of memory?)\n");
      return 1;
    }
  } else {
    std::fprintf(stderr,
                 "this folder is not a vault yet. Use --create to start one, "
                 "or --enrol to join one.\n");
    return 1;
  }
  const double key_seconds = SecondsSince(key_start);

  // THE IDENTITY IS MINTED ONLY BY THE TWO COMMANDS THAT MAY MINT ONE.
  //
  // Creating a vault and joining one are the moments a device legitimately
  // becomes a member. Every other mode -- a sync round, --approve, --revoke --
  // is run by a device that is already a member, so a missing key there means
  // something is wrong and a fresh one would silently make this machine a
  // stranger to every other device in the vault. It fails and explains instead.
  const std::string state_dir = cmdstate::StateDirFor(root, state_dir_override);
  DeviceKeyPair device;
  if (mode == Mode::kCreate || mode == Mode::kEnrol) {
    if (cmdstate::LoadDeviceKeys(state_dir, &device) !=
        cmdstate::DeviceKeyStatus::kOk) {
      (void)cmdstate::AdoptLegacyDeviceKey(root, state_dir);
      if (cmdstate::LoadDeviceKeys(state_dir, &device) !=
              cmdstate::DeviceKeyStatus::kOk &&
          !cmdstate::CreateDeviceKeys(state_dir, &device)) {
        return 1;
      }
    }
  } else if (!cmdstate::RequireDeviceKeys(root, state_dir, &device)) {
    return 1;
  }
  // ONE IDENTITY, NOT TWO. keys.h derives the replica id from the public key
  // precisely so a device cannot have a network identity and a CRDT identity
  // that disagree.
  const ReplicaId me = device.Replica();
  relay::VaultId vault;
  {
    // One vault per passphrase: the id is derived from the root key so two
    // directories with the same passphrase land in the same vault without
    // anyone configuring an id.
    const SecretKey vid = DeriveSubkey(keys.root(), 1, "umbVault");
    std::memcpy(vault.bytes.data(), vid.data(), vault.bytes.size());
  }
  // A JOINING DEVICE CANNOT DERIVE THE VAULT ID YET. The id comes from the
  // root key, the root key comes from the passphrase AND the vault's salt, and
  // the salt is what enrolment delivers -- so before enrolling, this device
  // would knock on a vault of its own that nobody else is in. The id is told
  // to it instead. That is not a leak: the relay sees the vault id on every
  // request that has ever been made against it.
  if (!vault_hex.empty()) {
    if (vault_hex.size() != vault.bytes.size() * 2) {
      std::fprintf(stderr, "--vault takes %zu hex characters\n",
                   vault.bytes.size() * 2);
      return 1;
    }
    for (std::size_t i = 0; i < vault.bytes.size(); ++i) {
      unsigned byte = 0;
      if (std::sscanf(vault_hex.c_str() + i * 2, "%2x", &byte) != 1) {
        std::fprintf(stderr, "--vault is not hex\n");
        return 1;
      }
      vault.bytes[i] = static_cast<uint8_t>(byte);
    }
  }
  std::string vault_id_hex;
  {
    static const char kHex[] = "0123456789abcdef";
    for (uint8_t b : vault.bytes) {
      vault_id_hex.push_back(kHex[b >> 4]);
      vault_id_hex.push_back(kHex[b & 0x0F]);
    }
  }

  std::unique_ptr<OpLog> log;
  if (OpLog::OpenEncrypted(root + "/.umbra/log", &keys, &log) !=
      LogStatus::kOk) {
    std::fprintf(stderr, "cannot open the local log\n");
    return 1;
  }
  std::unique_ptr<sync::Transport> transport =
      sync::NewTcpTransport(host, port);
  sync::Client client(vault, me, &keys, log.get(), transport.get());
  // ------------------------------------------------------------- enrolment
  //
  // These modes do one thing and exit. None of them touches the folder.
  if (mode == Mode::kEnrol) {
    sync::EnrollRequest req;
    req.device_public = device.public_key;
    if (client.PublishEnvelope(RequestTag(device.public_key),
                               sync::EncodeEnrollRequest(req)) !=
        sync::SyncStatus::kOk) {
      std::fprintf(stderr, "cannot reach the relay\n");
      return 1;
    }

    // Has anyone answered yet?
    std::vector<relay::Envelope> envelopes;
    if (client.CollectEnvelopes(&envelopes) != sync::SyncStatus::kOk) {
      std::fprintf(stderr, "cannot reach the relay\n");
      return 1;
    }
    const std::array<uint8_t, 32> want = GrantTag(device.public_key);
    for (const relay::Envelope& e : envelopes) {
      if (e.tag != want) continue;
      sync::EnrollGrant g;
      if (!sync::DecodeEnrollGrant(e.body, &g)) continue;
      if (g.to != device.public_key) continue;

      // THE COMPARISON HAPPENS HERE. A relay that put its own key in front of
      // this device sealed the grant itself, so g.from is the relay's key and
      // the code below is not the code the other device displayed. Checked
      // against digits the user typed, so "I looked" and "it matched" cannot
      // come apart.
      const std::string code = sync::PairingCode(g.from, device.public_key);
      const std::string bare = code.substr(0, 3) + code.substr(4);
      if (typed_code.empty()) {
        std::printf(
            "a device answered.\n"
            "  pairing code %s\n"
            "\n"
            "If that is the code the other device showed, run this again "
            "with\n"
            "  --enrol --code %s\n"
            "If it is not, do not enrol: something is between you and the "
            "relay.\n",
            code.c_str(), bare.c_str());
        return 0;
      }
      std::string got;
      for (char c : typed_code) {
        if (c != ' ' && c != '-') got.push_back(c);
      }
      if (got != bare) {
        std::fprintf(stderr,
                     "the code does not match.\n"
                     "  this device computed %s\n"
                     "  you typed             %s\n"
                     "Nothing was enrolled. Either the digits were mistyped, "
                     "or a key was substituted between you and the relay.\n",
                     code.c_str(), typed_code.c_str());
        return 1;
      }
      // ORDER MATTERS HERE, and getting it wrong is silent. The salt travels
      // with the grant because it is vault-level: a device that generated its
      // own is a different vault however identical the passphrase. But the
      // root key is derived from the passphrase AND the salt, and the epoch
      // key is stored wrapped under the root -- so wrapping it before adopting
      // the salt wraps it under a root this device is about to stop having.
      // The first run did exactly that and could not open its own vault on the
      // next invocation.
      //
      // So: adopt the salt, re-derive the root under it, and only then accept
      // and wrap. That costs a second Argon2id pass, once, on the one run that
      // enrols.
      (void)WriteWholeFile(
          root + "/.umbra/salt",
          std::string(reinterpret_cast<const char*>(g.salt.data()),
                      g.salt.size()));
      VaultKeys joined;
      if (VaultKeys::Create(pass, g.salt, Argon2idParams::Default(), &joined) !=
          CryptoStatus::kOk) {
        std::fprintf(stderr, "cannot derive the root key\n");
        return 1;
      }
      if (joined.AcceptSealedEpoch(g.epoch, g.sealed_epoch, device) !=
          CryptoStatus::kOk) {
        std::fprintf(stderr, "the grant does not open for this device\n");
        return 1;
      }
      if (!SaveEpochWrap(root, joined, g.epoch)) return 1;
      std::printf(
          "enrolled at epoch %u.\n"
          "  device %s\n"
          "Run again without --enrol to sync.\n",
          g.epoch, sync::DeviceLabel(me).c_str());
      return 0;
    }

    std::printf(
        "asked to join.\n"
        "  this device %s\n"
        "\n"
        "On a device that is already in the vault, run:\n"
        "  umbra_sync --dir PATH --relay %s --pass-file F --approve %s\n"
        "\n"
        "It will print a six digit code. Come back here with\n"
        "  --enrol --vault %s --code NNNNNN\n"
        "and check the digits match before you type them.\n",
        sync::DeviceLabel(me).c_str(), relay.c_str(),
        sync::DeviceLabel(me).c_str(), vault_id_hex.c_str());
    return 0;
  }

  if (mode == Mode::kApprove) {
    std::vector<relay::Envelope> envelopes;
    if (client.CollectEnvelopes(&envelopes) != sync::SyncStatus::kOk) {
      std::fprintf(stderr, "cannot reach the relay\n");
      return 1;
    }
    for (const relay::Envelope& e : envelopes) {
      sync::EnrollRequest req;
      if (!sync::DecodeEnrollRequest(e.body, &req)) continue;
      if (e.tag != RequestTag(req.device_public)) continue;
      ReplicaId who;
      {
        DeviceKeyPair probe;
        probe.public_key = req.device_public;
        who = probe.Replica();
      }
      if (sync::DeviceLabel(who) != target) continue;

      // THIS DEVICE DISPLAYS; THE JOINING DEVICE CHECKS. Only one of the two
      // can do the checking, and it has to be the one that RECEIVES the
      // grant, because that is where a substituted key would show up. A relay
      // that put its own key in front of this device would be approved here
      // whatever the user typed, and caught there.
      const std::string code =
          sync::PairingCode(device.public_key, req.device_public);

      CryptoStatus st = CryptoStatus::kOk;
      sync::EnrollGrant g;
      g.to = req.device_public;
      g.from = device.public_key;
      g.epoch = keys.current();
      g.salt = salt;
      std::memcpy(g.vault.data(), vault.bytes.data(), g.vault.size());
      g.sealed_epoch = keys.SealEpochToDevice(g.epoch, g.to, &st);
      if (st != CryptoStatus::kOk) {
        std::fprintf(stderr, "cannot seal the epoch key\n");
        return 1;
      }
      if (client.PublishEnvelope(GrantTag(g.to), sync::EncodeEnrollGrant(g)) !=
          sync::SyncStatus::kOk) {
        std::fprintf(stderr, "cannot reach the relay\n");
        return 1;
      }
      {
        std::vector<std::array<uint8_t, kPublicKeyBytes>> roster =
            LoadRoster(root);
        bool known = false;
        for (const std::array<uint8_t, kPublicKeyBytes>& k : roster) {
          if (k == g.to) known = true;
        }
        if (!known) roster.push_back(g.to);
        if (!SaveRoster(root, roster)) {
          std::fprintf(stderr, "cannot record the enrolled device\n");
          return 1;
        }
      }
      std::printf(
          "approved %s at epoch %u.\n"
          "  pairing code %s\n"
          "\n"
          "On that device run:\n"
          "  umbra_sync --dir PATH --relay %s --pass-file F --enrol --code %s\n"
          "It will show the same six digits. If it shows different ones, do\n"
          "not enrol it.\n",
          target.c_str(), g.epoch, code.c_str(), relay.c_str(),
          (code.substr(0, 3) + code.substr(4)).c_str());
      return 0;
    }
    std::fprintf(stderr, "no device %s is asking to join\n", target.c_str());
    return 1;
  }

  if (mode == Mode::kRevoke) {
    // Rotation is the whole mechanism: a new random epoch key, sealed to the
    // devices that remain and not to the one being removed. The list of who
    // remains comes from this device's own record, never from the relay -- see
    // LoadRoster.
    std::vector<std::array<uint8_t, kPublicKeyBytes>> keep;
    bool found = false;
    for (const std::array<uint8_t, kPublicKeyBytes>& pub : LoadRoster(root)) {
      DeviceKeyPair probe;
      probe.public_key = pub;
      if (sync::DeviceLabel(probe.Replica()) == target) {
        found = true;
        continue;
      }
      keep.push_back(pub);
    }
    if (!found) {
      std::fprintf(stderr,
                   "this device did not enrol %s, so it cannot remove it.\n"
                   "Run --revoke on the device that approved it.\n",
                   target.c_str());
      return 1;
    }
    const Epoch next = keys.Rotate();
    if (!SaveEpochWrap(root, keys, next)) return 1;
    if (!SaveRoster(root, keep)) {
      std::fprintf(stderr, "cannot record the remaining devices\n");
      return 1;
    }
    for (const std::array<uint8_t, kPublicKeyBytes>& pub : keep) {
      CryptoStatus st = CryptoStatus::kOk;
      sync::EnrollGrant g;
      g.to = pub;
      g.from = device.public_key;
      g.epoch = next;
      g.salt = salt;
      std::memcpy(g.vault.data(), vault.bytes.data(), g.vault.size());
      g.sealed_epoch = keys.SealEpochToDevice(next, pub, &st);
      if (st != CryptoStatus::kOk) continue;
      (void)client.PublishEnvelope(GrantTag(pub), sync::EncodeEnrollGrant(g));
    }
    // SAY EXACTLY WHAT HAPPENED. The removed device still holds every file it
    // had and every epoch key it was given; what it cannot do is read anything
    // written from now on. Claiming more here would be the easiest place in
    // the whole program to lie.
    //
    // THE COUNT IS SPELLED OUT RATHER THAN PRINTED. "0 device(s) hold it" is
    // both alarming and wrong -- this device holds it -- and "1 device(s)" is
    // the kind of thing that makes a person doubt the rest of the message. In
    // a security flow the sentence a user reads at the moment they remove
    // someone is worth writing out.
    std::printf("revoked %s. The vault is now at epoch %u.\n\n", target.c_str(),
                next);
    if (keep.empty()) {
      std::printf(
          "This device is now the only one that can read new writes.\n");
    } else if (keep.size() == 1) {
      std::printf(
          "This device and one other can read new writes. The other has the\n"
          "new key waiting for it and will pick it up on its next sync.\n");
    } else {
      std::printf(
          "This device and %zu others can read new writes. They have the new\n"
          "key waiting for them and will pick it up on their next sync.\n",
          keep.size());
    }
    std::printf(
        "\n"
        "%s can no longer read anything written from now on.\n"
        "It still has the files it already had, and can still read what was\n"
        "written before this point. Revocation moves writes forward; it does\n"
        "not reach backwards.\n",
        target.c_str());
    // THE ROSTER IS THIS DEVICE'S OWN, so this is the honest place to say what
    // that costs. A device enrolled by some other device is not in this list
    // and has NOT been given the new key: it will stop being able to read new
    // writes without anyone having asked for that. See ADR 0004.
    std::printf(
        "\n"
        "This used the list of devices this one enrolled. Any device enrolled\n"
        "from elsewhere was not given the new key and will stop reading new\n"
        "writes until it is enrolled again.\n");
    return 0;
  }

  std::printf(
      "vault %s\n  id %s\n  device %s\n  relay %s\n  key derivation %.2fs\n",
      root.c_str(), vault_id_hex.c_str(), me.Short().c_str(), relay.c_str(),
      key_seconds);
  std::fflush(stdout);

  int round = 0;
  for (;;) {
    const auto t0 = std::chrono::steady_clock::now();

    // 1. REBUILD THE WORLD ONCE, INTO ONE VAULT, AND KEEP IT FOR THE WHOLE
    // ROUND. An earlier version kept a separate document map filled from the
    // log BEFORE the local edits were appended, then applied the remote
    // operations onto that stale copy and wrote the result to disk. A device
    // therefore erased its own edit every time it pulled: the run where A
    // wrote "- two from A", pushed it, and then overwrote its own file with a
    // version that did not contain it.
    //
    // The vault holds the local edits (ApplyChange applies as it produces) and
    // the remote ones (ApplyOp / ApplyTreeOp below), so there is one document
    // per object and no second copy to fall behind.
    Vault v(me);
    RebuildFromLog(log.get(), &v);

    // 2. What is on disk that the vault does not know about, or differs.
    std::vector<std::string> on_disk;
    ListVault(root, &on_disk);
    std::size_t local_changes = 0;
    for (const std::string& rel : on_disk) {
      std::string body;
      if (!ReadWholeFile(root + "/" + rel, &body)) continue;
      ObjectId id;
      const bool known = v.ObjectAt(rel, &id);
      if (known) {
        const TextDoc* d = v.Doc(id);
        if (d != nullptr && d->Text() == body) continue;
      }
      ChangeEvent e;
      e.kind = known ? ChangeKind::kModified : ChangeKind::kCreated;
      e.path = rel;
      const ChangeOutcome c = v.ApplyChange(e, body);
      if (c.status != VaultOutcome::kOk) {
        if (verbose) {
          std::printf("  skipped %s: %s\n", rel.c_str(),
                      VaultOutcomeName(c.status));
        }
        continue;
      }
      if (!c.tree_ops.empty() && log->AppendTree(c.tree_ops) != LogStatus::kOk)
        return 1;
      if (!c.ops.empty() && log->Append(c.object, c.ops) != LogStatus::kOk)
        return 1;
      local_changes += c.ops.size() + c.tree_ops.size();
    }
    if (local_changes > 0 && log->Sync() != LogStatus::kOk) return 1;

    // 3. Push what we have, then learn who else exists, then pull.
    const auto push_start = std::chrono::steady_clock::now();
    std::size_t pushed = 0;
    std::size_t n = 0;
    // A ROUND THAT REACHED NOBODY IS NOT A QUIET ROUND. Every call below
    // already returned kUnreachable when the relay was gone and every one of
    // them was discarded, so a dead relay printed "0 pushed, 0 applied, 0
    // devices" -- the same line as a vault with nothing to do -- and exited
    // zero. Two containers ran for several minutes against a relay that had
    // crashed, both reporting healthy rounds. Silence about a network failure
    // is the one thing a sync client must not do.
    bool unreachable = false;
    if (client.PushObject(TreeObject(), &n) == sync::SyncStatus::kOk) {
      pushed += n;
    } else {
      unreachable = true;
    }
    for (const std::pair<std::string, ObjectId>& kv : v.tree().Listing()) {
      if (v.tree().IsDir(kv.second)) continue;
      if (client.PushObject(kv.second, &n) == sync::SyncStatus::kOk) {
        pushed += n;
      } else {
        unreachable = true;
      }
    }
    if (client.PublishReport(v.clock()->counter(), {TreeObject()}, me) !=
        sync::SyncStatus::kOk) {
      unreachable = true;
    }
    const double push_seconds = SecondsSince(push_start);

    const auto pull_start = std::chrono::steady_clock::now();
    std::vector<ReplicaId> devices;
    {
      uint64_t w = 0;
      std::size_t refused = 0;
      (void)client.CollectReports({}, &w, &refused);
      relay::GetReportsRequest gr;
      gr.vault = vault;
      relay::ReportsResponse rr;
      if (transport->GetReports(gr, &rr)) {
        for (const relay::SealedReport& s : rr.reports) {
          ReplicaId d;
          d.bytes = s.device.bytes;
          devices.push_back(d);
        }
      } else {
        unreachable = true;
      }
    }

    std::size_t applied = 0;
    for (const ReplicaId& d : devices) {
      if (d == me) continue;
      sync::FetchStats st;
      const sync::SyncStatus s = client.FetchObject(
          TreeObject(), d,
          [&v](const OpPayload& p) {
            TreeOp op;
            if (!DecodeTreeOp(p, &op)) return false;
            return v.ApplyTreeOp(op) != TreeApply::kMalformed;
          },
          &st);
      if (s != sync::SyncStatus::kOk && verbose) {
        std::printf("  tree fetch from %s: %s\n", d.Short().c_str(),
                    sync::SyncStatusName(s));
      }
      applied += st.applied;
    }
    // Objects can only be fetched once the tree names them.
    for (const std::pair<std::string, ObjectId>& kv : v.tree().Listing()) {
      if (v.tree().IsDir(kv.second)) continue;
      const ObjectId object = kv.second;
      for (const ReplicaId& d : devices) {
        if (d == me) continue;
        sync::FetchStats st;
        const sync::SyncStatus s = client.FetchObject(
            object, d,
            [&v, &object](const OpPayload& p) {
              Op op;
              if (!DecodeOp(p, &op)) return false;
              // kNotReady is not a refusal: the operation is real and the
              // log keeps it. Only a malformed one breaks the fetch.
              return v.ApplyOp(object, op) != ApplyResult::kMalformed;
            },
            &st);
        if (s != sync::SyncStatus::kOk && verbose) {
          std::printf("  fetch %s from %s: %s\n", kv.first.c_str(),
                      d.Short().c_str(), sync::SyncStatusName(s));
        }
        applied += st.applied;
      }
    }
    // THE PULL MUST BE DURABLE. FetchObject persists each operation and its
    // cursor through the log, but nothing forced those to disk, so a process
    // that exited here came back with the cursor at zero and re-applied
    // everything.
    if (applied > 0 && log->Sync() != LogStatus::kOk) return 1;
    // WRITE BACK WHAT THE LOG REPLAYS, NOT WHAT MEMORY HOLDS. The fetch
    // callback accepts an operation the document is not ready for -- it is in
    // the log, and holding it there is the point -- so the in-memory vault can
    // be missing operations the next round will replay. Rebuilding here makes
    // the file on disk equal to the document the next scan will diff against,
    // which is the invariant that stops the client generating operations
    // forever.
    if (applied > 0) {
      v = Vault(me);
      RebuildFromLog(log.get(), &v);
    }
    const double pull_seconds = SecondsSince(pull_start);

    // 4. Write the merged result back to the folder.
    std::size_t written = 0;
    for (const std::pair<std::string, ObjectId>& kv : v.tree().Listing()) {
      // A directory node is a directory. Materialising it through the text
      // path wrote an empty FILE named notes, after which the real
      // notes/meeting.md could not be created at all.
      if (v.tree().IsDir(kv.second)) {
        (void)MakeDirs(root + "/" + kv.first);
        continue;
      }
      const TextDoc* d = v.Doc(kv.second);
      if (d == nullptr) continue;
      const std::string want = d->Text();
      std::string have;
      if (ReadWholeFile(root + "/" + kv.first, &have) && have == want) continue;
      if (WriteWholeFile(root + "/" + kv.first, want)) ++written;
    }

    std::string why;
    const bool stale = client.RelayLooksStale(devices, &why);

    std::printf(
        "round %d: %zu local changes, %zu pushed, %zu applied, %zu written, "
        "%zu devices  [key %.2fs push %.3fs pull %.3fs total %.3fs]%s\n",
        ++round, local_changes, pushed, applied, written, devices.size(),
        key_seconds, push_seconds, pull_seconds, SecondsSince(t0),
        stale ? "  RELAY LOOKS STALE" : "");
    if (stale && verbose) std::printf("  %s\n", why.c_str());
    if (unreachable) {
      std::fprintf(stderr,
                   "  cannot reach the relay at %s. Nothing was pushed or "
                   "pulled this round.\n",
                   relay.c_str());
    }
    std::fflush(stdout);

    // A single round that reached nobody is a failure, and the exit status has
    // to say so: --once in a cron entry or a shell && chain is the whole
    // audience for this. --watch keeps going, because a relay that comes back
    // is the ordinary case there.
    //
    // EXCEPT AFTER --create, WHICH ASKED FOR A VAULT AND GOT ONE. The round it
    // runs afterwards is a convenience, and on one machine there is nothing to
    // reach yet -- so a vault that was created successfully must not report
    // failure. Found by following docs/USING.md: step three ended in exit 1
    // with the vault sitting there, correctly made, which stops any `set -e`
    // script and tells a first-time user their vault did not work.
    if (!watch) return (unreachable && mode != Mode::kCreate) ? 1 : 0;
    struct timespec ts;
    ts.tv_sec = interval;
    ts.tv_nsec = 0;
    ::nanosleep(&ts, nullptr);
  }
  return 0;
}
