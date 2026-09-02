// A vault client.
//
//     umbra_sync --dir ~/notes --relay 127.0.0.1:9000 --pass "..." --once
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
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "scan.h"
#include "umbra/crdt/oplog.h"
#include "umbra/crdt/tree.h"
#include "umbra/crdt/vault.h"
#include "umbra/sync/client.h"

namespace {

using namespace umbra;

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

ReplicaId LoadOrCreateReplica(const std::string& dir) {
  const std::string path = dir + "/.umbra/replica";
  std::string existing;
  ReplicaId r;
  if (ReadWholeFile(path, &existing) && existing.size() == r.bytes.size()) {
    std::memcpy(r.bytes.data(), existing.data(), r.bytes.size());
    return r;
  }
  r = NewReplicaId();
  (void)MakeDirs(dir + "/.umbra");
  (void)WriteWholeFile(
      path, std::string(reinterpret_cast<const char*>(r.bytes.data()),
                        r.bytes.size()));
  return r;
}

double SecondsSince(const std::chrono::steady_clock::time_point& t) {
  return std::chrono::duration_cast<std::chrono::duration<double>>(
             std::chrono::steady_clock::now() - t)
      .count();
}

void Usage() {
  std::fprintf(
      stderr,
      "umbra_sync --dir PATH --relay HOST:PORT --pass PASSPHRASE\n"
      "           [--salt-from PATH] [--once | --watch]\n"
      "           [--interval SECONDS] [-v]\n"
      "\n"
      "--salt-from copies another vault's .umbra/salt so the two are\n"
      "the same vault. Enrolment carries this in a real client.\n"
      "\n"
      "--pass on the command line is for driving tests. A real client\n"
      "prompts or reads a keychain; this lands in shell history.\n");
}

}  // namespace

int main(int argc, char** argv) {
  std::string dir;
  std::string relay = "127.0.0.1:9000";
  std::string pass;
  std::string salt_from;
  bool watch = false;
  int interval = 2;
  bool verbose = false;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    const char* next = (i + 1 < argc) ? argv[i + 1] : nullptr;
    if (a == "--dir" && next) {
      dir = next;
      ++i;
    } else if (a == "--relay" && next) {
      relay = next;
      ++i;
    } else if (a == "--pass" && next) {
      pass = next;
      ++i;
    } else if (a == "--salt-from" && next) {
      salt_from = next;
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
  if (dir.empty() || pass.empty()) {
    Usage();
    return 2;
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
  // THE SALT IS VAULT-LEVEL, NOT DEVICE-LEVEL, and a device that generates its
  // own is a different vault however identical its passphrase. Enrolment is
  // what carries it between devices; --salt-from stands in for that here, and
  // the first end-to-end run without it produced two vaults that could never
  // see each other.
  if (!salt_from.empty()) {
    std::string bytes;
    if (!ReadWholeFile(salt_from, &bytes) || bytes.size() != kSaltBytes) {
      std::fprintf(stderr, "cannot read a %zu-byte salt from %s\n",
                   static_cast<std::size_t>(kSaltBytes), salt_from.c_str());
      return 1;
    }
    (void)MakeDirs(root + "/.umbra");
    (void)WriteWholeFile(root + "/.umbra/salt", bytes);
  }
  const std::array<uint8_t, kSaltBytes> salt = LoadOrCreateSalt(root);
  if (VaultKeys::Create(pass, salt, Argon2idParams::Default(), &keys) !=
      CryptoStatus::kOk) {
    std::fprintf(stderr, "cannot derive the root key (out of memory?)\n");
    return 1;
  }
  const double key_seconds = SecondsSince(key_start);

  // EVERY VAULT SHARING A PASSPHRASE MUST AGREE ON THE EPOCH KEY, and Create
  // draws a random one. Two directories driven by this tool are the same vault,
  // so the epoch key is derived from the root rather than drawn -- which is
  // exactly what keys.h says NOT to do for a real vault, because a removed
  // device could then compute it. Enrollment is what makes this unnecessary;
  // this tool has no enrollment channel, and saying so is better than shipping
  // a client that looks enrolled and is not.
  {
    const SecretKey e0 = DeriveSubkey(keys.root(), 0, "umbBoot1");
    keys.OverwriteEpochForBootstrap(0, e0);
  }

  const ReplicaId me = LoadOrCreateReplica(root);
  relay::VaultId vault;
  {
    // One vault per passphrase: the id is derived from the root key so two
    // directories with the same passphrase land in the same vault without
    // anyone configuring an id.
    const SecretKey vid = DeriveSubkey(keys.root(), 1, "umbVault");
    std::memcpy(vault.bytes.data(), vid.data(), vault.bytes.size());
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

  std::printf("vault %s\n  device %s\n  relay %s\n  key derivation %.2fs\n",
              root.c_str(), me.Short().c_str(), relay.c_str(), key_seconds);
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
    if (client.PushObject(TreeObject(), &n) == sync::SyncStatus::kOk)
      pushed += n;
    for (const std::pair<std::string, ObjectId>& kv : v.tree().Listing()) {
      if (v.tree().IsDir(kv.second)) continue;
      if (client.PushObject(kv.second, &n) == sync::SyncStatus::kOk)
        pushed += n;
    }
    (void)client.PublishReport(v.clock()->counter(), {TreeObject()}, me);
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
    std::fflush(stdout);

    if (!watch) break;
    struct timespec ts;
    ts.tv_sec = interval;
    ts.tv_nsec = 0;
    ::nanosleep(&ts, nullptr);
  }
  return 0;
}
