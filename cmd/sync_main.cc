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
  WalkSubtree(root, std::string(), [&](const std::string& rel,
                                       const FileState& st) {
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
      path, std::string(reinterpret_cast<const char*>(salt.data()), kSaltBytes));
  return salt;
}

// A stable replica id for a vault directory, so restarting the client does not
// look like a new device.
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
  (void)WriteWholeFile(path, std::string(reinterpret_cast<const char*>(
                                             r.bytes.data()),
                                         r.bytes.size()));
  return r;
}

double SecondsSince(const std::chrono::steady_clock::time_point& t) {
  return std::chrono::duration_cast<std::chrono::duration<double>>(
             std::chrono::steady_clock::now() - t)
      .count();
}

void Usage() {
  std::fprintf(stderr,
               "umbra_sync --dir PATH --relay HOST:PORT --pass PASSPHRASE\n"
               "           [--once | --watch] [--interval SECONDS] [-v]\n"
               "\n"
               "--pass on the command line is for driving tests. A real client\n"
               "prompts or reads a keychain; this lands in shell history.\n");
}

}  // namespace

int main(int argc, char** argv) {
  std::string dir;
  std::string relay = "127.0.0.1:9000";
  std::string pass;
  bool watch = false;
  int interval = 2;
  bool verbose = false;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    const char* next = (i + 1 < argc) ? argv[i + 1] : nullptr;
    if (a == "--dir" && next) { dir = next; ++i; }
    else if (a == "--relay" && next) { relay = next; ++i; }
    else if (a == "--pass" && next) { pass = next; ++i; }
    else if (a == "--interval" && next) { interval = std::atoi(next); ++i; }
    else if (a == "--watch") { watch = true; }
    else if (a == "--once") { watch = false; }
    else if (a == "-v") { verbose = true; }
    else { Usage(); return 2; }
  }
  if (dir.empty() || pass.empty()) { Usage(); return 2; }

  const std::size_t colon = relay.rfind(':');
  if (colon == std::string::npos) { Usage(); return 2; }
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

    // 1. Rebuild the world from the local log.
    TreeDoc tree;
    std::map<ReplicaId, uint64_t> high;
    if (log->ReplayTree(&tree, &high) != LogStatus::kOk) {
      std::fprintf(stderr, "the tree log will not replay\n");
      return 1;
    }
    LamportClock clock(me);
    for (const std::map<ReplicaId, uint64_t>::value_type& kv : high) {
      clock.Observe(OpId{kv.second, kv.first});
    }

    std::map<ObjectId, TextDoc> docs;
    for (const std::pair<std::string, ObjectId>& kv : tree.Listing()) {
      TextDoc d;
      std::map<ReplicaId, uint64_t> h;
      if (log->Replay(kv.second, &d, &h) == LogStatus::kOk) {
        for (const std::map<ReplicaId, uint64_t>::value_type& e : h) {
          clock.Observe(OpId{e.second, e.first});
        }
        docs[kv.second] = d;
      }
    }

    // 2. What is on disk that the vault does not know about, or differs.
    std::vector<std::string> on_disk;
    ListVault(root, &on_disk);
    std::size_t local_changes = 0;
    for (const std::string& rel : on_disk) {
      std::string body;
      if (!ReadWholeFile(root + "/" + rel, &body)) continue;
      ObjectId id;
      const bool known = tree.Resolve(rel, &id) && !IsTreeRoot(id);
      if (known && docs.count(id) != 0 && docs[id].Text() == body) continue;

      Vault v(me);
      // Seed the vault's tree and document with what the log already says, so
      // the change it produces is a diff rather than a rewrite.
      for (const TreeOp& op : [&] {
             std::vector<TreeOp> all;
             (void)log->ReadTree(&all);
             return all;
           }()) {
        (void)v.ApplyTreeOp(op);
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
      if (!c.tree_ops.empty()) {
        if (log->AppendTree(c.tree_ops) != LogStatus::kOk) return 1;
      }
      if (!c.ops.empty()) {
        if (log->Append(c.object, c.ops) != LogStatus::kOk) return 1;
      }
      local_changes += c.ops.size() + c.tree_ops.size();
    }
    if (local_changes > 0 && log->Sync() != LogStatus::kOk) return 1;

    // 3. Push what we have, then learn who else exists, then pull.
    const auto push_start = std::chrono::steady_clock::now();
    std::size_t pushed = 0;
    std::size_t n = 0;
    if (client.PushObject(TreeObject(), &n) == sync::SyncStatus::kOk) pushed += n;
    for (const std::pair<std::string, ObjectId>& kv : tree.Listing()) {
      if (client.PushObject(kv.second, &n) == sync::SyncStatus::kOk) pushed += n;
    }
    (void)client.PublishReport(clock.counter(), {TreeObject()}, me);
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
          [&tree](const OpPayload& p) {
            TreeOp op;
            if (!DecodeTreeOp(p, &op)) return false;
            return tree.Apply(op) != TreeApply::kMalformed;
          },
          &st);
      if (s != sync::SyncStatus::kOk && verbose) {
        std::printf("  tree fetch from %s: %s\n", d.Short().c_str(),
                    sync::SyncStatusName(s));
      }
      applied += st.applied;
    }
    // Objects can only be fetched once the tree names them.
    for (const std::pair<std::string, ObjectId>& kv : tree.Listing()) {
      for (const ReplicaId& d : devices) {
        if (d == me) continue;
        TextDoc& doc = docs[kv.second];
        sync::FetchStats st;
        const sync::SyncStatus s = client.FetchObject(
            kv.second, d,
            [&doc](const OpPayload& p) {
              Op op;
              if (!DecodeOp(p, &op)) return false;
              return doc.Apply(op) != ApplyResult::kMalformed;
            },
            &st);
        if (s != sync::SyncStatus::kOk && verbose) {
          std::printf("  fetch %s from %s: %s\n", kv.first.c_str(),
                      d.Short().c_str(), sync::SyncStatusName(s));
        }
        applied += st.applied;
      }
    }
    const double pull_seconds = SecondsSince(pull_start);

    // 4. Write the merged result back to the folder.
    std::size_t written = 0;
    for (const std::pair<std::string, ObjectId>& kv : tree.Listing()) {
      const std::map<ObjectId, TextDoc>::const_iterator it =
          docs.find(kv.second);
      if (it == docs.end()) continue;
      const std::string want = it->second.Text();
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
