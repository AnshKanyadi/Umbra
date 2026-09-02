// The relay, the wire, and two clients syncing through a real running one.
//
// The RelayView tests in crypto_test.cc assert over a reopened LOG. These
// assert over what actually crosses a socket and what actually lands on the
// relay's disk, which is the stronger claim and the one item 2 asks for.
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <sodium.h>

#include "scan.h"
#include "server.h"
#include "store.h"
#include "umbra/crdt/oplog.h"
#include "umbra/crdt/vault.h"
#include "umbra/sync/client.h"
#include "wire.h"

namespace umbra {
namespace {

class TempDir {
 public:
  TempDir() {
    const char* tmp = ::getenv("TMPDIR");
    std::string base = tmp != nullptr && tmp[0] != '\0' ? tmp : "/tmp";
    if (!base.empty() && base.back() == '/') base.pop_back();
    std::string tpl = base + "/umbra-relay-test-XXXXXX";
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

// A relay running in this process on a real socket. Port 0 so tests never race
// for a fixed one.
class RunningRelay {
 public:
  explicit RunningRelay(const std::string& dir) {
    EXPECT_EQ(relay::Store::Open(dir, &store_), relay::StoreStatus::kOk);
    relay::ServerOptions o;
    o.port = 0;
    o.bind = "127.0.0.1";
    server_.reset(new relay::Server(store_.get(), o));
    EXPECT_TRUE(server_->Start());
    thread_ = std::thread([this] { server_->Run(); });
  }
  ~RunningRelay() {
    server_->Stop();
    if (thread_.joinable()) thread_.join();
  }
  uint16_t port() const { return server_->port(); }
  relay::Store* store() { return store_.get(); }

 private:
  std::unique_ptr<relay::Store> store_;
  std::unique_ptr<relay::Server> server_;
  std::thread thread_;
};

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

relay::VaultId TestVault() {
  relay::VaultId v;
  v.bytes[0] = 0x5A;
  v.bytes[15] = 0xA5;
  return v;
}

bool Contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

ChangeEvent Created(const std::string& path) {
  ChangeEvent e;
  e.kind = ChangeKind::kCreated;
  e.path = path;
  return e;
}

// ------------------------------------------------------------------- wire

TEST(Wire, RoundTripsEveryMessage) {
  relay::PushRequest push;
  push.vault = TestVault();
  relay::Blob b;
  b.object.bytes[0] = 1;
  b.replica.bytes[0] = 2;
  b.counter = 77;
  b.epoch = 3;
  b.payload = "opaque bytes";
  push.blobs.push_back(b);
  relay::PushRequest back;
  ASSERT_TRUE(relay::DecodePush(relay::EncodePush(push).substr(4), &back));
  ASSERT_EQ(back.blobs.size(), 1u);
  EXPECT_EQ(back.blobs[0].counter, 77u);
  EXPECT_EQ(back.blobs[0].payload, "opaque bytes");

  relay::FetchRequest fetch;
  fetch.vault = TestVault();
  fetch.after = 5;
  fetch.limit = 10;
  relay::FetchRequest fback;
  ASSERT_TRUE(relay::DecodeFetch(relay::EncodeFetch(fetch).substr(4), &fback));
  EXPECT_EQ(fback.after, 5u);
  EXPECT_EQ(fback.limit, 10u);
}

TEST(Wire, RefusesTruncatedAndOverlongFrames) {
  relay::PushRequest push;
  push.vault = TestVault();
  relay::Blob b;
  b.counter = 1;
  b.payload = "x";
  push.blobs.push_back(b);
  const std::string frame = relay::EncodePush(push);
  const std::string body = frame.substr(4);
  relay::PushRequest out;
  for (std::size_t cut = 1; cut < body.size(); ++cut) {
    EXPECT_FALSE(relay::DecodePush(body.substr(0, cut), &out))
        << "accepted a body truncated to " << cut;
  }
  EXPECT_FALSE(relay::DecodePush(body + "junk", &out)) << "trailing junk";

  // A LENGTH IS NOT A PROMISE. A claimed blob count far beyond the body must be
  // refused before anything is reserved for it.
  std::string lying = body;
  lying[17] = static_cast<char>(0xFF);
  lying[18] = static_cast<char>(0xFF);
  lying[19] = static_cast<char>(0xFF);
  lying[20] = static_cast<char>(0x7F);
  EXPECT_FALSE(relay::DecodePush(lying, &out));
}

// ------------------------------------------------------------------ store

TEST(RelayStore, PushIsIdempotentAndFetchIsOrdered) {
  TempDir dir;
  std::unique_ptr<relay::Store> store;
  ASSERT_EQ(relay::Store::Open(dir.path() + "/s", &store),
            relay::StoreStatus::kOk);

  relay::PushRequest req;
  req.vault = TestVault();
  for (uint64_t c : {uint64_t{9}, uint64_t{3}, uint64_t{5}}) {
    relay::Blob b;
    b.object.bytes[0] = 7;
    b.replica.bytes[0] = 8;
    b.counter = c;
    b.payload = "p" + std::to_string(c);
    req.blobs.push_back(b);
  }
  ASSERT_EQ(store->Push(req), relay::StoreStatus::kOk);
  const std::size_t after_one = store->BlobCount();
  // A CLIENT THAT CRASHED MID-PUSH SIMPLY PUSHES AGAIN.
  ASSERT_EQ(store->Push(req), relay::StoreStatus::kOk);
  EXPECT_EQ(store->BlobCount(), after_one) << "a repeated push stored twice";

  relay::FetchRequest f;
  f.vault = TestVault();
  f.object.bytes[0] = 7;
  f.replica.bytes[0] = 8;
  f.after = 0;
  relay::BlobsResponse resp;
  ASSERT_EQ(store->Fetch(f, &resp), relay::StoreStatus::kOk);
  ASSERT_EQ(resp.blobs.size(), 3u);
  EXPECT_EQ(resp.blobs[0].counter, 3u);
  EXPECT_EQ(resp.blobs[1].counter, 5u);
  EXPECT_EQ(resp.blobs[2].counter, 9u) << "fetch is not ordered by counter";

  // The cursor excludes what has been seen.
  f.after = 5;
  relay::BlobsResponse after5;
  ASSERT_EQ(store->Fetch(f, &after5), relay::StoreStatus::kOk);
  ASSERT_EQ(after5.blobs.size(), 1u);
  EXPECT_EQ(after5.blobs[0].counter, 9u);
}

TEST(RelayStore, FetchIsBoundedWhateverTheClientAsks) {
  TempDir dir;
  std::unique_ptr<relay::Store> store;
  ASSERT_EQ(relay::Store::Open(dir.path() + "/s", &store),
            relay::StoreStatus::kOk);
  relay::PushRequest req;
  req.vault = TestVault();
  for (uint64_t c = 1; c <= relay::kMaxFetchBlobs + 20; ++c) {
    relay::Blob b;
    b.object.bytes[0] = 1;
    b.replica.bytes[0] = 1;
    b.counter = c;
    b.payload = "x";
    req.blobs.push_back(b);
  }
  ASSERT_EQ(store->Push(req), relay::StoreStatus::kOk);

  relay::FetchRequest f;
  f.vault = TestVault();
  f.object.bytes[0] = 1;
  f.replica.bytes[0] = 1;
  f.limit = 4000000000u;  // a client asking for everything
  relay::BlobsResponse resp;
  ASSERT_EQ(store->Fetch(f, &resp), relay::StoreStatus::kOk);
  EXPECT_EQ(resp.blobs.size(), relay::kMaxFetchBlobs)
      << "the relay honoured a client's unbounded request";
  EXPECT_TRUE(resp.more);
}

TEST(RelayStore, VaultsAreIsolated) {
  TempDir dir;
  std::unique_ptr<relay::Store> store;
  ASSERT_EQ(relay::Store::Open(dir.path() + "/s", &store),
            relay::StoreStatus::kOk);
  relay::VaultId other = TestVault();
  other.bytes[0] = 0x11;

  relay::PushRequest a;
  a.vault = TestVault();
  relay::Blob b;
  b.counter = 1;
  b.payload = "mine";
  a.blobs.push_back(b);
  ASSERT_EQ(store->Push(a), relay::StoreStatus::kOk);

  relay::FetchRequest f;
  f.vault = other;
  relay::BlobsResponse resp;
  ASSERT_EQ(store->Fetch(f, &resp), relay::StoreStatus::kOk);
  EXPECT_TRUE(resp.blobs.empty()) << "one vault can read another's blobs";
}

// -------------------------------------------------------- over a socket

// Two devices, one relay, real sockets. The end-to-end shape of the system.
TEST(RelayEndToEnd, TwoDevicesSyncThroughARunningRelay) {
  TempDir dir;
  RunningRelay relay_(dir.path() + "/relay");
  ASSERT_NE(relay_.port(), 0);

  VaultKeys keys;
  ASSERT_EQ(
      VaultKeys::Create("shared passphrase", FixedSalt(1), FastParams(), &keys),
      CryptoStatus::kOk);

  const ReplicaId dev_a = ReplicaIdFromSeed(101);
  const ReplicaId dev_b = ReplicaIdFromSeed(202);

  std::unique_ptr<OpLog> log_a;
  std::unique_ptr<OpLog> log_b;
  ASSERT_EQ(OpLog::OpenEncrypted(dir.path() + "/a", &keys, &log_a),
            LogStatus::kOk);
  ASSERT_EQ(OpLog::OpenEncrypted(dir.path() + "/b", &keys, &log_b),
            LogStatus::kOk);

  std::unique_ptr<sync::Transport> ta =
      sync::NewTcpTransport("127.0.0.1", relay_.port());
  std::unique_ptr<sync::Transport> tb =
      sync::NewTcpTransport("127.0.0.1", relay_.port());
  sync::Client ca(TestVault(), dev_a, &keys, log_a.get(), ta.get());
  sync::Client cb(TestVault(), dev_b, &keys, log_b.get(), tb.get());

  // A writes a note.
  Vault va(dev_a);
  const ChangeOutcome made =
      va.ApplyChange(Created("notes/hello.md"), "# hello\n\nfrom device A");
  ASSERT_EQ(made.status, VaultOutcome::kOk);
  ASSERT_EQ(log_a->Append(made.object, made.ops), LogStatus::kOk);
  ASSERT_EQ(log_a->AppendTree(made.tree_ops), LogStatus::kOk);
  ASSERT_EQ(log_a->Sync(), LogStatus::kOk);

  std::size_t pushed = 0;
  ASSERT_EQ(ca.PushObject(made.object, &pushed), sync::SyncStatus::kOk);
  EXPECT_GT(pushed, 0u);
  std::size_t pushed_tree = 0;
  ASSERT_EQ(ca.PushObject(TreeObject(), &pushed_tree), sync::SyncStatus::kOk);
  EXPECT_GT(pushed_tree, 0u);

  // B fetches. The chain is verified as it goes.
  TextDoc doc_b;
  sync::FetchStats st;
  ASSERT_EQ(cb.FetchObject(
                made.object, dev_a,
                [&doc_b](const OpPayload& p) {
                  Op op;
                  if (!DecodeOp(p, &op)) return false;
                  const ApplyResult r = doc_b.Apply(op);
                  return r != ApplyResult::kMalformed;
                },
                &st),
            sync::SyncStatus::kOk);
  EXPECT_EQ(doc_b.Text(), "# hello\n\nfrom device A");
  EXPECT_GT(st.applied, 0u);
  EXPECT_EQ(st.cursor_before, 0u);
  EXPECT_GT(st.cursor_after, 0u);

  TreeDoc tree_b;
  sync::FetchStats tst;
  ASSERT_EQ(cb.FetchObject(
                TreeObject(), dev_a,
                [&tree_b](const OpPayload& p) {
                  TreeOp op;
                  if (!DecodeTreeOp(p, &op)) return false;
                  return tree_b.Apply(op) != TreeApply::kMalformed;
                },
                &tst),
            sync::SyncStatus::kOk);
  std::string path;
  ASSERT_TRUE(tree_b.PathOf(made.object, &path));
  EXPECT_EQ(path, "notes/hello.md");

  // THE CURSOR IS THE PREFIX MARK. A second fetch finds nothing new and does
  // not move it.
  sync::FetchStats again;
  ASSERT_EQ(
      cb.FetchObject(
          made.object, dev_a, [](const OpPayload&) { return true; }, &again),
      sync::SyncStatus::kOk);
  EXPECT_EQ(again.applied, 0u);
  EXPECT_EQ(again.cursor_after, st.cursor_after);
}

// WHAT IS ACTUALLY ON THE WIRE AND ON THE RELAY'S DISK.
TEST(RelayEndToEnd, TheRelayHoldsNoPlaintextAnywhere) {
  TempDir dir;
  const std::string kBody = "SECRET-BODY-xyzzy-plugh-2718281828";
  const std::string kName = "SECRET-NAME-quux-frobnitz.md";
  const std::string kDir = "SECRET-DIR-grault";

  RunningRelay relay_(dir.path() + "/relay");
  VaultKeys keys;
  ASSERT_EQ(VaultKeys::Create("pass", FixedSalt(2), FastParams(), &keys),
            CryptoStatus::kOk);
  const ReplicaId dev = ReplicaIdFromSeed(7);
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::OpenEncrypted(dir.path() + "/c", &keys, &log),
            LogStatus::kOk);
  std::unique_ptr<sync::Transport> t =
      sync::NewTcpTransport("127.0.0.1", relay_.port());
  sync::Client client(TestVault(), dev, &keys, log.get(), t.get());

  Vault v(dev);
  const ChangeOutcome made = v.ApplyChange(Created(kDir + "/" + kName), kBody);
  ASSERT_EQ(made.status, VaultOutcome::kOk);
  ASSERT_EQ(log->Append(made.object, made.ops), LogStatus::kOk);
  ASSERT_EQ(log->AppendTree(made.tree_ops), LogStatus::kOk);
  std::size_t n = 0;
  ASSERT_EQ(client.PushObject(made.object, &n), sync::SyncStatus::kOk);
  ASSERT_EQ(client.PushObject(TreeObject(), &n), sync::SyncStatus::kOk);
  ASSERT_EQ(relay_.store()->Sync(), relay::StoreStatus::kOk);

  // 1. NOTHING PLAINTEXT IN WHAT THE RELAY RETURNS. Read it back the way any
  // client would, which is also the way an operator with the disk would.
  std::string everything;
  for (const ObjectId& obj : {made.object, TreeObject()}) {
    relay::FetchRequest f;
    f.vault = TestVault();
    f.object.bytes = obj.bytes;
    f.replica.bytes = dev.bytes;
    relay::BlobsResponse resp;
    ASSERT_EQ(relay_.store()->Fetch(f, &resp), relay::StoreStatus::kOk);
    EXPECT_FALSE(resp.blobs.empty());
    for (const relay::Blob& b : resp.blobs) everything += b.payload;
  }
  EXPECT_FALSE(Contains(everything, kBody)) << "the relay holds the note";
  EXPECT_FALSE(Contains(everything, kName)) << "the relay holds the file name";
  EXPECT_FALSE(Contains(everything, kDir)) << "the relay holds the folder name";
  EXPECT_FALSE(Contains(everything, kBody.substr(0, 12)));
  EXPECT_FALSE(Contains(everything, kName.substr(0, 12)));

  // 2. NOR ANYWHERE ON ITS DISK. The strongest form of the claim: every byte of
  // every file the relay wrote.
  std::string on_disk;
  WalkSubtree(dir.path() + "/relay", dir.path() + "/relay",
              [&on_disk](const std::string& p, const FileState& st) {
                if (st.is_dir) return;
                FileState full;
                if (ReadFileState(p, 4, &full) != ReadOutcome::kOk) return;
                const int fd = ::open(p.c_str(), O_RDONLY);
                if (fd < 0) return;
                char buf[8192];
                for (;;) {
                  const ssize_t r = ::read(fd, buf, sizeof(buf));
                  if (r <= 0) break;
                  on_disk.append(buf, static_cast<std::size_t>(r));
                }
                ::close(fd);
              });
  EXPECT_GT(on_disk.size(), 0u)
      << "the relay wrote nothing, so this proves nothing";
  EXPECT_FALSE(Contains(on_disk, kBody))
      << "plaintext note on the relay's disk";
  EXPECT_FALSE(Contains(on_disk, kName))
      << "plaintext name on the relay's disk";
  EXPECT_FALSE(Contains(on_disk, kDir));

  // 3. AND THE RELAY CANNOT DECODE WHAT IT HOLDS. Not "we did not give it a
  // key" -- the bytes themselves do not parse as operations.
  relay::FetchRequest f;
  f.vault = TestVault();
  f.object.bytes = TreeObject().bytes;
  f.replica.bytes = dev.bytes;
  relay::BlobsResponse resp;
  ASSERT_EQ(relay_.store()->Fetch(f, &resp), relay::StoreStatus::kOk);
  for (const relay::Blob& b : resp.blobs) {
    TreeOp decoded;
    OpPayload p;
    p.bytes = b.payload;
    EXPECT_FALSE(DecodeTreeOp(p, &decoded))
        << "a stored payload decoded without a key";
  }
}

// --------------------------------------------------- A HOSTILE RELAY
//
// The relay is assumed hostile, so these are not edge cases -- they are the
// design's central claim under test. The transport below wraps a real store and
// then misbehaves in the specific ways the threat model says it can.
class HostileTransport : public sync::Transport {
 public:
  explicit HostileTransport(relay::Store* store) : store_(store) {}

  // Drop the blob at this counter from every fetch response, as though it had
  // never been stored. An INTERIOR omission.
  void OmitCounter(uint64_t c) { omit_.insert(c); }
  // Serve nothing beyond this counter, claiming there is nothing newer. A TAIL
  // omission, which is the stale view.
  void TruncateAfter(uint64_t c) { truncate_after_ = c; }
  // Replace every stored report with one claiming enormous marks.
  void ForgeReports(bool on) { forge_ = on; }
  // Serve the same blobs a second time.
  void DuplicateEverything(bool on) { duplicate_ = on; }

  bool Push(const relay::PushRequest& req) override {
    return store_->Push(req) == relay::StoreStatus::kOk;
  }

  bool Fetch(const relay::FetchRequest& req,
             relay::BlobsResponse* out) override {
    relay::BlobsResponse real;
    if (store_->Fetch(req, &real) != relay::StoreStatus::kOk) return false;
    for (const relay::Blob& b : real.blobs) {
      if (omit_.count(b.counter) != 0) continue;
      if (truncate_after_ != 0 && b.counter > truncate_after_) continue;
      out->blobs.push_back(b);
      if (duplicate_) out->blobs.push_back(b);
    }
    out->more = false;
    return true;
  }

  bool PutReport(const relay::PutReportRequest& req) override {
    return store_->PutReport(req) == relay::StoreStatus::kOk;
  }

  bool GetReports(const relay::GetReportsRequest& req,
                  relay::ReportsResponse* out) override {
    if (store_->GetReports(req, out) != relay::StoreStatus::kOk) return false;
    if (forge_) {
      // The relay holds no key, so the best it can do is scribble on the
      // ciphertext. That is the attack: it cannot produce a report that opens.
      for (relay::SealedReport& s : out->reports) {
        if (!s.sealed.empty()) {
          s.sealed[s.sealed.size() - 1] =
              static_cast<char>(s.sealed[s.sealed.size() - 1] ^ 0xFF);
        }
      }
    }
    return true;
  }

 private:
  relay::Store* store_;
  std::set<uint64_t> omit_;
  uint64_t truncate_after_ = 0;
  bool forge_ = false;
  bool duplicate_ = false;
};

// A fixture that puts several operations from one device on a relay.
class HostileRelay : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(relay::Store::Open(dir_.path() + "/relay", &store_),
              relay::StoreStatus::kOk);
    ASSERT_EQ(VaultKeys::Create("pass", FixedSalt(4), FastParams(), &keys_),
              CryptoStatus::kOk);
    ASSERT_EQ(OpLog::OpenEncrypted(dir_.path() + "/a", &keys_, &log_a_),
              LogStatus::kOk);
    ASSERT_EQ(OpLog::OpenEncrypted(dir_.path() + "/b", &keys_, &log_b_),
              LogStatus::kOk);

    Vault v(dev_a_);
    ChangeOutcome c = v.ApplyChange(Created("n.md"), "one");
    ASSERT_EQ(c.status, VaultOutcome::kOk);
    object_ = c.object;
    ASSERT_EQ(log_a_->Append(object_, c.ops), LogStatus::kOk);
    for (const Op& op : c.ops) counters_.push_back(op.id.counter);
    for (int i = 2; i <= 5; ++i) {
      ChangeOutcome m = v.ApplyChange(
          Modified("n.md"), "one two three four five " + std::to_string(i));
      ASSERT_EQ(m.status, VaultOutcome::kOk);
      ASSERT_EQ(log_a_->Append(object_, m.ops), LogStatus::kOk);
      for (const Op& op : m.ops) counters_.push_back(op.id.counter);
    }
    ASSERT_EQ(log_a_->Sync(), LogStatus::kOk);
    ASSERT_GE(counters_.size(), 4u);

    honest_.reset(new HostileTransport(store_.get()));
    sync::Client pusher(TestVault(), dev_a_, &keys_, log_a_.get(),
                        honest_.get());
    std::size_t n = 0;
    ASSERT_EQ(pusher.PushObject(object_, &n), sync::SyncStatus::kOk);
  }

  static ChangeEvent Modified(const std::string& path) {
    ChangeEvent e;
    e.kind = ChangeKind::kModified;
    e.path = path;
    return e;
  }

  TempDir dir_;
  std::unique_ptr<relay::Store> store_;
  VaultKeys keys_;
  std::unique_ptr<OpLog> log_a_;
  std::unique_ptr<OpLog> log_b_;
  std::unique_ptr<HostileTransport> honest_;
  ReplicaId dev_a_ = ReplicaIdFromSeed(11);
  ReplicaId dev_b_ = ReplicaIdFromSeed(22);
  ObjectId object_;
  std::vector<uint64_t> counters_;
};

// BREAKAGE 1: the relay omits an operation from the middle of a range. The
// client must refuse to advance its cursor past the gap. Without the
// back-pointer chain this is undetectable, because counters are sparse.
TEST_F(HostileRelay, RefusesToAdvancePastAnOmittedOperation) {
  HostileTransport hostile(store_.get());
  hostile.OmitCounter(counters_[1]);
  sync::Client cb(TestVault(), dev_b_, &keys_, log_b_.get(), &hostile);

  TextDoc doc;
  sync::FetchStats st;
  const sync::SyncStatus s = cb.FetchObject(
      object_, dev_a_,
      [&doc](const OpPayload& p) {
        Op op;
        if (!DecodeOp(p, &op)) return false;
        return doc.Apply(op) != ApplyResult::kMalformed;
      },
      &st);
  EXPECT_EQ(s, sync::SyncStatus::kChainBroken)
      << "the client accepted a range with a hole in it";
  // THE CURSOR STOPPED AT THE LAST VERIFIED OPERATION, not past it. That is
  // what keeps the prefix mark truthful and the watermark safe.
  EXPECT_EQ(st.cursor_after, counters_[0]);
  EXPECT_EQ(cb.Cursor(object_, dev_a_), counters_[0]);

  // And once the relay stops lying, the client catches up from where it was.
  sync::Client honest_client(TestVault(), dev_b_, &keys_, log_b_.get(),
                             honest_.get());
  sync::FetchStats st2;
  EXPECT_EQ(honest_client.FetchObject(
                object_, dev_a_,
                [&doc](const OpPayload& p) {
                  Op op;
                  if (!DecodeOp(p, &op)) return false;
                  return doc.Apply(op) != ApplyResult::kMalformed;
                },
                &st2),
            sync::SyncStatus::kOk);
  EXPECT_EQ(st2.cursor_before, counters_[0])
      << "it did not resume where it stopped";
  EXPECT_EQ(st2.cursor_after, counters_.back());
}

// BREAKAGE 2: the relay serves a correct but stale view, claiming to have
// nothing newer. The mark must stay where it was -- safe, not wrong.
TEST_F(HostileRelay, AStaleViewLeavesTheMarkWhereItWas) {
  HostileTransport hostile(store_.get());
  hostile.TruncateAfter(counters_[1]);
  sync::Client cb(TestVault(), dev_b_, &keys_, log_b_.get(), &hostile);

  TextDoc doc;
  sync::FetchStats st;
  EXPECT_EQ(cb.FetchObject(
                object_, dev_a_,
                [&doc](const OpPayload& p) {
                  Op op;
                  if (!DecodeOp(p, &op)) return false;
                  return doc.Apply(op) != ApplyResult::kMalformed;
                },
                &st),
            sync::SyncStatus::kOk)
      << "a stale view is not an error; the relay is allowed to be behind";
  // NOT AN ERROR, AND NOT A LIE EITHER. The cursor reflects exactly what was
  // verified, so the prefix mark this device reports is true and the watermark
  // computed from it is conservative.
  EXPECT_EQ(st.cursor_after, counters_[1]);
  EXPECT_LT(st.cursor_after, counters_.back());
  EXPECT_EQ(cb.Cursor(object_, dev_a_), counters_[1]);
}

// BREAKAGE 3: the relay forges an inflated mark. It holds no key, so all it can
// do is corrupt the ciphertext -- and the client must refuse it rather than
// letting a forged report move the watermark.
TEST_F(HostileRelay, RefusesAForgedReport) {
  // An honest report first, so there is something to forge.
  sync::Client ca(TestVault(), dev_a_, &keys_, log_a_.get(), honest_.get());
  ASSERT_EQ(ca.PublishReport(9999, {object_}, dev_a_), sync::SyncStatus::kOk);

  const std::vector<ReplicaId> enrolled{dev_a_};
  uint64_t honest_watermark = 0;
  std::size_t refused = 0;
  ASSERT_EQ(ca.CollectReports(enrolled, &honest_watermark, &refused),
            sync::SyncStatus::kOk);
  EXPECT_EQ(refused, 0u);
  EXPECT_GT(honest_watermark, 0u)
      << "the honest path produced nothing to compare";

  HostileTransport hostile(store_.get());
  hostile.ForgeReports(true);
  sync::Client cb(TestVault(), dev_b_, &keys_, log_b_.get(), &hostile);
  uint64_t forged_watermark = 0;
  std::size_t forged_refused = 0;
  ASSERT_EQ(cb.CollectReports(enrolled, &forged_watermark, &forged_refused),
            sync::SyncStatus::kOk);
  EXPECT_EQ(forged_refused, 1u) << "a tampered report was accepted";
  // A REFUSED REPORT COLLAPSES THE WATERMARK rather than failing loudly: the
  // safe direction, and the only one a relay can force.
  EXPECT_EQ(forged_watermark, 0u);
}

TEST_F(HostileRelay, DuplicateDeliveryIsHarmless) {
  HostileTransport hostile(store_.get());
  hostile.DuplicateEverything(true);
  sync::Client cb(TestVault(), dev_b_, &keys_, log_b_.get(), &hostile);

  TextDoc doc;
  sync::FetchStats st;
  // A duplicate arrives with a counter not greater than the last, which the
  // order check catches before the chain does. Either way the cursor does not
  // move backwards and nothing is corrupted.
  const sync::SyncStatus s = cb.FetchObject(
      object_, dev_a_,
      [&doc](const OpPayload& p) {
        Op op;
        if (!DecodeOp(p, &op)) return false;
        return doc.Apply(op) != ApplyResult::kMalformed;
      },
      &st);
  EXPECT_EQ(s, sync::SyncStatus::kOutOfOrder);
  EXPECT_EQ(st.cursor_after, counters_[0]);
  EXPECT_EQ(cb.Cursor(object_, dev_a_), counters_[0]);
}

// THE CURSOR AND THE HARNESS AGREE ON WHAT A PREFIX MARK IS.
//
// sim/ computes the mark from what a source produced against what a replica
// received, because the simulation knows both. The real client computes it from
// a cursor it advanced across a verified chain. They must be the same number or
// ADR 0003's condition is being tested against something other than what ships.
TEST_F(HostileRelay, TheCursorEqualsTheHarnessPrefixMark) {
  sync::Client cb(TestVault(), dev_b_, &keys_, log_b_.get(), honest_.get());
  TextDoc doc;
  sync::FetchStats st;
  ASSERT_EQ(cb.FetchObject(
                object_, dev_a_,
                [&doc](const OpPayload& p) {
                  Op op;
                  if (!DecodeOp(p, &op)) return false;
                  return doc.Apply(op) != ApplyResult::kMalformed;
                },
                &st),
            sync::SyncStatus::kOk);

  // The harness's definition, computed here from the same two facts it uses:
  // what the source produced, in order, and what this replica received.
  std::set<uint64_t> received;
  {
    std::vector<StoredBlob> got;
    ASSERT_EQ(log_b_->ReadStoredFrom(object_, dev_a_, 0, &got), LogStatus::kOk);
    for (const StoredBlob& b : got) received.insert(b.id.counter);
  }
  uint64_t harness_mark = 0;
  for (uint64_t c : counters_) {
    if (received.count(c) == 0) break;
    harness_mark = c;
  }

  EXPECT_EQ(cb.Cursor(object_, dev_a_), harness_mark)
      << "the shipped cursor and the harness disagree about the prefix mark";
  EXPECT_EQ(harness_mark, counters_.back());
}

// And they still agree when the relay withheld something, which is the case
// where disagreeing would matter.
TEST_F(HostileRelay, TheCursorEqualsTheMarkAfterAWithheldOperation) {
  HostileTransport hostile(store_.get());
  hostile.OmitCounter(counters_[1]);
  sync::Client cb(TestVault(), dev_b_, &keys_, log_b_.get(), &hostile);
  TextDoc doc;
  sync::FetchStats st;
  (void)cb.FetchObject(
      object_, dev_a_,
      [&doc](const OpPayload& p) {
        Op op;
        if (!DecodeOp(p, &op)) return false;
        return doc.Apply(op) != ApplyResult::kMalformed;
      },
      &st);

  std::set<uint64_t> received;
  {
    std::vector<StoredBlob> got;
    ASSERT_EQ(log_b_->ReadStoredFrom(object_, dev_a_, 0, &got), LogStatus::kOk);
    for (const StoredBlob& b : got) received.insert(b.id.counter);
  }
  uint64_t harness_mark = 0;
  for (uint64_t c : counters_) {
    if (received.count(c) == 0) break;
    harness_mark = c;
  }
  EXPECT_EQ(cb.Cursor(object_, dev_a_), harness_mark);
  EXPECT_EQ(harness_mark, counters_[0]) << "both should stop before the hole";
}

}  // namespace
}  // namespace umbra
