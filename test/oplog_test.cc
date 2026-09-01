// The oplog in Basalt, and the vault that feeds it.
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "scan.h"
#include "umbra/crdt/oplog.h"
#include "umbra/crdt/vault.h"

namespace umbra {
namespace {

class TempDir {
 public:
  TempDir() {
    const char* tmp = ::getenv("TMPDIR");
    std::string base = tmp != nullptr && tmp[0] != '\0' ? tmp : "/tmp";
    if (!base.empty() && base.back() == '/') base.pop_back();
    std::string tpl = base + "/umbra-oplog-test-XXXXXX";
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

ObjectId ObjectFromSeed(uint8_t seed) {
  ObjectId id;
  id.bytes[0] = seed;
  id.bytes[15] = seed;
  return id;
}

TEST(OpLogKey, RoundTripsAndOrdersByCounter) {
  const ObjectId obj = ObjectFromSeed(7);
  const ReplicaId rep = ReplicaIdFromSeed(3);
  const std::string a = MakeOpLogKey(obj, rep, 1);
  const std::string b = MakeOpLogKey(obj, rep, 2);
  const std::string big = MakeOpLogKey(obj, rep, 256);
  EXPECT_EQ(a.size(), kOpLogKeyBytes);
  // BIG-ENDIAN IS THE POINT: byte order must equal numeric order, or a range
  // scan for "everything after counter C" returns the wrong set.
  EXPECT_LT(a, b);
  EXPECT_LT(b, big);

  ObjectId o2;
  ReplicaId r2;
  uint64_t c2 = 0;
  ASSERT_TRUE(ParseOpLogKey(big, &o2, &r2, &c2));
  EXPECT_EQ(o2, obj);
  EXPECT_EQ(r2, rep);
  EXPECT_EQ(c2, 256u);
  EXPECT_FALSE(ParseOpLogKey("short", &o2, &r2, &c2));
}

TEST(OpLog, AppendsAndReplaysADocument) {
  TempDir dir;
  ASSERT_FALSE(dir.path().empty());
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::Open(dir.path() + "/db", &log), LogStatus::kOk);

  const ObjectId obj = ObjectFromSeed(1);
  TextDoc src;
  LamportClock clock(ReplicaIdFromSeed(1));
  std::vector<Op> ops;
  ASSERT_TRUE(src.LocalInsert(0, "# note\n", &clock, &ops));
  ASSERT_TRUE(src.LocalInsert(7, "body text", &clock, &ops));
  std::vector<Op> del;
  ASSERT_TRUE(src.LocalDelete(0, 2, &clock, &del));
  ops.insert(ops.end(), del.begin(), del.end());

  ASSERT_EQ(log->Append(obj, ops), LogStatus::kOk);
  ASSERT_EQ(log->Sync(), LogStatus::kOk);

  TextDoc rebuilt;
  std::map<ReplicaId, uint64_t> high;
  ASSERT_EQ(log->Replay(obj, &rebuilt, &high), LogStatus::kOk);
  EXPECT_EQ(rebuilt.Text(), src.Text());
  EXPECT_EQ(rebuilt.StateHash(), src.StateHash());

  // THE CLOCK MUST COME BACK AHEAD OF EVERY ID IN THE LOG, including the later
  // characters of a run. A clock rebuilt only from operation ids would reissue
  // them; see oplog.h.
  ASSERT_EQ(high.size(), 1u);
  EXPECT_EQ(high[ReplicaIdFromSeed(1)], clock.counter());
}

TEST(OpLog, SurvivesReopen) {
  TempDir dir;
  ASSERT_FALSE(dir.path().empty());
  const std::string db = dir.path() + "/db";
  const ObjectId obj = ObjectFromSeed(2);
  std::string expected;
  {
    std::unique_ptr<OpLog> log;
    ASSERT_EQ(OpLog::Open(db, &log), LogStatus::kOk);
    TextDoc doc;
    LamportClock clock(ReplicaIdFromSeed(5));
    std::vector<Op> ops;
    ASSERT_TRUE(doc.LocalInsert(0, "persisted", &clock, &ops));
    ASSERT_EQ(log->Append(obj, ops), LogStatus::kOk);
    ASSERT_EQ(log->Sync(), LogStatus::kOk);
    expected = doc.Text();
  }
  {
    std::unique_ptr<OpLog> log;
    ASSERT_EQ(OpLog::Open(db, &log), LogStatus::kOk);
    TextDoc doc;
    std::map<ReplicaId, uint64_t> high;
    ASSERT_EQ(log->Replay(obj, &doc, &high), LogStatus::kOk);
    EXPECT_EQ(doc.Text(), expected);
  }
}

TEST(OpLog, ObjectsAreIsolatedFromEachOther) {
  TempDir dir;
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::Open(dir.path() + "/db", &log), LogStatus::kOk);
  const ObjectId a = ObjectFromSeed(10);
  const ObjectId b = ObjectFromSeed(20);

  TextDoc da;
  TextDoc db_;
  LamportClock ca(ReplicaIdFromSeed(1));
  LamportClock cb(ReplicaIdFromSeed(2));
  std::vector<Op> oa;
  std::vector<Op> ob;
  ASSERT_TRUE(da.LocalInsert(0, "alpha", &ca, &oa));
  ASSERT_TRUE(db_.LocalInsert(0, "beta", &cb, &ob));
  ASSERT_EQ(log->Append(a, oa), LogStatus::kOk);
  ASSERT_EQ(log->Append(b, ob), LogStatus::kOk);

  TextDoc ra;
  TextDoc rb;
  std::map<ReplicaId, uint64_t> h;
  ASSERT_EQ(log->Replay(a, &ra, &h), LogStatus::kOk);
  ASSERT_EQ(log->Replay(b, &rb, &h), LogStatus::kOk);
  EXPECT_EQ(ra.Text(), "alpha");
  EXPECT_EQ(rb.Text(), "beta");
}

TEST(OpLog, ReadFromIsASyncCursor) {
  TempDir dir;
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::Open(dir.path() + "/db", &log), LogStatus::kOk);
  const ObjectId obj = ObjectFromSeed(3);
  const ReplicaId rep = ReplicaIdFromSeed(9);
  TextDoc doc;
  LamportClock clock(rep);
  std::vector<Op> ops;
  ASSERT_TRUE(doc.LocalInsert(0, "aaa", &clock, &ops));  // counters 1..3
  ASSERT_TRUE(doc.LocalInsert(3, "bbb", &clock, &ops));  // counters 4..6
  ASSERT_EQ(log->Append(obj, ops), LogStatus::kOk);

  std::vector<Op> after0;
  ASSERT_EQ(log->ReadFrom(obj, rep, 0, &after0), LogStatus::kOk);
  EXPECT_EQ(after0.size(), 2u);

  std::vector<Op> after1;
  ASSERT_EQ(log->ReadFrom(obj, rep, 1, &after1), LogStatus::kOk);
  EXPECT_EQ(after1.size(), 1u)
      << "the cursor must exclude what is already seen";
  EXPECT_EQ(after1[0].id.counter, 4u);

  std::vector<Op> after_all;
  ASSERT_EQ(log->ReadFrom(obj, rep, 100, &after_all), LogStatus::kOk);
  EXPECT_TRUE(after_all.empty());
}

TEST(OpLog, RefusesALogThatIsNotCausallyClosed) {
  // Write only the SECOND operation of a pair. Its parent is missing, so replay
  // can never satisfy it. It is reported rather than silently producing a
  // shorter document.
  TempDir dir;
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::Open(dir.path() + "/db", &log), LogStatus::kOk);
  const ObjectId obj = ObjectFromSeed(4);

  TextDoc doc;
  LamportClock clock(ReplicaIdFromSeed(6));
  std::vector<Op> ops;
  ASSERT_TRUE(doc.LocalInsert(0, "first", &clock, &ops));
  ASSERT_TRUE(doc.LocalInsert(5, "second", &clock, &ops));
  ASSERT_EQ(ops.size(), 2u);

  std::vector<Op> only_second{ops[1]};
  ASSERT_EQ(log->Append(obj, only_second), LogStatus::kOk);

  TextDoc rebuilt;
  std::map<ReplicaId, uint64_t> high;
  EXPECT_EQ(log->Replay(obj, &rebuilt, &high), LogStatus::kNotClosed);
}

// ------------------------------------------------------------------ vault

ChangeEvent Event(ChangeKind k, const std::string& path,
                  const std::string& old_path = std::string()) {
  ChangeEvent e;
  e.kind = k;
  e.path = path;
  e.old_path = old_path;
  return e;
}

TEST(Vault, CreateThenModifyProducesOperations) {
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c = v.ApplyChange(Event(ChangeKind::kCreated, "a.md"), "hello");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  EXPECT_FALSE(c.ops.empty());
  ASSERT_NE(v.Doc(c.object), nullptr);
  EXPECT_EQ(v.Doc(c.object)->Text(), "hello");

  ChangeOutcome m =
      v.ApplyChange(Event(ChangeKind::kModified, "a.md"), "hello there");
  ASSERT_EQ(m.status, VaultOutcome::kOk);
  EXPECT_EQ(m.object, c.object) << "a modify must not change identity";
  EXPECT_EQ(v.Doc(c.object)->Text(), "hello there");
}

TEST(Vault, ModifyEmitsOnlyTheChangedRegion) {
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c =
      v.ApplyChange(Event(ChangeKind::kCreated, "a.md"), "the quick brown fox");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  ChangeOutcome m =
      v.ApplyChange(Event(ChangeKind::kModified, "a.md"), "the quick red fox");
  ASSERT_EQ(m.status, VaultOutcome::kOk);
  EXPECT_EQ(v.Doc(c.object)->Text(), "the quick red fox");
  // "brown" -> "red": one delete and one insert, not a rewrite of the line.
  ASSERT_EQ(m.ops.size(), 2u);
  std::size_t touched = 0;
  for (const Op& op : m.ops) {
    touched += op.kind == OpKind::kInsert ? op.text.size() : op.count;
  }
  EXPECT_LE(touched, 8u) << "the diff touched more than the changed region";
}

// THE REQUIREMENT: a watcher move must not produce a delete plus a create.
TEST(Vault, MoveProducesNoOperationsAndKeepsIdentity) {
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c =
      v.ApplyChange(Event(ChangeKind::kCreated, "notes/a.md"), "content");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  const std::string before = v.Doc(c.object)->StateHash();

  ChangeOutcome mv = v.ApplyChange(
      Event(ChangeKind::kMoved, "archive/a.md", "notes/a.md"), std::string());
  ASSERT_EQ(mv.status, VaultOutcome::kOk);
  EXPECT_TRUE(mv.was_pure_move);
  EXPECT_TRUE(mv.ops.empty())
      << "a move put " << mv.ops.size() << " operations in the oplog";
  EXPECT_EQ(mv.object, c.object) << "a move must preserve object identity";
  EXPECT_EQ(v.Doc(c.object)->StateHash(), before)
      << "a move changed the document";

  ObjectId at_new;
  ASSERT_TRUE(v.ObjectAt("archive/a.md", &at_new));
  EXPECT_EQ(at_new, c.object);
  ObjectId at_old;
  EXPECT_FALSE(v.ObjectAt("notes/a.md", &at_old))
      << "the old path still resolves";
}

TEST(Vault, DeleteRemovesTextButKeepsTheObject) {
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c = v.ApplyChange(Event(ChangeKind::kCreated, "a.md"), "gone");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  ChangeOutcome d =
      v.ApplyChange(Event(ChangeKind::kDeleted, "a.md"), std::string());
  ASSERT_EQ(d.status, VaultOutcome::kOk);
  EXPECT_FALSE(d.ops.empty());
  EXPECT_EQ(v.Doc(c.object)->Text(), "");
  ObjectId still;
  EXPECT_FALSE(v.ObjectAt("a.md", &still));
  EXPECT_NE(v.Doc(c.object), nullptr) << "the object itself was forgotten";
}

// THE REQUIREMENT: a case collision is detected and surfaced, never merged.
TEST(Vault, CaseCollisionIsSurfacedNotMerged) {
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome a = v.ApplyChange(Event(ChangeKind::kCreated, "Notes.md"), "A");
  ASSERT_EQ(a.status, VaultOutcome::kOk);

  ChangeOutcome b = v.ApplyChange(Event(ChangeKind::kCreated, "notes.md"), "B");
  EXPECT_EQ(b.status, VaultOutcome::kCaseCollision);
  EXPECT_EQ(b.colliding_path, "Notes.md");
  EXPECT_TRUE(b.ops.empty()) << "a collision still produced operations";
  // And nothing was merged: the first object is untouched and the second path
  // was not assigned.
  EXPECT_EQ(v.Doc(a.object)->Text(), "A");
  ObjectId other;
  EXPECT_FALSE(v.ObjectAt("notes.md", &other));
  EXPECT_EQ(v.ObjectCount(), 1u);
}

TEST(Vault, MoveIntoACaseCollisionIsRefused) {
  Vault v(ReplicaIdFromSeed(1));
  ASSERT_EQ(v.ApplyChange(Event(ChangeKind::kCreated, "Alpha.md"), "A").status,
            VaultOutcome::kOk);
  ChangeOutcome b = v.ApplyChange(Event(ChangeKind::kCreated, "beta.md"), "B");
  ASSERT_EQ(b.status, VaultOutcome::kOk);

  ChangeOutcome mv = v.ApplyChange(
      Event(ChangeKind::kMoved, "alpha.md", "beta.md"), std::string());
  EXPECT_EQ(mv.status, VaultOutcome::kCaseCollision);
  EXPECT_EQ(mv.colliding_path, "Alpha.md");
  ObjectId still;
  EXPECT_TRUE(v.ObjectAt("beta.md", &still)) << "a refused move moved anyway";
}

TEST(Vault, IdentityDoesNotDependOnCase) {
  // Two vaults that saw the same file under different spellings must not be
  // expected to agree on identity -- identity comes from entropy, not the path
  // -- but within one vault the two spellings are never the same object.
  Vault v(ReplicaIdFromSeed(1));
  ASSERT_EQ(v.ApplyChange(Event(ChangeKind::kCreated, "a.md"), "x").status,
            VaultOutcome::kOk);
  ObjectId lower;
  ASSERT_TRUE(v.ObjectAt("a.md", &lower));
  // The fold is what detects collisions and is ASCII only; stated in vault.h.
  EXPECT_EQ(Vault::FoldCase("Notes/A.MD"), "notes/a.md");
  EXPECT_EQ(Vault::FoldCase("Café.md"), "café.md")
      << "the fold is ASCII only, by design";
}

TEST(Vault, RefusesFilesThatAreNotUtf8) {
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c = v.ApplyChange(Event(ChangeKind::kCreated, "a.md"),
                                  std::string("\xC3\x28", 2));
  EXPECT_EQ(c.status, VaultOutcome::kNotUtf8);
  EXPECT_TRUE(c.ops.empty());
}

TEST(Vault, OperationsFromAVaultReplayThroughTheOpLog) {
  // The whole path end to end: a watcher event becomes operations, the
  // operations go into Basalt, and replaying Basalt reproduces the document.
  TempDir dir;
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::Open(dir.path() + "/db", &log), LogStatus::kOk);

  Vault v(ReplicaIdFromSeed(2));
  ChangeOutcome c =
      v.ApplyChange(Event(ChangeKind::kCreated, "n.md"), "# title\n\nbody");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  ASSERT_EQ(log->Append(c.object, c.ops), LogStatus::kOk);
  ChangeOutcome m = v.ApplyChange(Event(ChangeKind::kModified, "n.md"),
                                  "# title\n\nbody and more");
  ASSERT_EQ(m.status, VaultOutcome::kOk);
  ASSERT_EQ(log->Append(c.object, m.ops), LogStatus::kOk);
  ASSERT_EQ(log->Sync(), LogStatus::kOk);

  TextDoc rebuilt;
  std::map<ReplicaId, uint64_t> high;
  ASSERT_EQ(log->Replay(c.object, &rebuilt, &high), LogStatus::kOk);
  EXPECT_EQ(rebuilt.Text(), "# title\n\nbody and more");
  EXPECT_EQ(rebuilt.StateHash(), v.Doc(c.object)->StateHash());
}

}  // namespace
}  // namespace umbra
