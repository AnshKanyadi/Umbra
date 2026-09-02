// The oplog in Basalt, and the vault that feeds it.
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <set>

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

TEST(OpLog, TreeOperationsShareTheKeyLayoutAndReplay) {
  TempDir dir;
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::Open(dir.path() + "/db", &log), LogStatus::kOk);

  TreeDoc src;
  LamportClock c(ReplicaIdFromSeed(4));
  ObjectId d;
  d.bytes[0] = 0x11;
  d.bytes[7] = 0xAA;
  ObjectId f;
  f.bytes[0] = 0x22;
  f.bytes[7] = 0xAA;
  std::vector<TreeOp> ops;
  ops.push_back(src.MakeMove(d, TreeRoot(), "notes", true, &c));
  ops.push_back(src.MakeMove(f, d, "a.md", false, &c));
  ops.push_back(src.MakeMove(f, TreeRoot(), "a.md", false, &c));
  for (const TreeOp& op : ops) ASSERT_EQ(src.Apply(op), TreeApply::kApplied);

  ASSERT_EQ(log->AppendTree(ops), LogStatus::kOk);
  ASSERT_EQ(log->Sync(), LogStatus::kOk);

  TreeDoc rebuilt;
  std::map<ReplicaId, uint64_t> high;
  ASSERT_EQ(log->ReplayTree(&rebuilt, &high), LogStatus::kOk);
  EXPECT_EQ(rebuilt.StateHash(), src.StateHash());
  EXPECT_EQ(high[ReplicaIdFromSeed(4)], c.counter());

  // THE SAME KEY LAYOUT. Tree operations are filed under a reserved object id,
  // so a raw read of that object finds them and a read of any other does not.
  std::vector<LoggedOp> raw;
  ASSERT_EQ(log->ReadRaw(TreeObject(), &raw), LogStatus::kOk);
  EXPECT_EQ(raw.size(), 3u);
  for (const LoggedOp& l : raw) {
    TreeOp decoded;
    EXPECT_TRUE(DecodeTreeOp(l.payload, &decoded))
        << "a stored tree payload did not decode";
    EXPECT_EQ(decoded.id, l.id)
        << "the key and the payload disagree on identity";
  }
  std::vector<LoggedOp> other;
  ObjectId unrelated;
  unrelated.bytes[0] = 0x99;
  ASSERT_EQ(log->ReadRaw(unrelated, &other), LogStatus::kOk);
  EXPECT_TRUE(other.empty()) << "tree operations leaked into another object";
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

TEST(Vault, DeleteIsATreeMoveAndLeavesTheTextAlone) {
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c = v.ApplyChange(Event(ChangeKind::kCreated, "a.md"), "gone");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  ChangeOutcome d =
      v.ApplyChange(Event(ChangeKind::kDeleted, "a.md"), std::string());
  ASSERT_EQ(d.status, VaultOutcome::kOk);

  // ONE TREE OPERATION, ZERO TEXT OPERATIONS. Phase 1 emptied the document,
  // which was the only way a flat path map could say "gone". The tree says it
  // now, and saying it twice would mean a restore produced an empty file --
  // see the restore test below.
  EXPECT_EQ(d.tree_ops.size(), 1u);
  EXPECT_TRUE(d.ops.empty()) << "a delete produced text operations";
  EXPECT_EQ(v.Doc(c.object)->Text(), "gone") << "the text was destroyed";

  ObjectId still;
  EXPECT_FALSE(v.ObjectAt("a.md", &still)) << "the path still resolves";
  EXPECT_TRUE(v.tree().IsDeleted(c.object));
  EXPECT_NE(v.Doc(c.object), nullptr) << "the object itself was forgotten";
}

TEST(Vault, ADeletedFileCanBeRestoredWithItsContent) {
  // The reason a delete must not empty the document: a delete is a move to the
  // trash, and a move back out is a move. If the delete had emptied the text,
  // this would restore an empty file.
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c =
      v.ApplyChange(Event(ChangeKind::kCreated, "a.md"), "still here");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  ASSERT_EQ(
      v.ApplyChange(Event(ChangeKind::kDeleted, "a.md"), std::string()).status,
      VaultOutcome::kOk);
  ASSERT_TRUE(v.tree().IsDeleted(c.object));

  // Move it back out of the trash directly through the tree, as a peer's
  // undelete would arrive.
  LamportClock* clock = v.clock();
  TreeDoc scratch;
  TreeOp back;
  back.id = clock->Tick(1);
  back.child = c.object;
  back.parent = TreeRoot();
  back.name = "a.md";
  back.is_dir = false;
  ASSERT_EQ(v.ApplyTreeOp(back), TreeApply::kApplied);

  ObjectId at;
  ASSERT_TRUE(v.ObjectAt("a.md", &at));
  EXPECT_EQ(at, c.object);
  EXPECT_EQ(v.Doc(c.object)->Text(), "still here");
}

TEST(Vault, CreateInsideNestedDirectoriesMakesThePath) {
  // The watcher reports the file, not the directories above it: a mkdir -p and
  // a write arrive as one create. The tree needs the parents, so the vault
  // makes them, and each one is an ordinary tree operation another device can
  // merge.
  Vault v(ReplicaIdFromSeed(1));
  ChangeOutcome c =
      v.ApplyChange(Event(ChangeKind::kCreated, "a/b/c/n.md"), "deep");
  ASSERT_EQ(c.status, VaultOutcome::kOk);
  EXPECT_EQ(c.tree_ops.size(), 4u) << "three directories and the file";
  ObjectId at;
  ASSERT_TRUE(v.ObjectAt("a/b/c/n.md", &at));
  EXPECT_EQ(v.Doc(at)->Text(), "deep");
  ObjectId dir;
  ASSERT_TRUE(v.ObjectAt("a/b", &dir));
  EXPECT_TRUE(v.tree().IsDir(dir));
}

TEST(Vault, MovingADirectoryMovesEveryFileUnderIt) {
  Vault v(ReplicaIdFromSeed(1));
  ASSERT_EQ(v.ApplyChange(Event(ChangeKind::kCreated, "old/n.md"), "x").status,
            VaultOutcome::kOk);
  ASSERT_EQ(v.ApplyChange(Event(ChangeKind::kCreated, "old/m.md"), "y").status,
            VaultOutcome::kOk);
  ObjectId n;
  ASSERT_TRUE(v.ObjectAt("old/n.md", &n));

  ChangeOutcome mv =
      v.ApplyChange(Event(ChangeKind::kMoved, "new", "old"), std::string());
  ASSERT_EQ(mv.status, VaultOutcome::kOk);
  // ONE tree operation for the whole subtree, and no text operations.
  EXPECT_EQ(mv.tree_ops.size(), 1u);
  EXPECT_TRUE(mv.ops.empty());

  ObjectId still;
  EXPECT_TRUE(v.ObjectAt("new/n.md", &still));
  EXPECT_EQ(still, n) << "a file under a moved directory changed identity";
  EXPECT_EQ(v.Doc(n)->Text(), "x");
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

// A vault seeded from a log or from a peer must not reissue counters it has
// already seen. This is the defect the first end-to-end run hit: three tree
// operations were produced for one round, every one of them at counter 1, and
// because the oplog is keyed by object||replica||counter the last write won and
// a file disappeared. The test asserts the counters are distinct rather than
// asserting the clock's value, because distinctness is the property the log
// actually depends on.
TEST(Vault, ASeededVaultDoesNotReissueCountersItHasSeen) {
  const ReplicaId r = NewReplicaId();
  Vault a(r);

  ChangeEvent e1;
  e1.kind = ChangeKind::kCreated;
  e1.path = "notes/one.md";
  const ChangeOutcome c1 = a.ApplyChange(e1, "first\n");
  ASSERT_EQ(c1.status, VaultOutcome::kOk);
  ASSERT_FALSE(c1.tree_ops.empty());

  // A second vault for the SAME replica, rebuilt from what the first produced,
  // as a client does on every start.
  Vault b(r);
  for (const TreeOp& op : c1.tree_ops)
    EXPECT_NE(b.ApplyTreeOp(op), TreeApply::kMalformed);
  for (const Op& op : c1.ops)
    EXPECT_NE(b.ApplyOp(c1.object, op), ApplyResult::kMalformed);

  ChangeEvent e2;
  e2.kind = ChangeKind::kCreated;
  e2.path = "notes/two.md";
  const ChangeOutcome c2 = b.ApplyChange(e2, "second\n");
  ASSERT_EQ(c2.status, VaultOutcome::kOk);

  std::set<uint64_t> seen;
  for (const TreeOp& op : c1.tree_ops)
    EXPECT_TRUE(seen.insert(op.id.counter).second);
  for (const TreeOp& op : c2.tree_ops) {
    EXPECT_TRUE(seen.insert(op.id.counter).second)
        << "tree counter " << op.id.counter << " was reissued after a replay";
  }
}

// The same property for text: a document rebuilt from its own operations must
// continue the counter sequence rather than restart it.
TEST(Vault, ASeededDocumentContinuesItsCounterSequence) {
  const ReplicaId r = NewReplicaId();
  Vault a(r);
  ChangeEvent e;
  e.kind = ChangeKind::kCreated;
  e.path = "n.md";
  const ChangeOutcome first = a.ApplyChange(e, "ab");
  ASSERT_EQ(first.status, VaultOutcome::kOk);

  Vault b(r);
  for (const TreeOp& op : first.tree_ops) (void)b.ApplyTreeOp(op);
  for (const Op& op : first.ops) (void)b.ApplyOp(first.object, op);

  ChangeEvent m;
  m.kind = ChangeKind::kModified;
  m.path = "n.md";
  const ChangeOutcome second = b.ApplyChange(m, "abc");
  ASSERT_EQ(second.status, VaultOutcome::kOk);
  ASSERT_FALSE(second.ops.empty());

  uint64_t highest = 0;
  for (const Op& op : first.ops) highest = std::max(highest, op.id.counter);
  for (const Op& op : second.ops) {
    EXPECT_GT(op.id.counter, highest)
        << "text counter " << op.id.counter << " was reissued after a replay";
  }
}

// The oplog is keyed by object||replica||counter, so reading an object back
// yields every operation from one replica, then every operation from the next.
// THAT IS NOT CAUSAL ORDER. A replica whose id sorts low can hold an insert
// whose parent belongs to a replica whose id sorts high, and that insert comes
// back before the node it hangs from.
//
// text_doc.h says kNotReady means hold it and retry. A client that instead
// drops it replays a shorter document than the one it had in memory, writes
// that to disk, and the next scan reads the difference back as a local edit --
// which is how a line came to be inserted twice and why two devices produced
// operations every round without ever settling. cmd/sync_main.cc RebuildFromLog
// is the retry loop; this is the property it exists for.
TEST(OpLog, ReplayingInLogOrderNeedsARetryPass) {
  TempDir dir;
  std::unique_ptr<OpLog> log;
  ASSERT_EQ(OpLog::Open(dir.path(), &log), LogStatus::kOk);

  // Chosen, not random: the replica that DEPENDS sorts first, so the log hands
  // its operation back before the one it needs.
  ReplicaId later;    // writes first, sorts second
  ReplicaId earlier;  // writes second, sorts first
  later.bytes.fill(0x02);
  earlier.bytes.fill(0x01);
  ASSERT_TRUE(earlier < later);

  const ObjectId object = ObjectFromSeed(42);

  TextDoc first;
  LamportClock c1(later);
  std::vector<Op> ops_later;
  ASSERT_TRUE(first.LocalInsert(0, "hello", &c1, &ops_later));

  // The second replica has seen the first, so its insert hangs off a node the
  // first replica created.
  TextDoc second;
  LamportClock c2(earlier);
  for (const Op& op : ops_later) {
    ASSERT_EQ(second.Apply(op), ApplyResult::kApplied);
    c2.Observe(LastId(op));
  }
  std::vector<Op> ops_earlier;
  ASSERT_TRUE(second.LocalInsert(5, " world", &c2, &ops_earlier));
  const std::string want = second.Text();
  ASSERT_EQ(want, "hello world");

  ASSERT_EQ(log->Append(object, ops_later), LogStatus::kOk);
  ASSERT_EQ(log->Append(object, ops_earlier), LogStatus::kOk);
  ASSERT_EQ(log->Sync(), LogStatus::kOk);

  std::vector<Op> in_log_order;
  ASSERT_EQ(log->ReadObject(object, &in_log_order), LogStatus::kOk);
  ASSERT_EQ(in_log_order.size(), ops_later.size() + ops_earlier.size());
  EXPECT_EQ(in_log_order.front().id.replica, earlier)
      << "the log did not order by replica, so this test proves nothing";

  // One pass, dropping what is not ready: this is the defect.
  {
    TextDoc naive;
    std::size_t not_ready = 0;
    for (const Op& op : in_log_order) {
      if (naive.Apply(op) == ApplyResult::kNotReady) ++not_ready;
    }
    EXPECT_GT(not_ready, 0u)
        << "no operation arrived early; the case is not set up";
    EXPECT_NE(naive.Text(), want)
        << "a single pass happened to be enough, so the retry loop is untested";
  }

  // The retry loop, which is what the client does.
  {
    TextDoc doc;
    std::vector<Op> pending = in_log_order;
    for (;;) {
      std::vector<Op> again;
      std::size_t applied = 0;
      for (const Op& op : pending) {
        const ApplyResult r = doc.Apply(op);
        if (r == ApplyResult::kApplied || r == ApplyResult::kDuplicate) {
          ++applied;
        } else if (r == ApplyResult::kNotReady) {
          again.push_back(op);
        }
      }
      if (again.empty() || applied == 0) break;
      pending.swap(again);
    }
    EXPECT_EQ(doc.Text(), want);
  }
}

}  // namespace umbra
