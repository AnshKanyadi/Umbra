// The file-tree CRDT, close up.
//
// The convergence harness proves replicas agree under arbitrary schedules.
// These pin down what the tree should SAY, so that agreement is not satisfied
// by every replica being wrong together.
// <algorithm> for std::sort and std::next_permutation.
//
// NOT OPTIONAL, and the omission compiled everywhere I could test it by hand:
// libc++ pulls it in behind another header and so does libstdc++ under gcc.
// Only ubuntu clang, which is libstdc++ WITHOUT gcc's transitive includes,
// says so. That combination is in the matrix for exactly this.
#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "umbra/crdt/tree.h"

namespace umbra {
namespace {

ObjectId Obj(uint8_t a, uint8_t b = 0) {
  ObjectId id;
  id.bytes[0] = a;
  id.bytes[1] = b;
  // Keep clear of the reserved ids, which are all-zero but for the last byte.
  id.bytes[7] = 0xAA;
  return id;
}

LamportClock ClockFor(uint64_t seed) {
  return LamportClock(ReplicaIdFromSeed(seed));
}

// Apply every operation to every document. Tree operations are never
// not-ready, so one pass in any order is enough -- which is itself worth
// asserting, and is asserted below.
void ApplyAll(TreeDoc* t, const std::vector<TreeOp>& ops) {
  for (const TreeOp& op : ops) {
    const TreeApply r = t->Apply(op);
    ASSERT_NE(r, TreeApply::kMalformed) << op.ToString();
  }
}

std::string PathOr(const TreeDoc& t, const ObjectId& id, const char* fallback) {
  std::string p;
  return t.PathOf(id, &p) ? p : fallback;
}

// ------------------------------------------------------------------ basics

TEST(Tree, CreateRenameMoveDelete) {
  TreeDoc t;
  LamportClock c = ClockFor(1);
  const ObjectId dir = Obj(1);
  const ObjectId file = Obj(2);

  ASSERT_EQ(t.Apply(t.MakeMove(dir, TreeRoot(), "notes", true, &c)),
            TreeApply::kApplied);
  ASSERT_EQ(t.Apply(t.MakeMove(file, dir, "a.md", false, &c)),
            TreeApply::kApplied);
  EXPECT_EQ(PathOr(t, file, "?"), "notes/a.md");
  EXPECT_TRUE(t.IsDir(dir));
  EXPECT_FALSE(t.IsDir(file));

  // Rename: same parent, new name.
  ASSERT_EQ(t.Apply(t.MakeMove(file, dir, "b.md", false, &c)),
            TreeApply::kApplied);
  EXPECT_EQ(PathOr(t, file, "?"), "notes/b.md");

  // Move: new parent.
  const ObjectId other = Obj(3);
  ASSERT_EQ(t.Apply(t.MakeMove(other, TreeRoot(), "archive", true, &c)),
            TreeApply::kApplied);
  ASSERT_EQ(t.Apply(t.MakeMove(file, other, "b.md", false, &c)),
            TreeApply::kApplied);
  EXPECT_EQ(PathOr(t, file, "?"), "archive/b.md");

  // Delete: move to the trash. Not a separate operation.
  ASSERT_EQ(t.Apply(t.MakeMove(file, TreeTrash(), "b.md", false, &c)),
            TreeApply::kApplied);
  EXPECT_TRUE(t.IsDeleted(file));
  std::string p;
  EXPECT_FALSE(t.PathOf(file, &p)) << "a deleted node still has a path";
}

TEST(Tree, MovingADirectoryMovesItsSubtree) {
  TreeDoc t;
  LamportClock c = ClockFor(1);
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  const ObjectId deep = Obj(3);
  const ObjectId file = Obj(4);
  ASSERT_EQ(t.Apply(t.MakeMove(a, TreeRoot(), "a", true, &c)),
            TreeApply::kApplied);
  ASSERT_EQ(t.Apply(t.MakeMove(b, TreeRoot(), "b", true, &c)),
            TreeApply::kApplied);
  ASSERT_EQ(t.Apply(t.MakeMove(deep, a, "deep", true, &c)),
            TreeApply::kApplied);
  ASSERT_EQ(t.Apply(t.MakeMove(file, deep, "n.md", false, &c)),
            TreeApply::kApplied);
  ASSERT_EQ(PathOr(t, file, "?"), "a/deep/n.md");

  // ONE OPERATION moves the whole subtree, because a node names its parent
  // rather than its path.
  ASSERT_EQ(t.Apply(t.MakeMove(a, b, "a", true, &c)), TreeApply::kApplied);
  EXPECT_EQ(PathOr(t, file, "?"), "b/a/deep/n.md");
  EXPECT_EQ(t.LogSize(), 5u);
}

TEST(Tree, RefusesTheFixedPointsAndIllegalNames) {
  TreeDoc t;
  LamportClock c = ClockFor(1);
  const ObjectId a = Obj(1);
  EXPECT_EQ(t.Apply(t.MakeMove(TreeRoot(), a, "x", true, &c)),
            TreeApply::kMalformed);
  EXPECT_EQ(t.Apply(t.MakeMove(TreeTrash(), a, "x", true, &c)),
            TreeApply::kMalformed);
  EXPECT_EQ(t.Apply(t.MakeMove(a, a, "x", true, &c)), TreeApply::kMalformed);
  // A name is ONE path component. A separator would make the tree and the
  // filesystem disagree about the shape of the vault.
  EXPECT_EQ(t.Apply(t.MakeMove(a, TreeRoot(), "x/y", false, &c)),
            TreeApply::kMalformed);
  EXPECT_EQ(t.Apply(t.MakeMove(a, TreeRoot(), "", false, &c)),
            TreeApply::kMalformed);
  EXPECT_EQ(t.Apply(t.MakeMove(a, TreeRoot(), "..", false, &c)),
            TreeApply::kMalformed);
}

TEST(Tree, DuplicateDeliveryChangesNothing) {
  TreeDoc t;
  LamportClock c = ClockFor(1);
  const ObjectId a = Obj(1);
  const TreeOp op = t.MakeMove(a, TreeRoot(), "a", true, &c);
  EXPECT_EQ(t.Apply(op), TreeApply::kApplied);
  const std::string before = t.StateHash();
  EXPECT_EQ(t.Apply(op), TreeApply::kDuplicate);
  EXPECT_EQ(t.StateHash(), before);
}

// --------------------------------------------------------- THE CYCLE CASE

// Two replicas concurrently move A into B and B into A. This is the case naive
// designs get wrong.
TEST(Tree, ConcurrentMoveIntoEachOtherIsResolvedByIgnoringOne) {
  TreeDoc seed;
  LamportClock cs = ClockFor(9);
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  std::vector<TreeOp> base;
  base.push_back(seed.MakeMove(a, TreeRoot(), "a", true, &cs));
  base.push_back(seed.MakeMove(b, TreeRoot(), "b", true, &cs));
  ApplyAll(&seed, base);

  TreeDoc left;
  TreeDoc right;
  ApplyAll(&left, base);
  ApplyAll(&right, base);
  LamportClock cl = ClockFor(1);
  LamportClock cr = ClockFor(2);
  for (const TreeOp& op : base) {
    cl.Observe(op.id);
    cr.Observe(op.id);
  }

  // Concurrent and contradictory.
  const TreeOp a_into_b = left.MakeMove(a, b, "a", true, &cl);
  const TreeOp b_into_a = right.MakeMove(b, a, "b", true, &cr);
  ASSERT_EQ(left.Apply(a_into_b), TreeApply::kApplied);
  ASSERT_EQ(right.Apply(b_into_a), TreeApply::kApplied);

  // Exchange, in opposite orders.
  const TreeApply l = left.Apply(b_into_a);
  const TreeApply r = right.Apply(a_into_b);

  // EXACTLY ONE of the two is ignored, and both replicas ignore the same one --
  // the later timestamp, whichever order they learned of them in.
  EXPECT_EQ(left.StateHash(), right.StateHash())
      << "left:  " << PathOr(left, a, "-") << " " << PathOr(left, b, "-")
      << "\nright: " << PathOr(right, a, "-") << " " << PathOr(right, b, "-");

  // And the tree is intact: both nodes are still reachable, one nested in the
  // other. Neither vanished, which is what a cycle would have done.
  const std::string pa = PathOr(left, a, "");
  const std::string pb = PathOr(left, b, "");
  EXPECT_FALSE(pa.empty()) << "a became unreachable";
  EXPECT_FALSE(pb.empty()) << "b became unreachable";
  const bool a_under_b = pa == "b/a";
  const bool b_under_a = pb == "a/b";
  EXPECT_TRUE(a_under_b != b_under_a)
      << "exactly one move must survive; got a=" << pa << " b=" << pb;
  // One of the two applications reported the cycle.
  EXPECT_TRUE(l == TreeApply::kIgnoredCycle || r == TreeApply::kIgnoredCycle);
}

TEST(Tree, ADirectMoveIntoOwnDescendantIsIgnored) {
  TreeDoc t;
  LamportClock c = ClockFor(1);
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  ASSERT_EQ(t.Apply(t.MakeMove(a, TreeRoot(), "a", true, &c)),
            TreeApply::kApplied);
  ASSERT_EQ(t.Apply(t.MakeMove(b, a, "b", true, &c)), TreeApply::kApplied);
  EXPECT_TRUE(t.WouldCycle(a, b));
  EXPECT_EQ(t.Apply(t.MakeMove(a, b, "a", true, &c)), TreeApply::kIgnoredCycle);
  // IGNORED means unchanged, not repaired: a is still where it was.
  EXPECT_EQ(PathOr(t, a, "?"), "a");
  EXPECT_EQ(PathOr(t, b, "?"), "a/b");
}

TEST(Tree, AnIgnoredMoveCanApplyLaterUnderADifferentOrder) {
  // The reason ignored operations stay in the log. Replica L learns of a move
  // that is illegal in its current state, then learns of an older move that
  // makes it legal; the replay reconsiders it.
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  LamportClock c1 = ClockFor(1);
  LamportClock c2 = ClockFor(2);

  TreeDoc src;
  std::vector<TreeOp> ops;
  ops.push_back(src.MakeMove(a, TreeRoot(), "a", true, &c1));
  ops.push_back(src.MakeMove(b, a, "b", true, &c1));
  ApplyAll(&src, ops);
  // Later timestamp from a different replica: move b out to the root first...
  c2.Observe(ops.back().id);
  const TreeOp b_out = src.MakeMove(b, TreeRoot(), "b", true, &c2);
  // ...then a under b. Legal only once b is out.
  const TreeOp a_under_b = src.MakeMove(a, b, "a", true, &c2);
  ASSERT_EQ(src.Apply(b_out), TreeApply::kApplied);
  ASSERT_EQ(src.Apply(a_under_b), TreeApply::kApplied);

  // Deliver to a fresh replica in the WORST order: the last operation first.
  TreeDoc dst;
  EXPECT_EQ(dst.Apply(a_under_b), TreeApply::kApplied);
  EXPECT_EQ(dst.Apply(ops[0]), TreeApply::kApplied);
  EXPECT_EQ(dst.Apply(ops[1]), TreeApply::kApplied);
  EXPECT_EQ(dst.Apply(b_out), TreeApply::kApplied);
  EXPECT_EQ(dst.StateHash(), src.StateHash())
      << "reverse delivery reached a different tree";
}

TEST(Tree, ArrivalOrderDoesNotMatter) {
  // Tree operations are never not-ready. Every permutation of a fixed set must
  // produce the same tree.
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  const ObjectId f = Obj(3);
  LamportClock c1 = ClockFor(1);
  LamportClock c2 = ClockFor(2);

  TreeDoc src;
  std::vector<TreeOp> ops;
  ops.push_back(src.MakeMove(a, TreeRoot(), "a", true, &c1));
  ops.push_back(src.MakeMove(b, TreeRoot(), "b", true, &c2));
  ops.push_back(src.MakeMove(f, a, "n.md", false, &c1));
  ops.push_back(src.MakeMove(a, b, "a", true, &c2));
  ApplyAll(&src, ops);
  const std::string want = src.StateHash();
  ASSERT_EQ(PathOr(src, f, "?"), "b/a/n.md");

  std::vector<std::size_t> order{0, 1, 2, 3};
  int permutations = 0;
  std::sort(order.begin(), order.end());
  do {
    TreeDoc t;
    for (std::size_t i : order) {
      const TreeApply r = t.Apply(ops[i]);
      ASSERT_NE(r, TreeApply::kMalformed);
    }
    EXPECT_EQ(t.StateHash(), want) << "permutation " << permutations;
    ++permutations;
  } while (std::next_permutation(order.begin(), order.end()));
  EXPECT_EQ(permutations, 24);
}

TEST(Tree, MoveConcurrentWithDeleteOfTheDestination) {
  // Replica 1 moves a file into a directory; replica 2 deletes that directory.
  // Both are moves, so the later timestamp wins and both replicas agree.
  const ObjectId dir = Obj(1);
  const ObjectId file = Obj(2);
  LamportClock c1 = ClockFor(1);
  LamportClock c2 = ClockFor(2);

  TreeDoc base;
  std::vector<TreeOp> setup;
  setup.push_back(base.MakeMove(dir, TreeRoot(), "d", true, &c1));
  setup.push_back(base.MakeMove(file, TreeRoot(), "n.md", false, &c1));
  ApplyAll(&base, setup);

  TreeDoc left;
  TreeDoc right;
  ApplyAll(&left, setup);
  ApplyAll(&right, setup);
  for (const TreeOp& op : setup) c2.Observe(op.id);

  const TreeOp into = left.MakeMove(file, dir, "n.md", false, &c1);
  const TreeOp gone = right.MakeMove(dir, TreeTrash(), "d", true, &c2);
  ASSERT_EQ(left.Apply(into), TreeApply::kApplied);
  ASSERT_EQ(right.Apply(gone), TreeApply::kApplied);
  ASSERT_EQ(left.Apply(gone), TreeApply::kApplied);
  ASSERT_EQ(right.Apply(into), TreeApply::kApplied);

  EXPECT_EQ(left.StateHash(), right.StateHash());
  // The file went into a directory that was then deleted, so it is deleted too.
  // Both replicas say so; nothing is orphaned or resurrected.
  EXPECT_TRUE(left.IsDeleted(file));
  EXPECT_TRUE(left.IsDeleted(dir));
}

// ------------------------------------------------------- log compaction

TEST(TreeCompaction, DropsThePrefixAndAbsorbsItsRedelivery) {
  TreeDoc t;
  LamportClock c = ClockFor(1);
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  std::vector<TreeOp> ops;
  ops.push_back(t.MakeMove(a, TreeRoot(), "a", true, &c));
  ops.push_back(t.MakeMove(b, TreeRoot(), "b", true, &c));
  ops.push_back(t.MakeMove(b, a, "b", true, &c));
  ApplyAll(&t, ops);
  ASSERT_EQ(t.LogSize(), 3u);
  const std::string before = t.StateHash();

  // Drop the first two.
  EXPECT_EQ(t.CompactLog(2), 2u);
  EXPECT_EQ(t.LogSize(), 1u);
  EXPECT_EQ(t.StateHash(), before) << "compaction changed the visible tree";
  EXPECT_EQ(t.compacted_through(), 2u);

  // CLAUSE 5: re-delivery of a dropped operation must be absorbed, not
  // re-applied. Re-applying would undo the whole remaining log to make room.
  for (const TreeOp& op : ops) {
    if (op.id.counter > 2) continue;
    EXPECT_EQ(t.Apply(op), TreeApply::kDuplicate) << op.ToString();
  }
  EXPECT_EQ(t.StateHash(), before);
  EXPECT_EQ(t.LogSize(), 1u);
}

TEST(TreeCompaction, LeavesTheUndoRangeThatIsStillReachable) {
  // An operation arriving after compaction must still be able to undo
  // everything newer than itself, which is exactly what was kept.
  TreeDoc t;
  LamportClock c1 = ClockFor(1);
  LamportClock c2 = ClockFor(2);
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  std::vector<TreeOp> early;
  early.push_back(t.MakeMove(a, TreeRoot(), "a", true, &c1));
  early.push_back(t.MakeMove(b, TreeRoot(), "b", true, &c1));
  ApplyAll(&t, early);

  c2.Observe(early.back().id);
  const TreeOp late = t.MakeMove(a, b, "a", true, &c2);
  ASSERT_EQ(t.Apply(late), TreeApply::kApplied);
  ASSERT_EQ(PathOr(t, a, "?"), "b/a");

  EXPECT_EQ(t.CompactLog(2), 2u);

  // Now an operation between the compacted prefix and `late` arrives. It has a
  // counter above the mark, so it is legal, and undoing `late` is still
  // possible because `late` was kept.
  LamportClock c3 = ClockFor(3);
  c3.Observe(early.back().id);
  const TreeOp middle = t.MakeMove(b, TreeRoot(), "renamed", true, &c3);
  ASSERT_LT(middle.id.counter, late.id.counter + 1);
  const TreeApply r = t.Apply(middle);
  EXPECT_NE(r, TreeApply::kMalformed);
  // Whatever the outcome, the tree is intact and both nodes are reachable.
  EXPECT_FALSE(PathOr(t, a, "").empty());
  EXPECT_FALSE(PathOr(t, b, "").empty());
}

TEST(TreeCompaction, HaveMarksStopAtTheFirstGap) {
  TreeDoc t;
  const ReplicaId r = ReplicaIdFromSeed(1);
  LamportClock c(r);
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);
  const ObjectId d = Obj(3);
  const TreeOp o1 = t.MakeMove(a, TreeRoot(), "a", true, &c);
  const TreeOp o2 = t.MakeMove(b, TreeRoot(), "b", true, &c);
  const TreeOp o3 = t.MakeMove(d, TreeRoot(), "d", true, &c);
  ASSERT_EQ(t.Apply(o1), TreeApply::kApplied);
  // o2 is deliberately skipped: the device has 1 and 3 but not 2.
  ASSERT_EQ(t.Apply(o3), TreeApply::kApplied);

  const std::map<ReplicaId, uint64_t> marks = t.HaveMarks();
  ASSERT_EQ(marks.count(r), 1u);
  EXPECT_EQ(marks.at(r), 1u)
      << "the mark must be the contiguous prefix, not the highest held";

  ASSERT_EQ(t.Apply(o2), TreeApply::kApplied);
  EXPECT_EQ(t.HaveMarks().at(r), 3u) << "the gap closed and the mark did not";
}

TEST(TreeCompaction, TheWatermarkIsAMinimumOverEverything) {
  const ReplicaId d1 = ReplicaIdFromSeed(1);
  const ReplicaId d2 = ReplicaIdFromSeed(2);
  const std::vector<ReplicaId> enrolled{d1, d2};

  DeviceReport r1;
  r1.device = d1;
  r1.clock = 100;
  r1.have[d1] = 50;
  r1.have[d2] = 40;
  DeviceReport r2;
  r2.device = d2;
  r2.clock = 100;
  r2.have[d1] = 45;
  r2.have[d2] = 60;

  // acked[d1] = min(50,45) = 45; acked[d2] = min(40,60) = 40; clocks are 100.
  EXPECT_EQ(CompactionWatermark(enrolled, {r1, r2}), 40u);

  // A SLOW CLOCK CAPS IT, and this is the term ADR 0002's text condition does
  // not have. A device at clock 10 will issue counter 11 next; compacting to 40
  // would drop entries that operation needs to undo.
  DeviceReport slow = r2;
  slow.clock = 10;
  EXPECT_EQ(CompactionWatermark(enrolled, {r1, slow}), 10u);

  // A MISSING REPORT COLLAPSES IT. This is what a withholding relay can force,
  // and it is the safe direction.
  EXPECT_EQ(CompactionWatermark(enrolled, {r1}), 0u);
  EXPECT_EQ(CompactionWatermark(enrolled, {}), 0u);

  // A device that has never heard of a source that HAS produced counts as zero,
  // because it is genuinely behind.
  DeviceReport blind = r2;
  blind.have.erase(d1);
  EXPECT_EQ(CompactionWatermark(enrolled, {r1, blind}), 0u);
}

TEST(TreeCompaction, ASilentSourceDoesNotBlockTheWatermark) {
  // A device that has produced nothing imposes no constraint. Without this the
  // first implementation compacted nothing at all in 420 schedules, because
  // some replica always happened not to have touched the tree.
  const ReplicaId writer = ReplicaIdFromSeed(1);
  const ReplicaId silent = ReplicaIdFromSeed(2);
  const std::vector<ReplicaId> enrolled{writer, silent};

  DeviceReport w;
  w.device = writer;
  w.clock = 80;
  w.have[writer] = 60;  // it has produced and holds its own
  DeviceReport s;
  s.device = silent;
  s.clock = 80;
  s.have[writer] = 60;  // caught up on the writer, and produced nothing itself

  EXPECT_EQ(CompactionWatermark(enrolled, {w, s}), 60u);

  // But the silent device's CLOCK still binds it. A device sitting at 10 will
  // issue counter 11 next, which must not fall below the watermark.
  DeviceReport slow = s;
  slow.clock = 10;
  EXPECT_EQ(CompactionWatermark(enrolled, {w, slow}), 10u);
}

TEST(TreeCompaction, ReportsFromUnenrolledDevicesAreIgnored) {
  const ReplicaId d1 = ReplicaIdFromSeed(1);
  const ReplicaId stranger = ReplicaIdFromSeed(9);
  const std::vector<ReplicaId> enrolled{d1};
  DeviceReport r1;
  r1.device = d1;
  r1.clock = 30;
  r1.have[d1] = 30;
  DeviceReport rs;
  rs.device = stranger;
  rs.clock = 1;
  rs.have[d1] = 1;
  // A revoked device must not be able to hold compaction back forever, and an
  // unknown one must not be able to push it forward.
  EXPECT_EQ(CompactionWatermark(enrolled, {r1, rs}), 30u);
}

// C2 IN THE PHASE REPORT: THE CLOCK TERM IS REDUNDANT, AND THIS IS WHY.
//
// Removing the clock term from CompactionWatermark was run as a deliberate
// defect and the sweep stayed green -- correctly, not through a gap in the
// harness. The term cannot bind, given one invariant:
//
//     a device's Lamport clock is never below the counter of any operation it
//     holds, because applying one Observes its id.
//
// Given that, for any source S with produced[S] > 0 the watermark satisfies
//     w <= acked[S] <= have_D[S] <= clock_D
// for every device D, so min(clock_D) is never the smaller term.
//
// The term is KEPT anyway, for the reason the ignored-undo guard in tree.cc is
// kept: it is free, and it makes the condition survive a future change that
// breaks the invariant -- a device that could hold operations without applying
// them, say. What is not acceptable is leaving the invariant implicit, so this
// asserts it directly.
TEST(TreeCompaction, AClockIsNeverBelowTheMarksItReports) {
  TreeDoc t;
  const ReplicaId r = ReplicaIdFromSeed(1);
  LamportClock c(r);
  const ObjectId a = Obj(1);
  const ObjectId b = Obj(2);

  // A second replica whose operations this one receives.
  const ReplicaId other = ReplicaIdFromSeed(2);
  LamportClock oc(other);
  TreeDoc source;
  std::vector<TreeOp> theirs;
  theirs.push_back(source.MakeMove(a, TreeRoot(), "a", true, &oc));
  theirs.push_back(source.MakeMove(b, TreeRoot(), "b", true, &oc));
  ApplyAll(&source, theirs);

  for (const TreeOp& op : theirs) {
    ASSERT_EQ(t.Apply(op), TreeApply::kApplied);
    // This is what a real client must do on every applied operation, and the
    // invariant above depends on it.
    c.Observe(op.id);
  }
  const TreeOp mine = t.MakeMove(a, b, "a", true, &c);
  ASSERT_EQ(t.Apply(mine), TreeApply::kApplied);

  const std::map<ReplicaId, uint64_t> marks = t.HaveMarks();
  for (const std::map<ReplicaId, uint64_t>::value_type& kv : marks) {
    EXPECT_GE(c.counter(), kv.second)
        << "the clock is behind a mark this device reports, which would make "
           "the clock term in the watermark load-bearing";
  }

  // And the watermark computed for a single-device vault is exactly its marks,
  // never capped by the clock.
  DeviceReport rep;
  rep.device = r;
  rep.have = marks;
  rep.clock = c.counter();
  const uint64_t w = CompactionWatermark({r}, {rep});
  uint64_t lowest_mark = UINT64_MAX;
  for (const std::map<ReplicaId, uint64_t>::value_type& kv : marks) {
    const std::map<ReplicaId, uint64_t>::const_iterator own =
        marks.find(kv.first);
    if (kv.first == r && own != marks.end() && own->second > 0) {
      lowest_mark = std::min(lowest_mark, kv.second);
    }
  }
  EXPECT_EQ(w, lowest_mark == UINT64_MAX ? c.counter() : lowest_mark);
}

// ------------------------------------------------------------------- codec

TEST(TreeCodec, RoundTripsAndRefusesMalformed) {
  TreeOp op;
  op.id = OpId{5, ReplicaIdFromSeed(3)};
  op.child = Obj(7);
  op.parent = Obj(8);
  op.name = "a name with spaces.md";
  op.is_dir = false;
  TreeOp back;
  ASSERT_TRUE(DecodeTreeOp(EncodeTreeOp(op), &back));
  EXPECT_EQ(back.id, op.id);
  EXPECT_EQ(back.child, op.child);
  EXPECT_EQ(back.parent, op.parent);
  EXPECT_EQ(back.name, op.name);
  EXPECT_EQ(back.is_dir, op.is_dir);

  const OpPayload p = EncodeTreeOp(op);
  for (std::size_t cut = 1; cut < p.bytes.size(); ++cut) {
    EXPECT_FALSE(DecodeTreeOp(OpPayload{p.bytes.substr(0, cut)}, &back))
        << "accepted a payload truncated to " << cut;
  }
  EXPECT_FALSE(DecodeTreeOp(OpPayload{p.bytes + "x"}, &back))
      << "trailing junk";

  // A name with a separator must not survive a round trip: it would make the
  // tree and the filesystem disagree.
  TreeOp bad = op;
  bad.name = "a/b";
  EXPECT_FALSE(DecodeTreeOp(EncodeTreeOp(bad), &back));
}

}  // namespace
}  // namespace umbra
