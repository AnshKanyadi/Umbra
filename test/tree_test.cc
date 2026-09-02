// The file-tree CRDT, close up.
//
// The convergence harness proves replicas agree under arbitrary schedules.
// These pin down what the tree should SAY, so that agreement is not satisfied
// by every replica being wrong together.
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
