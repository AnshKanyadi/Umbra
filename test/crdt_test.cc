// The CRDT's own behaviour, close up.
//
// The convergence harness (sim/) is what proves replicas agree under arbitrary
// schedules. These tests are the other half: they pin down what the document
// should SAY, so that "all replicas agree" is not satisfied by all of them
// being wrong together.
#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "umbra/crdt/op.h"
#include "umbra/crdt/op_id.h"
#include "umbra/crdt/text_doc.h"
#include "utf8.h"

namespace umbra {
namespace {

LamportClock ClockFor(uint64_t seed) {
  return LamportClock(ReplicaIdFromSeed(seed));
}

// Applies every op to every doc, in the given order, until nothing more can be
// applied. Ops that are not ready are retried; this is the minimum a delivery
// layer must do and the harness does the same thing with schedules.
void ApplyAll(TextDoc* doc, std::vector<Op> ops) {
  bool progress = true;
  while (progress && !ops.empty()) {
    progress = false;
    std::vector<Op> deferred;
    for (const Op& op : ops) {
      const ApplyResult r = doc->Apply(op);
      if (r == ApplyResult::kNotReady) {
        deferred.push_back(op);
      } else {
        ASSERT_NE(r, ApplyResult::kMalformed) << op.ToString();
        progress = true;
      }
    }
    ops.swap(deferred);
  }
  ASSERT_TRUE(ops.empty()) << "operations never became ready";
}

// ------------------------------------------------------------------- utf8

TEST(Utf8, RoundTripsAcrossPlanes) {
  const std::string in = "aé中\U0001F600 # heading\n";
  std::vector<char32_t> cp;
  ASSERT_TRUE(Utf8Decode(in, &cp));
  EXPECT_EQ(Utf8Encode(cp), in);
  // One node per CHARACTER, not per byte: the emoji is four bytes and one
  // element.
  EXPECT_EQ(cp.size(), 15u);
}

TEST(Utf8, RefusesMalformedRatherThanReplacing) {
  std::vector<char32_t> cp;
  EXPECT_FALSE(Utf8Decode(std::string("\xC3", 1), &cp)) << "truncated";
  EXPECT_FALSE(Utf8Decode(std::string("\x80", 1), &cp)) << "stray continuation";
  EXPECT_FALSE(Utf8Decode(std::string("\xC0\xAF", 2), &cp)) << "overlong slash";
  EXPECT_FALSE(Utf8Decode(std::string("\xE0\x80\xAF", 3), &cp)) << "overlong";
  EXPECT_FALSE(Utf8Decode(std::string("\xED\xA0\x80", 3), &cp)) << "surrogate";
  EXPECT_FALSE(Utf8Decode(std::string("\xF5\x80\x80\x80", 4), &cp))
      << "> U+10FFFF";
  EXPECT_TRUE(Utf8Decode("ok", &cp));
}

// ------------------------------------------------------------------ codec

TEST(OpCodec, RoundTripsInsertAndDelete) {
  Op ins;
  ins.kind = OpKind::kInsert;
  ins.id = OpId{7, ReplicaIdFromSeed(1)};
  ins.parent = OpId{3, ReplicaIdFromSeed(2)};
  ins.side = Side::kLeft;
  ins.text = {U'h', U'i', U'\U0001F600'};
  Op back;
  ASSERT_TRUE(DecodeOp(EncodeOp(ins), &back));
  EXPECT_EQ(back.kind, ins.kind);
  EXPECT_EQ(back.id, ins.id);
  EXPECT_EQ(back.parent, ins.parent);
  EXPECT_EQ(back.side, ins.side);
  EXPECT_EQ(back.text, ins.text);

  Op del;
  del.kind = OpKind::kDelete;
  del.id = OpId{9, ReplicaIdFromSeed(3)};
  del.target = OpId{2, ReplicaIdFromSeed(4)};
  del.count = 4;
  ASSERT_TRUE(DecodeOp(EncodeOp(del), &back));
  EXPECT_EQ(back.kind, del.kind);
  EXPECT_EQ(back.id, del.id);
  EXPECT_EQ(back.target, del.target)
      << "a delete's own identity and its target are different things";
  EXPECT_EQ(back.count, del.count);
}

TEST(OpCodec, EncodingIsCanonical) {
  // The same operation must produce the same bytes every time and on every
  // replica; otherwise two logs holding the same operation would not compare
  // equal. Built twice from separate objects rather than copied.
  Op a;
  a.kind = OpKind::kInsert;
  a.id = OpId{5, ReplicaIdFromSeed(11)};
  a.parent = RootId();
  a.side = Side::kRight;
  a.text = {U'x', U'y'};
  Op b = a;
  EXPECT_EQ(EncodeOp(a).bytes, EncodeOp(b).bytes);
}

TEST(OpCodec, RefusesMalformedPayloads) {
  Op op;
  EXPECT_FALSE(DecodeOp(OpPayload{""}, &op)) << "empty";
  EXPECT_FALSE(DecodeOp(OpPayload{std::string("\x02", 1)}, &op))
      << "bad version";

  Op good;
  good.kind = OpKind::kDelete;
  good.id = OpId{1, ReplicaIdFromSeed(1)};
  good.target = OpId{1, ReplicaIdFromSeed(2)};
  good.count = 1;
  const OpPayload p = EncodeOp(good);
  EXPECT_TRUE(DecodeOp(p, &op));
  // Truncation must be refused, not partially read.
  for (std::size_t cut = 1; cut < p.bytes.size(); ++cut) {
    EXPECT_FALSE(DecodeOp(OpPayload{p.bytes.substr(0, cut)}, &op))
        << "accepted a payload truncated to " << cut;
  }
  // Trailing junk means the payload is not what we think it is.
  EXPECT_FALSE(DecodeOp(OpPayload{p.bytes + "x"}, &op));
  // A delete of nothing is not an operation.
  Op zero = good;
  zero.count = 0;
  OpPayload z = EncodeOp(zero);
  EXPECT_FALSE(DecodeOp(z, &op));
}

// --------------------------------------------------------------- basics

TEST(TextDoc, InsertsAndRenders) {
  TextDoc d;
  LamportClock c = ClockFor(1);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "hello", &c, &ops));
  EXPECT_EQ(d.Text(), "hello");
  ASSERT_TRUE(d.LocalInsert(5, " world", &c, &ops));
  EXPECT_EQ(d.Text(), "hello world");
  ASSERT_TRUE(d.LocalInsert(0, ">> ", &c, &ops));
  EXPECT_EQ(d.Text(), ">> hello world");
  EXPECT_EQ(d.Length(), 14u);
}

TEST(TextDoc, DeletesLeaveTombstonesAndAreIdempotent) {
  TextDoc d;
  LamportClock c = ClockFor(1);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "abcdef", &c, &ops));
  ops.clear();
  ASSERT_TRUE(d.LocalDelete(1, 3, &c, &ops));
  EXPECT_EQ(d.Text(), "aef");
  EXPECT_EQ(d.TombstoneCount(), 3u);
  // Re-delivery changes nothing.
  for (const Op& op : ops) EXPECT_EQ(d.Apply(op), ApplyResult::kDuplicate);
  EXPECT_EQ(d.Text(), "aef");
}

TEST(TextDoc, TypingForwardIsOneRunOperation) {
  // A contiguous run costs one operation whatever its length, because the run's
  // internal shape is implied.
  TextDoc d;
  LamportClock c = ClockFor(1);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "the quick brown fox", &c, &ops));
  EXPECT_EQ(ops.size(), 1u);
  EXPECT_EQ(ops[0].text.size(), 19u);
}

TEST(TextDoc, DeleteWithinOneReplicasIdsIsOneOperation) {
  // Two runs typed by ONE replica take consecutive ids, so a delete spanning
  // the boundary is still one operation. Grouping is by consecutive ids, not by
  // which insert produced them, and that is the useful thing to group by.
  TextDoc d;
  LamportClock c = ClockFor(1);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "abc", &c, &ops));
  ASSERT_TRUE(d.LocalInsert(3, "xyz", &c, &ops));
  ops.clear();
  ASSERT_TRUE(d.LocalDelete(2, 2, &c, &ops));  // 'c' then 'x': ids 3 and 4
  EXPECT_EQ(d.Text(), "abyz");
  EXPECT_EQ(ops.size(), 1u);
  EXPECT_EQ(ops[0].count, 2u);
}

TEST(TextDoc, DeleteAcrossTwoReplicasIdsBecomesTwoOperations) {
  // Text from two replicas cannot share an id run, so a delete across the seam
  // must split. This is the ordinary case: removing a span that covers your own
  // text and a peer's.
  TextDoc d;
  LamportClock ca = ClockFor(1);
  LamportClock cb = ClockFor(2);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "abc", &ca, &ops));
  ASSERT_TRUE(d.LocalInsert(3, "xyz", &cb, &ops));
  ASSERT_EQ(d.Text(), "abcxyz");
  ops.clear();
  ASSERT_TRUE(d.LocalDelete(2, 2, &ca, &ops));  // 'c' from A, 'x' from B
  EXPECT_EQ(d.Text(), "abyz");
  EXPECT_EQ(ops.size(), 2u)
      << "a delete across two replicas' ids is two operations";
}

TEST(TextDoc, RejectsInvalidUtf8Input) {
  TextDoc d;
  LamportClock c = ClockFor(1);
  std::vector<Op> ops;
  EXPECT_FALSE(d.LocalInsert(0, std::string("\xC3", 1), &c, &ops));
  EXPECT_EQ(d.Length(), 0u);
}

TEST(TextDoc, OutOfRangePositionsAreRefused) {
  TextDoc d;
  LamportClock c = ClockFor(1);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "abc", &c, &ops));
  EXPECT_FALSE(d.LocalInsert(9, "x", &c, &ops));
  EXPECT_FALSE(d.LocalDelete(2, 5, &c, &ops));
  EXPECT_EQ(d.Text(), "abc");
}

// ------------------------------------------------------- causal readiness

TEST(TextDoc, OperationOutOfOrderIsNotReadyThenApplies) {
  TextDoc src;
  LamportClock c = ClockFor(1);
  std::vector<Op> ops;
  ASSERT_TRUE(src.LocalInsert(0, "ab", &c, &ops));
  ASSERT_TRUE(src.LocalInsert(2, "cd", &c, &ops));
  ASSERT_EQ(ops.size(), 2u);

  TextDoc dst;
  // The second operation names the first's last character as its parent.
  EXPECT_EQ(dst.Apply(ops[1]), ApplyResult::kNotReady);
  EXPECT_EQ(dst.Apply(ops[0]), ApplyResult::kApplied);
  EXPECT_EQ(dst.Apply(ops[1]), ApplyResult::kApplied);
  EXPECT_EQ(dst.Text(), "abcd");
}

TEST(TextDoc, DeleteOfUnseenTargetIsNotReady) {
  TextDoc src;
  LamportClock c = ClockFor(1);
  std::vector<Op> ins;
  ASSERT_TRUE(src.LocalInsert(0, "abc", &c, &ins));
  std::vector<Op> del;
  ASSERT_TRUE(src.LocalDelete(0, 1, &c, &del));

  TextDoc dst;
  EXPECT_EQ(dst.Apply(del[0]), ApplyResult::kNotReady);
  EXPECT_EQ(dst.Apply(ins[0]), ApplyResult::kApplied);
  EXPECT_EQ(dst.Apply(del[0]), ApplyResult::kApplied);
  EXPECT_EQ(dst.Text(), "bc");
}

// ------------------------------------------------------------ INTERLEAVING
//
// The property Fugue is chosen for. Two replicas type a run at the same
// position with no knowledge of each other; the merge must contain each run
// CONTIGUOUSLY, in one order or the other, and never alternate between them.

// Returns true if `whole` contains `run` as a contiguous substring.
bool Contiguous(const std::string& whole, const std::string& run) {
  return whole.find(run) != std::string::npos;
}

TEST(Interleaving, ConcurrentForwardRunsDoNotInterleave) {
  TextDoc a;
  TextDoc b;
  LamportClock ca = ClockFor(1);
  LamportClock cb = ClockFor(2);
  std::vector<Op> oa;
  std::vector<Op> ob;
  ASSERT_TRUE(a.LocalInsert(0, "aaaa", &ca, &oa));
  ASSERT_TRUE(b.LocalInsert(0, "bbbb", &cb, &ob));

  ApplyAll(&a, ob);
  ApplyAll(&b, oa);
  EXPECT_EQ(a.Text(), b.Text());
  EXPECT_EQ(a.Text().size(), 8u);
  EXPECT_TRUE(Contiguous(a.Text(), "aaaa")) << a.Text();
  EXPECT_TRUE(Contiguous(a.Text(), "bbbb")) << a.Text();
}

TEST(Interleaving, ConcurrentBackwardRunsDoNotInterleave) {
  // TYPED BACKWARD: each character is inserted at the SAME index, so every one
  // of them has the same left origin. This is the shape that interleaves under
  // RGA, and it is why the tree has sides. See docs/adr/0002-crdt.md.
  TextDoc seed;
  LamportClock cs = ClockFor(9);
  std::vector<Op> base;
  ASSERT_TRUE(seed.LocalInsert(0, "<>", &cs, &base));

  TextDoc a;
  TextDoc b;
  ApplyAll(&a, base);
  ApplyAll(&b, base);
  LamportClock ca = ClockFor(1);
  LamportClock cb = ClockFor(2);
  for (const Op& op : base) {
    ca.Observe(op.id);
    cb.Observe(op.id);
  }

  std::vector<Op> oa;
  std::vector<Op> ob;
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(a.LocalInsert(1, "a", &ca, &oa));
    ASSERT_TRUE(b.LocalInsert(1, "b", &cb, &ob));
  }
  ASSERT_EQ(a.Text(), "<aaaa>");
  ASSERT_EQ(b.Text(), "<bbbb>");

  ApplyAll(&a, ob);
  ApplyAll(&b, oa);
  EXPECT_EQ(a.Text(), b.Text());
  EXPECT_EQ(a.Text().size(), 10u);
  EXPECT_TRUE(Contiguous(a.Text(), "aaaa")) << "interleaved: " << a.Text();
  EXPECT_TRUE(Contiguous(a.Text(), "bbbb")) << "interleaved: " << a.Text();
}

TEST(Interleaving, ThreeConcurrentRunsEachStayContiguous) {
  TextDoc a;
  TextDoc b;
  TextDoc c;
  LamportClock ca = ClockFor(1);
  LamportClock cb = ClockFor(2);
  LamportClock cc = ClockFor(3);
  std::vector<Op> oa;
  std::vector<Op> ob;
  std::vector<Op> oc;
  ASSERT_TRUE(a.LocalInsert(0, "aaa", &ca, &oa));
  ASSERT_TRUE(b.LocalInsert(0, "bbb", &cb, &ob));
  ASSERT_TRUE(c.LocalInsert(0, "ccc", &cc, &oc));

  std::vector<Op> all;
  all.insert(all.end(), oa.begin(), oa.end());
  all.insert(all.end(), ob.begin(), ob.end());
  all.insert(all.end(), oc.begin(), oc.end());
  ApplyAll(&a, all);
  ApplyAll(&b, all);
  ApplyAll(&c, all);
  EXPECT_EQ(a.Text(), b.Text());
  EXPECT_EQ(b.Text(), c.Text());
  EXPECT_TRUE(Contiguous(a.Text(), "aaa")) << a.Text();
  EXPECT_TRUE(Contiguous(a.Text(), "bbb")) << a.Text();
  EXPECT_TRUE(Contiguous(a.Text(), "ccc")) << a.Text();
}

// ------------------------------------------------------------- compaction

TEST(Compaction, DropsStableLeafTombstonesOnly) {
  TextDoc d;
  const ReplicaId r = ReplicaIdFromSeed(1);
  LamportClock c(r);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "abcdef", &c, &ops));
  std::vector<Op> del;
  ASSERT_TRUE(d.LocalDelete(5, 1, &c, &del));  // the last character: a leaf
  ASSERT_EQ(d.Text(), "abcde");
  ASSERT_EQ(d.NodeCount(), 6u);

  // A watermark that does not cover the delete's target drops nothing.
  std::map<ReplicaId, uint64_t> low;
  low[r] = 1;
  EXPECT_EQ(d.Compact(low), 0u);
  EXPECT_EQ(d.NodeCount(), 6u);

  std::map<ReplicaId, uint64_t> high;
  high[r] = 1000;
  EXPECT_EQ(d.Compact(high), 1u);
  EXPECT_EQ(d.NodeCount(), 5u);
  EXPECT_EQ(d.Text(), "abcde");
}

TEST(Compaction, WillNotDropATombstoneThatStillAnchorsSomething) {
  // 'b' is deleted but 'c' hangs off it. Dropping 'b' would move 'c'.
  TextDoc d;
  const ReplicaId r = ReplicaIdFromSeed(1);
  LamportClock c(r);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "abc", &c, &ops));
  std::vector<Op> del;
  ASSERT_TRUE(d.LocalDelete(1, 1, &c, &del));
  ASSERT_EQ(d.Text(), "ac");

  std::map<ReplicaId, uint64_t> high;
  high[r] = 1000;
  EXPECT_EQ(d.Compact(high), 0u) << "dropped an anchor";
  EXPECT_EQ(d.Text(), "ac");
}

TEST(Compaction, ChainsCollapseFromTheOutsideIn) {
  TextDoc d;
  const ReplicaId r = ReplicaIdFromSeed(1);
  LamportClock c(r);
  std::vector<Op> ops;
  ASSERT_TRUE(d.LocalInsert(0, "abcd", &c, &ops));
  std::vector<Op> del;
  ASSERT_TRUE(
      d.LocalDelete(1, 3, &c, &del));  // b, c and d: a chain of tombstones
  ASSERT_EQ(d.Text(), "a");

  std::map<ReplicaId, uint64_t> high;
  high[r] = 1000;
  // One call does as much as it can: d is a leaf, then c becomes one, then b.
  EXPECT_EQ(d.Compact(high), 3u);
  EXPECT_EQ(d.NodeCount(), 1u);
  EXPECT_EQ(d.Text(), "a");
}

TEST(Compaction, DoesNotChangeTheVisibleDocument) {
  TextDoc a;
  const ReplicaId r = ReplicaIdFromSeed(4);
  LamportClock c(r);
  std::vector<Op> ops;
  ASSERT_TRUE(a.LocalInsert(0, "hello world", &c, &ops));
  std::vector<Op> del;
  ASSERT_TRUE(a.LocalDelete(5, 6, &c, &del));
  const std::string before = a.Text();
  const std::string hash_before = a.StateHash();

  std::map<ReplicaId, uint64_t> high;
  high[r] = 1000;
  a.Compact(high);
  EXPECT_EQ(a.Text(), before);
  EXPECT_EQ(a.StateHash(), hash_before);
}

}  // namespace
}  // namespace umbra
