// Index replication: the manifest CRDT, the retirement safety condition, and
// what the relay can see.
//
// The adversarial cases are here rather than in the harness because they are
// about specific orderings that a random schedule reaches rarely and a named
// test reaches always: a segment referencing a manifest entry that has not
// arrived, a stale manifest, two devices compacting at once, a device on the
// wrong model, and a segment that arrives damaged.
#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "umbra/ai/answer.h"
#include "umbra/ai/chunk.h"
#include "umbra/ai/embed.h"
#include "umbra/ai/index.h"
#include "umbra/ai/manifest.h"

namespace umbra {
namespace ai {
namespace {

int RemoveEntry(const char* path, const struct stat*, int type, struct FTW*) {
  if (type == FTW_DP) return ::rmdir(path);
  return ::remove(path);
}

void RemoveTree(const std::string& path) {
  if (path.empty()) return;
  (void)::nftw(path.c_str(), RemoveEntry, 16, FTW_DEPTH | FTW_PHYS);
}

class TempDir {
 public:
  TempDir() {
    char t[] = "/tmp/umbra_repl_XXXXXX";
    const char* p = ::mkdtemp(t);
    path_ = (p != nullptr) ? p : "";
  }
  ~TempDir() { RemoveTree(path_); }
  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

Argon2idParams Fast() {
  Argon2idParams p = Argon2idParams::Default();
  p.opslimit = 1;
  p.memlimit = 8u * 1024 * 1024;
  return p;
}

VaultKeys MakeKeys() {
  std::array<uint8_t, kSaltBytes> salt{};
  salt.fill(11);
  VaultKeys k;
  EXPECT_EQ(VaultKeys::Create("replication", salt, Fast(), &k),
            CryptoStatus::kOk);
  const SecretKey e0 = DeriveSubkey(k.root(), 0, "umbRepl1");
  k.OverwriteEpochForBootstrap(0, e0);
  return k;
}

ReplicaId Replica(uint8_t seed) {
  ReplicaId r;
  r.bytes.fill(seed);
  return r;
}

ObjectId Object(uint8_t seed) {
  ObjectId id;
  id.bytes.fill(seed);
  return id;
}

const char* const kTopics[] = {
    "# Keys\n\nAn epoch key is random and never derived, because a removed "
    "device knows the root and could compute a derived one.\n",
    "# Chunking\n\nA fenced code block is never split, because half a code "
    "block embeds as something that looks like code and is not.\n",
    "# Relay\n\nThe relay stores ciphertext it cannot read and learns sizes "
    "and timing and nothing else about the contents.\n",
    "# Cats\n\nThe cat sleeps on the windowsill in the afternoon and objects "
    "to being moved from it.\n",
};

// One device: an index, its keys, and its embedder. Two of these plus a shared
// list of published operations is the whole model of a vault.
struct Device {
  TempDir dir;
  VaultKeys keys;
  std::unique_ptr<Embedder> embedder;
  std::unique_ptr<Index> index;
  ReplicaId replica;

  void Open(uint8_t seed, uint32_t dim = 96) {
    keys = MakeKeys();
    replica = Replica(seed);
    embedder = NewHashingEmbedder(dim);
    ASSERT_NE(embedder, nullptr);
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, embedder->id(),
                          embedder->dimension(), replica, &index),
              IndexStatus::kOk);
  }

  void Reopen() {
    index.reset();
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, embedder->id(),
                          embedder->dimension(), replica, &index),
              IndexStatus::kOk);
  }

  // Index one note, returning the sealed bytes of the segment it produced so a
  // test can move them by hand.
  void IndexNote(uint8_t object_seed, const std::string& body) {
    const ObjectId object = Object(object_seed);
    std::vector<Chunk> chunks;
    ASSERT_EQ(ChunkMarkdown(object, body, &chunks), ChunkStatus::kOk);
    std::vector<std::string> texts;
    for (const Chunk& c : chunks) texts.push_back(c.text);
    std::vector<Vector> vs;
    ASSERT_EQ(embedder->EmbedDocuments(texts, &vs), EmbedStatus::kOk);
    ASSERT_EQ(index->PutObject(object, chunks, vs), IndexStatus::kOk);
  }

  std::string SealedBytes(const SegmentId& id) const {
    const std::string path = dir.path() + "/segments/" + id.Hex() + ".seg";
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) return std::string();
    std::string out;
    char buf[65536];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    std::fclose(f);
    return out;
  }
};

// Move every pending operation from one device to another, the way a client
// would after a push and a fetch.
std::size_t Ship(Device* from, Device* to) {
  const std::vector<ManifestOp> ops = from->index->TakePending();
  for (const ManifestOp& op : ops) {
    (void)to->index->ApplyManifestOp(op);
  }
  return ops.size();
}

// Move the bytes of every segment the destination is missing.
std::size_t ShipSegments(Device* from, Device* to) {
  std::size_t moved = 0;
  for (const SegmentId& id : to->index->Missing()) {
    const std::string sealed = from->SealedBytes(id);
    if (sealed.empty()) continue;
    if (to->index->AdoptSegment(sealed) == IndexStatus::kOk) ++moved;
  }
  return moved;
}

}  // namespace

// ------------------------------------------------------------------ lattice

TEST(Manifest, TheFoldDoesNotDependOnArrivalOrder) {
  std::unique_ptr<Embedder> e = NewHashingEmbedder(64);
  const EmbeddingModelId model = e->id();

  std::vector<ManifestOp> ops;
  for (uint8_t i = 1; i <= 6; ++i) {
    ManifestOp add;
    add.kind = ManifestOpKind::kAdd;
    add.id.replica = Replica(i);
    add.id.counter = i;
    add.segment.bytes.fill(i);
    add.count = 10u + i;
    add.bytes = 100u * i;
    add.model = model;
    ops.push_back(add);
  }
  ManifestOp t;
  t.kind = ManifestOpKind::kTombstone;
  t.id.replica = Replica(9);
  t.id.counter = 1;
  t.segment.bytes.fill(3);
  t.slot = 4;
  ops.push_back(t);
  ManifestOp r;
  r.kind = ManifestOpKind::kRetire;
  r.id.replica = Replica(9);
  r.id.counter = 2;
  r.prev = 1;
  r.segment.bytes.fill(2);
  r.superseded_by.bytes.fill(5);
  ops.push_back(r);

  // Every permutation of a lattice fold must agree. Shuffled deterministically
  // rather than randomly, so a failure names an order that can be reproduced.
  std::string reference;
  for (int rotation = 0; rotation < 8; ++rotation) {
    std::vector<ManifestOp> order = ops;
    std::rotate(order.begin(), order.begin() + rotation, order.end());
    // And a duplicate of everything, because re-delivery is normal.
    for (const ManifestOp& op : ops) order.push_back(op);

    ManifestDoc doc(model);
    for (const ManifestOp& op : order) (void)doc.Apply(op);

    std::string state;
    for (const std::pair<const SegmentId, SegmentState>& kv : doc.segments()) {
      state += kv.first.Short();
      state += ":" + std::to_string(kv.second.count);
      state += ":d" + std::to_string(kv.second.dead.size());
      state += ":s" + std::to_string(kv.second.superseded_by.size());
      state += ";";
    }
    if (rotation == 0) {
      reference = state;
    } else {
      EXPECT_EQ(state, reference) << "rotation " << rotation;
    }
  }
  EXPECT_FALSE(reference.empty());
}

TEST(Manifest, ADuplicateOperationChangesNothing) {
  std::unique_ptr<Embedder> e = NewHashingEmbedder(64);
  ManifestDoc doc(e->id());
  ManifestOp add;
  add.kind = ManifestOpKind::kAdd;
  add.id.replica = Replica(1);
  add.id.counter = 1;
  add.segment.bytes.fill(7);
  add.count = 5;
  add.model = e->id();
  EXPECT_EQ(doc.Apply(add), ManifestApply::kApplied);
  EXPECT_EQ(doc.Apply(add), ManifestApply::kDuplicate);
  EXPECT_EQ(doc.segments().size(), 1u);
}

TEST(Manifest, RefusesASegmentFromAnotherModel) {
  std::unique_ptr<Embedder> mine = NewHashingEmbedder(64);
  std::unique_ptr<Embedder> theirs = NewHashingEmbedder(128);
  ManifestDoc doc(mine->id());
  ManifestOp add;
  add.kind = ManifestOpKind::kAdd;
  add.id.replica = Replica(1);
  add.id.counter = 1;
  add.segment.bytes.fill(7);
  add.count = 5;
  add.model = theirs->id();
  EXPECT_EQ(doc.Apply(add), ManifestApply::kModelMismatch);
  EXPECT_TRUE(doc.segments().empty())
      << "a foreign segment entered the manifest";
  EXPECT_EQ(doc.refused_model(), 1u)
      << "the refusal was not counted, so a device could not report why its "
         "index looks empty";
}

// A TOMBSTONE ROUTINELY ARRIVES BEFORE THE SEGMENT IT NAMES, because operations
// are small and segments are not. Dropping it would lose a deletion.
TEST(Manifest, ATombstoneBeforeItsSegmentIsKept) {
  std::unique_ptr<Embedder> e = NewHashingEmbedder(64);
  ManifestDoc doc(e->id());
  ManifestOp t;
  t.kind = ManifestOpKind::kTombstone;
  t.id.replica = Replica(2);
  t.id.counter = 1;
  t.segment.bytes.fill(7);
  t.slot = 3;
  EXPECT_EQ(doc.Apply(t), ManifestApply::kApplied);
  // Not wanted yet: nobody has said it exists.
  EXPECT_TRUE(doc.Wanted().empty());

  ManifestOp add;
  add.kind = ManifestOpKind::kAdd;
  add.id.replica = Replica(1);
  add.id.counter = 1;
  add.segment.bytes.fill(7);
  add.count = 5;
  add.model = e->id();
  EXPECT_EQ(doc.Apply(add), ManifestApply::kApplied);
  ASSERT_EQ(doc.Wanted().size(), 1u);
  const SegmentState* st = doc.Get(add.segment);
  ASSERT_NE(st, nullptr);
  EXPECT_EQ(st->dead.count(3), 1u) << "the early tombstone was lost";
}

TEST(Manifest, EncodingRoundTripsAndRefusesAForwardChain) {
  ManifestOp op;
  op.kind = ManifestOpKind::kRetire;
  op.id.replica = Replica(4);
  op.id.counter = 9;
  op.prev = 8;
  op.segment.bytes.fill(1);
  op.superseded_by.bytes.fill(2);
  op.count = 3;
  op.bytes = 4444;
  op.slot = 5;
  const std::string wire = EncodeManifestOp(op);
  ManifestOp back;
  ASSERT_TRUE(DecodeManifestOp(wire, &back));
  EXPECT_EQ(back.kind, op.kind);
  EXPECT_EQ(back.id.counter, op.id.counter);
  EXPECT_EQ(back.prev, op.prev);
  EXPECT_EQ(back.segment, op.segment);
  EXPECT_EQ(back.superseded_by, op.superseded_by);

  // The same rule op.cc enforces: a back-pointer names an EARLIER operation.
  ManifestOp forward = op;
  forward.prev = forward.id.counter;
  ManifestOp ignored;
  EXPECT_FALSE(DecodeManifestOp(EncodeManifestOp(forward), &ignored));

  // And nothing past the end, and nothing short.
  std::string truncated = wire.substr(0, wire.size() - 1);
  EXPECT_FALSE(DecodeManifestOp(truncated, &ignored));
  EXPECT_FALSE(DecodeManifestOp(wire + "x", &ignored));
}

// ------------------------------------------------------- the safety condition

// THE CASE THE CONDITION EXISTS FOR: operations arrive long before bytes.
TEST(Replication, ARetiredSegmentStaysLiveUntilItsReplacementArrives) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  for (uint8_t i = 0; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i % 4]));
  }
  // B catches up completely.
  Ship(&a, &b);
  ShipSegments(&a, &b);
  ASSERT_TRUE(b.index->Complete());
  const IndexStats before = b.index->Stats();
  ASSERT_GE(before.segments, 2u);

  // A compacts. B receives the operations -- which include the retirements --
  // and NOT the new segment.
  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  ASSERT_EQ(a.index->Compact(2, 10, &merged, &reclaimed), IndexStatus::kOk);
  ASSERT_GT(merged, 1u);
  Ship(&a, &b);

  // THE POINT. B has been told those segments are retired and must keep using
  // them, because what replaces them is not here.
  EXPECT_FALSE(b.index->Complete())
      << "B thinks it is complete while missing the replacement";
  EXPECT_FALSE(b.index->AwaitingReplacement().empty())
      << "B is not holding anything open, so it dropped data it still needs";
  EXPECT_EQ(b.index->Stats().segments, before.segments)
      << "B dropped a retired segment before its replacement arrived";

  // Search still answers from the old segments.
  Vector q;
  ASSERT_EQ(b.embedder->EmbedQuery("epoch key is random and never derived", &q),
            EmbedStatus::kOk);
  std::vector<SearchHit> hits;
  ASSERT_EQ(b.index->Search(q, 5, 64, &hits), IndexStatus::kOk);
  EXPECT_FALSE(hits.empty()) << "B lost its index while waiting";

  // The replacement lands and the old segments go.
  ShipSegments(&a, &b);
  EXPECT_TRUE(b.index->Complete());
  EXPECT_TRUE(b.index->AwaitingReplacement().empty());
  EXPECT_LT(b.index->Stats().segments, before.segments)
      << "the retirement never took effect, so the store only grows";

  std::vector<SearchHit> after;
  ASSERT_EQ(b.index->Search(q, 5, 64, &after), IndexStatus::kOk);
  EXPECT_FALSE(after.empty());
}

// A SEGMENT WHOSE MANIFEST ENTRY HAS NOT ARRIVED. The bytes are adopted on
// their own terms -- the content hash is what names them -- and the operations
// fill in behind.
TEST(Replication, ASegmentCanArriveBeforeItsManifestEntry) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));

  const std::vector<SegmentId> ids = a.index->SegmentIds();
  ASSERT_EQ(ids.size(), 1u);
  const std::string sealed = a.SealedBytes(ids[0]);
  ASSERT_FALSE(sealed.empty());

  // Bytes first, operations never.
  EXPECT_EQ(b.index->AdoptSegment(sealed), IndexStatus::kOk);
  Vector q;
  ASSERT_EQ(b.embedder->EmbedQuery("epoch key random derived", &q),
            EmbedStatus::kOk);
  std::vector<SearchHit> hits;
  ASSERT_EQ(b.index->Search(q, 5, 64, &hits), IndexStatus::kOk);
  EXPECT_FALSE(hits.empty()) << "an adopted segment did not answer";
  // And it is not "missing", because it is here.
  EXPECT_TRUE(b.index->Missing().empty());

  // The operations arriving afterwards change nothing.
  Ship(&a, &b);
  EXPECT_TRUE(b.index->Complete());
  std::vector<SearchHit> again;
  ASSERT_EQ(b.index->Search(q, 5, 64, &again), IndexStatus::kOk);
  EXPECT_EQ(again.size(), hits.size());
}

// A STALE MANIFEST IS A CORRECT PREFIX, and a device holding one must not
// report its index as complete when it is merely old.
TEST(Replication, AStaleManifestIsIncompleteNotWrong) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  Ship(&a, &b);
  ShipSegments(&a, &b);
  EXPECT_TRUE(b.index->Complete());

  // A indexes more; B receives the operations but nothing else.
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(2, kTopics[1]));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(3, kTopics[2]));
  Ship(&a, &b);

  EXPECT_FALSE(b.index->Complete())
      << "a device that knows it is missing segments called itself complete";
  EXPECT_EQ(b.index->Missing().size(), 2u);

  // What it does have still answers correctly.
  Vector q;
  ASSERT_EQ(b.embedder->EmbedQuery("epoch key random derived", &q),
            EmbedStatus::kOk);
  std::vector<SearchHit> hits;
  ASSERT_EQ(b.index->Search(q, 5, 64, &hits), IndexStatus::kOk);
  EXPECT_FALSE(hits.empty());
}

// ------------------------------------------------------------- convergence

TEST(Replication, TwoDevicesIndexingDifferentNotesConverge) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(2, kTopics[1]));
  ASSERT_NO_FATAL_FAILURE(b.IndexNote(3, kTopics[2]));
  ASSERT_NO_FATAL_FAILURE(b.IndexNote(4, kTopics[3]));

  // Both directions, twice, the way two clients syncing would.
  for (int round = 0; round < 2; ++round) {
    Ship(&a, &b);
    Ship(&b, &a);
    ShipSegments(&a, &b);
    ShipSegments(&b, &a);
  }

  EXPECT_TRUE(a.index->Complete());
  EXPECT_TRUE(b.index->Complete());
  EXPECT_EQ(a.index->SegmentIds(), b.index->SegmentIds())
      << "the two devices hold different segments";
  EXPECT_EQ(a.index->Stats().objects, b.index->Stats().objects);

  // And they answer the same question the same way.
  for (int t = 0; t < 4; ++t) {
    Vector q;
    ASSERT_EQ(a.embedder->EmbedQuery(kTopics[t], &q), EmbedStatus::kOk);
    std::vector<SearchHit> ha;
    std::vector<SearchHit> hb;
    ASSERT_EQ(a.index->Search(q, 5, 64, &ha), IndexStatus::kOk);
    ASSERT_EQ(b.index->Search(q, 5, 64, &hb), IndexStatus::kOk);
    ASSERT_EQ(ha.size(), hb.size()) << "topic " << t;
    for (std::size_t i = 0; i < ha.size(); ++i) {
      EXPECT_EQ(ha[i].object, hb[i].object) << "topic " << t << " rank " << i;
      EXPECT_EQ(ha[i].start, hb[i].start);
    }
  }
}

// BOTH DEVICES INDEX THE SAME NOTE AT THE SAME TIME. The prompt asks what
// happens, so it is asserted rather than described.
TEST(Replication, BothDevicesIndexingOneNoteDoNotClobberEachOther) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  // The same note, the same bytes, indexed independently.
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  ASSERT_NO_FATAL_FAILURE(b.IndexNote(1, kTopics[0]));

  const std::vector<SegmentId> from_a = a.index->SegmentIds();
  const std::vector<SegmentId> from_b = b.index->SegmentIds();
  ASSERT_EQ(from_a.size(), 1u);
  ASSERT_EQ(from_b.size(), 1u);
  // THE SEGMENTS ARE IDENTICAL. Chunking is deterministic, the stand-in
  // embedder is deterministic, and a segment is named by its bytes -- so two
  // devices that index the same note produce the same segment id and the
  // lattice absorbs the two operations as one.
  EXPECT_EQ(from_a[0], from_b[0])
      << "the same note produced two different segments";

  for (int round = 0; round < 2; ++round) {
    Ship(&a, &b);
    Ship(&b, &a);
    ShipSegments(&a, &b);
    ShipSegments(&b, &a);
  }
  EXPECT_EQ(a.index->SegmentIds().size(), 1u)
      << "concurrent indexing of one note left two segments";
  EXPECT_EQ(a.index->SegmentIds(), b.index->SegmentIds());
  EXPECT_EQ(a.index->Stats().objects, 1u);

  // And the note is returned once, not twice.
  Vector q;
  ASSERT_EQ(a.embedder->EmbedQuery(kTopics[0], &q), EmbedStatus::kOk);
  std::vector<SearchHit> hits;
  ASSERT_EQ(a.index->Search(q, 10, 64, &hits), IndexStatus::kOk);
  std::set<std::pair<uint32_t, uint32_t>> ranges;
  for (const SearchHit& h : hits) {
    EXPECT_TRUE(ranges.insert({h.start, h.end}).second)
        << "the same passage was returned twice";
  }
}

// TWO DEVICES COMPACTING AT ONCE. Input selection is a pure function of the
// manifest, so two devices with the same view choose the same inputs, and
// because building is deterministic they produce the same segment.
TEST(Replication, ConcurrentCompactionIsIdempotent) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  for (uint8_t i = 0; i < 6; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i % 4]));
  }
  Ship(&a, &b);
  ShipSegments(&a, &b);
  ASSERT_TRUE(b.index->Complete());
  ASSERT_EQ(a.index->SegmentIds(), b.index->SegmentIds());

  // Both compact, neither having seen the other.
  uint32_t ma = 0;
  uint32_t mb = 0;
  uint32_t ra = 0;
  uint32_t rb = 0;
  ASSERT_EQ(a.index->Compact(2, 10, &ma, &ra), IndexStatus::kOk);
  ASSERT_EQ(b.index->Compact(2, 10, &mb, &rb), IndexStatus::kOk);
  EXPECT_EQ(ma, mb) << "the two chose different numbers of inputs";
  EXPECT_EQ(a.index->SegmentIds(), b.index->SegmentIds())
      << "concurrent compaction produced different segments";

  for (int round = 0; round < 2; ++round) {
    Ship(&a, &b);
    Ship(&b, &a);
    ShipSegments(&a, &b);
    ShipSegments(&b, &a);
  }
  EXPECT_EQ(a.index->SegmentIds(), b.index->SegmentIds());
  EXPECT_EQ(a.index->Stats().objects, b.index->Stats().objects);
  EXPECT_TRUE(a.index->Complete());
  EXPECT_TRUE(b.index->Complete());
}

TEST(Replication, TieredCompactionLeavesTheLargeSegmentAlone) {
  std::unique_ptr<Embedder> e = NewHashingEmbedder(64);
  ManifestDoc doc(e->id());
  std::vector<SegmentId> live;
  // One large segment and several small ones, which is what an index looks like
  // after a compaction followed by a week of editing.
  const uint32_t counts[] = {5000, 12, 9, 11, 14};
  for (uint8_t i = 0; i < 5; ++i) {
    ManifestOp add;
    add.kind = ManifestOpKind::kAdd;
    add.id.replica = Replica(1);
    add.id.counter = i + 1;
    add.prev = i;
    add.segment.bytes.fill(static_cast<uint8_t>(i + 1));
    add.count = counts[i];
    add.model = e->id();
    ASSERT_EQ(doc.Apply(add), ManifestApply::kApplied);
    live.push_back(add.segment);
  }
  const CompactionPlan plan = PlanCompaction(doc, live, 2, 10, 4);
  ASSERT_GE(plan.inputs.size(), 2u);
  // THE 5000-VECTOR SEGMENT IS NOT IN THE ROUND. Phase 4 measured an
  // all-or-nothing merge of a 13,838-vector index at 103 seconds; tiering is
  // what keeps a routine merge from paying that.
  SegmentId big;
  big.bytes.fill(1);
  EXPECT_EQ(std::find(plan.inputs.begin(), plan.inputs.end(), big),
            plan.inputs.end())
      << "the large segment was dragged into a routine merge";
  EXPECT_EQ(plan.inputs.size(), 4u);
}

TEST(Replication, CompactionPlanningIsAPureFunction) {
  std::unique_ptr<Embedder> e = NewHashingEmbedder(64);
  ManifestDoc doc(e->id());
  std::vector<SegmentId> live;
  for (uint8_t i = 0; i < 6; ++i) {
    ManifestOp add;
    add.kind = ManifestOpKind::kAdd;
    add.id.replica = Replica(static_cast<uint8_t>(i + 1));
    add.id.counter = 1;
    add.segment.bytes.fill(static_cast<uint8_t>(i + 1));
    add.count = 10 + i;
    add.model = e->id();
    ASSERT_EQ(doc.Apply(add), ManifestApply::kApplied);
    live.push_back(add.segment);
  }
  const CompactionPlan first = PlanCompaction(doc, live, 2, 10, 4);
  // The same manifest, the live set handed over in a different order.
  std::vector<SegmentId> shuffled = live;
  std::reverse(shuffled.begin(), shuffled.end());
  const CompactionPlan second = PlanCompaction(doc, shuffled, 2, 10, 4);
  EXPECT_EQ(first.inputs, second.inputs)
      << "planning depended on the order of the live set, so two devices "
         "would choose different inputs";
}

// ---------------------------------------------------------------- refusals

TEST(Replication, ADeviceOnAnotherModelRefusesTheSegments) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1, 96));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2, 128));  // a different model identity
  ASSERT_NE(a.embedder->id(), b.embedder->id());

  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  const std::vector<ManifestOp> ops = a.index->TakePending();
  ASSERT_FALSE(ops.empty());
  bool refused = false;
  for (const ManifestOp& op : ops) {
    if (b.index->ApplyManifestOp(op) == ManifestApply::kModelMismatch) {
      refused = true;
    }
  }
  EXPECT_TRUE(refused) << "a foreign model's operations were absorbed";
  EXPECT_TRUE(b.index->Missing().empty())
      << "B is trying to fetch segments it cannot use";

  // And the bytes themselves are refused, not merely the operations.
  const std::vector<SegmentId> ids = a.index->SegmentIds();
  ASSERT_EQ(ids.size(), 1u);
  const std::string sealed = a.SealedBytes(ids[0]);
  ASSERT_FALSE(sealed.empty());
  EXPECT_EQ(b.index->AdoptSegment(sealed), IndexStatus::kModelMismatch);
  EXPECT_EQ(b.index->Stats().segments, 0u);
}

// A SEGMENT THAT ARRIVES DAMAGED IS REFUSED BEFORE IT REACHES THE DISK, because
// the name it would be stored under is derived from its bytes.
TEST(Replication, ACorruptedSegmentIsRefusedAtTheDoor) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));

  const std::vector<SegmentId> ids = a.index->SegmentIds();
  ASSERT_EQ(ids.size(), 1u);
  std::string sealed = a.SealedBytes(ids[0]);
  ASSERT_GT(sealed.size(), 300u);

  std::string damaged = sealed;
  damaged[250] = static_cast<char>(damaged[250] ^ 0x55);
  EXPECT_EQ(b.index->AdoptSegment(damaged), IndexStatus::kSegmentLost);
  EXPECT_EQ(b.index->Stats().segments, 0u)
      << "a damaged segment reached the store";

  std::string truncated = sealed.substr(0, sealed.size() / 2);
  EXPECT_NE(b.index->AdoptSegment(truncated), IndexStatus::kOk);
  EXPECT_EQ(b.index->Stats().segments, 0u);

  // The intact one still works, so the refusals were about the damage.
  EXPECT_EQ(b.index->AdoptSegment(sealed), IndexStatus::kOk);
  EXPECT_EQ(b.index->Stats().segments, 1u);
}

// ------------------------------------------------------------------ restart

TEST(Replication, ARestartDoesNotReissueManifestCounters) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  const std::vector<ManifestOp> first = a.index->TakePending();
  ASSERT_FALSE(first.empty());
  uint64_t highest = 0;
  for (const ManifestOp& op : first) {
    highest = std::max(highest, op.id.counter);
  }

  ASSERT_NO_FATAL_FAILURE(a.Reopen());
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(2, kTopics[1]));
  const std::vector<ManifestOp> second = a.index->TakePending();
  ASSERT_FALSE(second.empty());
  for (const ManifestOp& op : second) {
    EXPECT_GT(op.id.counter, highest)
        << "a restart reissued manifest counter " << op.id.counter
        << ", which the oplog would treat as a lost write rather than a "
           "conflict";
  }
}

// ------------------------------------------------------- honest degradation

// A PHONE THAT NEVER INDEXES MUST STILL SEARCH, AND MUST SAY WHAT IT HAS.
//
// The prompt asks what happens when nobody has indexed recent notes yet. The
// answer has to be visible in the result rather than inferred, because a
// partial vault presented as the whole one is the same failure as an ungrounded
// answer presented as a grounded one.
TEST(Replication, ADeviceThatNeverIndexesSearchesAndSaysWhatItHas) {
  Device laptop;
  ASSERT_NO_FATAL_FAILURE(laptop.Open(0xA1));
  Device phone;
  ASSERT_NO_FATAL_FAILURE(phone.Open(0xB2));

  // The vault's documents, so a passage can be resolved on either device.
  std::map<std::string, std::string> vault;
  const auto key = [](const ObjectId& o) {
    return std::string(reinterpret_cast<const char*>(o.bytes.data()),
                       o.bytes.size());
  };
  for (uint8_t i = 0; i < 4; ++i) {
    vault[key(Object(static_cast<uint8_t>(i + 1)))] = kTopics[i];
  }
  const DocumentSource source = [&vault, &key](const ObjectId& o,
                                               std::string* out) {
    const std::map<std::string, std::string>::const_iterator it =
        vault.find(key(o));
    if (it == vault.end()) return false;
    *out = it->second;
    return true;
  };

  // The laptop indexes everything. The phone indexes nothing, ever.
  for (uint8_t i = 0; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        laptop.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i]));
  }

  AnswerOptions o;
  o.min_score = -1.0f;
  o.relative_floor = -1.0f;

  // Operations only: the phone knows what exists and holds none of it.
  Ship(&laptop, &phone);
  {
    const AnswerResult r = Answer(*phone.index, phone.embedder.get(), nullptr,
                                  source, "epoch key random derived", o);
    EXPECT_FALSE(r.index_complete)
        << "a device holding no segments reported a complete index";
    EXPECT_GT(r.segments_missing, 0u);
    EXPECT_EQ(r.status, AnswerStatus::kNoPassages);
    EXPECT_NE(r.text.find("not finished pulling"), std::string::npos)
        << "an empty result from a catching-up device read as an empty vault";
  }

  // Half the bytes. Still incomplete, and now it answers from what it has.
  const std::vector<SegmentId> missing = phone.index->Missing();
  ASSERT_GE(missing.size(), 2u);
  ASSERT_EQ(phone.index->AdoptSegment(laptop.SealedBytes(missing[0])),
            IndexStatus::kOk);
  {
    const AnswerResult r = Answer(*phone.index, phone.embedder.get(), nullptr,
                                  source, "epoch key random derived", o);
    EXPECT_FALSE(r.index_complete);
    EXPECT_LT(r.segments_missing, missing.size());
  }

  // Fully caught up: complete, and searching as well as the device that did
  // the work.
  ShipSegments(&laptop, &phone);
  ASSERT_TRUE(phone.index->Complete());
  for (int t = 0; t < 4; ++t) {
    const AnswerResult on_phone = Answer(*phone.index, phone.embedder.get(),
                                         nullptr, source, kTopics[t], o);
    const AnswerResult on_laptop = Answer(*laptop.index, laptop.embedder.get(),
                                          nullptr, source, kTopics[t], o);
    EXPECT_TRUE(on_phone.index_complete);
    ASSERT_EQ(on_phone.passages.size(), on_laptop.passages.size())
        << "topic " << t;
    for (std::size_t i = 0; i < on_phone.passages.size(); ++i) {
      EXPECT_EQ(on_phone.passages[i].object, on_laptop.passages[i].object)
          << "topic " << t << " rank " << i;
      EXPECT_EQ(on_phone.passages[i].start, on_laptop.passages[i].start);
      EXPECT_NEAR(on_phone.passages[i].score, on_laptop.passages[i].score,
                  1e-6);
    }
  }
}

// A LAPTOP THAT HAS BEEN OFFLINE CATCHES UP WITHOUT REDOING WORK.
TEST(Replication, AnOfflineDeviceCatchesUpWithoutReindexing) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  Ship(&a, &b);
  ShipSegments(&a, &b);
  ASSERT_TRUE(b.index->Complete());

  // B goes away. A indexes the rest of the vault.
  for (uint8_t i = 1; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i]));
  }
  // B produced nothing while it was away.
  EXPECT_TRUE(b.index->TakePending().empty());

  // B comes back and pulls. THE WORK IS NOT REDONE: B embeds nothing, and its
  // segments are byte-identical to A's because they ARE A's.
  Ship(&a, &b);
  const std::size_t pulled = ShipSegments(&a, &b);
  EXPECT_EQ(pulled, 3u) << "B did not pull exactly the three it was missing";
  EXPECT_TRUE(b.index->Complete());
  EXPECT_EQ(a.index->SegmentIds(), b.index->SegmentIds());
  EXPECT_TRUE(b.index->TakePending().empty())
      << "catching up made B publish operations of its own, which means it "
         "redid work rather than adopting it";
}

}  // namespace ai
}  // namespace umbra
