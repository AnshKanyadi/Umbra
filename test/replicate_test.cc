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

#include "basalt/db.h"
#include "basalt/posix_env.h"
#include "basalt/slice.h"
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

// SHIP THE WAY A CLIENT SHIPS, verifying the back-pointer chain instead of
// trusting it. `Ship` above applies operations straight across, which is what a
// test wants when the subject is the fold -- and it is exactly why no test
// caught a device whose chain pointed at an operation it had never published.
// Client::FetchObjectWith refuses that (src/sync/client.cc:189) and returns
// chain-broken; a cursor of zero here means the same thing.
struct Chain {
  uint64_t cursor = 0;
  std::size_t applied = 0;
  bool broken = false;
};

Chain ShipChecked(Device* from, Device* to, uint64_t cursor = 0) {
  Chain c;
  c.cursor = cursor;
  for (const ManifestOp& op : from->index->TakePending()) {
    if (op.prev != c.cursor) {
      c.broken = true;
      return c;
    }
    (void)to->index->ApplyManifestOp(op);
    c.cursor = op.id.counter;
    ++c.applied;
  }
  return c;
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

  // A COMPACTION FIRST. Without one this test passed even with the counter
  // recovery removed, because reopening replays the local segments and
  // tombstones and happens to reconstruct a counter as large as the published
  // one. Retirements are NOT reconstructed -- they are not derivable from what
  // is on disk -- so a compaction is what makes the published counter outrun
  // anything the replay can rebuild, which is the case the recovery exists for.
  for (uint8_t i = 1; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i]));
  }
  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  ASSERT_EQ(a.index->Compact(2, 10, &merged, &reclaimed), IndexStatus::kOk);
  ASSERT_GT(merged, 1u);
  for (const ManifestOp& op : a.index->TakePending()) {
    highest = std::max(highest, op.id.counter);
  }

  ASSERT_NO_FATAL_FAILURE(a.Reopen());
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(9, kTopics[1]));
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

// PENDING OPERATIONS OUTLIVE THE PROCESS THAT MADE THEM.
//
// The end-to-end run found this: a device indexed a whole vault, exited, and
// the next process pushed ten segments and zero operations -- so the bytes were
// on the relay and nothing said they existed. A peer would have seen an empty
// manifest and called itself complete.
TEST(Replication, PendingOperationsSurviveTheProcessThatMadeThem) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  for (uint8_t i = 0; i < 3; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i]));
  }
  // The indexing process ends without publishing anything.
  ASSERT_NO_FATAL_FAILURE(a.Reopen());

  const std::vector<ManifestOp> ops = a.index->TakePending();
  EXPECT_GE(ops.size(), 3u)
      << "operations made before a restart were lost, so the segments would be "
         "on the relay with nothing saying they exist";

  // And a peer given exactly those operations wants exactly those segments.
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));
  for (const ManifestOp& op : ops) {
    (void)b.index->ApplyManifestOp(op);
  }
  EXPECT_EQ(b.index->Missing().size(), a.index->SegmentIds().size());
  EXPECT_FALSE(b.index->Complete());

  // Taken means taken: a second call does not hand them out again.
  EXPECT_TRUE(a.index->TakePending().empty());
}

// RE-INDEXING AN UNCHANGED NOTE MUST NOT KILL IT.
//
// The end-to-end run found this: a second build over a vault that had not
// changed left 19 of 20 vectors tombstoned and one object where there were ten.
// Segments are content addressed, so re-indexing identical content produces the
// SAME segment id -- and the object's previous slots are then the very slots
// the call just wrote. Tombstoning them is self-destruction with no error.
TEST(Replication, ReindexingUnchangedContentIsANoOp) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  for (uint8_t i = 0; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i]));
  }
  const IndexStats first = a.index->Stats();
  ASSERT_EQ(first.objects, 4u);
  ASSERT_EQ(first.tombstoned, 0u);
  const std::vector<SegmentId> ids = a.index->SegmentIds();

  // The same notes, the same bytes, indexed again.
  for (uint8_t i = 0; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i]));
  }
  const IndexStats second = a.index->Stats();
  EXPECT_EQ(second.tombstoned, 0u)
      << "re-indexing unchanged content tombstoned " << second.tombstoned
      << " of its own vectors";
  EXPECT_EQ(second.objects, 4u) << "objects vanished on a re-index";
  EXPECT_EQ(second.vectors, first.vectors);
  EXPECT_EQ(a.index->SegmentIds(), ids)
      << "identical content produced different segments";

  // And search still works, which is the part a user would notice.
  Vector q;
  ASSERT_EQ(a.embedder->EmbedQuery(kTopics[0], &q), EmbedStatus::kOk);
  std::vector<SearchHit> hits;
  ASSERT_EQ(a.index->Search(q, 5, 64, &hits), IndexStatus::kOk);
  EXPECT_FALSE(hits.empty()) << "the vault searched empty after a re-index";
}

// A CHANGED NOTE STILL RETIRES ITS OLD CHUNKS, which is the property the filter
// above must not break.
TEST(Replication, ReindexingChangedContentStillTombstonesTheOld) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  const IndexStats before = a.index->Stats();
  ASSERT_EQ(before.tombstoned, 0u);

  ASSERT_NO_FATAL_FAILURE(a.IndexNote(
      1,
      "# Keys\n\nRewritten completely, with different words about how a "
      "vault handles its rotation schedule.\n"));
  const IndexStats after = a.index->Stats();
  EXPECT_GT(after.tombstoned, 0u)
      << "an edited note kept its old chunks live, so search returns text the "
         "vault no longer holds";
  EXPECT_EQ(after.objects, 1u);
}

// A SEGMENT NOBODY HAS BEEN TOLD ABOUT GETS ANNOUNCED.
//
// The 24 MB transfer found this: an index built before manifest operations
// existed pushed its segments to the relay and published nothing, so the second
// device learned of no segments, pulled nothing, and reported itself complete.
// The bytes were there and no operation said so.
//
// The same shape happens without any legacy data: pending operations are taken
// and then lost before they reach a relay.
TEST(Replication, AnUnannouncedSegmentIsAnnouncedOnOpen) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(2, kTopics[1]));

  // The operations are taken and thrown away, as a crash between taking and
  // pushing would do.
  const std::vector<ManifestOp> lost = a.index->TakePending();
  ASSERT_FALSE(lost.empty());
  ASSERT_TRUE(a.index->TakePending().empty());

  // A device that has already announced does not announce again.
  ASSERT_NO_FATAL_FAILURE(a.Reopen());
  const std::vector<ManifestOp> after_clean = a.index->TakePending();
  EXPECT_TRUE(after_clean.empty())
      << "a segment that had been announced was announced a second time";

  // Now the same situation as the legacy index: the segments are present and
  // the announcement markers are not.
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));
  for (const SegmentId& id : a.index->SegmentIds()) {
    ASSERT_EQ(b.index->AdoptSegment(a.SealedBytes(id)), IndexStatus::kOk);
  }
  // Adoption marks them announced, because whoever we took them from said so.
  ASSERT_NO_FATAL_FAILURE(b.Reopen());
  EXPECT_TRUE(b.index->TakePending().empty())
      << "an adopted segment was re-announced";
}

// The legacy shape directly: segments on disk that the store has no
// announcement for.
TEST(Replication, ASegmentPresentWithoutAnAnnouncementIsPublished) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  const std::vector<SegmentId> ids = a.index->SegmentIds();
  ASSERT_EQ(ids.size(), 1u);
  (void)a.index->TakePending();

  // Remove the announcement marker the way an index written by older code
  // would never have had one.
  a.index.reset();
  {
    std::unique_ptr<basalt::Env> env = basalt::NewPosixEnv();
    std::unique_ptr<basalt::DB> db;
    const basalt::wal::Caps caps;
    ASSERT_TRUE(
        basalt::DB::Open(env.get(), a.dir.path() + "/manifest", caps, &db)
            .ok());
    std::string key(1, 'a');
    key.append(reinterpret_cast<const char*>(ids[0].bytes.data()),
               ids[0].bytes.size());
    basalt::WriteBatch batch;
    batch.Delete(basalt::Slice(key));
    basalt::wal::SeqNum seq = 0;
    ASSERT_TRUE(db->Write(batch, &seq).ok());
    basalt::wal::SeqNum watermark = 0;
    (void)db->Sync(&watermark);
  }

  ASSERT_EQ(Index::Open(a.dir.path(), &a.keys, 0, a.embedder->id(),
                        a.embedder->dimension(), a.replica, &a.index),
            IndexStatus::kOk);
  const std::vector<ManifestOp> republished = a.index->TakePending();
  ASSERT_FALSE(republished.empty())
      << "a segment on disk that nobody had been told about stayed a secret";
  bool saw_add = false;
  for (const ManifestOp& op : republished) {
    if (op.kind == ManifestOpKind::kAdd && op.segment == ids[0]) saw_add = true;
  }
  EXPECT_TRUE(saw_add);

  // And a peer given those operations wants that segment.
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));
  for (const ManifestOp& op : republished) {
    (void)b.index->ApplyManifestOp(op);
  }
  EXPECT_EQ(b.index->Missing().size(), 1u);
}

// THE CHAIN SURVIVES A RESTART, which is where it broke.
//
// Reopening an index rebuilds the manifest fold by replaying the segments on
// disk, and those reconstructed operations burn counters so they cannot collide
// with published ones (src/ai/index.cc:407). The chain head is a different
// number: the counter of the last operation that actually reached a relay. It
// used to be set from the counter, so the first operation published after a
// restart pointed back at a counter no peer had ever seen, and a real puller
// answered chain-broken and applied nothing.
//
// Nothing caught this for two phases because both "devices" in the driver
// derived one replica id from their index path, so the puller recognised every
// operation as its own and never verified a chain at all.
TEST(Replication, TheBackPointerChainSurvivesARestart) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  ASSERT_NO_FATAL_FAILURE(a.IndexNote(1, kTopics[0]));
  const Chain first = ShipChecked(&a, &b);
  EXPECT_FALSE(first.broken) << "the very first operation broke the chain";
  EXPECT_GT(first.applied, 0u);

  // The restart, and then more work. A device that indexes again after being
  // reopened is the ordinary case, not an exotic one.
  ASSERT_NO_FATAL_FAILURE(a.Reopen());
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(2, kTopics[1]));
  const Chain second = ShipChecked(&a, &b, first.cursor);
  EXPECT_FALSE(second.broken)
      << "a restart left the chain pointing at an operation the peer never saw";
  EXPECT_GT(second.applied, 0u);

  // And a second restart, because the chain head is persisted by the operation
  // that advances it -- a value written once at open would survive one restart
  // and not two.
  ASSERT_NO_FATAL_FAILURE(a.Reopen());
  ASSERT_NO_FATAL_FAILURE(a.IndexNote(3, kTopics[2]));
  const Chain third = ShipChecked(&a, &b, second.cursor);
  EXPECT_FALSE(third.broken) << "the chain head did not survive two restarts";
  EXPECT_GT(third.applied, 0u);
}

// A DEVICE THAT PULLS BEFORE IT PUBLISHES STILL CHAINS FROM ZERO.
//
// Adopted segments are replayed into the fold at open exactly like locally
// built ones, so a device that pulled ten segments and then indexed one note of
// its own had burnt ten counters and anchored its first published operation to
// the tenth. Its peer had seen none of them.
TEST(Replication, APullerThatLaterPublishesChainsFromZero) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));

  for (uint8_t i = 0; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i % 4]));
  }
  ASSERT_GT(Ship(&a, &b), 0u);
  ASSERT_GT(ShipSegments(&a, &b), 0u);

  // B has never published anything, so its chain must start at zero no matter
  // how many of A's segments it is now carrying.
  ASSERT_NO_FATAL_FAILURE(b.Reopen());
  ASSERT_NO_FATAL_FAILURE(b.IndexNote(40, kTopics[0]));
  Device c;
  ASSERT_NO_FATAL_FAILURE(c.Open(0xC3));
  const Chain fresh = ShipChecked(&b, &c);
  EXPECT_FALSE(fresh.broken)
      << "a device that pulled before it published anchored its first "
         "operation to a counter burnt by the segments it adopted";
  EXPECT_GT(fresh.applied, 0u);
}

// AN INDEX BUILT BEFORE MANIFEST OPERATIONS EXISTED PUBLISHES A FOLLOWABLE
// CHAIN. The announce-on-open path (src/ai/index.cc:441) is the recovery for a
// segment nobody has been told about, and it runs after the fold has already
// burnt a counter per segment. This is the shape that failed against a live
// relay with a 24 MB index: ten operations pushed, zero applied.
TEST(Replication, AnAnnouncedLegacyIndexPublishesAFollowableChain) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  for (uint8_t i = 0; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i % 4]));
  }
  // Drop what it was going to publish, and the record that it ever announced
  // anything: a store from before announcements existed.
  (void)a.index->TakePending();
  a.index.reset();
  {
    std::unique_ptr<basalt::Env> env = basalt::NewPosixEnv();
    std::unique_ptr<basalt::DB> db;
    const basalt::wal::Caps caps;
    ASSERT_TRUE(
        basalt::DB::Open(env.get(), a.dir.path() + "/manifest", caps, &db)
            .ok());
    basalt::WriteBatch batch;
    basalt::IterOptions o;
    const std::string lo(1, 'a');
    const std::string hi(1, 'b');
    o.lower = basalt::Bound::At(basalt::Slice(lo));
    o.upper = basalt::Bound::At(basalt::Slice(hi));
    std::unique_ptr<basalt::Iterator> it = db->NewIter(o);
    for (bool ok = it->First(); ok; ok = it->Next()) {
      batch.Delete(it->Key());
    }
    ASSERT_TRUE(it->Close().ok());
    const std::string head = std::string(1, 'm') + "published";
    batch.Delete(basalt::Slice(head));
    basalt::wal::SeqNum seq = 0;
    ASSERT_TRUE(db->Write(batch, &seq).ok());
    basalt::wal::SeqNum watermark = 0;
    ASSERT_TRUE(db->Sync(&watermark).ok());
  }
  ASSERT_NO_FATAL_FAILURE(a.Reopen());

  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));
  const Chain c = ShipChecked(&a, &b);
  EXPECT_FALSE(c.broken)
      << "a legacy index announced itself with a chain no peer could follow";
  EXPECT_GT(c.applied, 0u);
  // And what it announced is what it holds: the peer now knows about every
  // segment and can fetch the bytes.
  EXPECT_EQ(b.index->Missing().size(), a.index->Stats().segments);
  EXPECT_EQ(ShipSegments(&a, &b), a.index->Stats().segments);
  EXPECT_EQ(b.index->Stats().segments, a.index->Stats().segments);
}

// A COLD PULLER DOES NOT FETCH WHAT COMPACTION ALREADY RETIRED.
//
// MissingFrom is right to list a retired segment: the safety condition keeps it
// live until its replacement is present, and a device that dropped it early
// would lose data. But a puller that walks that list in manifest order asks for
// every retired segment before the one that retires them, and each of those is
// a round trip for bytes the relay does not have and that stop being wanted a
// moment later.
//
// Free on localhost, ruinous on a network: a cold pull of a compacted
// 2000-note index made 2000 doomed fetches, half a second at a sub-millisecond
// round trip and about seven minutes at 200ms. cmd/ai_main.cc orders the fetch
// so replacements come first; this pins the property that makes that possible.
TEST(Replication, WhatCompactionRetiredIsNotWantedOnceItsReplacementIsHeld) {
  Device a;
  ASSERT_NO_FATAL_FAILURE(a.Open(0xA1));
  for (uint8_t i = 0; i < 4; ++i) {
    ASSERT_NO_FATAL_FAILURE(
        a.IndexNote(static_cast<uint8_t>(i + 1), kTopics[i % 4]));
  }
  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  ASSERT_EQ(a.index->Compact(2, 10, &merged, &reclaimed), IndexStatus::kOk);
  ASSERT_GT(merged, 1u);

  Device b;
  ASSERT_NO_FATAL_FAILURE(b.Open(0xB2));
  ASSERT_GT(Ship(&a, &b), 0u);

  // Everything is wanted, and most of it is a segment A no longer holds.
  //
  // Note which question separates them. Index::AwaitingReplacement answers
  // "what do I hold that I cannot drop yet", which for a cold puller is
  // nothing; the useful one is whether the manifest has retired it, which is
  // `superseded_by` and which a device with no segments can still answer.
  const std::vector<SegmentId> want = b.index->Missing();
  EXPECT_TRUE(b.index->AwaitingReplacement().empty())
      << "a device holding no segments cannot be waiting to drop one";
  std::size_t retired = 0;
  for (const SegmentId& id : want) {
    const SegmentState* st = b.index->manifest().Get(id);
    if (st != nullptr && !st->superseded_by.empty()) ++retired;
  }
  EXPECT_EQ(retired, static_cast<std::size_t>(merged));
  EXPECT_GT(want.size(), retired)
      << "nothing here supersedes anything, so the ordering has no work to do";

  // The replacement is what A actually still has. Adopt only that.
  std::size_t adopted = 0;
  for (const SegmentId& id : want) {
    const SegmentState* st = b.index->manifest().Get(id);
    if (st != nullptr && !st->superseded_by.empty()) continue;
    const std::string sealed = a.SealedBytes(id);
    ASSERT_FALSE(sealed.empty()) << "a segment nobody deferred is not held";
    ASSERT_EQ(b.index->AdoptSegment(sealed), IndexStatus::kOk);
    ++adopted;
  }
  EXPECT_GT(adopted, 0u);

  // And now nothing else is wanted: every one of those round trips would have
  // been spent on bytes this device stopped needing.
  EXPECT_TRUE(b.index->Missing().empty())
      << b.index->Missing().size() << " segment(s) still wanted after the "
      << "replacement arrived";
  EXPECT_TRUE(b.index->Complete());
}

}  // namespace ai
}  // namespace umbra
