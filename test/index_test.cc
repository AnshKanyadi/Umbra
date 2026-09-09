// The vector store: segments, the manifest, incremental update, deletes and
// compaction.
//
// Retrieval QUALITY is not asserted here. It is not a pass/fail property and
// pretending otherwise would produce a threshold nobody could justify; the
// fixture-corpus measurement is reported separately. What is asserted is the
// part that does have a right answer: that the graph finds what brute force
// finds, that an edit does not reindex the vault, that a delete stops being
// returned, that compaction reclaims what it says it reclaims, and that the
// same vectors produce the same bytes.
#include "umbra/ai/index.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "umbra/ai/chunk.h"
#include "umbra/ai/embed.h"

namespace umbra {
namespace ai {
namespace {

class TempDir {
 public:
  TempDir() {
    char t[] = "/tmp/umbra_index_XXXXXX";
    const char* p = ::mkdtemp(t);
    path_ = (p != nullptr) ? p : "";
  }
  ~TempDir() {
    if (!path_.empty()) {
      const std::string cmd = "rm -rf '" + path_ + "'";
      (void)std::system(cmd.c_str());
    }
  }
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
  salt.fill(9);
  VaultKeys k;
  EXPECT_EQ(VaultKeys::Create("index test", salt, Fast(), &k),
            CryptoStatus::kOk);
  return k;
}

ObjectId ObjectFromSeed(uint32_t seed) {
  ObjectId id;
  for (std::size_t i = 0; i < id.bytes.size(); ++i) {
    id.bytes[i] = static_cast<uint8_t>((seed >> ((i % 4) * 8)) & 0xFF);
  }
  id.bytes[15] = static_cast<uint8_t>(seed & 0xFF);
  return id;
}

// A small corpus with real structure, so the chunker is exercised too rather
// than the index being fed hand-made vectors.
const char* const kTopics[] = {
    "# Encryption\n\nEpoch keys are random and rotated when a device is "
    "removed. A revoked device keeps what it already had.\n",
    "# Chunking\n\nMarkdown is split by structure. A fenced code block is "
    "never cut in half because half a function embeds as nothing.\n",
    "# Relay\n\nThe relay stores ciphertext it cannot read and cannot order "
    "operations. It learns sizes and timing.\n",
    "# Harness\n\nAdversarial schedules cover a relay that drops one "
    "operation and keeps dropping it, and a restart from the log.\n",
    "# Cats\n\nThe cat sleeps on the windowsill in the afternoon sun and "
    "objects to being moved.\n",
    "# Index\n\nSegments are immutable and sealed. Deletes are tombstones "
    "because a graph edge cannot be removed safely.\n",
};

struct Corpus {
  std::vector<ObjectId> objects;
  std::vector<std::vector<Chunk>> chunks;
  std::vector<std::vector<Vector>> vectors;
};

Corpus BuildCorpus(Embedder* e, uint32_t notes) {
  Corpus c;
  for (uint32_t i = 0; i < notes; ++i) {
    const ObjectId object = ObjectFromSeed(i + 1);
    const std::string body = std::string(kTopics[i % 6]) + "\nNote number " +
                             std::to_string(i) +
                             " with some extra prose so "
                             "the chunker has something to work with.\n";
    std::vector<Chunk> chunks;
    EXPECT_EQ(ChunkMarkdown(object, body, &chunks), ChunkStatus::kOk);
    std::vector<std::string> texts;
    for (const Chunk& ch : chunks) texts.push_back(ch.text);
    std::vector<Vector> vs;
    EXPECT_EQ(e->EmbedDocuments(texts, &vs), EmbedStatus::kOk);
    c.objects.push_back(object);
    c.chunks.push_back(chunks);
    c.vectors.push_back(vs);
  }
  return c;
}

}  // namespace

TEST(Index, RoundTripsThroughDiskAndFindsWhatItStored) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  ASSERT_NE(e, nullptr);
  const Corpus c = BuildCorpus(e.get(), 24);

  {
    std::unique_ptr<Index> idx;
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
              IndexStatus::kOk);
    for (std::size_t i = 0; i < c.objects.size(); ++i) {
      ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
                IndexStatus::kOk);
    }
    EXPECT_EQ(idx->Stats().objects, 24u);
  }

  // REOPENED FROM DISK. An index that only works while it is in memory is not
  // an index, and the manifest plus segments shape is the whole point.
  std::unique_ptr<Index> idx;
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);
  EXPECT_EQ(idx->Stats().objects, 24u);
  EXPECT_GT(idx->Stats().vectors, 0u);

  Vector q;
  ASSERT_EQ(e->EmbedQuery("fenced code block never cut in half", &q),
            EmbedStatus::kOk);
  std::vector<SearchHit> hits;
  ASSERT_EQ(idx->Search(q, 5, 64, &hits), IndexStatus::kOk);
  ASSERT_FALSE(hits.empty());
  // The chunking note should be the nearest; assert the ordering property
  // rather than an absolute score, which would be a threshold with no argument
  // behind it.
  EXPECT_GE(hits[0].score, hits.back().score);
  EXPECT_LT(hits[0].start, hits[0].end);
}

// THE GRAPH MUST FIND WHAT AN EXHAUSTIVE SCAN FINDS. This is the correctness
// property of an approximate index: not that it is perfect, but that it is
// close to the answer it is approximating, measured rather than assumed.
TEST(Index, RecallAgainstBruteForce) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(128);
  ASSERT_NE(e, nullptr);
  const Corpus c = BuildCorpus(e.get(), 200);

  std::unique_ptr<Index> idx;
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);
  for (std::size_t i = 0; i < c.objects.size(); ++i) {
    ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
              IndexStatus::kOk);
  }
  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  ASSERT_EQ(idx->Compact(2, 20, &merged, &reclaimed), IndexStatus::kOk);

  const uint32_t k = 10;
  std::size_t hit = 0;
  std::size_t total = 0;
  for (uint32_t qi = 0; qi < 40; ++qi) {
    Vector q;
    ASSERT_EQ(
        e->EmbedQuery(
            std::string(kTopics[qi % 6]) + " query " + std::to_string(qi), &q),
        EmbedStatus::kOk);
    std::vector<SearchHit> approx;
    std::vector<SearchHit> exact;
    ASSERT_EQ(idx->Search(q, k, 64, &approx), IndexStatus::kOk);
    ASSERT_EQ(idx->BruteForce(q, k, &exact), IndexStatus::kOk);
    std::set<std::pair<std::string, uint32_t>> want;
    for (const SearchHit& h : exact) {
      want.insert({h.segment.Hex(), h.slot});
    }
    for (const SearchHit& h : approx) {
      if (want.count({h.segment.Hex(), h.slot}) != 0) ++hit;
    }
    total += want.size();
  }
  ASSERT_GT(total, 0u);
  const double recall = static_cast<double>(hit) / static_cast<double>(total);
  std::printf("recall@%u against brute force: %.4f over %zu results\n", k,
              recall, total);
  // A FLOOR, NOT A TARGET. It is set low enough that only a broken graph fails
  // it -- an unreachable region, a search that never leaves the entry point --
  // rather than at a number chosen to look good. The measured value is printed
  // so a regression shows as a number rather than as a pass.
  EXPECT_GT(recall, 0.80);
}

// EDITING ONE NOTE MUST NOT REINDEX THE VAULT.
TEST(Index, AnEditTouchesOneObject) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 12);

  std::unique_ptr<Index> idx;
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);
  for (std::size_t i = 0; i < c.objects.size(); ++i) {
    ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
              IndexStatus::kOk);
  }
  const std::vector<SegmentId> before = idx->SegmentIds();
  const IndexStats s0 = idx->Stats();

  // Re-put ONE object with different content.
  const std::string edited =
      "# Chunking\n\nRewritten entirely, with different words about splitting "
      "documents at structural boundaries.\n";
  std::vector<Chunk> chunks;
  ASSERT_EQ(ChunkMarkdown(c.objects[1], edited, &chunks), ChunkStatus::kOk);
  std::vector<std::string> texts;
  for (const Chunk& ch : chunks) texts.push_back(ch.text);
  std::vector<Vector> vs;
  ASSERT_EQ(e->EmbedDocuments(texts, &vs), EmbedStatus::kOk);
  ASSERT_EQ(idx->PutObject(c.objects[1], chunks, vs), IndexStatus::kOk);

  const std::vector<SegmentId> after = idx->SegmentIds();
  // Every segment that existed before still exists: nothing was rewritten.
  for (const SegmentId& id : before) {
    EXPECT_NE(std::find(after.begin(), after.end(), id), after.end())
        << "an edit rewrote segment " << id.Short();
  }
  EXPECT_EQ(after.size(), before.size() + 1)
      << "an edit should add exactly one segment";
  const IndexStats s1 = idx->Stats();
  EXPECT_GT(s1.tombstoned, s0.tombstoned)
      << "the old chunks of the edited note were not tombstoned";
  EXPECT_EQ(s1.objects, s0.objects) << "the object count changed";
}

TEST(Index, ADeletedObjectStopsBeingReturned) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 12);

  std::unique_ptr<Index> idx;
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);
  for (std::size_t i = 0; i < c.objects.size(); ++i) {
    ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
              IndexStatus::kOk);
  }

  Vector q;
  ASSERT_EQ(e->EmbedQuery("the cat sleeps on the windowsill", &q),
            EmbedStatus::kOk);
  std::vector<SearchHit> before;
  ASSERT_EQ(idx->Search(q, 20, 64, &before), IndexStatus::kOk);
  const ObjectId victim = c.objects[4];  // the cats note
  bool present = false;
  for (const SearchHit& h : before) {
    if (h.object == victim) present = true;
  }
  ASSERT_TRUE(present) << "the object to delete was not being returned anyway";

  ASSERT_EQ(idx->RemoveObject(victim), IndexStatus::kOk);
  std::vector<SearchHit> after;
  ASSERT_EQ(idx->Search(q, 20, 64, &after), IndexStatus::kOk);
  for (const SearchHit& h : after) {
    EXPECT_NE(h.object, victim) << "a deleted object was still returned";
  }
  // And it stays deleted across a reopen, which is what says the tombstone is
  // in the manifest rather than only in memory.
  idx.reset();
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);
  std::vector<SearchHit> reopened;
  ASSERT_EQ(idx->Search(q, 20, 64, &reopened), IndexStatus::kOk);
  for (const SearchHit& h : reopened) {
    EXPECT_NE(h.object, victim) << "a delete did not survive a reopen";
  }
}

// A STORE THAT ONLY GROWS HAS THE PROBLEM THE OPLOG HAD.
TEST(Index, CompactionReclaimsTombstonedSlots) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 30);

  std::unique_ptr<Index> idx;
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);
  for (std::size_t i = 0; i < c.objects.size(); ++i) {
    ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
              IndexStatus::kOk);
  }
  for (std::size_t i = 0; i < 10; ++i) {
    ASSERT_EQ(idx->RemoveObject(c.objects[i]), IndexStatus::kOk);
  }
  const IndexStats before = idx->Stats();
  ASSERT_GT(before.tombstoned, 0u);
  EXPECT_EQ(before.objects, 20u);

  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  ASSERT_EQ(idx->Compact(2, 10, &merged, &reclaimed), IndexStatus::kOk);
  EXPECT_GT(merged, 1u);
  EXPECT_EQ(reclaimed, before.tombstoned)
      << "compaction did not drop exactly the tombstoned slots";

  const IndexStats after = idx->Stats();
  EXPECT_EQ(after.tombstoned, 0u);
  EXPECT_EQ(after.vectors, before.vectors - before.tombstoned);
  EXPECT_LT(after.segments, before.segments);
  EXPECT_EQ(after.objects, 20u) << "compaction lost or gained objects";

  // The removed objects stay removed, and the survivors still answer.
  Vector q;
  ASSERT_EQ(e->EmbedQuery("segments are immutable and sealed", &q),
            EmbedStatus::kOk);
  std::vector<SearchHit> hits;
  ASSERT_EQ(idx->Search(q, 10, 64, &hits), IndexStatus::kOk);
  ASSERT_FALSE(hits.empty());
  for (const SearchHit& h : hits) {
    for (std::size_t i = 0; i < 10; ++i) {
      EXPECT_NE(h.object, c.objects[i]) << "compaction resurrected a delete";
    }
  }
}

TEST(Index, CompactionDoesNothingOnAnIdleStore) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 3);
  std::unique_ptr<Index> idx;
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);
  for (std::size_t i = 0; i < c.objects.size(); ++i) {
    ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
              IndexStatus::kOk);
  }
  const std::vector<SegmentId> before = idx->SegmentIds();
  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  // A high threshold and nothing dead: an idle vault must not rewrite itself.
  ASSERT_EQ(idx->Compact(100, 90, &merged, &reclaimed), IndexStatus::kOk);
  EXPECT_EQ(merged, 0u);
  EXPECT_EQ(idx->SegmentIds(), before);
}

// SAME VECTORS, SAME SEGMENT, BYTE FOR BYTE. The index half of item 5's
// determinism requirement. It is stated over vectors rather than over note text
// because inference is not reproducible across machines and does not need to
// be; see the note in embed.h.
TEST(Index, TheSameVectorsProduceTheSameSegmentBytes) {
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 8);

  std::vector<SegmentId> first;
  std::vector<SegmentId> second;
  for (int round = 0; round < 2; ++round) {
    TempDir dir;
    std::unique_ptr<Index> idx;
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
              IndexStatus::kOk);
    for (std::size_t i = 0; i < c.objects.size(); ++i) {
      ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
                IndexStatus::kOk);
    }
    (round == 0 ? first : second) = idx->SegmentIds();
  }
  ASSERT_FALSE(first.empty());
  // The id is the hash of the sealed bytes, so equal ids is equal bytes.
  EXPECT_EQ(first, second)
      << "two builds over identical vectors produced different segments";
}

TEST(Index, CompactionIsAlsoReproducible) {
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 20);
  std::vector<SegmentId> results[2];
  for (int round = 0; round < 2; ++round) {
    TempDir dir;
    std::unique_ptr<Index> idx;
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
              IndexStatus::kOk);
    for (std::size_t i = 0; i < c.objects.size(); ++i) {
      ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
                IndexStatus::kOk);
    }
    for (std::size_t i = 0; i < 6; ++i) {
      ASSERT_EQ(idx->RemoveObject(c.objects[i]), IndexStatus::kOk);
    }
    uint32_t merged = 0;
    uint32_t reclaimed = 0;
    ASSERT_EQ(idx->Compact(2, 10, &merged, &reclaimed), IndexStatus::kOk);
    results[round] = idx->SegmentIds();
  }
  EXPECT_EQ(results[0], results[1])
      << "compaction is not reproducible, so two devices would diverge";
}

// A SEGMENT FROM A DIFFERENT MODEL IS REFUSED, NOT SKIPPED. Skipping it would
// silently halve someone's index; loading it would put two vector spaces in one
// store.
TEST(Index, RefusesAnIndexBuiltByAnotherModel) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> a = NewHashingEmbedder(96);
  std::unique_ptr<Embedder> b = NewHashingEmbedder(128);
  ASSERT_NE(a->id(), b->id());

  const Corpus c = BuildCorpus(a.get(), 4);
  {
    std::unique_ptr<Index> idx;
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, a->id(), a->dimension(), &idx),
              IndexStatus::kOk);
    for (std::size_t i = 0; i < c.objects.size(); ++i) {
      ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
                IndexStatus::kOk);
    }
  }
  std::unique_ptr<Index> wrong;
  EXPECT_EQ(Index::Open(dir.path(), &keys, 0, b->id(), b->dimension(), &wrong),
            IndexStatus::kModelMismatch);
}

TEST(Index, RefusesVectorsOfTheWrongWidth) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  std::unique_ptr<Index> idx;
  ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kOk);

  std::vector<Chunk> chunks;
  ASSERT_EQ(
      ChunkMarkdown(ObjectFromSeed(1), "# H\n\nbody text here\n", &chunks),
      ChunkStatus::kOk);
  ASSERT_FALSE(chunks.empty());
  std::vector<Vector> wrong(chunks.size(), Vector(32, 0.1f));
  EXPECT_EQ(idx->PutObject(ObjectFromSeed(1), chunks, wrong),
            IndexStatus::kBadArgument);
  // And a length mismatch between chunks and vectors.
  EXPECT_EQ(idx->PutObject(ObjectFromSeed(1), chunks, {}),
            IndexStatus::kBadArgument);
}

// A TAMPERED SEGMENT IS REFUSED. The manifest names files by the hash of their
// sealed bytes, and the AEAD binds the contents; either check alone would be
// enough, and both are asserted because a store that loads a corrupted segment
// answers queries with whatever the corruption produced.
TEST(Index, RefusesASegmentThatWasAlteredOnDisk) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 4);
  {
    std::unique_ptr<Index> idx;
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
              IndexStatus::kOk);
    for (std::size_t i = 0; i < c.objects.size(); ++i) {
      ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
                IndexStatus::kOk);
    }
  }
  // Flip a byte deep inside one segment file.
  const std::string seg_dir = dir.path() + "/segments";
  const std::string cmd =
      "f=$(ls " + seg_dir +
      "/*.seg | head -1); printf 'X' | dd of=\"$f\" bs=1 seek=200 conv=notrunc "
      "status=none";
  ASSERT_EQ(std::system(cmd.c_str()), 0);

  std::unique_ptr<Index> idx;
  EXPECT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kSegmentLost);
}

TEST(Index, ReportsAMissingSegmentRatherThanSearchingWithoutIt) {
  TempDir dir;
  VaultKeys keys = MakeKeys();
  std::unique_ptr<Embedder> e = NewHashingEmbedder(96);
  const Corpus c = BuildCorpus(e.get(), 4);
  {
    std::unique_ptr<Index> idx;
    ASSERT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
              IndexStatus::kOk);
    for (std::size_t i = 0; i < c.objects.size(); ++i) {
      ASSERT_EQ(idx->PutObject(c.objects[i], c.chunks[i], c.vectors[i]),
                IndexStatus::kOk);
    }
  }
  const std::string cmd =
      "rm -f $(ls " + dir.path() + "/segments/*.seg | head -1)";
  ASSERT_EQ(std::system(cmd.c_str()), 0);
  std::unique_ptr<Index> idx;
  EXPECT_EQ(Index::Open(dir.path(), &keys, 0, e->id(), e->dimension(), &idx),
            IndexStatus::kSegmentLost);
}

}  // namespace ai
}  // namespace umbra
