// The embedding interface and its two backends.
//
// The Ollama tests SKIP rather than fail when no backend is running. A test
// suite that goes red because a service is down teaches people to ignore red,
// and CI has no Ollama. What must never be skipped is anything about the model
// id, because that is the correctness half.
#include "umbra/ai/embed.h"

#include <cmath>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace umbra {
namespace ai {
namespace {

ModelDescriptor Base() {
  ModelDescriptor d;
  d.family = "all-minilm";
  d.version = "v1";
  d.dimension = 384;
  d.quantisation = "f16";
  d.pooling = "mean";
  d.normalised = true;
  return d;
}

}  // namespace

// EVERY FIELD IN THE DESCRIPTOR CHANGES THE VECTOR SPACE, so every field must
// change the id. A field that did not would let two incompatible models share
// an identity, and Phase 5 would merge their segments into a store where
// distance means nothing.
TEST(ModelId, EveryFieldChangesTheIdentity) {
  const EmbeddingModelId base = ComputeModelId(Base());
  std::set<std::string> seen;
  seen.insert(base.Hex());

  ModelDescriptor d = Base();
  d.family = "bge-small";
  EXPECT_TRUE(seen.insert(ComputeModelId(d).Hex()).second) << "family";

  d = Base();
  d.version = "v2";
  EXPECT_TRUE(seen.insert(ComputeModelId(d).Hex()).second) << "version";

  d = Base();
  d.dimension = 768;
  EXPECT_TRUE(seen.insert(ComputeModelId(d).Hex()).second) << "dimension";

  d = Base();
  d.quantisation = "q8_0";
  EXPECT_TRUE(seen.insert(ComputeModelId(d).Hex()).second) << "quantisation";

  d = Base();
  d.pooling = "cls";
  EXPECT_TRUE(seen.insert(ComputeModelId(d).Hex()).second) << "pooling";

  d = Base();
  d.normalised = false;
  EXPECT_TRUE(seen.insert(ComputeModelId(d).Hex()).second) << "normalised";
}

// THE CLASSIC HASHING BUG. Without length-prefixed fields, ("bge", "small-v1")
// and ("bgesmall", "v1") hash the same string of bytes and two different models
// get one identity. This is the test that says the separators are load bearing.
TEST(ModelId, FieldBoundariesAreNotAmbiguous) {
  ModelDescriptor a = Base();
  a.family = "bge";
  a.version = "small-v1";
  ModelDescriptor b = Base();
  b.family = "bgesmall";
  b.version = "-v1";
  EXPECT_NE(ComputeModelId(a), ComputeModelId(b));
}

TEST(ModelId, TheSameDescriptorGivesTheSameId) {
  EXPECT_EQ(ComputeModelId(Base()), ComputeModelId(Base()));
  EXPECT_EQ(ComputeModelId(Base()).Hex().size(), 32u);
  EXPECT_EQ(ComputeModelId(Base()).Short().size(), 8u);
}

TEST(Vectors, NormaliseRefusesWhatHasNoDirection) {
  Vector zero(8, 0.0f);
  EXPECT_FALSE(Normalise(&zero)) << "an all-zero vector has no direction";

  Vector nan(4, 1.0f);
  nan[2] = std::nanf("");
  EXPECT_FALSE(Normalise(&nan));

  Vector inf(4, 1.0f);
  inf[1] = std::numeric_limits<float>::infinity();
  EXPECT_FALSE(Normalise(&inf));

  Vector v = {3.0f, 4.0f};
  ASSERT_TRUE(Normalise(&v));
  EXPECT_NEAR(v[0], 0.6f, 1e-6);
  EXPECT_NEAR(v[1], 0.8f, 1e-6);
  EXPECT_NEAR(Similarity(v, v), 1.0f, 1e-6);
}

TEST(Vectors, SimilarityRefusesMismatchedWidths) {
  const Vector a(4, 0.5f);
  const Vector b(8, 0.5f);
  EXPECT_EQ(Similarity(a, b), 0.0f)
      << "a width mismatch must not read past an end";
}

TEST(HashingEmbedder, IsDeterministicAndSeparatesUnrelatedText) {
  std::unique_ptr<Embedder> e = NewHashingEmbedder(256);
  ASSERT_NE(e, nullptr);
  EXPECT_EQ(e->dimension(), 256u);
  // Named for what it is, so no number measured with it reads as a model score.
  EXPECT_NE(e->descriptor().family.find("not-a-model"), std::string::npos);

  const std::vector<std::string> docs = {
      "the relay stores bytes it cannot read",
      "the relay stores bytes it cannot read and nothing else",
      "my cat is asleep on the windowsill",
  };
  std::vector<Vector> a;
  std::vector<Vector> b;
  ASSERT_EQ(e->EmbedDocuments(docs, &a), EmbedStatus::kOk);
  ASSERT_EQ(e->EmbedDocuments(docs, &b), EmbedStatus::kOk);
  ASSERT_EQ(a.size(), 3u);
  for (std::size_t i = 0; i < a.size(); ++i) {
    EXPECT_EQ(a[i], b[i]) << "run " << i << " was not deterministic";
    EXPECT_NEAR(Similarity(a[i], a[i]), 1.0f, 1e-5);
  }
  EXPECT_GT(Similarity(a[0], a[1]), Similarity(a[0], a[2]))
      << "texts that share wording must sit closer than texts that do not";
}

TEST(HashingEmbedder, TextWithNoWordsStillGetsADirection) {
  std::unique_ptr<Embedder> e = NewHashingEmbedder(64);
  ASSERT_NE(e, nullptr);
  Vector v;
  ASSERT_EQ(e->EmbedQuery("--- ... !!!", &v), EmbedStatus::kOk);
  EXPECT_NEAR(Similarity(v, v), 1.0f, 1e-5)
      << "a chunk of only punctuation must not become a zero vector";
}

TEST(HashingEmbedder, RefusesAZeroDimension) {
  EXPECT_EQ(NewHashingEmbedder(0), nullptr);
}

// ------------------------------------------------------------------- backend

namespace {
// Skipped, not failed, when nothing is listening. See the note at the top.
std::unique_ptr<Embedder> TryOllama(const std::string& model,
                                    EmbedStatus* status) {
  return NewOllamaEmbedder(model, "127.0.0.1", 11434, status);
}
}  // namespace

TEST(OllamaEmbedder, EmbedsAndRanksWhenABackendIsRunning) {
  EmbedStatus st = EmbedStatus::kOk;
  std::unique_ptr<Embedder> e = TryOllama("all-minilm", &st);
  if (e == nullptr) {
    GTEST_SKIP() << "no local Ollama with all-minilm (" << EmbedStatusName(st)
                 << ")";
  }
  EXPECT_GT(e->dimension(), 0u);
  EXPECT_EQ(e->descriptor().dimension, e->dimension());

  const std::vector<std::string> docs = {
      "The relay stores ciphertext and cannot read the notes it holds.",
      "My cat is asleep on the windowsill in the afternoon sun.",
  };
  std::vector<Vector> vs;
  ASSERT_EQ(e->EmbedDocuments(docs, &vs), EmbedStatus::kOk);
  ASSERT_EQ(vs.size(), 2u);
  for (const Vector& v : vs) {
    EXPECT_EQ(v.size(), e->dimension());
    EXPECT_NEAR(Similarity(v, v), 1.0f, 1e-4) << "vectors must arrive unit";
  }
  Vector q;
  ASSERT_EQ(e->EmbedQuery("what can the relay see", &q), EmbedStatus::kOk);
  EXPECT_GT(Similarity(q, vs[0]), Similarity(q, vs[1]))
      << "the relevant passage did not rank first";
}

TEST(OllamaEmbedder, ReportsAModelThatIsNotThere) {
  EmbedStatus st = EmbedStatus::kOk;
  std::unique_ptr<Embedder> probe = TryOllama("all-minilm", &st);
  if (probe == nullptr) GTEST_SKIP() << "no local Ollama";
  EmbedStatus missing = EmbedStatus::kOk;
  std::unique_ptr<Embedder> e =
      TryOllama("umbra-no-such-model-exists-here", &missing);
  EXPECT_EQ(e, nullptr);
  EXPECT_NE(missing, EmbedStatus::kOk);
}

// A LOCAL-FIRST TOOL MUST NOT BE ONE FLAG AWAY FROM AN UPLOADER.
TEST(OllamaEmbedder, RefusesToDialAnythingButLoopback) {
  EmbedStatus st = EmbedStatus::kOk;
  // A routable address that would otherwise resolve. Nothing is dialled: the
  // refusal is on the host, before any socket.
  std::unique_ptr<Embedder> e =
      NewOllamaEmbedder("all-minilm", "203.0.113.7", 11434, &st);
  EXPECT_EQ(e, nullptr);
  EXPECT_EQ(st, EmbedStatus::kUnreachable);

  std::unique_ptr<Embedder> named =
      NewOllamaEmbedder("all-minilm", "example.invalid", 11434, &st);
  EXPECT_EQ(named, nullptr);
  EXPECT_EQ(st, EmbedStatus::kUnreachable);
}

}  // namespace ai
}  // namespace umbra
