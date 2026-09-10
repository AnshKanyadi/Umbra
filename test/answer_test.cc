// Retrieval, citations, and what happens when the vault has nothing.
//
// The generator is scripted in most of these, because what is being tested is
// the grounding logic and not a model. The one test that uses a real model
// skips when none is running.
#include "umbra/ai/answer.h"

#include <ftw.h>

#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "umbra/ai/chunk.h"
#include "umbra/ai/index.h"

namespace umbra {
namespace ai {
namespace {

// REMOVING A DIRECTORY WITHOUT A SHELL. std::system spawns a command
// processor, which clang-tidy flags (cert-env33-c) and which is genuinely worse
// here: it depends on a shell being present, on rm accepting these flags, and
// on the path surviving quoting. nftw walks the tree and unlinks as it goes.
int RemoveEntry(const char* path, const struct stat*, int type, struct FTW*) {
  if (type == FTW_DP) return ::rmdir(path);
  return ::remove(path);
}

void RemoveTree(const std::string& path) {
  if (path.empty()) return;
  // FTW_DEPTH so a directory is visited after its contents; FTW_PHYS so a
  // symlink is unlinked rather than followed out of the temporary directory.
  (void)::nftw(path.c_str(), RemoveEntry, 16, FTW_DEPTH | FTW_PHYS);
}

class TempDir {
 public:
  TempDir() {
    char t[] = "/tmp/umbra_answer_XXXXXX";
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

// A tiny vault: the documents, and a source that hands their current text back
// the way the real one reads from the CRDT.
struct Vault {
  std::map<std::string, std::string> documents;  // object bytes -> text
  std::vector<ObjectId> ids;

  DocumentSource Source() {
    return [this](const ObjectId& o, std::string* out) {
      const std::string key(reinterpret_cast<const char*>(o.bytes.data()),
                            o.bytes.size());
      const std::map<std::string, std::string>::const_iterator it =
          documents.find(key);
      if (it == documents.end()) return false;
      *out = it->second;
      return true;
    };
  }
};

ReplicaId TestReplicaFor(uint8_t seed) {
  ReplicaId r;
  r.bytes.fill(seed);
  return r;
}
const ReplicaId kTestReplica = TestReplicaFor(0xC3);

ObjectId ObjectFromSeed(uint8_t seed) {
  ObjectId id;
  id.bytes.fill(seed);
  return id;
}

struct Fixture {
  TempDir dir;
  VaultKeys keys;
  std::unique_ptr<Embedder> embedder;
  std::unique_ptr<Index> index;
  Vault vault;
};

void Build(Fixture* f, const std::vector<std::string>& docs) {
  std::array<uint8_t, kSaltBytes> salt{};
  salt.fill(3);
  ASSERT_EQ(VaultKeys::Create("answer test", salt, Fast(), &f->keys),
            CryptoStatus::kOk);
  f->embedder = NewHashingEmbedder(128);
  ASSERT_NE(f->embedder, nullptr);
  ASSERT_EQ(Index::Open(f->dir.path(), &f->keys, 0, f->embedder->id(),
                        f->embedder->dimension(), kTestReplica, &f->index),
            IndexStatus::kOk);
  for (std::size_t i = 0; i < docs.size(); ++i) {
    const ObjectId object = ObjectFromSeed(static_cast<uint8_t>(i + 1));
    f->vault.ids.push_back(object);
    f->vault.documents[std::string(
        reinterpret_cast<const char*>(object.bytes.data()),
        object.bytes.size())] = docs[i];
    std::vector<Chunk> chunks;
    ASSERT_EQ(ChunkMarkdown(object, docs[i], &chunks), ChunkStatus::kOk);
    std::vector<std::string> texts;
    for (const Chunk& c : chunks) texts.push_back(c.text);
    std::vector<Vector> vs;
    ASSERT_EQ(f->embedder->EmbedDocuments(texts, &vs), EmbedStatus::kOk);
    ASSERT_EQ(f->index->PutObject(object, chunks, vs), IndexStatus::kOk);
  }
}

const std::vector<std::string>& Docs() {
  static const std::vector<std::string> docs = {
      "# Revocation\n\nRevoking a device rotates the epoch key and seals the "
      "new one to the devices that remain. The removed device keeps every file "
      "it already had and can still read anything written before the "
      "rotation.\n",
      "# Chunking\n\nA fenced code block is never split across chunks. Half a "
      "code block embeds as something that looks like code and is not.\n",
      "# Relay\n\nThe relay stores ciphertext and cannot read it. It learns "
      "message sizes and timing and nothing else.\n",
  };
  return docs;
}

}  // namespace

TEST(Answer, CitationsPointAtRealBytesInTheDocument) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = 0.05f;

  std::vector<Passage> passages;
  ASSERT_EQ(Retrieve(*f.index, f.embedder.get(), f.vault.Source(),
                     "what does revoking a device do to the epoch key", o,
                     &passages, nullptr),
            IndexStatus::kOk);
  ASSERT_FALSE(passages.empty());

  for (const Passage& p : passages) {
    EXPECT_TRUE(p.resolved);
    // THE CITED BYTES MUST BE THE DOCUMENT'S BYTES. This is the property that
    // makes a citation followable; without it the range is decoration.
    std::string document;
    ASSERT_TRUE(f.vault.Source()(p.object, &document));
    ASSERT_LE(p.end, document.size());
    ASSERT_LT(p.start, p.end);
    EXPECT_EQ(p.text, document.substr(p.start, p.end - p.start));
  }
  // And the top passage is from the revocation note.
  const std::string top = passages[0].text;
  EXPECT_NE(top.find("rotat"), std::string::npos)
      << "the nearest passage was not about revocation: " << top;
}

// THE CASE THE FEATURE STANDS ON.
TEST(Answer, RefusesToAnswerWhenNothingIsNearEnough) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = 0.95f;  // nothing will clear this

  std::unique_ptr<Generator> gen = NewScriptedGenerator(
      "The capital of France is Paris, which I know independently of any "
      "passage.");
  const AnswerResult r =
      Answer(*f.index, f.embedder.get(), gen.get(), f.vault.Source(),
             "what is the capital of France", o);
  EXPECT_EQ(r.status, AnswerStatus::kNoPassages);
  EXPECT_TRUE(r.passages.empty());
  // THE MODEL WAS NEVER ASKED. Not asked and then filtered -- never asked, so
  // there is no plausible ungrounded text sitting in the result for a caller to
  // render by accident.
  EXPECT_EQ(r.text.find("Paris"), std::string::npos)
      << "the generator was consulted despite nothing being retrieved";
  EXPECT_NE(r.text.find("Nothing in the vault"), std::string::npos);
  // The near misses are offered so a person can tell "the vault has nothing"
  // from "I asked it badly".
  EXPECT_FALSE(r.near_misses.empty());
}

TEST(Answer, MarksAnAnswerThatCitesNothing) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  // NO FLOOR HERE ON PURPOSE. These tests are about what happens to an answer
  // once passages exist, and the floor has its own test. Tying them to an
  // absolute score would also tie them to the stand-in embedder, whose numbers
  // are not on the same scale as a real model's -- measured on one probe,
  // all-minilm separates relevant from unrelated at 0.48 against 0.01 while
  // nomic-embed-text puts them at 0.79 and 0.52, and the hashing stand-in is
  // lower than either.
  o.min_score = -1.0f;  // cosine bottoms out at -1; 0 is not "no floor"
  o.relative_floor = -1.0f;

  std::unique_ptr<Generator> gen = NewScriptedGenerator(
      "VERDICT: ANSWER\n"
      "Revocation works by rotating a key. I am confident about this and will "
      "not tell you where I got it.");
  const AnswerResult r = Answer(*f.index, f.embedder.get(), gen.get(),
                                f.vault.Source(), "what does revocation do", o);
  EXPECT_EQ(r.status, AnswerStatus::kUngrounded)
      << "an answer with no citation was accepted as grounded";
  EXPECT_TRUE(r.cited.empty());
  // The text is returned rather than discarded: the caller decides what to show
  // and can say why it is marked.
  EXPECT_FALSE(r.text.empty());
}

TEST(Answer, AcceptsAnAnswerThatCitesAPassage) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;  // cosine bottoms out at -1; 0 is not "no floor"
  o.relative_floor = -1.0f;
  std::unique_ptr<Generator> gen = NewScriptedGenerator(
      "VERDICT: ANSWER\n"
      "Rotation seals a new epoch key to the remaining "
      "devices [1].");
  const AnswerResult r = Answer(*f.index, f.embedder.get(), gen.get(),
                                f.vault.Source(), "what does revocation do", o);
  ASSERT_EQ(r.status, AnswerStatus::kAnswered);
  ASSERT_EQ(r.cited.size(), 1u);
  EXPECT_EQ(r.cited[0], 0u);
  EXPECT_LT(r.cited[0], r.passages.size());
}

// A MODEL MUST NOT BE ABLE TO MAKE UP A CITATION THAT RESOLVES.
TEST(Answer, IgnoresCitationsToPassagesThatDoNotExist) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;  // cosine bottoms out at -1; 0 is not "no floor"
  o.relative_floor = -1.0f;
  o.k = 2;
  std::unique_ptr<Generator> gen = NewScriptedGenerator(
      "VERDICT: ANSWER\n"
      "This is supported by [7] and also by [99] and definitely [0].");
  const AnswerResult r = Answer(*f.index, f.embedder.get(), gen.get(),
                                f.vault.Source(), "what does revocation do", o);
  EXPECT_TRUE(r.cited.empty()) << "an invented citation resolved to a passage";
  EXPECT_EQ(r.status, AnswerStatus::kUngrounded);
}

TEST(Answer, ParsesCitationsWithoutTrustingOutOfRangeOnes) {
  EXPECT_EQ(ParseCitations("nothing here", 5).size(), 0u);
  EXPECT_EQ(ParseCitations("one [1] two [2]", 5).size(), 2u);
  EXPECT_EQ(ParseCitations("[3] repeated [3]", 5).size(), 1u)
      << "a repeated citation is one citation";
  EXPECT_EQ(ParseCitations("[0]", 5).size(), 0u) << "passages are 1-based";
  EXPECT_EQ(ParseCitations("[6]", 5).size(), 0u) << "out of range";
  EXPECT_EQ(ParseCitations("[99999999999]", 5).size(), 0u)
      << "a long run of digits must not overflow into range";
  EXPECT_EQ(ParseCitations("[abc] [1x] [", 5).size(), 0u);
}

// A PASSAGE WHOSE NOTE HAS CHANGED IS NOT CITED. The index holds ranges, the
// vault holds text, and the two can disagree between an edit and a reindex.
TEST(Answer, DropsAPassageThatNoLongerResolves) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = 0.05f;

  // The note is truncated to a few bytes, so the indexed ranges run past its
  // end -- exactly what an edit before a reindex looks like.
  const ObjectId victim = f.vault.ids[0];
  f.vault
      .documents[std::string(reinterpret_cast<const char*>(victim.bytes.data()),
                             victim.bytes.size())] = "# R\n";

  std::vector<Passage> passages;
  ASSERT_EQ(Retrieve(*f.index, f.embedder.get(), f.vault.Source(),
                     "what does revoking a device do to the epoch key", o,
                     &passages, nullptr),
            IndexStatus::kOk);
  for (const Passage& p : passages) {
    EXPECT_TRUE(p.resolved);
    EXPECT_NE(p.object, victim)
        << "a passage was cited into a note that no longer contains it";
  }
}

TEST(Answer, AMissingDocumentIsNotCited) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = 0.05f;
  // A source that has lost everything: the vault is there, the notes are not.
  const DocumentSource none = [](const ObjectId&, std::string*) {
    return false;
  };
  std::vector<Passage> passages;
  ASSERT_EQ(Retrieve(*f.index, f.embedder.get(), none, "revocation", o,
                     &passages, nullptr),
            IndexStatus::kOk);
  EXPECT_TRUE(passages.empty())
      << "passages were returned for documents that could not be read";
}

TEST(Answer, ThePromptSaysWhatTheRulesAre) {
  // The rules are enforced by a prompt, so the prompt is asserted rather than
  // described in a comment nobody checks.
  const std::string system = SystemPrompt();
  EXPECT_NE(system.find("ONLY"), std::string::npos);
  EXPECT_NE(system.find("VERDICT: ANSWER"), std::string::npos);
  EXPECT_NE(system.find("VERDICT: NO-ANSWER"), std::string::npos);
  EXPECT_NE(system.find("Do not invent passage numbers"), std::string::npos);

  Passage p;
  p.text = "the body of a passage";
  p.heading_path = "Notes > Revocation";
  const std::string prompt = BuildPrompt("a question", {p});
  EXPECT_NE(prompt.find("[1]"), std::string::npos);
  EXPECT_NE(prompt.find("the body of a passage"), std::string::npos);
  EXPECT_NE(prompt.find("Notes > Revocation"), std::string::npos);
}

TEST(Answer, WithoutAGeneratorItStillGrounds) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = 0.05f;
  const AnswerResult r = Answer(*f.index, f.embedder.get(), nullptr,
                                f.vault.Source(), "revocation and keys", o);
  EXPECT_EQ(r.status, AnswerStatus::kAnswered);
  EXPECT_FALSE(r.passages.empty());
  EXPECT_TRUE(r.text.empty()) << "no generator means no generated text";
}

TEST(Generator, OllamaRefusesAnythingButLoopback) {
  std::unique_ptr<Generator> g =
      NewOllamaGenerator("llama3.2:1b", "203.0.113.7", 11434);
  ASSERT_NE(g, nullptr);
  std::string out;
  EXPECT_FALSE(g->Generate("system", "user", &out))
      << "a non-loopback host was dialled";
}

TEST(Generator, AnswersThroughARealModelWhenOneIsRunning) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  std::unique_ptr<Generator> g =
      NewOllamaGenerator("llama3.2:1b", "127.0.0.1", 11434);
  std::string probe;
  if (!g->Generate("Reply with the word ready.", "ready?", &probe)) {
    GTEST_SKIP() << "no local Ollama with llama3.2:1b";
  }
  AnswerOptions o;
  o.min_score = 0.05f;
  const AnswerResult r =
      Answer(*f.index, f.embedder.get(), g.get(), f.vault.Source(),
             "what happens to a device after it is revoked", o);
  std::printf("status=%s cited=%zu\ntext: %s\n", AnswerStatusName(r.status),
              r.cited.size(), r.text.c_str());
  // The status is asserted, not the wording: a model's phrasing is not a
  // property this project controls.
  EXPECT_NE(r.status, AnswerStatus::kRetrievalFailed);
  EXPECT_NE(r.status, AnswerStatus::kGenerationFailed);
  for (uint32_t c : r.cited) EXPECT_LT(c, r.passages.size());
}

// ------------------------------------------------------ the model's verdict

// A CITATION PROVES THE MODEL LOOKED AT A PASSAGE, NOT THAT THE PASSAGE SAYS SO.
//
// The shape that made this necessary, observed on a real vault and reproduced
// on a synthetic one: asked to explain a topic the vault has never covered, a
// small model opens by admitting there is no such passage, then offers "an
// educated guess", fabricates a paragraph, and cites a real passage about a
// neighbouring subject. Every citation resolved, so it came back kAnswered and
// was rendered exactly like a grounded answer. A grounded citation to an
// irrelevant passage is worse than no answer, because it looks verified.
//
// So the verdict is a token the code reads, not prose it interprets.
TEST(Answer, AGuessWearingACitationIsNotAnAnswer) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;
  o.relative_floor = -1.0f;
  std::unique_ptr<Generator> gen = NewScriptedGenerator(
      "VERDICT: NO-ANSWER\n"
      "There is no passage about monotonic stacks. However, I can make an "
      "educated guess from the discussion of recursion [1]: they track "
      "function calls and return addresses.");
  const AnswerResult r =
      Answer(*f.index, f.embedder.get(), gen.get(), f.vault.Source(),
             "explain monotonic stacks", o);
  EXPECT_EQ(r.status, AnswerStatus::kNoAnswerInPassages)
      << "a guess with a resolving citation was presented as an answer";
  // The citation still resolves and is still reported: what the model looked at
  // is the useful part of a refusal.
  EXPECT_FALSE(r.cited.empty());
}

// FAILS CLOSED. A model that ignored the format ignored the instructions, which
// is exactly when its output must not be dressed as an answer.
TEST(Answer, AReplyWithNoVerdictIsNotAnAnswer) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;
  o.relative_floor = -1.0f;
  std::unique_ptr<Generator> gen =
      NewScriptedGenerator("Revocation rotates the epoch key [1].");
  const AnswerResult r = Answer(*f.index, f.embedder.get(), gen.get(),
                                f.vault.Source(), "what does revocation do", o);
  EXPECT_EQ(r.status, AnswerStatus::kNoAnswerInPassages)
      << "a reply that skipped the verdict was accepted as an answer";
  EXPECT_NE(r.text.find("did not follow the answering format"),
            std::string::npos)
      << "the caller was not told why the reply is not being shown as one";
}

// The verdict is bookkeeping and must not survive into what a user reads.
TEST(Answer, TheVerdictLineIsNotShownToTheUser) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;
  o.relative_floor = -1.0f;
  std::unique_ptr<Generator> gen = NewScriptedGenerator(
      "VERDICT: ANSWER\nRotation seals a new epoch key [1].");
  const AnswerResult r = Answer(*f.index, f.embedder.get(), gen.get(),
                                f.vault.Source(), "what does revocation do", o);
  ASSERT_EQ(r.status, AnswerStatus::kAnswered);
  EXPECT_EQ(r.text.find("VERDICT"), std::string::npos)
      << "the verdict line was left in the answer";
  EXPECT_NE(r.text.find("Rotation seals"), std::string::npos);
}

// "VERDICT: NO-ANSWER" contains the word ANSWER, so order of checking matters.
TEST(Answer, NoAnswerIsNotReadAsAnswer) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;
  o.relative_floor = -1.0f;
  for (const char* reply : {"VERDICT: NO-ANSWER\nnothing here [1].",
                            "verdict: no-answer\nnothing here [1].",
                            "**VERDICT: NO ANSWER**\nnothing here [1]."}) {
    std::unique_ptr<Generator> gen = NewScriptedGenerator(reply);
    const AnswerResult r = Answer(*f.index, f.embedder.get(), gen.get(),
                                  f.vault.Source(), "a question", o);
    EXPECT_EQ(r.status, AnswerStatus::kNoAnswerInPassages) << reply;
  }
}

// THE SHAPE OF THE SCORES IS REPORTED, because an absolute score cannot be read
// on its own: the same 0.71 is a strong hit in one query and the top of an
// undifferentiated cluster in another.
TEST(Answer, RetrievalReportsTheShapeOfItsScores) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;
  o.relative_floor = -1.0f;
  std::vector<Passage> passages;
  RetrievalShape shape;
  ASSERT_EQ(Retrieve(*f.index, f.embedder.get(), f.vault.Source(),
                     "what does revocation do", o, &passages, nullptr, &shape),
            IndexStatus::kOk);
  EXPECT_GT(shape.candidates, 0u);
  EXPECT_GE(shape.best, shape.second);
  EXPECT_GE(shape.best, shape.mean);
  EXPECT_GE(shape.Gap(), 0.0f);
  EXPECT_GE(shape.stddev, 0.0f);
}

// AN ANSWER SAYS HOW MUCH OF THE VAULT IT SAW.
//
// The failure this exists for passes every other guard. Asked to summarize the
// notes, retrieval returns k passages and the model summarizes those: the
// citations resolve, the passages really do support each claim, and the verdict
// is honestly ANSWER, because a summary of six chunks is a true summary of six
// chunks. It is correct about the passages and wrong about the question, and no
// property of the text distinguishes it.
//
// The counts come from the index, not from the retrieval, so they are right
// even when the retrieval is not -- and "6 of 6" against "6 of 2000" is the
// difference a reader needs.
TEST(Answer, AnAnswerReportsHowMuchOfTheVaultItSaw) {
  Fixture f;
  ASSERT_NO_FATAL_FAILURE(Build(&f, Docs()));
  AnswerOptions o;
  o.min_score = -1.0f;
  o.relative_floor = -1.0f;
  o.k = 2;
  std::vector<Passage> passages;
  const AnswerResult r = Answer(*f.index, f.embedder.get(), nullptr,
                                f.vault.Source(), "what does revocation do", o);
  const IndexStats st = f.index->Stats();
  EXPECT_EQ(r.vault_passages, st.vectors - st.tombstoned);
  EXPECT_EQ(r.vault_notes, st.objects);
  EXPECT_GT(r.vault_passages, 0u);
  EXPECT_LE(r.passages.size(), r.vault_passages)
      << "more passages were answered from than the vault holds";
  // The point of the number: a caller can see that the answer is a sample.
  EXPECT_LT(r.passages.size(), static_cast<std::size_t>(r.vault_passages))
      << "this fixture is meant to hold more than k, so the share is visible";
}

}  // namespace ai

}  // namespace umbra
