// Retrieval, and answering from it with citations.
//
// ---------------------------------------------------------------------------
// WHAT HAPPENS WHEN NOTHING RELEVANT IS FOUND
//
// It says so, and it does not answer.
//
// This is the decision the whole feature stands on. A retrieval system that
// falls back to the model's own knowledge when the vault has nothing produces
// its most confident-sounding output exactly when it knows least, and the user
// has no way to tell that answer from a grounded one. Once someone finds a
// fluent, wrong, uncited answer among the right ones, they stop trusting the
// right ones too -- and they are correct to.
//
// So there are three outcomes and they are distinguishable:
//
//   kAnswered      passages cleared the floor, the model used them, and every
//                  citation resolves to a real byte range
//   kNoPassages    nothing in the vault was near enough. No answer is produced
//                  and the nearest misses are listed so the user can judge
//   kUngrounded    passages were found and the model answered without citing
//                  any of them. The text is returned, MARKED, never silently
//   kNoAnswerInPassages
//                  passages were found and the model said they do not answer
//                  the question. The guard working, not an error
//
// WHAT THIS DOES NOT DO, MEASURED RATHER THAN HOPED.
//
// The verdict is a mitigation, not a guarantee. Across two corpora and 45
// questions, with llama3.2:3b: 25 of 28 answerable questions were answered, and
// 13 of 17 unanswerable ones were refused. The four that got through on the
// design corpus produced exactly the failure this exists to stop -- "a
// monotonic stack is related to convergence ... it avoids backward
// interleaving", cited to a real CRDT passage at 0.6001.
//
// Four prompt wordings were measured. They trade the two errors against each
// other and cannot remove both: the strictest refused 7 of 10 real answers, the
// most permissive let the monotonic-stack case through on both corpora.
// llama3.1:8b caught one more of the four than the 3B did. The wording here is
// the precision-leaning one, because a refusal is visible and recoverable --
// the passages are printed underneath it -- and a fabrication is neither.
//
// A SECOND PASS WAS BUILT, MEASURED, AND NOT SHIPPED. Do not rebuild it without
// reading this.
//
// The shape was the obvious one: after the answer is generated, a second call
// receives only the claims and the passages they cite -- no question, no
// citation markers, no sign that it wrote the text -- and judges each claim as
// SUPPORTED or NOT-SUPPORTED. Entailment rather than generation. An unsupported
// claim downgraded the answer to kUngrounded.
//
// Over the same 45 questions, with and without, in one session:
//
//                    answered      fabrications through
//   single pass      25/28 (89%)   3/17 (18%)
//   with verifier    18/28 (64%)   1/17  (6%)
//
// It destroyed SEVEN real answers to catch TWO fabrications. On the algorithms
// corpus it was pure loss: nothing caught, three good answers marked
// ungrounded. And it did not catch the case that motivated it -- the fabricated
// paragraph about monotonic stacks survived, because the sentence quoted a
// fragment that really is in the cited passage ("a move operation that would
// create a cycle is ignored") and wrapped it in an invented conclusion.
// Entailment judged by the same model turns out to be presence-checking.
//
// Latency was NOT the reason. It cost 4% (2.88s -> 2.99s), not the doubling
// everyone including me predicted: a verifier emits one short line per claim,
// and generation time goes on output tokens. The cost was recall, and recall is
// where every attempt at this has ended up.
//
// So an answer remains a MODEL'S CLAIM ABOUT PASSAGES, and the passages are
// shown so the claim can be checked. Anything stronger needs a judge that is
// not this model -- a different and larger one, or a person.
//
// THE MODEL'S VERDICT IS READ FROM A TOKEN, NOT FROM ITS PROSE. The prompt has
// always told the model to decline when the passages fall short, and a small
// model says "there is no passage that explains this" and then guesses anyway.
// So it must now open with VERDICT: ANSWER or VERDICT: NO-ANSWER, and the
// verdict is what the code believes -- prose is not parsed for hedging, because
// hedging is a style and this needs a fact. A missing verdict fails closed.
//
// kUngrounded is not treated as success. It is the case where a model wrote
// something plausible from its own weights, and the caller is told.
//
// ---------------------------------------------------------------------------
// A CITATION NAMES A PASSAGE, NOT A FILE
//
// Every citation carries (object id, byte range) and the text that lay in that
// range at retrieval time. "See meeting-notes.md" is not a citation: it hands
// the reader a file and the job of finding the claim in it. The point of the
// byte range is that following the citation lands on the sentence.
//
// The passage text is read from the vault at retrieval time rather than stored
// in the index (see segment.h), so a citation into a note that has since
// changed is visibly stale rather than quietly serving text the vault no longer
// holds.
//
// ---------------------------------------------------------------------------
// THE RELEVANCE FLOOR IS PER MODEL, AND MEASURED
//
// Similarity scores are not comparable between models, and the difference is
// categorical rather than marginal. On the eval corpus, nomic-embed-text
// answers ALL THREE questions the vault cannot answer at any floor up to 0.50,
// because its scores sit in a narrow band; at 0.60 it refuses all three and
// gives up nothing. all-minilm never reaches that point at all: its best
// refusal behaviour costs a false refusal.
//
// So the floor travels with the model in AnswerOptions, its default is
// documented as measured rather than chosen, and a caller using a different
// model is expected to measure. A floor that has not been measured is a number
// deciding when to refuse to answer, on no evidence.
#ifndef UMBRA_AI_ANSWER_H_
#define UMBRA_AI_ANSWER_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "umbra/ai/embed.h"
#include "umbra/ai/index.h"

namespace umbra {
namespace ai {

// A retrieved passage, resolved back to the text it names.
struct Passage {
  ObjectId object;
  uint32_t start = 0;
  uint32_t end = 0;
  std::string heading_path;
  // The bytes in [start, end) as the vault holds them now. Empty if the
  // document could not be read, which is reported rather than hidden.
  std::string text;
  float score = 0.0f;
  ChunkKind kind = ChunkKind::kProse;
  uint32_t link_ratio = 0;
  // Whether the range could be resolved at all. A passage that cannot be
  // resolved is never cited.
  bool resolved = false;
};

// How a document's current text is obtained. A callback rather than a
// dependency on the vault, so the answer layer can be tested without a CRDT and
// so it never holds a second copy of anyone's notes.
using DocumentSource =
    std::function<bool(const ObjectId& object, std::string* out)>;

// Closed; -Werror=switch applies.
enum class AnswerStatus : uint8_t {
  kAnswered,
  // Nothing cleared the relevance floor. No answer was produced.
  kNoPassages,
  // Passages were found and the model reported that they do not answer the
  // question. A SUCCESS OF THE GUARD, not a failure: the vault was searched,
  // something came back, and the model declined to build an answer out of it.
  //
  // This case existed all along and had nowhere to go. Asked about a topic the
  // vault has never heard of, a model would open with "there is no passage
  // that explains X", then add "however, I can make an educated guess",
  // fabricate a paragraph, and cite a real passage that says nothing of the
  // kind. Because a citation resolved, that came back kAnswered -- rendered
  // exactly like a grounded answer, with a real byte range under it. A citation
  // proves the model referenced a passage. It does not prove the passage
  // supports the claim, and the two were being treated as the same thing.
  kNoAnswerInPassages,
  // Passages were found and the model's answer cited none of them. Returned
  // and marked; see the note at the top.
  kUngrounded,
  // The embedder or the index failed.
  kRetrievalFailed,
  // The generator was unreachable or refused.
  kGenerationFailed,
};

const char* AnswerStatusName(AnswerStatus s);

// Text generation, behind an interface. The interface is the deliverable; the
// model is not built here.
class Generator {
 public:
  virtual ~Generator() = default;
  // Returns false when the backend could not be reached or answered with
  // something unusable. `system` and `user` are kept separate because backends
  // apply their own chat template.
  virtual bool Generate(const std::string& system, const std::string& user,
                        std::string* out) = 0;
  virtual const std::string& model() const = 0;
};

// Ollama over loopback, on the same terms as the embedder: nothing but
// loopback, no dependency, and a bounded response.
std::unique_ptr<Generator> NewOllamaGenerator(const std::string& model,
                                              const std::string& host,
                                              uint16_t port);

// A generator that returns a fixed string. For tests that are about the
// grounding logic rather than about a model.
std::unique_ptr<Generator> NewScriptedGenerator(const std::string& reply);

struct AnswerOptions {
  // How many passages to retrieve, and the per-segment beam.
  uint32_t k = 6;
  uint32_t ef = 64;
  // THE FLOOR, MEASURED. 0.60 is where nomic-embed-text refuses all three
  // unanswerable questions in test/fixtures/eval and still returns 11/14 at
  // rank one -- see the sweep in ADR 0007. A caller using a different model
  // MUST measure its own: at this same floor all-minilm returns almost
  // nothing, and at all-minilm's floor of 0.25 nomic answers every question it
  // should decline.
  //
  // COSINE RUNS FROM -1 TO 1, so the value that disables this is -1.0 and NOT
  // zero. Zero is already a meaningful floor -- it discards everything
  // negatively correlated with the query, which is most of a corpus -- and
  // setting it there expecting "no filtering" is a mistake that looks like
  // retrieval finding nothing.
  float min_score = 0.60f;
  // A passage this far below the best one is dropped even if it clears the
  // floor, so one strong hit is not padded out with six weak ones. A fraction
  // of the best score, so -1.0 disables it.
  float relative_floor = 0.55f;
  // Link-dominated chunks are real notes and are retrieved, but a map of
  // contents is rarely the answer to a question. Above this ratio a passage is
  // kept only if nothing else cleared the floor.
  uint32_t demote_link_ratio = 6000;
};

// THE SHAPE OF THE SCORES, NOT JUST THE TOP ONE.
//
// An absolute cosine score cannot tell a hit from a miss, and this was found
// the way such things are found -- by using it. A vault holding a note on depth
// first search answered "DFS" with that note at 0.79 and an 0.08 gap to the
// next passage. The same vault, asked about monotonic stacks, which it has
// never heard of, returned six unrelated notes inside a 0.024 band. Both
// cleared a floor of 0.60. The absolute numbers say the second is nearly as
// good as the first; the SHAPE says the second is a ranking of noise.
//
// So retrieval reports what its scores looked like, and the caller can see why
// a query was answered or refused rather than only that it was.
struct RetrievalShape {
  // How many candidates the index returned, before any filtering.
  uint32_t candidates = 0;
  float best = 0.0f;
  // The runner-up. Equal to `best` when there was only one candidate, so a gap
  // of zero means "nothing to compare against" as well as "indistinguishable",
  // which are the same thing for this purpose.
  float second = 0.0f;
  // Over the whole candidate pool, which is what makes this a statement about
  // the query rather than about the two passages that happened to win.
  float mean = 0.0f;
  float stddev = 0.0f;

  // How far the winner stands clear of the runner-up.
  float Gap() const { return best - second; }
  // How far the winner stands clear of the pool, in standard deviations. The
  // discriminating measure: a query the vault can answer has a top score that
  // is an outlier among its own candidates, and one it cannot has a top score
  // that is merely the largest of a cluster.
  float Standout() const {
    if (stddev <= 0.0f) return 0.0f;
    return (best - mean) / stddev;
  }
};

struct AnswerResult {
  AnswerStatus status = AnswerStatus::kNoPassages;

  // WHETHER THE INDEX SEARCHED WAS COMPLETE. False when the manifest names
  // segments this device does not hold yet -- a phone that has pulled the
  // operations but not the bytes, or a laptop catching up after a week away.
  //
  // The result is still correct as far as it goes, and saying so is the point:
  // an answer drawn from part of a vault, presented as if drawn from all of it,
  // is the same failure as an ungrounded answer presented as a grounded one.
  // Retrieval degrades, and the caller is told that it did.
  bool index_complete = true;
  // How many segments were missing when the search ran, so a caller can say
  // "still catching up, 3 of 11 segments" rather than only "incomplete".
  uint32_t segments_missing = 0;
  std::string text;
  // Every passage that was put in front of the model, in the order it was
  // numbered.
  std::vector<Passage> passages;
  // The indices into `passages` that the answer actually cited.
  std::vector<uint32_t> cited;
  // Populated for kNoPassages: the nearest things that did not clear the floor,
  // so a user can see whether the vault has nothing or the query was wrong.
  std::vector<Passage> near_misses;
  // What the scores looked like. Populated on every path, including refusals.
  RetrievalShape shape;

  // HOW MUCH OF THE VAULT THIS ANSWER SAW.
  //
  // Retrieval answers questions about things IN the notes. It cannot answer
  // questions about the notes AS A WHOLE, because it never sees the whole -- it
  // sees k passages. Asked to "summarize what is in these notes", it returns
  // six chunks and summarizes those, and every guard passes: the citations
  // resolve, the passages really do support each claim, and the verdict is
  // honestly ANSWER. The answer is correct about six chunks and wrong about the
  // question, and nothing in the text says which.
  //
  // These two numbers are what make that visible. Six of six passages is
  // unremarkable for "what is the classic binary search bug" and damning for
  // "summarize my vault", and the reader can tell the difference even though
  // the machinery cannot. They are counted from the index rather than inferred,
  // so they are right even when the retrieval is not.
  uint32_t vault_passages = 0;
  uint32_t vault_notes = 0;
};

// Retrieve only. Exposed because search without generation is useful on its own
// and because it is the half that can be measured.
IndexStatus Retrieve(const Index& index, Embedder* embedder,
                     const DocumentSource& source, const std::string& query,
                     const AnswerOptions& options, std::vector<Passage>* out,
                     std::vector<Passage>* near_misses,
                     RetrievalShape* shape = nullptr);

// Retrieve, then answer. `generator` may be null, in which case the passages
// are returned with kNoPassages or kAnswered and no text -- useful for a caller
// that wants grounding without generation.
AnswerResult Answer(const Index& index, Embedder* embedder,
                    Generator* generator, const DocumentSource& source,
                    const std::string& query, const AnswerOptions& options);

// The prompt the model is given. Exposed so a test can assert what it says
// rather than trusting a comment about it.
std::string BuildPrompt(const std::string& query,
                        const std::vector<Passage>& passages);

// The instruction that tells the model to answer only from the passages and to
// say when they do not contain the answer.
const char* SystemPrompt();

// Which passage numbers a piece of text cites, as [1] [2] style markers.
// Numbers outside the range are ignored rather than trusted, because a model
// that invents a citation must not be able to make one resolve.
std::vector<uint32_t> ParseCitations(const std::string& text,
                                     uint32_t passage_count);

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_ANSWER_H_
