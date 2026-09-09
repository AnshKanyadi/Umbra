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
// Similarity scores are not comparable between models. Measured on the same
// three-document probe: all-minilm separates the relevant passage from an
// unrelated one 0.48 to 0.01, while nomic-embed-text puts them at 0.79 and
// 0.52. A single hard-coded floor would be far too strict for one and useless
// for the other.
//
// So the floor travels with the model in AnswerOptions, its default is
// documented as measured rather than chosen, and a caller using a different
// model is expected to measure. A floor that has not been measured is a number
// that decides when to refuse to answer, on no evidence.
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
  // THE FLOOR. Measured for all-minilm on the fixture corpus; a caller using
  // another model must measure its own. See the note at the top of this file.
  //
  // COSINE RUNS FROM -1 TO 1, so the value that disables this is -1.0 and NOT
  // zero. Zero is already a meaningful floor -- it discards everything
  // negatively correlated with the query, which is most of a corpus -- and
  // setting it there expecting "no filtering" is a mistake that looks like
  // retrieval finding nothing.
  float min_score = 0.25f;
  // A passage this far below the best one is dropped even if it clears the
  // floor, so one strong hit is not padded out with six weak ones. A fraction
  // of the best score, so -1.0 disables it.
  float relative_floor = 0.55f;
  // Link-dominated chunks are real notes and are retrieved, but a map of
  // contents is rarely the answer to a question. Above this ratio a passage is
  // kept only if nothing else cleared the floor.
  uint32_t demote_link_ratio = 6000;
};

struct AnswerResult {
  AnswerStatus status = AnswerStatus::kNoPassages;
  std::string text;
  // Every passage that was put in front of the model, in the order it was
  // numbered.
  std::vector<Passage> passages;
  // The indices into `passages` that the answer actually cited.
  std::vector<uint32_t> cited;
  // Populated for kNoPassages: the nearest things that did not clear the floor,
  // so a user can see whether the vault has nothing or the query was wrong.
  std::vector<Passage> near_misses;
};

// Retrieve only. Exposed because search without generation is useful on its own
// and because it is the half that can be measured.
IndexStatus Retrieve(const Index& index, Embedder* embedder,
                     const DocumentSource& source, const std::string& query,
                     const AnswerOptions& options, std::vector<Passage>* out,
                     std::vector<Passage>* near_misses);

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
