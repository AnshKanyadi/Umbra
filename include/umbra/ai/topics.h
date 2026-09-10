// What is in a vault, answered from structure rather than by reading it.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NOT A SUMMARY
//
// Retrieval answers questions about things IN the notes and cannot answer
// questions about the notes AS A WHOLE, because it sees k passages. Asked to
// summarize a vault it summarizes six chunks and sounds certain doing it, and
// every guard passes, correctly: the citations resolve, the passages support
// each sentence, and the model honestly reports that they answer the question.
// A summary of six chunks IS a true summary of six chunks. It is right about
// the passages and wrong about the question.
//
// The obvious repair -- read every note, summarize each, reduce the summaries --
// was specified, measured, and rejected. It costs about 41 minutes on a 3000
// note vault, and the reduce step destroys what it was for: at a fan-in of a
// hundred, three thousand notes reduce in two levels, and depth two produces
// "this collection covers various topics in distributed systems", which is
// unfalsifiable. See ADR 0009.
//
// So the question is answered from what has already been computed. Every chunk
// in the index has an embedding; the structure of a vault is in those vectors
// and does not need to be read out of the notes a second time.
//
// ---------------------------------------------------------------------------
// COUNTABLE, NOT NARRATIVE
//
// The output is groups with counts and members, not prose. That is a better
// answer to "what is in my notes" and it keeps the guarantees meaningful: a
// group is a set of real chunks with real byte ranges, so every number here can
// be checked against the index, and every example can be opened and read.
//
// WHAT IS A FACT AND WHAT IS A GUESS. The membership, the counts and the
// cohesion are computed and exact. The LABEL is a model's description of a few
// members and is worth what that is worth -- it is filled in by the caller, not
// by this file, so a topic map built without a generator is still complete and
// still true, just unnamed.
#ifndef UMBRA_AI_TOPICS_H_
#define UMBRA_AI_TOPICS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "umbra/ai/index.h"

namespace umbra {
namespace ai {

// One chunk that belongs to a topic, near enough to the middle of it to be
// worth showing.
struct TopicExample {
  ObjectId object;
  uint32_t start = 0;
  uint32_t end = 0;
  std::string heading_path;
  // Cosine to the group's centre. How representative this example is.
  float similarity = 0.0f;
};

struct Topic {
  // Filled by the caller if it has a generator. Empty is a valid topic map.
  std::string label;
  uint32_t chunks = 0;
  // Distinct notes, which is not the same number and is usually the one a
  // person means.
  uint32_t notes = 0;
  // Mean cosine of the members to the centre. THE HONESTY NUMBER: a tight group
  // is a real subject, and a loose one is whatever was left over. Reported
  // rather than hidden, because a bad clustering should look bad.
  float cohesion = 0.0f;
  std::vector<TopicExample> examples;
};

struct TopicMap {
  std::vector<Topic> topics;  // largest first
  uint32_t chunks = 0;
  uint32_t notes = 0;
  uint32_t k = 0;
  uint32_t iterations = 0;
  // Mean cohesion across groups, weighted by size. One number for "did this
  // clustering find anything".
  float cohesion = 0.0f;
};

struct TopicOptions {
  // Zero asks for the default, which is chosen for READABILITY rather than
  // discovered from the data: round(sqrt(n/2)) clamped to [2, 20]. A topic map
  // with sixty rows is not an answer to "what is in my notes", and there is no
  // cheap honest way to find a true k -- silhouette scoring is quadratic in the
  // number of chunks, and within-cluster distance improves monotonically with k
  // so it cannot choose one. So k is a presentation decision, it is said to be
  // one, and cohesion is reported so a wrong k is visible.
  uint32_t k = 0;
  uint32_t max_iterations = 25;
  uint32_t examples_per_topic = 3;
};

enum class TopicStatus : uint8_t {
  kOk,
  // Fewer chunks than groups asked for, or an empty index.
  kNotEnoughChunks,
  kBadArgument,
};

const char* TopicStatusName(TopicStatus s);

// Groups every live chunk in the index. Deterministic: the same index gives the
// same map, because enumeration is ordered and the seeding is not random.
TopicStatus BuildTopicMap(const Index& index, const TopicOptions& options,
                          TopicMap* out);

// The default k for a given number of chunks, exposed so a caller can report
// what it would have chosen.
uint32_t DefaultTopicCount(uint32_t chunks);

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_TOPICS_H_
