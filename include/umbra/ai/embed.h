// Turning chunks into vectors, behind an interface.
//
// ---------------------------------------------------------------------------
// THE MODEL VERSION IS PART OF THE INDEX, NOT A NOTE IN A README
//
// A vector from one model and a vector from another are numbers of the same
// shape with no relationship. Cosine similarity between them is not a poor
// answer, it is a meaningless one, and nothing in the arithmetic says so. Phase
// 5 syncs segments between devices; if it merged segments built by two models
// the result would be a store where distance means nothing and search degrades
// with no error anywhere.
//
// So every segment records an EmbeddingModelId and a mismatch is REPORTED
// rather than reconciled. The only correct response to "this segment was built
// by a different model" is to re-embed, and that is the user's decision.
//
// ---------------------------------------------------------------------------
// WHAT DOES *NOT* HAVE TO MATCH
//
// Bit-identical vectors across devices. Floating-point inference is not
// reproducible across SIMD widths, FMA contraction or reduction order, and
// requiring it would be determinism theatre. It is not needed: Phase 5 copies
// segments as sealed bytes rather than recomputing them, so two devices never
// independently embed the same chunk and compare. Chunk BOUNDARIES must be
// identical (ADR 0006); vectors need only be COMPATIBLE, which is what the
// model id establishes.
//
// ---------------------------------------------------------------------------
// QUERIES AND DOCUMENTS ARE NOT THE SAME CALL
//
// Several retrieval models are asymmetric: BGE wants an instruction prefix on
// the query and nothing on the document, E5 wants "query: " and "passage: ".
// Getting it wrong costs real recall and raises no error at all. The asymmetry
// therefore lives in the interface, where a backend can implement it once,
// rather than in the memory of whoever writes the next caller.
#ifndef UMBRA_AI_EMBED_H_
#define UMBRA_AI_EMBED_H_

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace umbra {
namespace ai {

// A vector is float32 and unit length. Storing normalised means cosine
// similarity is a dot product, which is one multiply-add per dimension with no
// square roots on the hot path.
using Vector = std::vector<float>;

// One result of a nearest-neighbour search: which vector, and how near.
//
// It lives here rather than in the index because it is a fact about vectors,
// and because both the public segment API and the private graph need it --
// defining it in the graph header would have made the public one depend on a
// private one.
struct Neighbour {
  uint32_t id = 0;
  float score = 0.0f;  // similarity, higher is nearer
};

// What makes two vectors comparable.
//
// NOT the hash of the model file: two people who quantise the same weights with
// different tool versions get different files and compatible vectors, and
// refusing to merge those would be wrong in the annoying direction. NOT the
// family name alone either: the same family at Q4 and at Q8 is close enough to
// be tempting and far enough apart to be wrong.
struct EmbeddingModelId {
  std::array<uint8_t, 16> bytes{};

  bool operator==(const EmbeddingModelId& o) const { return bytes == o.bytes; }
  bool operator!=(const EmbeddingModelId& o) const { return !(*this == o); }
  bool operator<(const EmbeddingModelId& o) const { return bytes < o.bytes; }
  std::string Hex() const;
  std::string Short() const;
};

// The fields that go into the id. Everything here changes the vector space;
// nothing here is cosmetic.
struct ModelDescriptor {
  std::string family;   // "all-minilm", "nomic-embed-text"
  std::string version;  // "v1.5", or the tag the backend resolved
  uint32_t dimension = 0;
  std::string quantisation;  // "f16", "q8_0", "unknown"
  std::string pooling;       // "mean", "cls"
  bool normalised = true;
};

EmbeddingModelId ComputeModelId(const ModelDescriptor& d);

// Closed; -Werror=switch applies.
enum class EmbedStatus : uint8_t {
  kOk,
  // The backend is not reachable. Distinguished from a refusal because the
  // caller's response differs: retry later rather than reconfigure.
  kUnreachable,
  // The backend answered something this cannot parse, or a vector of the wrong
  // width. A backend that changes dimension under a pinned name is a
  // correctness problem, not a transient one.
  kBadResponse,
  // The model is not present on the backend.
  kNoSuchModel,
  // A vector came back as all zeros or with a non-finite component. Refused
  // rather than stored: a zero vector has no direction and would match
  // everything or nothing depending on the metric.
  kDegenerateVector,
};

const char* EmbedStatusName(EmbedStatus s);

class Embedder {
 public:
  virtual ~Embedder() = default;

  // Embed passages for storage. Batched because per-call overhead dominates on
  // a local HTTP backend and a vault is tens of thousands of chunks.
  virtual EmbedStatus EmbedDocuments(const std::vector<std::string>& texts,
                                     std::vector<Vector>* out) = 0;

  // Embed a query for search. Separate from the above on purpose; see the note
  // at the top of this file.
  virtual EmbedStatus EmbedQuery(const std::string& text, Vector* out) = 0;

  virtual uint32_t dimension() const = 0;
  virtual const EmbeddingModelId& id() const = 0;
  virtual const ModelDescriptor& descriptor() const = 0;
};

// Talks to a local Ollama over HTTP. `host` and `port` default to Ollama's own.
//
// The descriptor's dimension is discovered by embedding once at construction
// rather than being configured, because a configured dimension that disagrees
// with the backend is a silent corruption and a discovered one cannot.
std::unique_ptr<Embedder> NewOllamaEmbedder(const std::string& model,
                                            const std::string& host,
                                            uint16_t port, EmbedStatus* status);

// A DETERMINISTIC STAND-IN FOR TESTS. It is not a model and makes no semantic
// claim: it hashes token trigrams into a fixed number of dimensions, so texts
// that share wording land near each other and texts that do not, do not. That
// is enough to exercise an index, a recall harness, and a citation path without
// a 300 MB download in CI.
//
// It is named for what it is so that no measurement taken with it can be
// mistaken for a measurement of retrieval quality.
std::unique_ptr<Embedder> NewHashingEmbedder(uint32_t dimension);

// Cosine similarity of two unit vectors, which is their dot product. Both must
// have the same width; mismatched widths return 0 rather than reading past an
// end.
float Similarity(const Vector& a, const Vector& b);

// Scales to unit length in place. Returns false for a vector with no direction
// -- all zeros, or holding a non-finite component -- which the caller must
// treat as kDegenerateVector rather than storing.
bool Normalise(Vector* v);

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_EMBED_H_
