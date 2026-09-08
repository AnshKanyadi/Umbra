// A deterministic stand-in for an embedding model.
//
// IT IS NOT A MODEL AND MAKES NO SEMANTIC CLAIM. It hashes lowercased word
// trigrams, bigrams and unigrams into a fixed number of dimensions, so texts
// that share wording land near each other and texts that do not, do not. That
// is enough to exercise an index, a recall harness against brute force, a
// delete path and a citation path, without a download in CI and without making
// every test depend on a service being up.
//
// It is named for what it is. No number measured with this may be reported as a
// measurement of retrieval quality, and the retrieval evaluation in item 5 uses
// a real model for exactly that reason.
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "umbra/ai/embed.h"

namespace umbra {
namespace ai {
namespace {

// Locale-free, and over unsigned char. The same reasoning as chunk.cc: this
// runs in tests on every platform in the matrix and a locale-sensitive fold
// would make a recall number depend on the machine.
std::vector<std::string> Words(const std::string& text) {
  std::vector<std::string> out;
  std::string current;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const uint8_t c = static_cast<uint8_t>(text[i]);
    const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c >= 0x80;
    if (alnum) {
      current.push_back(static_cast<char>(
          (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c - 'A' + 'a') : c));
    } else if (!current.empty()) {
      out.push_back(current);
      current.clear();
    }
  }
  if (!current.empty()) out.push_back(current);
  return out;
}

uint64_t HashToken(const std::string& s) {
  uint8_t digest[8];
  crypto_generichash(digest, sizeof(digest),
                     reinterpret_cast<const unsigned char*>(s.data()), s.size(),
                     nullptr, 0);
  uint64_t v = 0;
  for (std::size_t i = 0; i < sizeof(digest); ++i) {
    v = (v << 8) | digest[i];
  }
  return v;
}

class HashingEmbedder : public Embedder {
 public:
  explicit HashingEmbedder(uint32_t dimension) {
    descriptor_.family = "umbra-hashing-not-a-model";
    descriptor_.version = "1";
    descriptor_.dimension = dimension;
    descriptor_.quantisation = "none";
    descriptor_.pooling = "sum";
    descriptor_.normalised = true;
    id_ = ComputeModelId(descriptor_);
  }

  EmbedStatus EmbedDocuments(const std::vector<std::string>& texts,
                             std::vector<Vector>* out) override {
    out->clear();
    out->reserve(texts.size());
    for (const std::string& t : texts) {
      Vector v;
      if (!Encode(t, &v)) return EmbedStatus::kDegenerateVector;
      out->push_back(v);
    }
    return EmbedStatus::kOk;
  }

  EmbedStatus EmbedQuery(const std::string& text, Vector* out) override {
    // Symmetric on purpose: this has no instruction tuning to respect, and
    // pretending otherwise would model an asymmetry it does not have.
    if (!Encode(text, out)) return EmbedStatus::kDegenerateVector;
    return EmbedStatus::kOk;
  }

  uint32_t dimension() const override { return descriptor_.dimension; }
  const EmbeddingModelId& id() const override { return id_; }
  const ModelDescriptor& descriptor() const override { return descriptor_; }

 private:
  bool Encode(const std::string& text, Vector* out) const {
    out->assign(descriptor_.dimension, 0.0f);
    const std::vector<std::string> words = Words(text);
    if (words.empty()) {
      // A CHUNK WITH NO WORDS STILL NEEDS A DIRECTION. An all-zero vector
      // matches everything or nothing depending on the metric, so a fixed
      // non-zero direction is used and the caller is not handed a degenerate
      // vector for a chunk that is only punctuation.
      (*out)[0] = 1.0f;
      return true;
    }
    const auto add = [&](const std::string& token, float weight) {
      const uint64_t h = HashToken(token);
      const uint32_t slot = static_cast<uint32_t>(h % descriptor_.dimension);
      // The sign comes from a different part of the hash than the slot, so two
      // tokens sharing a slot are as likely to cancel as to reinforce, which is
      // what keeps unrelated texts apart.
      const float sign = ((h >> 32) & 1u) ? 1.0f : -1.0f;
      (*out)[slot] += sign * weight;
    };
    for (std::size_t i = 0; i < words.size(); ++i) {
      add(words[i], 1.0f);
      if (i + 1 < words.size()) add(words[i] + " " + words[i + 1], 2.0f);
      if (i + 2 < words.size()) {
        add(words[i] + " " + words[i + 1] + " " + words[i + 2], 3.0f);
      }
    }
    return Normalise(out);
  }

  ModelDescriptor descriptor_;
  EmbeddingModelId id_;
};

}  // namespace

std::unique_ptr<Embedder> NewHashingEmbedder(uint32_t dimension) {
  if (dimension == 0) return nullptr;
  return std::unique_ptr<Embedder>(new HashingEmbedder(dimension));
}

}  // namespace ai
}  // namespace umbra
