#include "umbra/ai/embed.h"

#include <sodium.h>

#include <cmath>
#include <cstring>

namespace umbra {
namespace ai {
namespace {

void HexInto(const uint8_t* p, std::size_t n, std::string* out) {
  static const char kHex[] = "0123456789abcdef";
  for (std::size_t i = 0; i < n; ++i) {
    out->push_back(kHex[p[i] >> 4]);
    out->push_back(kHex[p[i] & 0x0F]);
  }
}

}  // namespace

std::string EmbeddingModelId::Hex() const {
  std::string out;
  out.reserve(bytes.size() * 2);
  HexInto(bytes.data(), bytes.size(), &out);
  return out;
}

std::string EmbeddingModelId::Short() const { return Hex().substr(0, 8); }

EmbeddingModelId ComputeModelId(const ModelDescriptor& d) {
  if (sodium_init() < 0) return EmbeddingModelId();
  // FIELD SEPARATORS, NOT CONCATENATION. Without them ("bge", "small-v1") and
  // ("bgesmall", "v1") hash the same, and two different models would share an
  // identity -- which is the one failure this type exists to prevent.
  crypto_generichash_state st;
  crypto_generichash_init(&st, nullptr, 0, 16);
  const auto field = [&st](const std::string& s) {
    uint32_t n = static_cast<uint32_t>(s.size());
    uint8_t len[4] = {static_cast<uint8_t>((n >> 24) & 0xFF),
                      static_cast<uint8_t>((n >> 16) & 0xFF),
                      static_cast<uint8_t>((n >> 8) & 0xFF),
                      static_cast<uint8_t>(n & 0xFF)};
    crypto_generichash_update(&st, len, sizeof(len));
    crypto_generichash_update(
        &st, reinterpret_cast<const unsigned char*>(s.data()), s.size());
  };
  field("umbra-embedding-model-v1");
  field(d.family);
  field(d.version);
  field(d.quantisation);
  field(d.pooling);
  uint8_t tail[5];
  tail[0] = static_cast<uint8_t>((d.dimension >> 24) & 0xFF);
  tail[1] = static_cast<uint8_t>((d.dimension >> 16) & 0xFF);
  tail[2] = static_cast<uint8_t>((d.dimension >> 8) & 0xFF);
  tail[3] = static_cast<uint8_t>(d.dimension & 0xFF);
  tail[4] = d.normalised ? 1u : 0u;
  crypto_generichash_update(&st, tail, sizeof(tail));

  EmbeddingModelId id;
  crypto_generichash_final(&st, id.bytes.data(), id.bytes.size());
  return id;
}

const char* EmbedStatusName(EmbedStatus s) {
  switch (s) {
    case EmbedStatus::kOk:
      return "ok";
    case EmbedStatus::kUnreachable:
      return "unreachable";
    case EmbedStatus::kBadResponse:
      return "bad-response";
    case EmbedStatus::kNoSuchModel:
      return "no-such-model";
    case EmbedStatus::kDegenerateVector:
      return "degenerate-vector";
  }
  return "unknown";
}

float Similarity(const Vector& a, const Vector& b) {
  if (a.size() != b.size()) return 0.0f;
  // Accumulated in double. Over 768 terms a float accumulator loses enough
  // precision to reorder near-ties, and a ranking that depends on accumulator
  // width is a ranking that changes when someone enables vectorisation.
  double sum = 0.0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    sum += static_cast<double>(a[i]) * static_cast<double>(b[i]);
  }
  return static_cast<float>(sum);
}

bool Normalise(Vector* v) {
  double sum = 0.0;
  for (std::size_t i = 0; i < v->size(); ++i) {
    const float x = (*v)[i];
    if (!std::isfinite(x)) return false;
    sum += static_cast<double>(x) * static_cast<double>(x);
  }
  if (!(sum > 0.0)) return false;
  const double inv = 1.0 / std::sqrt(sum);
  for (std::size_t i = 0; i < v->size(); ++i) {
    (*v)[i] = static_cast<float>(static_cast<double>((*v)[i]) * inv);
  }
  return true;
}

}  // namespace ai
}  // namespace umbra
