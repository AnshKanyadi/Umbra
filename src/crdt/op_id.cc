#include "umbra/crdt/op_id.h"

#include <random>

#include "check.h"

namespace umbra {
namespace {

std::string HexOf(const uint8_t* p, std::size_t n) {
  static const char kHex[] = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    s.push_back(kHex[p[i] >> 4]);
    s.push_back(kHex[p[i] & 0x0f]);
  }
  return s;
}

}  // namespace

std::string ReplicaId::ToHex() const {
  return HexOf(bytes.data(), bytes.size());
}

std::string ReplicaId::Short() const { return HexOf(bytes.data(), 3); }

std::string OpId::ToString() const {
  return std::to_string(counter) + "@" + replica.Short();
}

OpId RootId() { return OpId{0, ReplicaId{}}; }

bool IsRoot(const OpId& id) {
  // counter 0 is never issued: LamportClock::Tick pre-increments. So the
  // counter alone identifies the root and the all-zero replica is redundant --
  // checked anyway, because a replica id that happened to be all zero would
  // otherwise silently become the root.
  return id.counter == 0;
}

OpId LamportClock::Tick(uint64_t count) {
  UMBRA_CHECK(count >= 1, "a Lamport tick must allocate at least one id");
  const OpId first{counter_ + 1, replica_};
  counter_ += count;
  return first;
}

void LamportClock::Observe(const OpId& id) {
  if (id.counter > counter_) counter_ = id.counter;
}

ReplicaId NewReplicaId() {
  ReplicaId r;
  std::random_device rd;
  std::uniform_int_distribution<unsigned int> dist(0, 255);
  for (std::size_t i = 0; i < r.bytes.size(); ++i) {
    r.bytes[i] = static_cast<uint8_t>(dist(rd));
  }
  return r;
}

ReplicaId ReplicaIdFromSeed(uint64_t seed) {
  // SplitMix64: a fixed, documented bit mixer, so that a seed produces the same
  // replica id on every platform and every compiler. std::mt19937_64 would also
  // be reproducible, but its output depends on the sequence of calls made to
  // it, and this must depend on nothing but the seed.
  ReplicaId r;
  uint64_t x = seed + 0x9E3779B97F4A7C15ULL;
  for (int half = 0; half < 2; ++half) {
    uint64_t z = (x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    for (int i = 0; i < 8; ++i) {
      r.bytes[static_cast<std::size_t>(half * 8 + i)] =
          static_cast<uint8_t>((z >> (56 - 8 * i)) & 0xFF);
    }
  }
  // The root is the id with counter 0; a replica of all zeros would make a real
  // operation from that replica look like the root under IsRoot's redundant
  // check. Vanishingly unlikely and cheap to exclude.
  bool all_zero = true;
  for (uint8_t b : r.bytes) {
    if (b != 0) all_zero = false;
  }
  if (all_zero) r.bytes[0] = 1;
  return r;
}

}  // namespace umbra
