// Operation identity, and the clock that produces it.
//
// THE CHOICE, RECORDED HERE AND ARGUED IN docs/adr/0002-crdt.md: a LAMPORT
// counter plus a replica ID, and NOT a vector clock.
//
// What a CRDT needs from a timestamp is two separate things, and they are worth
// separating because they have different cheapest answers:
//
//   1. A TOTAL ORDER on operations, to break ties when two replicas insert at
//      the same place concurrently. (counter, replica) gives that, and the
//      order is the same on every replica because it is computed from the ID
//      alone.
//
//   2. CAUSAL READINESS -- knowing an operation's prerequisites have arrived.
//      A vector clock answers this for arbitrary prerequisites, at a cost of
//      one entry per replica that has EVER existed. Umbra does not need the
//      general answer: every operation names its own structural dependency (an
//      insert names its parent node, a delete names the nodes it removes), so
//      readiness is "do I have these specific nodes", which is exact and costs
//      nothing per replica.
//
// Vector clocks were rejected on the second point. Device keys rotate
// (docs/threat-model.md), so the set of replica IDs a vault has seen only ever
// grows; a vector clock would carry a slot for every device the user has ever
// owned, on every operation, forever.
#ifndef UMBRA_CRDT_OP_ID_H_
#define UMBRA_CRDT_OP_ID_H_

#include <array>
#include <cstdint>
#include <string>

namespace umbra {

// Which device produced an operation. Opaque, like ObjectId, and for the same
// threat-model reason: it travels to the relay, so it must not encode anything
// about the device.
//
// In a later phase this is derived from the device keypair. Until then it is
// drawn from the same entropy source ObjectIds are.
struct ReplicaId {
  std::array<uint8_t, 16> bytes{};

  bool operator==(const ReplicaId& o) const { return bytes == o.bytes; }
  bool operator!=(const ReplicaId& o) const { return !(*this == o); }
  bool operator<(const ReplicaId& o) const { return bytes < o.bytes; }

  std::string ToHex() const;
  // Short form for test failure messages. Not a wire format.
  std::string Short() const;
};

// A single operation's identity, and by extension a single character's.
//
// ORDERING IS (counter, replica), LEXICOGRAPHIC, AND BOTH HALVES ARE
// LOAD-BEARING. The counter orders causally related operations. The replica ID
// breaks ties between concurrent ones, and WITHOUT IT TWO CONCURRENT
// OPERATIONS COMPARE EQUAL -- which does not merely pick an arbitrary winner,
// it makes the sibling ordering depend on insertion order into the container,
// and two replicas that learned of the operations in different orders then
// build different documents. That is the deliberate defect introduced in the
// phase report; the convergence harness catches it.
struct OpId {
  uint64_t counter = 0;
  ReplicaId replica;

  bool operator==(const OpId& o) const {
    return counter == o.counter && replica == o.replica;
  }
  bool operator!=(const OpId& o) const { return !(*this == o); }
  bool operator<(const OpId& o) const {
    if (counter != o.counter) return counter < o.counter;
    return replica < o.replica;
  }
  bool operator>(const OpId& o) const { return o < *this; }

  // True when this and `o` come from the same replica and this is exactly
  // `n` steps earlier. Run operations allocate consecutive counters from one
  // replica, so this is how a run's members are recognized.
  bool IsSameReplicaOffset(const OpId& o, uint64_t n) const {
    return replica == o.replica && counter + n == o.counter;
  }

  OpId Plus(uint64_t n) const { return OpId{counter + n, replica}; }

  std::string ToString() const;
};

// The sentinel every document hangs from.
//
// counter 0 is never issued by the clock below (it starts at 1), so this cannot
// collide with a real operation. The root is not a character and is never
// rendered; it exists so that "insert at the very beginning" has a left origin
// to name, which removes the only special case the insert rule would otherwise
// need.
OpId RootId();
bool IsRoot(const OpId& id);

// A Lamport clock.
//
// Not thread-safe, deliberately: a document is owned by one thread at a time
// and adding a mutex here would suggest otherwise.
class LamportClock {
 public:
  explicit LamportClock(ReplicaId replica) : replica_(replica) {}

  // Allocates `count` consecutive ticks and returns the id of the first. A run
  // insert of n characters takes n of them at once, which is what makes the
  // run's internal structure implicit rather than encoded.
  OpId Tick(uint64_t count = 1);

  // Fold in an id observed from elsewhere, so that anything this replica
  // produces afterwards sorts after it.
  void Observe(const OpId& id);

  uint64_t counter() const { return counter_; }
  const ReplicaId& replica() const { return replica_; }

 private:
  ReplicaId replica_;
  uint64_t counter_ = 0;
};

// Random, from the platform entropy source; see object_id.h for the note on
// std::random_device that applies here too.
ReplicaId NewReplicaId();
// Deterministic, for tests and for the convergence harness, which must be able
// to replay a seed exactly.
ReplicaId ReplicaIdFromSeed(uint64_t seed);

}  // namespace umbra

#endif  // UMBRA_CRDT_OP_ID_H_
