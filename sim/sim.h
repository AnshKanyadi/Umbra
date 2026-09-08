// The convergence harness.
//
// WHAT IT IS FOR. A CRDT's whole claim is that replicas which have seen the
// same set of operations, in any order, with any duplication, agree. That claim
// is not testable by reading the code and it is not testable by a handful of
// hand-written merges. It is testable by running a great many schedules and
// checking the claim after each one.
//
// DETERMINISM IS THE FEATURE. Every choice -- which replica edits, where, what
// gets delivered when, who partitions from whom, who crashes -- comes from one
// seeded generator. A failing seed replays exactly, on any machine, so a
// failure is a bug report rather than a rumour.
//
// AND CONVERGENCE ALONE IS NOT ENOUGH. Replicas that all lose the same
// character agree perfectly. So every schedule is also checked against a
// reference model (Oracle below) that knows, independently of the CRDT, which
// characters must be present and in what relative order.
#ifndef UMBRA_SIM_SIM_H_
#define UMBRA_SIM_SIM_H_

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "umbra/crdt/op.h"
#include "umbra/crdt/op_id.h"
#include "umbra/crdt/text_doc.h"
#include "umbra/crdt/tree.h"

namespace umbra {
namespace sim {

// SplitMix64. Chosen because it is four lines, has no hidden state, and
// produces the same stream on every platform and compiler -- which
// std::mt19937_64 also would, but std::uniform_int_distribution would not:
// its mapping from raw bits to a range is implementation-defined, so the same
// seed gives different schedules under libc++ and libstdc++. A harness whose
// seeds do not mean the same thing on two machines cannot be used to report a
// failure.
class Rng {
 public:
  explicit Rng(uint64_t seed) : state_(seed) {}

  uint64_t Next() {
    uint64_t z = (state_ += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }

  // Uniform on [0, n). Rejection-sampled rather than modulo, so the
  // distribution does not skew, and written out rather than delegated for the
  // portability reason above.
  uint64_t Below(uint64_t n) {
    if (n <= 1) return 0;
    const uint64_t limit = UINT64_MAX - (UINT64_MAX % n) - 1;
    uint64_t x;
    do {
      x = Next();
    } while (x > limit);
    return x % n;
  }

  bool Chance(uint64_t percent) { return Below(100) < percent; }

 private:
  uint64_t state_;
};

// What the reference model knows, built from the operations the simulation
// generated rather than from anything the CRDT reports.
//
// IT DOES NOT PREDICT THE EXACT STRING, and it could not: the merge order of
// two concurrent inserts is the CRDT's to decide and any answer is correct. It
// knows the things that are NOT the CRDT's to decide, and those are enough to
// fail a wrong answer that every replica agrees on:
//
//   - which characters exist (inserted and not deleted)
//   - what each of them is
//   - the relative order of characters within one insert run
//   - that a run's surviving characters are CONTIGUOUS, which is the
//     non-interleaving property Fugue is chosen for
class Oracle {
 public:
  // contiguity_exempt marks a run that the schedule DELIBERATELY has replicas
  // type into -- a shared seed, say. Splitting such a run is the point of the
  // schedule, not an anomaly, and holding it to the contiguity standard would
  // fail a correct document. Membership, values and order still apply to it.
  void RecordInsert(const Op& op, bool contiguity_exempt = false);
  void RecordDelete(const Op& op);

  // Declare that these characters must end up contiguous and in this order.
  //
  // WHY THIS EXISTS SEPARATELY FROM THE PER-RUN CHECK. The run check can only
  // speak about runs of two characters or more, so a schedule that types ONE
  // character at a time -- which is exactly the backward-typing shape that
  // interleaves under RGA -- produces nothing for it to check. A defect that
  // scattered those characters among another replica's went unnoticed until a
  // deliberately broken insert rule was run past it. The schedule knows which
  // characters were typed together; this is how it says so.
  void RequireContiguousGroup(const std::vector<OpId>& ids,
                              const std::string& label);

  // Returns an empty string if the document satisfies the model, or a
  // description of the first violation.
  //
  // require_contiguous_runs IS NOT ALWAYS TRUE AND MUST NOT BE ASSERTED WHERE
  // IT IS NOT. Non-interleaving says that two runs typed CONCURRENTLY at the
  // same position do not alternate. It does NOT say a run is contiguous
  // forever: a user who later puts the cursor in the middle of a sentence and
  // types has split that run, legitimately, and if the characters between the
  // halves are then deleted the original run ends up separated by the new text.
  //
  // So contiguity is asserted only for schedules in which no replica ever
  // inserts into text it received from another -- where the only way two runs
  // could interleave is the anomaly itself. Membership, values and within-run
  // ORDER are checked always, because those hold under every schedule.
  std::string Check(const TextDoc& doc, bool require_contiguous_runs) const;

  std::size_t inserted_chars() const { return values_.size(); }
  std::size_t deleted_chars() const { return deleted_.size(); }

 private:
  std::map<OpId, char32_t> values_;
  std::set<OpId> deleted_;
  // (first id, count) per insert operation, in generation order.
  std::vector<std::pair<OpId, uint32_t>> runs_;
  std::set<OpId> contiguity_exempt_;
  std::vector<std::pair<std::string, std::vector<OpId>>> groups_;
};

// THE TREE'S REFERENCE MODEL.
//
// It cannot predict which of two concurrent moves wins -- that is the CRDT's to
// decide by timestamp, and either answer is correct. It knows the things that
// are NOT the CRDT's to decide, and those are enough to fail a wrong answer
// that every replica agrees on:
//
//   - THE TREE IS ACYCLIC and every live node reaches the root. This is the one
//     that matters: the failure mode of a naive design is a cycle, which makes
//     files vanish from every replica at once, so convergence alone would call
//     it a success.
//   - Every node that was ever created still exists somewhere -- under the root
//     or under the trash. Nodes do not evaporate.
//   - A node's name is one it was actually given by some operation.
//   - The winner of a set of moves for one child is the one with the highest
//     timestamp that was not refused for a cycle, computed here by replaying
//     the operations independently of TreeDoc.
class TreeOracle {
 public:
  void Record(const TreeOp& op);
  // Empty when the tree satisfies the model, otherwise the first violation.
  std::string Check(const TreeDoc& tree) const;
  std::size_t ops() const { return ops_.size(); }

 private:
  std::vector<TreeOp> ops_;
};

// One simulated device.
struct Replica {
  ReplicaId id;
  LamportClock clock{ReplicaId{}};
  TextDoc doc;
  TreeDoc tree;

  // Operations this replica has accepted and persisted, in the order it
  // persisted them. A crash rebuilds the document from exactly this.
  std::vector<Op> durable;
  // Accepted into memory but not yet persisted. A crash loses these.
  std::vector<Op> uncommitted;
  // Arrived but not yet applicable, because something they name is missing.
  std::vector<Op> pending;

  // Per source, the counters of TREE operations this replica has received. The
  // compaction mark is computed from this against what the source actually
  // produced, which is the honest form of clause 2's prefix mark -- see the
  // note where HaveMarks used to be in tree.h.
  std::map<ReplicaId, std::set<uint64_t>> got_tree;

  // WHAT THIS REPLICA HAS ALREADY BEEN SENT, which is what a sync cursor
  // remembers. The final flush re-offers only what is NOT here.
  //
  // Without this the harness was far more forgiving than reality: it re-sent
  // every operation to everybody at the end, so an operation a replica had
  // silently DROPPED came back and was applied, and a defect that loses
  // operations converged anyway. A real replica advances a cursor and never
  // asks for that operation again. Reset from the durable log on a crash,
  // because that is exactly what a recovered cursor knows.
  std::set<OpId> received;

  bool crashed_this_run = false;
};

// A message in flight. Exactly one of the two operation kinds is set, which is
// what `is_tree` says; the network does not care which.
struct Message {
  std::size_t to = 0;
  bool is_tree = false;
  Op op;
  TreeOp tree_op;
};

struct Config {
  std::size_t replicas = 4;
  std::size_t steps = 200;
  // Percent chances, per step.
  uint64_t p_edit = 45;
  uint64_t p_deliver = 40;
  uint64_t p_partition = 5;
  uint64_t p_crash = 3;
  uint64_t p_duplicate = 20;    // of a delivery, also deliver it again later
  uint64_t p_delete_edit = 30;  // of an edit, make it a deletion
  // Compaction is NOT a per-step action. See the note on Sim::CompactRound in
  // sim.cc: dropping a tombstone while any replica may still anchor an insert
  // to it diverges, and the harness proved it. It runs at quiescence, as a
  // coordinated round.
  bool verbose = false;
};

struct Result {
  uint64_t seed = 0;
  bool ok = false;
  std::string failure;     // empty when ok
  std::string final_text;  // the agreed document, when they agreed
  std::size_t ops = 0;
  std::size_t deliveries = 0;
  std::size_t crashes = 0;
  std::size_t restarts = 0;
  std::size_t max_partition_steps = 0;
  std::size_t tombstones_dropped = 0;
  std::size_t tree_ops = 0;
  std::size_t cycles_refused = 0;
  std::size_t tree_log_dropped = 0;
};

// Named, hand-built schedules that exercise shapes a uniform random walk
// reaches rarely or never. Run alongside the random ones, never instead of
// them.
enum class Adversarial : uint8_t {
  kNone = 0,
  // Every replica inserts at the same position with no knowledge of the others.
  kSamePositionPileup,
  // One replica deletes a range while another inserts into the middle of it.
  kDeleteRangeUnderInsert,
  // One replica is offline for the whole edit phase and rejoins at the end.
  kLongOfflineRejoin,
  // Every message is delivered twice, and in reverse order.
  kDuplicateAndReverse,
  // Concurrent backward typing at one anchor: the RGA interleaving shape.
  kBackwardTypingRace,
  // A replica crashes after every single apply.
  kCrashAfterEveryApply,
  // Edit, settle, run a coordinated compaction round, then keep editing. The
  // schedule that asks whether compaction breaks anything that comes after it.
  kCompactThenEdit,

  // ---------------------------------------------------------------- tree
  // Random tree operations alongside text ones.
  kTreeRandom,
  // TWO REPLICAS MOVE THE SAME DIRECTORY INTO EACH OTHER. The case naive
  // designs turn into a cycle, and therefore into files that vanish.
  kTreeMoveIntoEachOther,
  // A move into a directory, concurrent with a delete of that directory.
  kTreeMoveIntoDeleted,
  // A directory moved while another replica edits a file inside it. The move
  // must cost zero text operations and the edits must survive.
  kTreeMoveWhileEditingInside,
  // A -> B -> C -> A, issued by three replicas at once.
  kTreeRenameCycleThreeWay,
  // Tree operations, a coordinated log compaction round, then more tree
  // operations. The schedule that asks whether truncating the log breaks the
  // undo the algorithm still needs.
  kTreeCompactThenMove,

  // --------------------------------------------------------------- network
  // These four are about the RELAY, not the link. See the block comment above
  // their implementations in sim.cc.
  //
  // A relay drops one operation and keeps dropping it. The replica must not
  // claim it, and must recover when it is finally served.
  kRelayDropsPermanently,
  // A relay serves ciphertext again after a compaction round has truncated the
  // logs that produced it.
  kRelayReplaysOldCiphertext,
  // One replica's counter is a million ahead of the others.
  kClockSkew,
  // A relay serves a correct prefix and claims there is nothing newer.
  kRelayStaleView,

  // A replica is torn down mid run and rebuilt from its own durable logs, then
  // keeps working. The path a real client takes on every start.
  kRestartFromLog,
};

const char* AdversarialName(Adversarial a);
constexpr std::size_t kAdversarialCount = 19;

// True when a schedule never has a replica insert into text it received from
// another, which is the condition under which every run must still be
// contiguous. See Oracle::Check.
bool ScheduleRequiresContiguousRuns(Adversarial a);

// Runs one schedule to completion and checks it. Never aborts on a divergence:
// it reports, so that a sweep can keep going and name every failing seed.
Result RunSchedule(uint64_t seed, const Config& cfg, Adversarial adversarial);

}  // namespace sim
}  // namespace umbra

#endif  // UMBRA_SIM_SIM_H_
