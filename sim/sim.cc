#include "sim.h"

#include <algorithm>
#include <sstream>

#include "check.h"
#include "utf8.h"

namespace umbra {
namespace sim {
namespace {

std::string Quote(const std::string& s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '\n') {
      out += "\\n";
    } else if (c == '"') {
      out += "\\\"";
    } else {
      out.push_back(c);
    }
  }
  return out + "\"";
}

// Short, distinguishable text so a failure is readable. Each replica writes
// characters only it writes, which is what lets the oracle attribute a missing
// character to a replica by eye.
std::string TextFor(std::size_t replica, Rng* rng) {
  static const char* kAlphabets[] = {"abcde", "fghij", "klmno",
                                     "pqrst", "uvwxy", "z0123"};
  const char* alpha = kAlphabets[replica % 6];
  const std::size_t n = 1 + static_cast<std::size_t>(rng->Below(4));
  std::string s;
  for (std::size_t i = 0; i < n; ++i) {
    s.push_back(alpha[rng->Below(5)]);
  }
  return s;
}

}  // namespace

const char* AdversarialName(Adversarial a) {
  switch (a) {
    case Adversarial::kNone:
      return "random";
    case Adversarial::kSamePositionPileup:
      return "same-position-pileup";
    case Adversarial::kDeleteRangeUnderInsert:
      return "delete-range-under-insert";
    case Adversarial::kLongOfflineRejoin:
      return "long-offline-rejoin";
    case Adversarial::kDuplicateAndReverse:
      return "duplicate-and-reverse";
    case Adversarial::kBackwardTypingRace:
      return "backward-typing-race";
    case Adversarial::kCrashAfterEveryApply:
      return "crash-after-every-apply";
  }
  return "unknown";
}

void Oracle::RecordInsert(const Op& op, bool contiguity_exempt) {
  for (std::size_t i = 0; i < op.text.size(); ++i) {
    values_[op.id.Plus(i)] = op.text[i];
  }
  runs_.emplace_back(op.id, static_cast<uint32_t>(op.text.size()));
  if (contiguity_exempt) contiguity_exempt_.insert(op.id);
}

void Oracle::RecordDelete(const Op& op) {
  for (uint32_t i = 0; i < op.count; ++i) deleted_.insert(op.id.Plus(i));
}

bool ScheduleRequiresContiguousRuns(Adversarial a) {
  switch (a) {
    // Every replica types only into its own text until the final merge, so no
    // run can be legitimately split. Any separation here is the interleaving
    // anomaly.
    case Adversarial::kSamePositionPileup:
    case Adversarial::kBackwardTypingRace:
      return true;
    // These all have replicas editing text they received, which splits runs
    // legitimately.
    case Adversarial::kNone:
    case Adversarial::kDeleteRangeUnderInsert:
    case Adversarial::kLongOfflineRejoin:
    case Adversarial::kDuplicateAndReverse:
    case Adversarial::kCrashAfterEveryApply:
      return false;
  }
  return false;
}

std::string Oracle::Check(const TextDoc& doc,
                          bool require_contiguous_runs) const {
  const std::vector<OpId> visible = doc.VisibleIds();
  const std::vector<char32_t> chars = doc.Chars();
  if (visible.size() != chars.size()) {
    return "document reported a different number of ids and characters";
  }

  // 1. EXACTLY THE RIGHT CHARACTERS ARE PRESENT. This is the check that fails
  // when every replica agrees on a wrong answer: a dropped insert, a
  // resurrected tombstone or a duplicated apply all show up here.
  std::set<OpId> seen;
  for (std::size_t i = 0; i < visible.size(); ++i) {
    const OpId& id = visible[i];
    if (!seen.insert(id).second) {
      return "character " + id.ToString() + " appears more than once";
    }
    const std::map<OpId, char32_t>::const_iterator v = values_.find(id);
    if (v == values_.end()) {
      return "document contains " + id.ToString() + " which was never inserted";
    }
    if (v->second != chars[i]) {
      return "character " + id.ToString() + " has the wrong value";
    }
    if (deleted_.count(id) != 0) {
      return "deleted character " + id.ToString() + " is visible";
    }
  }
  for (const std::map<OpId, char32_t>::value_type& kv : values_) {
    if (deleted_.count(kv.first) != 0) continue;
    if (seen.count(kv.first) == 0) {
      return "character " + kv.first.ToString() +
             " was inserted, never deleted, and is missing";
    }
  }

  // 2. RUNS STAY IN ORDER AND STAY TOGETHER. Order within a run is not the
  // CRDT's to choose, and contiguity is the non-interleaving property Fugue is
  // chosen for -- so a violation here is a real defect even though every
  // replica agrees.
  std::map<OpId, std::size_t> position;
  for (std::size_t i = 0; i < visible.size(); ++i) position[visible[i]] = i;

  for (const std::pair<OpId, uint32_t>& run : runs_) {
    std::vector<std::size_t> pos;
    for (uint32_t i = 0; i < run.second; ++i) {
      const std::map<OpId, std::size_t>::const_iterator p =
          position.find(run.first.Plus(i));
      if (p != position.end()) pos.push_back(p->second);
    }
    if (pos.size() < 2) continue;
    for (std::size_t i = 1; i < pos.size(); ++i) {
      if (pos[i] <= pos[i - 1]) {
        return "run " + run.first.ToString() + " is out of order";
      }
      // Contiguous means each surviving member follows the previous one with
      // nothing between. Characters deleted from the run's middle are already
      // absent from `pos`, so this is a statement about what SURVIVES.
      if (require_contiguous_runs && contiguity_exempt_.count(run.first) == 0 &&
          pos[i] != pos[i - 1] + 1) {
        return "run " + run.first.ToString() +
               " is interleaved: another replica's character sits inside it";
      }
    }
  }
  return std::string();
}

namespace {

// One replica's world. Separated from Replica so the schedule code reads as
// what it does rather than as bookkeeping.
struct Sim {
  Rng rng;
  Config cfg;
  std::vector<Replica> replicas;
  std::vector<Message> in_flight;
  Oracle oracle;
  // partition[i] is the step at which replica i rejoins. Steps below it mean
  // isolated.
  std::vector<std::size_t> isolated_until;
  std::size_t step = 0;
  bool require_contiguous_runs = false;
  Result result;

  explicit Sim(uint64_t seed, const Config& c) : rng(seed), cfg(c) {
    result.seed = seed;
    replicas.resize(cfg.replicas);
    isolated_until.assign(cfg.replicas, 0);
    for (std::size_t i = 0; i < cfg.replicas; ++i) {
      // Derived from the seed AND the index, so a seed fixes the whole replica
      // set and two runs of the same seed use the same ids -- which is what
      // makes a tiebreak-dependent failure reproduce.
      replicas[i].id = ReplicaIdFromSeed(seed * 1000003ULL + i);
      replicas[i].clock = LamportClock(replicas[i].id);
    }
  }

  bool Isolated(std::size_t i) const { return step < isolated_until[i]; }

  // Accept an operation this replica produced: apply, PERSIST, then publish.
  //
  // PERSIST BEFORE PUBLISH IS A DESIGN RULE, NOT AN ORDERING PREFERENCE, and
  // the harness is what established it. A replica that sends an operation
  // before logging it, then crashes, rebuilds its Lamport clock from a log
  // missing that operation -- and the clock is now BEHIND ids the replica has
  // already published. The next thing it types reuses one of them. Two
  // different operations then share an identity, whichever arrives second is
  // swallowed as a duplicate, and replicas that saw them in different orders
  // keep different documents.
  //
  // That is exactly what the sweep produced: divergence and id collisions,
  // only ever on the schedules that crash. Remote operations are still
  // persisted lazily below, because losing those is harmless -- a peer still
  // has them and will send them again.
  void Originate(std::size_t i, const std::vector<Op>& ops,
                 bool contiguity_exempt = false) {
    // THE LOG MUST BE REPLAYABLE IN ITS OWN ORDER, so everything this
    // operation depends on has to be in it first. A locally produced insert
    // names a parent that may be a REMOTE operation this replica has applied
    // but not yet persisted; writing the local one alone leaves a log whose
    // replay meets a child before its parent and cannot rebuild the document.
    //
    // The harness found this immediately after the write-ahead rule went in:
    // "durable log replay hit a not-ready operation". The fix is not to reorder
    // the log but to widen what gets committed -- the applied-but-unpersisted
    // prefix goes down with it, in apply order. In the real oplog that is one
    // atomic batch (see oplog.h), which is why Basalt's WriteBatch is the unit
    // rather than one key per operation.
    Commit(i);
    for (const Op& op : ops) {
      if (op.kind == OpKind::kInsert) {
        oracle.RecordInsert(op, contiguity_exempt);
      } else {
        oracle.RecordDelete(op);
      }
      replicas[i].durable.push_back(op);
      ++result.ops;
      for (std::size_t j = 0; j < replicas.size(); ++j) {
        if (j == i) continue;
        in_flight.push_back(Message{j, op});
      }
    }
  }

  void Commit(std::size_t i) {
    Replica& r = replicas[i];
    for (const Op& op : r.uncommitted) r.durable.push_back(op);
    r.uncommitted.clear();
  }

  // Deliver one operation into a replica, buffering it if it is early.
  void Deliver(std::size_t to, const Op& op) {
    Replica& r = replicas[to];
    const ApplyResult res = r.doc.Apply(op);
    ++result.deliveries;
    switch (res) {
      case ApplyResult::kApplied:
        r.clock.Observe(LastId(op));
        r.uncommitted.push_back(op);
        DrainPending(to);
        break;
      case ApplyResult::kDuplicate:
        r.clock.Observe(LastId(op));
        break;
      case ApplyResult::kNotReady:
        r.pending.push_back(op);
        break;
      case ApplyResult::kMalformed:
        // The simulation only ever produces well-formed operations, so this is
        // a defect in the CRDT rather than a schedule outcome. Recorded rather
        // than aborted, so the sweep can report the seed.
        result.failure =
            "replica " + std::to_string(to) +
            " called a generated operation malformed: " + op.ToString();
        break;
    }
  }

  void DrainPending(std::size_t i) {
    Replica& r = replicas[i];
    bool progress = true;
    while (progress) {
      progress = false;
      std::vector<Op> still;
      for (const Op& op : r.pending) {
        const ApplyResult res = r.doc.Apply(op);
        switch (res) {
          case ApplyResult::kApplied:
            r.clock.Observe(LastId(op));
            r.uncommitted.push_back(op);
            progress = true;
            break;
          case ApplyResult::kDuplicate:
            progress = true;
            break;
          case ApplyResult::kNotReady:
            still.push_back(op);
            break;
          case ApplyResult::kMalformed:
            result.failure = "pending operation became malformed";
            break;
        }
      }
      r.pending.swap(still);
    }
  }

  // CRASH AND RESTART. Everything not persisted is lost: the in-memory
  // document, the pending buffer, and any operation accepted since the last
  // commit. The replica comes back by replaying its durable log in log order,
  // which is the only recovery path a real device has.
  //
  // The operations it lost are still held by its peers, which is why the
  // schedule can lose them here and still expect convergence -- the final
  // flush re-delivers everything to everyone.
  void Crash(std::size_t i) {
    Replica& r = replicas[i];
    r.uncommitted.clear();
    r.pending.clear();
    r.doc = TextDoc();
    r.clock = LamportClock(r.id);
    for (const Op& op : r.durable) {
      const ApplyResult res = r.doc.Apply(op);
      r.clock.Observe(LastId(op));
      if (res == ApplyResult::kNotReady) {
        // The durable log is written in apply order, so replaying it in that
        // order must never find an operation early. If it does, the log is not
        // self-sufficient and recovery is broken.
        result.failure = "durable log replay hit a not-ready operation at " +
                         op.ToString() + " on replica " + std::to_string(i);
        return;
      }
    }
    ++result.crashes;
  }

  void LocalEdit(std::size_t i) {
    Replica& r = replicas[i];
    std::vector<Op> ops;
    const std::size_t len = r.doc.Length();
    if (len > 0 && rng.Chance(cfg.p_delete_edit)) {
      const std::size_t at = static_cast<std::size_t>(rng.Below(len));
      const std::size_t n = 1 + static_cast<std::size_t>(
                                    rng.Below(std::min<uint64_t>(4, len - at)));
      if (!r.doc.LocalDelete(at, n, &ops)) return;
    } else {
      const std::size_t at = static_cast<std::size_t>(rng.Below(len + 1));
      if (!r.doc.LocalInsert(at, TextFor(i, &rng), &r.clock, &ops)) return;
    }
    Originate(i, ops);
  }

  // Deliver everything to everyone, repeatedly, until nothing is in flight and
  // nothing is pending. This is the "the network eventually works" step that
  // makes convergence a fair question.
  void Quiesce() {
    isolated_until.assign(replicas.size(), 0);
    // Ops a crash lost must come back from peers; the simplest faithful way to
    // model that is for every replica to re-offer its durable log to every
    // other. A real sync does the same thing with a cursor.
    for (std::size_t i = 0; i < replicas.size(); ++i) {
      for (std::size_t j = 0; j < replicas.size(); ++j) {
        if (i == j) continue;
        for (const Op& op : replicas[i].durable) {
          in_flight.push_back(Message{j, op});
        }
        for (const Op& op : replicas[i].uncommitted) {
          in_flight.push_back(Message{j, op});
        }
      }
    }
    // Bounded, so a bug that leaves an operation permanently not-ready fails
    // the run rather than hanging it.
    for (int round = 0; round < 64 && !in_flight.empty(); ++round) {
      std::vector<Message> batch;
      batch.swap(in_flight);
      for (const Message& m : batch) Deliver(m.to, m.op);
      for (std::size_t i = 0; i < replicas.size(); ++i) DrainPending(i);
    }
    for (std::size_t i = 0; i < replicas.size(); ++i) Commit(i);
  }

  std::string CheckConverged() {
    // 1. All replicas agree.
    const std::string ref = replicas[0].doc.Text();
    for (std::size_t i = 1; i < replicas.size(); ++i) {
      if (replicas[i].doc.Text() != ref) {
        std::ostringstream os;
        os << "replicas 0 and " << i << " diverged\n"
           << "  0: " << Quote(ref) << "\n"
           << "  " << i << ": " << Quote(replicas[i].doc.Text());
        return os.str();
      }
    }
    // 2. Nothing is stuck. An operation left pending after quiescence means a
    // causal dependency that never arrives, which convergence checks alone
    // would not notice because every replica can be equally stuck.
    for (std::size_t i = 0; i < replicas.size(); ++i) {
      if (!replicas[i].pending.empty()) {
        return "replica " + std::to_string(i) + " still holds " +
               std::to_string(replicas[i].pending.size()) +
               " operations it could never apply";
      }
    }
    // 3. And the agreed answer is the right one.
    const std::string oracle_says =
        oracle.Check(replicas[0].doc, require_contiguous_runs);
    if (!oracle_says.empty()) {
      return "all replicas agree on a document the reference model rejects: " +
             oracle_says + "\n  text: " + Quote(ref);
    }
    result.final_text = ref;
    return std::string();
  }
};

// -------------------------------------------------------------- schedules

void RunRandom(Sim* s) {
  for (s->step = 0; s->step < s->cfg.steps; ++s->step) {
    const std::size_t n = s->replicas.size();
    if (s->rng.Chance(s->cfg.p_edit)) {
      s->LocalEdit(static_cast<std::size_t>(s->rng.Below(n)));
    }
    if (s->rng.Chance(s->cfg.p_deliver) && !s->in_flight.empty()) {
      // A RANDOM message, not the oldest: this is where reordering comes from.
      const std::size_t k =
          static_cast<std::size_t>(s->rng.Below(s->in_flight.size()));
      const Message m = s->in_flight[k];
      s->in_flight.erase(s->in_flight.begin() + static_cast<long>(k));
      if (!s->Isolated(m.to)) {
        s->Deliver(m.to, m.op);
        if (s->rng.Chance(s->cfg.p_duplicate)) {
          // DUPLICATE DELIVERY, put back to arrive again later.
          s->in_flight.push_back(m);
        }
      } else {
        s->in_flight.push_back(m);  // isolated: try again after it rejoins
      }
    }
    if (s->rng.Chance(s->cfg.p_partition)) {
      const std::size_t who = static_cast<std::size_t>(s->rng.Below(n));
      const std::size_t how_long =
          1 + static_cast<std::size_t>(s->rng.Below(30));
      s->isolated_until[who] = s->step + how_long;
      s->result.max_partition_steps =
          std::max(s->result.max_partition_steps, how_long);
    }
    if (s->rng.Chance(s->cfg.p_crash)) {
      const std::size_t who = static_cast<std::size_t>(s->rng.Below(n));
      // Commit a random prefix first, so the crash lands MID-APPLY rather than
      // always at a clean boundary.
      Replica& r = s->replicas[who];
      if (!r.uncommitted.empty()) {
        const std::size_t keep =
            static_cast<std::size_t>(s->rng.Below(r.uncommitted.size() + 1));
        for (std::size_t k = 0; k < keep; ++k) {
          r.durable.push_back(r.uncommitted[k]);
        }
        r.uncommitted.clear();
      }
      s->Crash(who);
      if (!s->result.failure.empty()) return;
    } else if (s->rng.Chance(50)) {
      s->Commit(static_cast<std::size_t>(s->rng.Below(n)));
    }
  }
}

void RunSamePositionPileup(Sim* s) {
  // Every replica inserts at position 0, knowing nothing of the others, several
  // times over. The merge must contain every run whole.
  for (int round = 0; round < 5; ++round) {
    for (std::size_t i = 0; i < s->replicas.size(); ++i) {
      std::vector<Op> ops;
      if (s->replicas[i].doc.LocalInsert(0, TextFor(i, &s->rng),
                                         &s->replicas[i].clock, &ops)) {
        s->Originate(i, ops);
      }
    }
  }
}

void RunBackwardTypingRace(Sim* s) {
  // Concurrent BACKWARD typing at one anchor: every character goes in at the
  // same index, so they all share a left origin. This is the shape RGA
  // interleaves on.
  std::vector<Op> seed;
  if (!s->replicas[0].doc.LocalInsert(0, "<>", &s->replicas[0].clock, &seed)) {
    return;
  }
  // EXEMPT: every replica is about to type into the middle of this run on
  // purpose, so it is meant to be split. The per-replica runs that follow are
  // not exempt, and they are what the interleaving check is about.
  s->Originate(0, seed, /*contiguity_exempt=*/true);
  for (std::size_t i = 1; i < s->replicas.size(); ++i) {
    for (const Op& op : seed) s->Deliver(i, op);
  }
  for (int round = 0; round < 6; ++round) {
    for (std::size_t i = 0; i < s->replicas.size(); ++i) {
      std::vector<Op> ops;
      const std::string one(1, "abcdef"[i % 6]);
      if (s->replicas[i].doc.LocalInsert(1, one, &s->replicas[i].clock, &ops)) {
        s->Originate(i, ops);
      }
    }
  }
}

void RunDeleteRangeUnderInsert(Sim* s) {
  // Replica 0 lays down a span everyone sees. Then 0 deletes the whole span
  // while 1 inserts into its middle, concurrently.
  std::vector<Op> base;
  if (!s->replicas[0].doc.LocalInsert(0, "0123456789", &s->replicas[0].clock,
                                      &base)) {
    return;
  }
  s->Originate(0, base);
  for (std::size_t i = 1; i < s->replicas.size(); ++i) {
    for (const Op& op : base) s->Deliver(i, op);
  }
  s->in_flight.clear();  // everyone is caught up; what follows is concurrent

  std::vector<Op> del;
  if (s->replicas[0].doc.LocalDelete(2, 6, &del)) s->Originate(0, del);
  if (s->replicas.size() > 1) {
    std::vector<Op> ins;
    if (s->replicas[1].doc.LocalInsert(5, "INSIDE", &s->replicas[1].clock,
                                       &ins)) {
      s->Originate(1, ins);
    }
  }
  if (s->replicas.size() > 2) {
    std::vector<Op> ins2;
    if (s->replicas[2].doc.LocalInsert(4, "ALSO", &s->replicas[2].clock,
                                       &ins2)) {
      s->Originate(2, ins2);
    }
  }
}

void RunLongOfflineRejoin(Sim* s) {
  // The last replica is isolated for the whole edit phase and edits anyway.
  // Everyone else converses freely. Quiesce then has to reconcile a long
  // divergence in both directions.
  const std::size_t offline = s->replicas.size() - 1;
  s->isolated_until[offline] = s->cfg.steps + 1;
  for (s->step = 0; s->step < s->cfg.steps; ++s->step) {
    const std::size_t who = static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(s->replicas.size())));
    s->LocalEdit(who);
    if (!s->in_flight.empty() && s->rng.Chance(70)) {
      const std::size_t k =
          static_cast<std::size_t>(s->rng.Below(s->in_flight.size()));
      const Message m = s->in_flight[k];
      s->in_flight.erase(s->in_flight.begin() + static_cast<long>(k));
      if (m.to == offline) {
        s->in_flight.push_back(m);
      } else {
        s->Deliver(m.to, m.op);
      }
    }
  }
}

void RunDuplicateAndReverse(Sim* s) {
  for (s->step = 0; s->step < s->cfg.steps; ++s->step) {
    s->LocalEdit(static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(s->replicas.size()))));
  }
  // Everything at once, newest first, twice over. Reverse order guarantees a
  // maximal amount of not-ready buffering; the duplication guarantees every
  // operation is applied at least twice.
  std::vector<Message> all = s->in_flight;
  s->in_flight.clear();
  std::reverse(all.begin(), all.end());
  for (const Message& m : all) s->Deliver(m.to, m.op);
  for (const Message& m : all) s->Deliver(m.to, m.op);
}

void RunCrashAfterEveryApply(Sim* s) {
  for (s->step = 0; s->step < s->cfg.steps; ++s->step) {
    const std::size_t who = static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(s->replicas.size())));
    s->LocalEdit(who);
    if (!s->in_flight.empty()) {
      const Message m = s->in_flight.front();
      s->in_flight.erase(s->in_flight.begin());
      s->Deliver(m.to, m.op);
      // Persist what just arrived, then immediately crash: the replica comes
      // back from its log with that operation and nothing after it.
      s->Commit(m.to);
      s->Crash(m.to);
      if (!s->result.failure.empty()) return;
    }
  }
}

}  // namespace

Result RunSchedule(uint64_t seed, const Config& cfg, Adversarial adversarial) {
  Sim s(seed, cfg);
  s.require_contiguous_runs = ScheduleRequiresContiguousRuns(adversarial);
  switch (adversarial) {
    case Adversarial::kNone:
      RunRandom(&s);
      break;
    case Adversarial::kSamePositionPileup:
      RunSamePositionPileup(&s);
      break;
    case Adversarial::kDeleteRangeUnderInsert:
      RunDeleteRangeUnderInsert(&s);
      break;
    case Adversarial::kLongOfflineRejoin:
      RunLongOfflineRejoin(&s);
      break;
    case Adversarial::kDuplicateAndReverse:
      RunDuplicateAndReverse(&s);
      break;
    case Adversarial::kBackwardTypingRace:
      RunBackwardTypingRace(&s);
      break;
    case Adversarial::kCrashAfterEveryApply:
      RunCrashAfterEveryApply(&s);
      break;
  }
  if (!s.result.failure.empty()) {
    s.result.ok = false;
    return s.result;
  }
  s.Quiesce();
  if (!s.result.failure.empty()) {
    s.result.ok = false;
    return s.result;
  }
  const std::string problem = s.CheckConverged();
  s.result.ok = problem.empty();
  s.result.failure = problem;
  return s.result;
}

}  // namespace sim
}  // namespace umbra
