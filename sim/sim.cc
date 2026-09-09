#include "sim.h"

#include "umbra/ai/manifest.h"

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
    case Adversarial::kCompactThenEdit:
      return "compact-then-edit";
    case Adversarial::kTreeRenameCycleThreeWay:
      return "tree-rename-cycle-three-way";
    case Adversarial::kTreeCompactThenMove:
      return "tree-compact-then-move";
    case Adversarial::kTreeMoveWhileEditingInside:
      return "tree-move-while-editing-inside";
    case Adversarial::kTreeMoveIntoDeleted:
      return "tree-move-into-deleted";
    case Adversarial::kTreeMoveIntoEachOther:
      return "tree-move-into-each-other";
    case Adversarial::kRelayDropsPermanently:
      return "relay-drops-permanently";
    case Adversarial::kRelayReplaysOldCiphertext:
      return "relay-replays-old-ciphertext";
    case Adversarial::kClockSkew:
      return "clock-skew";
    case Adversarial::kRelayStaleView:
      return "relay-stale-view";
    case Adversarial::kRestartFromLog:
      return "restart-from-log";
    case Adversarial::kIndexSegmentBeforeManifest:
      return "index-segment-before-manifest";
    case Adversarial::kIndexStaleManifest:
      return "index-stale-manifest";
    case Adversarial::kIndexConcurrentCompaction:
      return "index-concurrent-compaction";
    case Adversarial::kIndexForeignModel:
      return "index-foreign-model";
    case Adversarial::kIndexCorruptedSegment:
      return "index-corrupted-segment";
    case Adversarial::kTreeRandom:
      return "tree-random";
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
  for (uint32_t i = 0; i < op.count; ++i) deleted_.insert(op.target.Plus(i));
}

// ------------------------------------------------------------- tree oracle

namespace {

struct ModelEntry {
  ObjectId parent;
  std::string name;
  bool is_dir = false;
};
using Model = std::map<ObjectId, ModelEntry>;

bool ModelWouldCycle(const Model& m, const ObjectId& child,
                     const ObjectId& parent) {
  if (child == parent) return true;
  ObjectId cur = parent;
  std::size_t steps = 0;
  while (!IsTreeRoot(cur) && !IsTreeTrash(cur)) {
    if (cur == child) return true;
    const Model::const_iterator it = m.find(cur);
    if (it == m.end()) return false;
    cur = it->second.parent;
    if (++steps > m.size() + 2) return true;  // a cycle already, refuse
  }
  return false;
}

bool ModelPathOf(const Model& m, const ObjectId& id, std::string* out) {
  if (IsTreeRoot(id)) {
    out->clear();
    return true;
  }
  std::vector<std::string> parts;
  ObjectId cur = id;
  std::size_t steps = 0;
  while (!IsTreeRoot(cur)) {
    if (IsTreeTrash(cur)) return false;
    const Model::const_iterator it = m.find(cur);
    if (it == m.end()) return false;
    parts.push_back(it->second.name);
    cur = it->second.parent;
    if (++steps > m.size() + 2) return false;
  }
  std::string path;
  for (std::vector<std::string>::reverse_iterator it = parts.rbegin();
       it != parts.rend(); ++it) {
    if (!path.empty()) path.push_back('/');
    path += *it;
  }
  *out = path;
  return true;
}

}  // namespace

void TreeOracle::Record(const TreeOp& op) { ops_.push_back(op); }

std::string TreeOracle::Check(const TreeDoc& tree) const {
  // THE INDEPENDENT MODEL: sort every operation by timestamp and apply in that
  // order with the cycle rule, and nothing else. No undo, no redo, no log.
  //
  // That is the whole claim TreeDoc makes -- that incrementally undoing and
  // redoing reaches the same place as sorting would have -- so computing it the
  // other way is a real second opinion rather than a restatement.
  std::vector<TreeOp> sorted = ops_;
  std::sort(sorted.begin(), sorted.end(),
            [](const TreeOp& a, const TreeOp& b) { return a.id < b.id; });

  Model model;
  for (const TreeOp& op : sorted) {
    if (ModelWouldCycle(model, op.child, op.parent)) continue;  // ignored
    ModelEntry e;
    e.parent = op.parent;
    e.name = op.name;
    e.is_dir = op.is_dir;
    model[op.child] = e;
  }

  std::vector<std::pair<std::string, ObjectId>> want;
  for (const Model::value_type& kv : model) {
    std::string p;
    if (!ModelPathOf(model, kv.first, &p)) continue;  // trashed or detached
    want.emplace_back(p, kv.first);
  }
  std::sort(want.begin(), want.end());

  const std::vector<std::pair<std::string, ObjectId>> got = tree.Listing();
  if (want.size() != got.size()) {
    std::ostringstream os;
    os << "the tree has " << got.size() << " live paths, the model expects "
       << want.size();
    // Naming the first difference is worth more than the counts.
    std::set<std::string> gp;
    for (const std::pair<std::string, ObjectId>& kv : got) gp.insert(kv.first);
    for (const std::pair<std::string, ObjectId>& kv : want) {
      if (gp.count(kv.first) == 0) {
        os << "; missing \"" << kv.first << "\"";
        break;
      }
    }
    return os.str();
  }
  for (std::size_t i = 0; i < want.size(); ++i) {
    if (want[i].first != got[i].first) {
      return "path mismatch: model says \"" + want[i].first +
             "\", tree says \"" + got[i].first + "\"";
    }
    if (!(want[i].second == got[i].second)) {
      return "\"" + want[i].first +
             "\" holds a different object than the model expects";
    }
  }

  // EVERY NODE STILL EXISTS SOMEWHERE. A cycle in the tree makes nodes
  // unreachable, which the listing comparison above would catch as a missing
  // path -- but a node moved to the trash is legitimately absent from the
  // listing, so this checks the stronger thing separately.
  for (const Model::value_type& kv : model) {
    if (!tree.Exists(kv.first)) {
      return "node " + kv.first.ToHex().substr(0, 8) +
             " was moved at least once and is not in the tree at all";
    }
  }
  return std::string();
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
    case Adversarial::kCompactThenEdit:
    case Adversarial::kTreeRandom:
    case Adversarial::kTreeMoveIntoEachOther:
    case Adversarial::kTreeMoveIntoDeleted:
    case Adversarial::kTreeMoveWhileEditingInside:
    case Adversarial::kTreeRenameCycleThreeWay:
    case Adversarial::kTreeCompactThenMove:
    case Adversarial::kRelayDropsPermanently:
    case Adversarial::kRelayReplaysOldCiphertext:
    case Adversarial::kClockSkew:
    case Adversarial::kRelayStaleView:
    case Adversarial::kRestartFromLog:
    case Adversarial::kIndexSegmentBeforeManifest:
    case Adversarial::kIndexStaleManifest:
    case Adversarial::kIndexConcurrentCompaction:
    case Adversarial::kIndexForeignModel:
    case Adversarial::kIndexCorruptedSegment:
      return false;
  }
  return false;
}

void Oracle::RequireContiguousGroup(const std::vector<OpId>& ids,
                                    const std::string& label) {
  if (ids.size() < 2) return;
  groups_.emplace_back(label, ids);
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
  // 3. DECLARED GROUPS. Characters a schedule says were typed together must
  // still be together. This is the interleaving check for one-character
  // inserts, which the per-run check above cannot see: a run of one has
  // nothing to be contiguous with.
  for (const std::pair<std::string, std::vector<OpId>>& g : groups_) {
    std::vector<std::size_t> pos;
    for (const OpId& id : g.second) {
      const std::map<OpId, std::size_t>::const_iterator p = position.find(id);
      if (p != position.end()) pos.push_back(p->second);
    }
    if (pos.size() < 2) continue;
    // CONTIGUITY AS A SET, NOT AN ORDER. Which of a replica's own runs ends up
    // first is the CRDT's choice and any answer is correct; that they all end
    // up TOGETHER is not its choice, and is the interleaving property. Order
    // within a single run is already held to account by the per-run check
    // above.
    std::sort(pos.begin(), pos.end());
    for (std::size_t i = 1; i < pos.size(); ++i) {
      if (pos[i] != pos[i - 1] + 1) {
        return "group " + g.first +
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
  TreeOracle tree_oracle;
  // Object ids handed out by this simulation, so a schedule can move one.
  std::vector<ObjectId> objects;
  std::vector<ObjectId> dirs;
  // What each replica has produced, so the final flush can re-offer it.
  std::vector<std::vector<TreeOp>> tree_log;
  // WHAT EACH REPLICA HAS ON DISK, which is a different thing: everything it
  // accepted, whether it made the operation or received it. tree_log holds only
  // what a replica ORIGINATED, which is the right set to re-offer to peers and
  // the wrong set to rebuild from -- a real client persists what it fetches
  // (OpLog::AppendStored) and replays all of it on start. Restarting from
  // tree_log alone would rebuild a replica that had forgotten every operation
  // anyone else ever sent it.
  std::vector<std::vector<TreeOp>> tree_durable;
  // Per source, the counters of every tree operation it has produced, in order.
  std::map<ReplicaId, std::vector<uint64_t>> produced_tree;
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
    tree_log.resize(cfg.replicas);
    tree_durable.resize(cfg.replicas);
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
      replicas[i].received.insert(op.id);
      ++result.ops;
      for (std::size_t j = 0; j < replicas.size(); ++j) {
        if (j == i) continue;
        Message m;
        m.to = j;
        m.op = op;
        in_flight.push_back(m);
      }
    }
  }

  // A tree operation this replica produced. Same rules as text: it is durable
  // before it is published, and the applied-but-unpersisted prefix goes with
  // it.
  void OriginateTree(std::size_t i, const TreeOp& op) {
    tree_oracle.Record(op);
    tree_log[i].push_back(op);
    tree_durable[i].push_back(op);
    produced_tree[op.id.replica].push_back(op.id.counter);
    replicas[i].got_tree[op.id.replica].insert(op.id.counter);
    ++result.tree_ops;
    replicas[i].received.insert(op.id);
    for (std::size_t j = 0; j < replicas.size(); ++j) {
      if (j == i) continue;
      Message m;
      m.to = j;
      m.is_tree = true;
      m.tree_op = op;
      in_flight.push_back(m);
    }
  }

  // Allocate an object id deterministically from the seed, so a failing seed
  // replays with the same ids.
  ObjectId NextObjectId() {
    ObjectId id;
    const uint64_t a = rng.Next();
    const uint64_t b = rng.Next();
    for (int k = 0; k < 8; ++k) {
      id.bytes[static_cast<std::size_t>(k)] =
          static_cast<uint8_t>((a >> (56 - 8 * k)) & 0xFF);
      id.bytes[static_cast<std::size_t>(8 + k)] =
          static_cast<uint8_t>((b >> (56 - 8 * k)) & 0xFF);
    }
    // Keep clear of the reserved ids, which are all-zero but for the last byte.
    id.bytes[0] |= 0x40;
    return id;
  }

  void Commit(std::size_t i) {
    Replica& r = replicas[i];
    for (const Op& op : r.uncommitted) r.durable.push_back(op);
    r.uncommitted.clear();
  }

  void DeliverTree(std::size_t to, const TreeOp& op) {
    Replica& r = replicas[to];
    r.received.insert(op.id);
    r.got_tree[op.id.replica].insert(op.id.counter);
    ++result.deliveries;
    const TreeApply res = r.tree.Apply(op);
    switch (res) {
      case TreeApply::kApplied:
      case TreeApply::kDuplicate:
        r.clock.Observe(op.id);
        tree_durable[to].push_back(op);
        break;
      case TreeApply::kIgnoredCycle:
        // Persisted even though it changed nothing: a refused move is still an
        // operation this replica holds, and a replica that dropped it would
        // ask for it again forever.
        tree_durable[to].push_back(op);
        // NOT AN ERROR. It is the defined outcome for a move that would make a
        // node its own ancestor, and both replicas must reach it for the same
        // operation. Counted so the report can say the schedules actually
        // produced cycles rather than merely claiming to.
        r.clock.Observe(op.id);
        ++result.cycles_refused;
        break;
      case TreeApply::kMalformed:
        result.failure =
            "replica " + std::to_string(to) +
            " called a generated tree operation malformed: " + op.ToString();
        break;
    }
  }

  // A RELAY THAT DROPS ONE OPERATION AND KEEPS DROPPING IT. Set by
  // RunRelayDropsPermanently; honoured here so that Quiesce cannot quietly heal
  // the gap the schedule exists to create.
  std::size_t blocked_to = static_cast<std::size_t>(-1);
  ReplicaId blocked_from;
  uint64_t blocked_counter = 0;

  bool Blocked(const Message& m) const {
    if (blocked_counter == 0) return false;
    if (m.to != blocked_to) return false;
    const OpId& id = m.is_tree ? m.tree_op.id : m.op.id;
    return id.replica == blocked_from && id.counter == blocked_counter;
  }

  // Re-offer every durable operation to every peer that has not been sent it.
  // The same thing Quiesce does, without the delivery loop, so a schedule can
  // put everything in flight and then choose how it is served.
  void ReofferAll() {
    for (std::size_t i = 0; i < replicas.size(); ++i) {
      for (std::size_t j = 0; j < replicas.size(); ++j) {
        if (i == j) continue;
        for (const Op& op : replicas[i].durable) {
          if (replicas[j].received.count(op.id) == 0) {
            Message m;
            m.to = j;
            m.op = op;
            in_flight.push_back(m);
          }
        }
        for (const TreeOp& op : tree_log[i]) {
          if (replicas[j].received.count(op.id) == 0) {
            Message m;
            m.to = j;
            m.is_tree = true;
            m.tree_op = op;
            in_flight.push_back(m);
          }
        }
      }
    }
  }

  // Deliver everything currently in flight, once, to whoever is not isolated.
  void FlushInFlight() {
    std::vector<Message> batch;
    batch.swap(in_flight);
    for (const Message& m : batch) DeliverMessage(m);
    for (std::size_t i = 0; i < replicas.size(); ++i) DrainPending(i);
  }

  void DeliverMessage(const Message& m) {
    if (Blocked(m)) return;
    if (m.is_tree) {
      DeliverTree(m.to, m.tree_op);
    } else {
      Deliver(m.to, m.op);
    }
  }

  // Deliver one operation into a replica, buffering it if it is early.
  void Deliver(std::size_t to, const Op& op) {
    Replica& r = replicas[to];
    r.received.insert(op.id);
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
  // A PROCESS RESTART, NOT A CRASH. Crash() models losing what was not
  // persisted; this models losing EVERYTHING that was not persisted, which
  // includes the in-memory tree. Crash() never rebuilt r.tree at all -- the
  // TreeDoc survived in memory across every simulated crash the harness has
  // ever run -- so the path a real client takes on every single start had
  // never been exercised here. Vault::ApplyTreeOp's clock bug lived in exactly
  // that path and it took an end-to-end run on real files to find it.
  //
  // Everything comes back from the two durable logs and nothing from memory:
  // the documents, the tree, the clock, the cursor, and the set of tree
  // operations this replica can honestly claim to hold.
  void RestartFromLog(std::size_t i) {
    Replica& r = replicas[i];
    r.uncommitted.clear();
    r.pending.clear();
    r.doc = TextDoc();
    r.tree = TreeDoc();
    r.clock = LamportClock(r.id);
    r.received.clear();
    r.got_tree.clear();

    for (const Op& op : r.durable) {
      const ApplyResult res = r.doc.Apply(op);
      // LastId, not op.id: a run owns a range of counters. See op.h.
      r.clock.Observe(LastId(op));
      r.received.insert(op.id);
      if (res == ApplyResult::kNotReady) {
        result.failure =
            "restart: durable text log hit a not-ready operation "
            "at " +
            op.ToString() + " on replica " + std::to_string(i);
        return;
      }
    }
    for (const TreeOp& op : tree_durable[i]) {
      const TreeApply res = r.tree.Apply(op);
      if (res == TreeApply::kMalformed) {
        result.failure =
            "restart: durable tree log holds a malformed "
            "operation on replica " +
            std::to_string(i);
        return;
      }
      // THE CLOCK MUST MOVE FOR TREE OPERATIONS TOO. A replica rebuilt from a
      // log that observed only its text operations comes back with a clock
      // below tree operations it has already issued, and its next tree
      // operation reuses a counter. The oplog is keyed
      // object||replica||counter, so that is a lost write rather than a
      // conflict. This is the defect Vault::ApplyTreeOp had.
      r.clock.Observe(op.id);
      r.received.insert(op.id);
      r.got_tree[op.id.replica].insert(op.id.counter);
    }
    ++result.restarts;
  }

  void Crash(std::size_t i) {
    Replica& r = replicas[i];
    r.uncommitted.clear();
    r.pending.clear();
    r.doc = TextDoc();
    r.clock = LamportClock(r.id);
    // The cursor comes back from the log, so anything received but not
    // persisted will legitimately be asked for again.
    r.received.clear();
    for (const Op& op : r.durable) r.received.insert(op.id);
    // The tree log is durable by construction, so what this replica has of the
    // tree survives the crash and so does the cursor derived from it.
    for (const TreeOp& op : tree_log[i]) r.received.insert(op.id);
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

  // THE SAFETY CONDITION, COMPUTED. A tombstone may be dropped once every
  // replica has seen the operation that created the character, so the watermark
  // is the MINIMUM across replicas of what each has seen from each origin. A
  // replica that is behind holds the whole vault's compaction back, which is
  // the honest consequence of the condition rather than a flaw in it -- see
  // docs/adr/0002-crdt.md.
  std::map<ReplicaId, uint64_t> GlobalWatermark() const {
    std::map<ReplicaId, uint64_t> low;
    bool first = true;
    for (const Replica& r : replicas) {
      std::map<ReplicaId, uint64_t> mine;
      for (const Op& op : r.durable) {
        const OpId last = LastId(op);
        uint64_t& hw = mine[last.replica];
        if (last.counter > hw) hw = last.counter;
      }
      if (first) {
        low = mine;
        first = false;
        continue;
      }
      std::map<ReplicaId, uint64_t> merged;
      for (const std::map<ReplicaId, uint64_t>::value_type& kv : low) {
        const std::map<ReplicaId, uint64_t>::const_iterator m =
            mine.find(kv.first);
        // A replica that has seen NOTHING from an origin pins that origin's
        // watermark to zero, which is what "every replica has seen it" means.
        merged[kv.first] = m == mine.end() ? 0 : std::min(kv.second, m->second);
      }
      low.swap(merged);
    }
    return low;
  }

  // A COORDINATED COMPACTION ROUND, AND IT HAS TO BE COORDINATED.
  //
  // The first version ran on a random replica at a random step, at the
  // watermark every replica had provably received. THAT IS NOT SUFFICIENT AND
  // THE HARNESS PROVED IT WITHIN THIRTY SEEDS: having SEEN a node is not the
  // same as being finished with it. A replica that still holds a tombstone can
  // anchor a new insert to it at any moment -- insert origins are taken from
  // the full tree order, tombstones included -- and that operation names a
  // parent the compacting replica has already dropped. It can never be applied
  // there, and the two documents part company for good.
  //
  // So compaction is a ROUND, run where every replica has the same durable set
  // and nothing is in flight. Afterwards no replica can anchor to a dropped
  // node, because no replica still has one.
  //
  // The consequence, stated rather than hidden: compaction needs agreement, so
  // it needs the sync protocol to provide one, and a device that never
  // participates holds the whole vault's tombstones. docs/adr/0002-crdt.md
  // carries the condition.
  // THE TREE LOG COMPACTION ROUND, per docs/adr/0003-tree.md.
  //
  // The watermark is computed from what every replica honestly reports, and the
  // simulation reports honestly -- a device that lies is out of scope, and a
  // relay that lies can only withhold, which lowers the watermark. Every
  // replica compacts to the SAME mark, because a mark computed from a minimum
  // over all of them is the same number for all of them.
  // The true prefix mark: the largest prefix of what `source` produced that
  // `who` has actually received. In the real system a sync cursor gives this
  // for free, because the fetch is ordered by counter. Here the simulation
  // knows what was produced, so it can compute the same number without
  // pretending a log can answer it.
  uint64_t PrefixMark(std::size_t who, const ReplicaId& source) const {
    const std::map<ReplicaId, std::vector<uint64_t>>::const_iterator p =
        produced_tree.find(source);
    if (p == produced_tree.end() || p->second.empty()) return 0;
    const std::map<ReplicaId, std::set<uint64_t>>::const_iterator g =
        replicas[who].got_tree.find(source);
    if (g == replicas[who].got_tree.end()) return 0;
    uint64_t mark = 0;
    for (uint64_t c : p->second) {
      if (g->second.count(c) == 0) break;
      mark = c;
    }
    return mark;
  }

  void CompactTreeLogRound() {
    std::vector<ReplicaId> enrolled;
    std::vector<DeviceReport> reports;
    for (std::size_t i = 0; i < replicas.size(); ++i) {
      const Replica& r = replicas[i];
      enrolled.push_back(r.id);
      // AN ISOLATED DEVICE'S REPORT DOES NOT ARRIVE, which is both what a
      // partition looks like and what a withholding relay looks like. The
      // watermark must collapse rather than assume the silent device is caught
      // up -- deliberate defect C3 removes exactly that and the sweep has to
      // notice.
      if (Isolated(i)) continue;
      DeviceReport rep;
      rep.device = r.id;
      for (const Replica& source : replicas) {
        const uint64_t m = PrefixMark(i, source.id);
        // A ZERO MARK IS OMITTED, not sent as a zero, because that is what a
        // wire format does -- there is no reason to spend bytes saying "I have
        // nothing from this device". It also means the watermark must read a
        // MISSING entry as "has nothing" rather than "no constraint", which is
        // deliberate defect C3 and was unreachable while this loop wrote a zero
        // for every source.
        if (m > 0) rep.have[source.id] = m;
      }
      rep.clock = r.clock.counter();
      reports.push_back(rep);
    }
    const uint64_t w = CompactionWatermark(enrolled, reports);
    if (w == 0) return;
    for (Replica& r : replicas) {
      result.tree_log_dropped += r.tree.CompactLog(w);
    }
  }

  void CompactRound(bool everyone) {
    const std::map<ReplicaId, uint64_t> w = GlobalWatermark();
    for (std::size_t i = 0; i < replicas.size(); ++i) {
      if (!everyone && (i % 2) != 0) continue;
      result.tombstones_dropped += replicas[i].doc.Compact(w);
    }
  }

  void LocalEdit(std::size_t i) {
    Replica& r = replicas[i];
    std::vector<Op> ops;
    const std::size_t len = r.doc.Length();
    if (len > 0 && rng.Chance(cfg.p_delete_edit)) {
      const std::size_t at = static_cast<std::size_t>(rng.Below(len));
      const std::size_t n = 1 + static_cast<std::size_t>(
                                    rng.Below(std::min<uint64_t>(4, len - at)));
      if (!r.doc.LocalDelete(at, n, &r.clock, &ops)) return;
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
        // ONLY WHAT THE PEER HAS NOT BEEN SENT. See Replica::received.
        for (const Op& op : replicas[i].durable) {
          if (replicas[j].received.count(op.id) == 0) {
            Message m;
            m.to = j;
            m.op = op;
            in_flight.push_back(m);
          }
        }
        for (const Op& op : replicas[i].uncommitted) {
          if (replicas[j].received.count(op.id) == 0) {
            Message m;
            m.to = j;
            m.op = op;
            in_flight.push_back(m);
          }
        }
        // Tree operations too. A replica's tree log is durable by construction
        // -- there is no uncommitted tier for it, because a tree operation is
        // never not-ready and so never waits.
        for (const TreeOp& op : tree_log[i]) {
          if (replicas[j].received.count(op.id) == 0) {
            Message m;
            m.to = j;
            m.is_tree = true;
            m.tree_op = op;
            in_flight.push_back(m);
          }
        }
      }
    }
    // Bounded, so a bug that leaves an operation permanently not-ready fails
    // the run rather than hanging it.
    for (int round = 0; round < 64 && !in_flight.empty(); ++round) {
      std::vector<Message> batch;
      batch.swap(in_flight);
      for (const Message& m : batch) DeliverMessage(m);
      for (std::size_t i = 0; i < replicas.size(); ++i) DrainPending(i);
    }
    for (std::size_t i = 0; i < replicas.size(); ++i) Commit(i);
    // Only SOME replicas, so the final comparison is between documents in
    // different compaction states. Safe here because nothing follows: if
    // compaction ever changed the visible text, this is where it would show.
    CompactRound(/*everyone=*/false);
    // The tree log too, on every replica: unlike tombstones, the watermark is
    // one number and every replica computes the same one.
    CompactTreeLogRound();
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
        // Naming the operation and what it wanted matters more than the count:
        // "one operation stuck" is a mystery, "a delete of a node nobody has"
        // is a diagnosis.
        std::string detail;
        for (const Op& op : replicas[i].pending) {
          detail += "\n    " + op.ToString();
          if (op.kind == OpKind::kDelete) {
            detail += replicas[i].doc.HasNode(op.target) ? " [target present]"
                                                         : " [TARGET MISSING]";
          } else {
            detail += replicas[i].doc.HasNode(op.parent) ? " [parent present]"
                                                         : " [PARENT MISSING]";
          }
        }
        return "replica " + std::to_string(i) + " still holds " +
               std::to_string(replicas[i].pending.size()) +
               " operations it could never apply:" + detail;
      }
    }
    // 3. All replicas agree on the SHAPE of the vault, not only its contents.
    const std::string tref = replicas[0].tree.StateHash();
    for (std::size_t i = 1; i < replicas.size(); ++i) {
      if (replicas[i].tree.StateHash() != tref) {
        std::ostringstream os;
        os << "replicas 0 and " << i << " have different trees\n";
        for (const std::pair<std::string, ObjectId>& kv :
             replicas[0].tree.Listing()) {
          os << "  0: " << kv.first << "\n";
        }
        for (const std::pair<std::string, ObjectId>& kv :
             replicas[i].tree.Listing()) {
          os << "  " << i << ": " << kv.first << "\n";
        }
        return os.str();
      }
    }

    // 4. And the agreed answers are the right ones.
    const std::string oracle_says =
        oracle.Check(replicas[0].doc, require_contiguous_runs);
    if (!oracle_says.empty()) {
      return "all replicas agree on a document the reference model rejects: " +
             oracle_says + "\n  text: " + Quote(ref);
    }
    const std::string tree_says = tree_oracle.Check(replicas[0].tree);
    if (!tree_says.empty()) {
      std::string listing;
      for (const std::pair<std::string, ObjectId>& kv :
           replicas[0].tree.Listing()) {
        listing += "\n    " + kv.first;
      }
      return "all replicas agree on a tree the reference model rejects: " +
             tree_says + listing;
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
  std::vector<std::vector<OpId>> typed(s->replicas.size());
  for (int round = 0; round < 5; ++round) {
    for (std::size_t i = 0; i < s->replicas.size(); ++i) {
      std::vector<Op> ops;
      if (s->replicas[i].doc.LocalInsert(0, TextFor(i, &s->rng),
                                         &s->replicas[i].clock, &ops)) {
        for (const Op& op : ops) {
          for (std::size_t k = 0; k < op.text.size(); ++k) {
            typed[i].push_back(op.id.Plus(k));
          }
        }
        s->Originate(i, ops);
      }
    }
  }
  // Every replica typed only into its own text, so its characters must come out
  // as one block. Which order its own runs land in is the CRDT's business.
  for (std::size_t i = 0; i < typed.size(); ++i) {
    s->oracle.RequireContiguousGroup(typed[i], "replica " + std::to_string(i));
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
  // Each replica types ONE character at a time at the same anchor. The ids it
  // produces are declared as a group, because a run of one character gives the
  // per-run contiguity check nothing to hold on to -- and this is precisely the
  // shape that interleaves under RGA, so it is the shape that most needs
  // checking.
  std::vector<std::vector<OpId>> typed(s->replicas.size());
  for (int round = 0; round < 6; ++round) {
    for (std::size_t i = 0; i < s->replicas.size(); ++i) {
      std::vector<Op> ops;
      const std::string one(1, "abcdef"[i % 6]);
      if (s->replicas[i].doc.LocalInsert(1, one, &s->replicas[i].clock, &ops)) {
        for (const Op& op : ops) typed[i].push_back(op.id);
        s->Originate(i, ops);
      }
    }
  }
  for (std::size_t i = 0; i < typed.size(); ++i) {
    s->oracle.RequireContiguousGroup(typed[i], "replica " + std::to_string(i));
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
  if (s->replicas[0].doc.LocalDelete(2, 6, &s->replicas[0].clock, &del)) {
    s->Originate(0, del);
  }
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

// Edit, settle, compact EVERYWHERE at once, then edit again. The second half is
// the point: it asks whether operations produced after a compaction round still
// apply, on replicas that compacted and on the tree that is left.
// ------------------------------------------------------------ tree schedules

namespace {

// Give every replica the same starting tree, delivered directly so the setup is
// not itself the thing under test.
std::vector<TreeOp> SeedTree(Sim* s, const std::vector<std::string>& dir_names,
                             std::vector<ObjectId>* dirs) {
  std::vector<TreeOp> ops;
  for (const std::string& name : dir_names) {
    const ObjectId id = s->NextObjectId();
    const TreeOp op = s->replicas[0].tree.MakeMove(id, TreeRoot(), name, true,
                                                   &s->replicas[0].clock);
    if (s->replicas[0].tree.Apply(op) != TreeApply::kApplied) continue;
    s->tree_oracle.Record(op);
    s->tree_log[0].push_back(op);
    // Durable too, or a replica rebuilt from its log comes back without the
    // directories the whole schedule hangs off. DeliverTree persists for
    // replicas 1..n below; replica 0 originated these, so it persists here.
    s->tree_durable[0].push_back(op);
    s->replicas[0].received.insert(op.id);
    s->replicas[0].got_tree[op.id.replica].insert(op.id.counter);
    ++s->result.tree_ops;
    ops.push_back(op);
    dirs->push_back(id);
  }
  for (std::size_t i = 1; i < s->replicas.size(); ++i) {
    for (const TreeOp& op : ops) s->DeliverTree(i, op);
  }
  return ops;
}

// A file under `parent` on replica i, with content, published.
ObjectId MakeFile(Sim* s, std::size_t i, const ObjectId& parent,
                  const std::string& name) {
  const ObjectId id = s->NextObjectId();
  const TreeOp op = s->replicas[i].tree.MakeMove(id, parent, name, false,
                                                 &s->replicas[i].clock);
  if (s->replicas[i].tree.Apply(op) == TreeApply::kMalformed) return id;
  s->OriginateTree(i, op);
  return id;
}

void MoveNode(Sim* s, std::size_t i, const ObjectId& child,
              const ObjectId& parent, const std::string& name, bool is_dir) {
  const TreeOp op = s->replicas[i].tree.MakeMove(child, parent, name, is_dir,
                                                 &s->replicas[i].clock);
  const TreeApply r = s->replicas[i].tree.Apply(op);
  if (r == TreeApply::kMalformed) return;
  if (r == TreeApply::kIgnoredCycle) ++s->result.cycles_refused;
  s->OriginateTree(i, op);
}

}  // namespace

// Tree operations mixed in with text ones, under the same partitions,
// reordering, duplication and crashes.
// Tree operations, a coordinated log compaction round, then MORE tree
// operations, some of them arriving out of order. The second half is the point:
// it asks whether an operation produced after compaction can still undo what it
// needs to.
void RunTreeCompactThenMove(Sim* s) {
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b", "c"}, &dirs);
  if (dirs.size() < 3) return;
  std::vector<ObjectId> files;
  for (std::size_t i = 0; i < 4; ++i) {
    files.push_back(MakeFile(s, i % s->replicas.size(), dirs[i % dirs.size()],
                             "f" + std::to_string(i) + ".md"));
  }
  for (std::size_t k = 0; k < s->cfg.steps / 4; ++k) {
    const std::size_t who = static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(s->replicas.size())));
    const ObjectId child = files[static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(files.size())))];
    const ObjectId parent = dirs[static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(dirs.size())))];
    MoveNode(s, who, child, parent, "m" + std::to_string(k) + ".md", false);
    if (!s->in_flight.empty() && s->rng.Chance(70)) {
      const std::size_t j =
          static_cast<std::size_t>(s->rng.Below(s->in_flight.size()));
      const Message m = s->in_flight[j];
      s->in_flight.erase(s->in_flight.begin() + static_cast<long>(j));
      s->DeliverMessage(m);
    }
  }
  s->Quiesce();
  s->CompactTreeLogRound();

  // Now keep going, compacting as we go rather than only at rest. Operations produced after the round have counters above the
  // watermark by construction, so the undo they need is still there -- and
  // delivery is deliberately reordered so that undo actually runs.
  for (std::size_t k = 0; k < s->cfg.steps / 4; ++k) {
    const std::size_t who = static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(s->replicas.size())));
    const ObjectId child = dirs[static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(dirs.size())))];
    const ObjectId parent = dirs[static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(dirs.size())))];
    if (!(child == parent)) MoveNode(s, who, child, parent, "d", true);
    if (!s->in_flight.empty() && s->rng.Chance(50)) {
      const std::size_t j =
          static_cast<std::size_t>(s->rng.Below(s->in_flight.size()));
      const Message m = s->in_flight[j];
      s->in_flight.erase(s->in_flight.begin() + static_cast<long>(j));
      s->DeliverMessage(m);
    }
    if (s->rng.Chance(15)) s->CompactTreeLogRound();
  }
  // And re-offer some already-delivered operations past the cursor, which is
  // what a relay resending looks like and what clause 5 has to absorb.
  {
    std::vector<Message> replays;
    for (std::size_t i = 0; i < s->replicas.size(); ++i) {
      for (const TreeOp& op : s->tree_log[i]) {
        if (!s->rng.Chance(30)) continue;
        const std::size_t to = static_cast<std::size_t>(
            s->rng.Below(static_cast<uint64_t>(s->replicas.size())));
        if (to == i) continue;
        Message m;
        m.to = to;
        m.is_tree = true;
        m.tree_op = op;
        replays.push_back(m);
      }
    }
    for (const Message& m : replays) s->DeliverMessage(m);
  }
}

void RunTreeRandom(Sim* s) {
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b", "c"}, &dirs);
  std::vector<ObjectId> files;
  for (s->step = 0; s->step < s->cfg.steps; ++s->step) {
    const std::size_t n = s->replicas.size();
    const std::size_t who = static_cast<std::size_t>(s->rng.Below(n));
    const uint64_t what = s->rng.Below(100);
    if (what < 20) {
      const ObjectId parent = dirs[static_cast<std::size_t>(
          s->rng.Below(static_cast<uint64_t>(dirs.size())))];
      files.push_back(
          MakeFile(s, who, parent, "f" + std::to_string(s->step) + ".md"));
    } else if (what < 35 && !files.empty()) {
      const ObjectId child = files[static_cast<std::size_t>(
          s->rng.Below(static_cast<uint64_t>(files.size())))];
      const ObjectId parent = dirs[static_cast<std::size_t>(
          s->rng.Below(static_cast<uint64_t>(dirs.size())))];
      MoveNode(s, who, child, parent, "m" + std::to_string(s->step) + ".md",
               false);
    } else if (what < 42 && !files.empty()) {
      const ObjectId child = files[static_cast<std::size_t>(
          s->rng.Below(static_cast<uint64_t>(files.size())))];
      MoveNode(s, who, child, TreeTrash(), "gone.md", false);
    } else if (what < 50) {
      // Move a DIRECTORY into another, which is where cycles come from.
      const ObjectId child = dirs[static_cast<std::size_t>(
          s->rng.Below(static_cast<uint64_t>(dirs.size())))];
      const ObjectId parent = dirs[static_cast<std::size_t>(
          s->rng.Below(static_cast<uint64_t>(dirs.size())))];
      if (!(child == parent)) MoveNode(s, who, child, parent, "d", true);
    } else if (what < 75) {
      s->LocalEdit(who);
    }
    if (!s->in_flight.empty() && s->rng.Chance(60)) {
      const std::size_t k =
          static_cast<std::size_t>(s->rng.Below(s->in_flight.size()));
      const Message m = s->in_flight[k];
      s->in_flight.erase(s->in_flight.begin() + static_cast<long>(k));
      if (s->Isolated(m.to)) {
        s->in_flight.push_back(m);
      } else {
        s->DeliverMessage(m);
        if (s->rng.Chance(s->cfg.p_duplicate)) s->in_flight.push_back(m);
      }
    }
    if (s->rng.Chance(s->cfg.p_partition)) {
      s->isolated_until[static_cast<std::size_t>(s->rng.Below(n))] =
          s->step + 1 + static_cast<std::size_t>(s->rng.Below(20));
    }
    // COMPACTION RUNS MID-SCHEDULE, not only at quiescence, and that is the
    // point rather than a detail. The condition is built to be safe at any
    // moment; running it only when every replica is already identical means the
    // clauses that protect against lagging clocks, missing reports and gapped
    // logs are never exercised. Three deliberate defects went uncaught until
    // this moved.
    if (s->rng.Chance(8)) s->CompactTreeLogRound();
  }
}

// TWO REPLICAS MOVE THE SAME DIRECTORY INTO EACH OTHER. The case a naive design
// turns into a cycle, which makes both directories and everything under them
// vanish from every replica at once.
void RunTreeMoveIntoEachOther(Sim* s) {
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b"}, &dirs);
  if (dirs.size() < 2) return;
  // Files inside, so a cycle would take real content with it and the oracle
  // would see paths disappear.
  MakeFile(s, 0, dirs[0], "inside-a.md");
  MakeFile(s, 0, dirs[1], "inside-b.md");
  s->Quiesce();

  // Concurrent and contradictory, issued with no knowledge of each other.
  MoveNode(s, 0, dirs[0], dirs[1], "a", true);
  if (s->replicas.size() > 1) MoveNode(s, 1, dirs[1], dirs[0], "b", true);
  // And a third replica piling on, if there is one.
  if (s->replicas.size() > 2) MoveNode(s, 2, dirs[0], dirs[1], "a2", true);
}

// A move into a directory, concurrent with a delete of that directory.
void RunTreeMoveIntoDeleted(Sim* s) {
  std::vector<ObjectId> dirs;
  SeedTree(s, {"target", "other"}, &dirs);
  if (dirs.size() < 2) return;
  const ObjectId file = MakeFile(s, 0, dirs[1], "n.md");
  s->Quiesce();

  MoveNode(s, 0, file, dirs[0], "n.md", false);
  if (s->replicas.size() > 1) {
    MoveNode(s, 1, dirs[0], TreeTrash(), "target", true);
  }
  if (s->replicas.size() > 2) {
    // A third replica moves it straight back out, so the winner is not simply
    // whoever went last.
    MoveNode(s, 2, file, TreeRoot(), "rescued.md", false);
  }
}

// A directory moved while another replica edits a file inside it. The move must
// cost ZERO text operations and the edits must survive it.
void RunTreeMoveWhileEditingInside(Sim* s) {
  std::vector<ObjectId> dirs;
  SeedTree(s, {"src", "dst"}, &dirs);
  if (dirs.size() < 2) return;
  MakeFile(s, 0, dirs[0], "n.md");
  s->Quiesce();

  const std::size_t tree_ops_before = s->result.tree_ops;
  const std::size_t text_ops_before = s->result.ops;

  // Replica 0 moves the containing directory.
  MoveNode(s, 0, dirs[0], dirs[1], "src", true);
  const std::size_t after_move_text = s->result.ops;
  UMBRA_CHECK(after_move_text == text_ops_before,
              "moving a directory produced text operations");
  (void)tree_ops_before;

  // Everyone else edits, concurrently, knowing nothing of the move.
  for (std::size_t i = 1; i < s->replicas.size(); ++i) {
    for (int k = 0; k < 4; ++k) s->LocalEdit(i);
  }
  for (int k = 0; k < 4; ++k) s->LocalEdit(0);
}

// A -> B -> C -> A, issued by three replicas at once.
void RunTreeRenameCycleThreeWay(Sim* s) {
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b", "c"}, &dirs);
  if (dirs.size() < 3) return;
  MakeFile(s, 0, dirs[0], "in-a.md");
  MakeFile(s, 0, dirs[1], "in-b.md");
  MakeFile(s, 0, dirs[2], "in-c.md");
  s->Quiesce();

  // Each replica moves one directory into the next, so the three together
  // describe a loop. At most two of the three can survive.
  const std::size_t n = s->replicas.size();
  MoveNode(s, 0 % n, dirs[0], dirs[1], "a", true);
  MoveNode(s, 1 % n, dirs[1], dirs[2], "b", true);
  MoveNode(s, 2 % n, dirs[2], dirs[0], "c", true);
}

void RunCompactThenEdit(Sim* s) {
  const std::size_t half = s->cfg.steps / 2;
  for (s->step = 0; s->step < half; ++s->step) {
    s->LocalEdit(static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(s->replicas.size()))));
    if (!s->in_flight.empty()) {
      const std::size_t k =
          static_cast<std::size_t>(s->rng.Below(s->in_flight.size()));
      const Message m = s->in_flight[k];
      s->in_flight.erase(s->in_flight.begin() + static_cast<long>(k));
      s->Deliver(m.to, m.op);
    }
  }
  s->Quiesce();
  s->CompactRound(/*everyone=*/true);

  // RE-DELIVER OLD OPERATIONS PAST THE CURSOR, on purpose.
  //
  // A cursor stops a replica ASKING for an operation twice. It does not stop
  // one ARRIVING twice: the relay may resend, two peers may both forward the
  // same thing, and a device restored from a backup replays a log everyone
  // already has. Every one of those hands a compacted replica an operation for
  // a character it has dropped.
  //
  // Without this the compaction watermark could be deleted from Apply and the
  // sweep stayed green, because nothing ever re-offered a compacted operation.
  // That is condition 5 in docs/adr/0002-crdt.md, and this is what holds it to
  // account.
  {
    std::vector<Message> replays;
    for (std::size_t i = 0; i < s->replicas.size(); ++i) {
      for (const Op& op : s->replicas[i].durable) {
        if (!s->rng.Chance(25)) continue;
        const std::size_t to = static_cast<std::size_t>(
            s->rng.Below(static_cast<uint64_t>(s->replicas.size())));
        if (to == i) continue;
        Message m;
        m.to = to;
        m.op = op;
        replays.push_back(m);
      }
    }
    for (const Message& m : replays) s->Deliver(m.to, m.op);
  }

  for (s->step = 0; s->step < half; ++s->step) {
    s->LocalEdit(static_cast<std::size_t>(
        s->rng.Below(static_cast<uint64_t>(s->replicas.size()))));
    if (!s->in_flight.empty()) {
      const std::size_t k =
          static_cast<std::size_t>(s->rng.Below(s->in_flight.size()));
      const Message m = s->in_flight[k];
      s->in_flight.erase(s->in_flight.begin() + static_cast<long>(k));
      s->Deliver(m.to, m.op);
    }
  }
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

// ---------------------------------------------------------------- network
//
// The four schedules below model the RELAY rather than the link. Everything
// above assumes messages move between replicas; these ask what happens when
// something in the middle chooses what to move.

// A RELAY DROPS ONE OPERATION AND KEEPS DROPPING IT.
//
// The assertion is not convergence -- a replica that never receives an
// operation cannot converge, and pretending otherwise would make the schedule
// worthless. It is that the replica KNOWS: its prefix mark for that source must
// stay below the gap, which is the claim the encrypted back-pointer chain makes
// in docs/adr/0001-storage.md. A gap stops the cursor; it is not stepped over.
//
// The block is then lifted and the run converges, so the schedule also asserts
// that the damage is a delay and not a corruption.
void RunRelayDropsPermanently(Sim* s) {
  const std::size_t n = s->replicas.size();
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b"}, &dirs);
  // NOTHING IS DELIVERED YET. The block has to be in place before the operation
  // it drops is served, or the victim already holds it and the schedule asserts
  // nothing. The first version flushed here and failed on all 200 seeds with a
  // prefix mark that was perfectly correct.
  for (int round = 0; round < 6; ++round) {
    for (std::size_t i = 0; i < n; ++i) {
      (void)MakeFile(
          s, i, dirs[0],
          "f" + std::to_string(round) + "_" + std::to_string(i) + ".md");
    }
  }

  const std::size_t victim = static_cast<std::size_t>(s->rng.Below(n));
  std::size_t source = static_cast<std::size_t>(s->rng.Below(n));
  if (source == victim) source = (source + 1) % n;
  const ReplicaId source_id = s->replicas[source].id;
  const std::vector<uint64_t>& made = s->produced_tree[source_id];
  if (made.size() < 3) return;  // nothing to interrupt on this seed
  const uint64_t dropped = made[made.size() / 2];
  s->blocked_to = victim;
  s->blocked_from = source_id;
  s->blocked_counter = dropped;
  s->FlushInFlight();

  for (int round = 6; round < 10; ++round) {
    for (std::size_t i = 0; i < n; ++i) {
      (void)MakeFile(
          s, i, dirs[1],
          "g" + std::to_string(round) + "_" + std::to_string(i) + ".md");
    }
    s->FlushInFlight();
  }
  // Re-offer everything the victim has not been sent, still with the block on.
  s->ReofferAll();
  s->FlushInFlight();

  const uint64_t mark = s->PrefixMark(victim, source_id);
  if (mark >= dropped) {
    s->result.failure = "a replica that never received tree op " +
                        std::to_string(dropped) +
                        " reported a prefix mark of " + std::to_string(mark) +
                        ", claiming an operation it does not have";
    return;
  }
  for (std::size_t i = 0; i < n; ++i) {
    if (i == victim || i == source) continue;
    if (s->PrefixMark(i, source_id) < dropped) {
      s->result.failure =
          "a replica the relay did not drop for is missing tree op " +
          std::to_string(dropped);
      return;
    }
  }
  // Lift it: the operation was withheld, not destroyed.
  s->blocked_counter = 0;
}

// A RELAY REPLAYS CIPHERTEXT IT SERVED BEFORE, after a compaction round. That
// is the dangerous moment: the operations it re-serves are below the watermark
// and the log no longer holds them, so Apply must refuse them as duplicates
// rather than re-applying them into a tree that has forgotten they happened.
void RunRelayReplaysOldCiphertext(Sim* s) {
  const std::size_t n = s->replicas.size();
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b", "c"}, &dirs);
  std::vector<ObjectId> files;
  for (int round = 0; round < 8; ++round) {
    for (std::size_t i = 0; i < n; ++i) {
      files.push_back(MakeFile(
          s, i, dirs[round % dirs.size()],
          "f" + std::to_string(round) + "_" + std::to_string(i) + ".md"));
      s->LocalEdit(i);
    }
    s->FlushInFlight();
  }

  std::vector<Message> replays;
  for (std::size_t i = 0; i < n; ++i) {
    for (const TreeOp& op : s->tree_log[i]) {
      for (std::size_t j = 0; j < n; ++j) {
        if (i == j) continue;
        Message m;
        m.to = j;
        m.is_tree = true;
        m.tree_op = op;
        replays.push_back(m);
      }
    }
  }

  s->Quiesce();
  if (!s->result.failure.empty()) return;
  s->CompactTreeLogRound();
  if (!s->result.failure.empty()) return;

  // Served again, twice, after the logs were truncated.
  for (const Message& m : replays) s->DeliverMessage(m);
  for (const Message& m : replays) s->DeliverMessage(m);
  for (std::size_t i = 0; i < n; ++i) s->DrainPending(i);
}

// TWO REPLICAS WHOSE COUNTERS ARE NOWHERE NEAR EACH OTHER.
//
// A Lamport counter is not a wall clock, so skew here means what it actually
// means for this design: one device has made a million operations and another
// has made three. The chain is per (object, replica) and must not care; the
// marks must not care either.
//
// WHAT THIS SCHEDULE CATCHES, MEASURED RATHER THAN ASSUMED. Deliberate breakage
// found the line:
//
//   - Observe() made a complete no-op, so a replica never advances its clock
//     for anything it RECEIVES: every schedule still converges. Cross-replica
//     observation turns out not to be load-bearing here, because every
//     operation carries its own id and ties break by replica id, so causally
//     inconsistent timestamps still order identically on every replica.
//   - Tick() made not to advance for single-id operations, so a replica reuses
//     its OWN counters: this schedule fails, and so do tree-random and
//     relay-stale-view, while the plain random schedule still passes because
//     its text inserts are runs and runs still advance.
//
// So the property is uniqueness within a replica, not agreement between them.
// That is worth having written down: it is the same property the Vault violated
// when ApplyTreeOp did not advance the clock, and a reader who assumes the
// clock is about ordering will not see why that mattered.
void RunClockSkew(Sim* s) {
  const std::size_t n = s->replicas.size();
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b"}, &dirs);
  const std::size_t ahead = static_cast<std::size_t>(s->rng.Below(n));
  OpId far;
  far.counter = 1000000;
  far.replica = s->replicas[ahead].id;
  s->replicas[ahead].clock.Observe(far);

  for (int round = 0; round < 10; ++round) {
    for (std::size_t i = 0; i < n; ++i) {
      s->LocalEdit(i);
      if (s->rng.Chance(50)) {
        (void)MakeFile(
            s, i, dirs[i % dirs.size()],
            "s" + std::to_string(round) + "_" + std::to_string(i) + ".md");
      }
    }
    if (s->rng.Chance(60)) s->FlushInFlight();
  }
}

// A RELAY THAT IS CORRECT BUT BEHIND. It serves a prefix of what it holds and
// says there is nothing newer. Nothing it says is false; it is out of date,
// which a client cannot distinguish from a quiet vault.
//
// While it is behind, every mark must be justified by something that actually
// arrived -- a mark is a claim about what this replica holds, and a stale view
// must never inflate it.
void RunRelayStaleView(Sim* s) {
  const std::size_t n = s->replicas.size();
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b"}, &dirs);
  for (int round = 0; round < 10; ++round) {
    for (std::size_t i = 0; i < n; ++i) {
      (void)MakeFile(
          s, i, dirs[i % dirs.size()],
          "t" + std::to_string(round) + "_" + std::to_string(i) + ".md");
      s->LocalEdit(i);
    }
    // Only the OLDEST half: a correct prefix of the truth, and nothing newer.
    const std::size_t half = s->in_flight.size() / 2;
    std::vector<Message> serve(s->in_flight.begin(),
                               s->in_flight.begin() + static_cast<long>(half));
    s->in_flight.erase(s->in_flight.begin(),
                       s->in_flight.begin() + static_cast<long>(half));
    for (const Message& m : serve) s->DeliverMessage(m);
    for (std::size_t i = 0; i < n; ++i) s->DrainPending(i);

    for (std::size_t i = 0; i < n; ++i) {
      for (std::size_t j = 0; j < n; ++j) {
        if (i == j) continue;
        const ReplicaId src = s->replicas[j].id;
        const uint64_t mark = s->PrefixMark(i, src);
        if (mark == 0) continue;
        const std::map<ReplicaId, std::set<uint64_t>>::const_iterator g =
            s->replicas[i].got_tree.find(src);
        if (g == s->replicas[i].got_tree.end()) {
          s->result.failure = "a stale relay produced a mark of " +
                              std::to_string(mark) +
                              " for a source nothing arrived from";
          return;
        }
        // THE WHOLE PREFIX, not just the marked operation. Checking only that
        // the marked operation arrived is far too weak: a mark that skipped a
        // gap and landed on some later operation the replica does happen to
        // hold passes that check, which is precisely the defect this schedule
        // exists to catch. It did pass, under probe N1, until this loop was
        // written.
        for (uint64_t c : s->produced_tree[src]) {
          if (c > mark) break;
          if (g->second.count(c) == 0) {
            s->result.failure = "a stale relay produced a mark of " +
                                std::to_string(mark) + " while operation " +
                                std::to_string(c) + " never arrived";
            return;
          }
        }
      }
    }
  }
}

// TEAR A REPLICA DOWN AND REBUILD IT FROM ITS OWN LOG, MID RUN.
//
// The schedule that was missing. Every other schedule keeps a TreeDoc alive in
// memory for the whole run, including the crash ones, so the thing a real
// client does on every start -- construct an empty vault and replay a log into
// it -- had never been simulated. That is where Vault::ApplyTreeOp's clock bug
// lived, and only running the real binary on real files found it.
//
// Restarts happen while operations are still in flight, so a rebuilt replica
// has to keep accepting deliveries that were sent to the process that died.
//
// WHAT DELIBERATE BREAKAGE SAYS THIS CATCHES. Dropping the clock observation
// for tree operations in the rebuild fails here and does NOT fail the crash
// schedule, which is the measurement that says this schedule was missing
// rather than redundant. Observing op.id instead of LastId in the text rebuild
// fails here too.
//
// What it does NOT catch on its own: rebuilding the tree from what the replica
// ORIGINATED rather than what it PERSISTED still converges, because the cursor
// is rebuilt from the same log and a replica that forgets an operation also
// forgets that it has it, so peers send it again. Breaking that coupling --
// content from one log, cursor from the other -- does fail, and that is the
// shape of the Phase 3 defect where FetchObject advanced a cursor across
// operations it had not yet persisted.
void RunRestartFromLog(Sim* s) {
  const std::size_t n = s->replicas.size();
  std::vector<ObjectId> dirs;
  SeedTree(s, {"a", "b", "c"}, &dirs);
  std::vector<ObjectId> files;

  for (int round = 0; round < 12; ++round) {
    for (std::size_t i = 0; i < n; ++i) {
      s->LocalEdit(i);
      if (s->rng.Chance(60)) {
        files.push_back(MakeFile(
            s, i, dirs[(round + i) % dirs.size()],
            "r" + std::to_string(round) + "_" + std::to_string(i) + ".md"));
      }
      if (s->rng.Chance(40) && !files.empty()) {
        const ObjectId child = files[static_cast<std::size_t>(
            s->rng.Below(static_cast<uint64_t>(files.size())))];
        MoveNode(s, i, child,
                 dirs[static_cast<std::size_t>(
                     s->rng.Below(static_cast<uint64_t>(dirs.size())))],
                 "m" + std::to_string(round) + "_" + std::to_string(i) + ".md",
                 false);
      }
    }

    // Deliver some of it, so a restart lands with work still in flight.
    if (s->rng.Chance(70)) {
      const std::size_t half = s->in_flight.size() / 2;
      std::vector<Message> serve(
          s->in_flight.begin(), s->in_flight.begin() + static_cast<long>(half));
      s->in_flight.erase(s->in_flight.begin(),
                         s->in_flight.begin() + static_cast<long>(half));
      for (const Message& m : serve) s->DeliverMessage(m);
      for (std::size_t i = 0; i < n; ++i) s->DrainPending(i);
    }

    // Commit, then restart somebody. Committing first is what makes this a
    // restart rather than a crash: the question is whether a replica can be
    // rebuilt from what it persisted, not whether it loses what it did not.
    for (std::size_t i = 0; i < n; ++i) s->Commit(i);
    if (s->rng.Chance(50)) {
      const std::size_t who = static_cast<std::size_t>(s->rng.Below(n));
      s->RestartFromLog(who);
      if (!s->result.failure.empty()) return;

      // AND THEN IT KEEPS WORKING. A rebuilt replica that cannot produce a new
      // operation without colliding with one of its own is the failure this
      // schedule exists to catch, so it must edit again immediately.
      s->LocalEdit(who);
      files.push_back(
          MakeFile(s, who, dirs[0], "after" + std::to_string(round) + ".md"));
    }
  }
}

// ------------------------------------------------------------------- index
//
// PHASE 5 SCHEDULES. What is modelled here is the manifest lattice and the
// retirement safety condition, not the vectors: a "segment" is an id, a size
// and a bag of bytes whose hash is checked. That is deliberate -- what can go
// wrong when an index replicates is who stops using a segment and when, and
// putting real embeddings in the simulator would make it slow without making it
// sharper.

namespace {

// One device's view of the index: the fold of every manifest operation it has
// seen, and the segments whose bytes it actually holds.
// The model the index schedules pretend to use. Fixed, because what is under
// test is the manifest and not the embeddings.
ai::ModelDescriptor SimModel() {
  ai::ModelDescriptor d;
  d.family = "umbra-sim";
  d.version = "1";
  d.dimension = 64;
  d.quantisation = "none";
  d.pooling = "sum";
  d.normalised = true;
  return d;
}

struct IndexPeer {
  std::unique_ptr<ai::ManifestDoc> manifest;
  std::set<ai::SegmentId> present;
  uint64_t counter = 0;

  bool Present(const ai::SegmentId& id) const { return present.count(id) != 0; }

  ai::ManifestOp Make(ai::ManifestOpKind kind, const ReplicaId& who) {
    ai::ManifestOp op;
    op.kind = kind;
    op.id.replica = who;
    op.id.counter = ++counter;
    op.prev = op.id.counter - 1;
    return op;
  }
};

ai::SegmentId SegmentFromSeed(uint64_t seed) {
  ai::SegmentId id;
  for (std::size_t i = 0; i < id.bytes.size(); ++i) {
    id.bytes[i] = static_cast<uint8_t>((seed >> ((i % 8) * 8)) & 0xFF);
  }
  id.bytes[31] = static_cast<uint8_t>(seed & 0xFF);
  return id;
}

// The live set a device would search, under the safety condition.
std::vector<ai::SegmentId> LiveFor(const IndexPeer& p) {
  return p.manifest->Live(
      [&p](const ai::SegmentId& id) { return p.Present(id); });
}

// EVERYTHING THE FOLD DECIDED, not just which ids are live. The first version
// compared ids and dead-counts only, so a peer whose fold had lost a segment's
// COUNT -- which is what happens when a placeholder entry is mistaken for a
// prior add -- compared equal to one that had not. Deliberate breakage caught
// the defect in a unit test and not here, and this is why.
std::string StateOf(const IndexPeer& p) {
  std::string out;
  for (const ai::SegmentId& id : LiveFor(p)) {
    const ai::SegmentState* st = p.manifest->Get(id);
    out += id.Short();
    out += ":n" + std::to_string(st == nullptr ? 0 : st->count);
    out += ":b" + std::to_string(st == nullptr ? 0 : st->bytes);
    out += ":d" + std::to_string(st == nullptr ? 0 : st->dead.size());
    out += ":s" + std::to_string(st == nullptr ? 0 : st->superseded_by.size());
    out += ";";
  }
  return out;
}

}  // namespace

// A SEGMENT ARRIVES BEFORE THE OPERATION THAT NAMES IT, and the operation
// arrives before the bytes, in both directions, repeatedly. Neither order may
// change where a device ends up.
void RunIndexSegmentBeforeManifest(Sim* s) {
  const ai::EmbeddingModelId model = ai::ComputeModelId(SimModel());
  std::vector<IndexPeer> peers(s->replicas.size());
  for (IndexPeer& p : peers) p.manifest.reset(new ai::ManifestDoc(model));

  std::vector<ai::ManifestOp> published;
  for (int round = 0; round < 12; ++round) {
    const std::size_t who =
        static_cast<std::size_t>(s->rng.Below(s->replicas.size()));
    ai::ManifestOp add =
        peers[who].Make(ai::ManifestOpKind::kAdd, s->replicas[who].id);
    add.segment = SegmentFromSeed(static_cast<uint64_t>(round) * 7919 + who);
    add.count = 1 + static_cast<uint32_t>(s->rng.Below(40));
    add.bytes = add.count * 400;
    add.model = model;
    (void)peers[who].manifest->Apply(add);
    peers[who].present.insert(add.segment);
    published.push_back(add);
    ++s->result.manifest_ops;

    // A tombstone against the segment, which is what an edit on another device
    // produces. It is delivered in an order the schedule chooses -- INCLUDING
    // BEFORE THE ADD IT REFERS TO, which is the ordering that makes the fold
    // depend on arrival order if a placeholder entry is mistaken for a prior
    // add. Deliberate breakage found this schedule too weak without it: the
    // defect was caught by a unit test and not here.
    ai::ManifestOp tomb =
        peers[who].Make(ai::ManifestOpKind::kTombstone, s->replicas[who].id);
    tomb.segment = add.segment;
    tomb.slot = static_cast<uint32_t>(s->rng.Below(add.count));
    (void)peers[who].manifest->Apply(tomb);
    ++s->result.manifest_ops;

    for (std::size_t j = 0; j < peers.size(); ++j) {
      if (j == who) continue;
      const bool bytes_first = s->rng.Chance(50);
      const bool tombstone_first = s->rng.Chance(50);
      if (bytes_first) {
        peers[j].present.insert(add.segment);
        ++s->result.segments_adopted;
      }
      if (tombstone_first) {
        (void)peers[j].manifest->Apply(tomb);
        (void)peers[j].manifest->Apply(add);
      } else {
        (void)peers[j].manifest->Apply(add);
        (void)peers[j].manifest->Apply(tomb);
      }
      if (!bytes_first) {
        peers[j].present.insert(add.segment);
        ++s->result.segments_adopted;
      }
    }
  }

  // Everyone saw the same operations and holds the same bytes, so everyone must
  // agree on what is live.
  const std::string reference = StateOf(peers[0]);
  for (std::size_t i = 1; i < peers.size(); ++i) {
    if (StateOf(peers[i]) != reference) {
      s->result.failure = "index peers disagree after the same operations: " +
                          StateOf(peers[i]) + " against " + reference;
      return;
    }
  }
}

// A RELAY THAT SERVES A CORRECT PREFIX OF THE MANIFEST. Nothing it says is
// false; it is simply behind. A device holding a stale manifest must not
// conclude anything is missing that is not, and must not call itself complete.
void RunIndexStaleManifest(Sim* s) {
  const ai::EmbeddingModelId model = ai::ComputeModelId(SimModel());
  IndexPeer writer;
  writer.manifest.reset(new ai::ManifestDoc(model));
  IndexPeer reader;
  reader.manifest.reset(new ai::ManifestDoc(model));

  std::vector<ai::ManifestOp> published;
  for (int round = 0; round < 16; ++round) {
    ai::ManifestOp add =
        writer.Make(ai::ManifestOpKind::kAdd, s->replicas[0].id);
    add.segment = SegmentFromSeed(static_cast<uint64_t>(round) * 104729 + 3);
    add.count = 1 + static_cast<uint32_t>(s->rng.Below(20));
    add.bytes = add.count * 512;
    add.model = model;
    (void)writer.manifest->Apply(add);
    writer.present.insert(add.segment);
    published.push_back(add);
    ++s->result.manifest_ops;
  }

  // The relay serves a prefix, of a length it chooses.
  const std::size_t served =
      static_cast<std::size_t>(s->rng.Below(published.size() + 1));
  for (std::size_t i = 0; i < served; ++i) {
    (void)reader.manifest->Apply(published[i]);
  }

  // Everything the reader believes exists must really exist, and it must not
  // believe it has everything unless it does.
  for (const ai::SegmentId& id : reader.manifest->Wanted()) {
    if (writer.manifest->Get(id) == nullptr) {
      s->result.failure = "a stale manifest named a segment nobody published";
      return;
    }
  }
  const std::size_t known = reader.manifest->Wanted().size();
  if (known > published.size()) {
    s->result.failure = "a stale manifest knew more than was ever published";
    return;
  }
  if (served < published.size() && known == published.size()) {
    s->result.failure =
        "a device served a strict prefix reported the whole manifest";
    return;
  }
}

// TWO DEVICES COMPACT FROM THE SAME VIEW. Input selection is a pure function of
// the manifest, so they must choose the same inputs -- which is what makes the
// outputs the same segment and the two operations one.
void RunIndexConcurrentCompaction(Sim* s) {
  const ai::EmbeddingModelId model = ai::ComputeModelId(SimModel());
  IndexPeer a;
  a.manifest.reset(new ai::ManifestDoc(model));
  IndexPeer b;
  b.manifest.reset(new ai::ManifestDoc(model));

  std::vector<ai::SegmentId> live;
  for (int round = 0; round < 10; ++round) {
    ai::ManifestOp add = a.Make(ai::ManifestOpKind::kAdd, s->replicas[0].id);
    add.segment = SegmentFromSeed(static_cast<uint64_t>(round) * 15485863 + 11);
    add.count = 1 + static_cast<uint32_t>(s->rng.Below(50));
    add.bytes = add.count * 400;
    add.model = model;
    (void)a.manifest->Apply(add);
    (void)b.manifest->Apply(add);
    a.present.insert(add.segment);
    b.present.insert(add.segment);
    live.push_back(add.segment);
    ++s->result.manifest_ops;
  }

  const ai::CompactionPlan pa =
      ai::PlanCompaction(*a.manifest, LiveFor(a), 2, 10, 4);
  // The same manifest, the live set in a different order, which is what two
  // devices with different insertion histories would hand it.
  std::vector<ai::SegmentId> shuffled = LiveFor(b);
  for (std::size_t i = shuffled.size(); i > 1; --i) {
    const std::size_t j = static_cast<std::size_t>(s->rng.Below(i));
    std::swap(shuffled[i - 1], shuffled[j]);
  }
  const ai::CompactionPlan pb =
      ai::PlanCompaction(*b.manifest, shuffled, 2, 10, 4);

  if (pa.inputs != pb.inputs) {
    s->result.failure =
        "two devices with one manifest chose different compaction inputs, so "
        "their outputs would be two segments rather than one";
    return;
  }
}

// A DEVICE ON A DIFFERENT MODEL. Its manifest must refuse every operation and
// it must not go looking for segments it could never use.
void RunIndexForeignModel(Sim* s) {
  ai::ModelDescriptor other = SimModel();
  other.dimension += 128;
  const ai::EmbeddingModelId mine = ai::ComputeModelId(SimModel());
  const ai::EmbeddingModelId theirs = ai::ComputeModelId(other);

  IndexPeer peer;
  peer.manifest.reset(new ai::ManifestDoc(mine));
  for (int round = 0; round < 12; ++round) {
    ai::ManifestOp add = peer.Make(ai::ManifestOpKind::kAdd, s->replicas[0].id);
    add.segment = SegmentFromSeed(static_cast<uint64_t>(round) * 2654435761u);
    add.count = 1 + static_cast<uint32_t>(s->rng.Below(30));
    add.model = theirs;
    const ai::ManifestApply r = peer.manifest->Apply(add);
    ++s->result.manifest_ops;
    if (r != ai::ManifestApply::kModelMismatch) {
      s->result.failure = "a foreign model's segment was absorbed";
      return;
    }
    ++s->result.segments_refused;
  }
  if (!peer.manifest->Wanted().empty()) {
    s->result.failure =
        "a device is fetching segments from a model it cannot "
        "read";
    return;
  }
  if (peer.manifest->refused_model() == 0) {
    s->result.failure =
        "refusals were not counted, so a device could not say "
        "why its index is empty";
    return;
  }
}

// RETIREMENT UNDER PARTIAL DELIVERY. The condition under test is the one stated
// in manifest.h: a retired segment stays live until its replacement is here.
void RunIndexCorruptedSegment(Sim* s) {
  const ai::EmbeddingModelId model = ai::ComputeModelId(SimModel());
  IndexPeer peer;
  peer.manifest.reset(new ai::ManifestDoc(model));

  std::vector<ai::SegmentId> inputs;
  for (int i = 0; i < 6; ++i) {
    ai::ManifestOp add = peer.Make(ai::ManifestOpKind::kAdd, s->replicas[0].id);
    add.segment = SegmentFromSeed(static_cast<uint64_t>(i) * 999983 + 5);
    add.count = 10;
    add.model = model;
    (void)peer.manifest->Apply(add);
    peer.present.insert(add.segment);
    inputs.push_back(add.segment);
    ++s->result.manifest_ops;
  }

  // A compaction elsewhere produces a replacement this device does not have --
  // because the transfer failed, or the bytes arrived damaged and were refused.
  const ai::SegmentId replacement = SegmentFromSeed(0xDEADBEEFull);
  ai::ManifestOp add = peer.Make(ai::ManifestOpKind::kAdd, s->replicas[1].id);
  add.segment = replacement;
  add.count = 60;
  add.model = model;
  (void)peer.manifest->Apply(add);
  ++s->result.manifest_ops;
  for (const ai::SegmentId& id : inputs) {
    ai::ManifestOp r =
        peer.Make(ai::ManifestOpKind::kRetire, s->replicas[1].id);
    r.segment = id;
    r.superseded_by = replacement;
    (void)peer.manifest->Apply(r);
    ++s->result.manifest_ops;
  }
  ++s->result.segments_refused;

  // EVERY INPUT MUST STILL BE LIVE. This is the whole safety condition: the
  // device was told they are retired and it does not have what replaces them.
  const std::vector<ai::SegmentId> live = LiveFor(peer);
  for (const ai::SegmentId& id : inputs) {
    if (std::find(live.begin(), live.end(), id) == live.end()) {
      s->result.failure =
          "a segment was dropped while its replacement was missing, so the "
          "index is silently incomplete";
      return;
    }
  }
  s->result.retirements_held += inputs.size();

  // And once the replacement is here, they go.
  peer.present.insert(replacement);
  const std::vector<ai::SegmentId> after = LiveFor(peer);
  for (const ai::SegmentId& id : inputs) {
    if (std::find(after.begin(), after.end(), id) != after.end()) {
      s->result.failure =
          "a retirement never took effect, so the index only grows";
      return;
    }
  }
  if (std::find(after.begin(), after.end(), replacement) == after.end()) {
    s->result.failure = "the replacement is not live";
    return;
  }
}

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
    case Adversarial::kCompactThenEdit:
      RunCompactThenEdit(&s);
      break;
    case Adversarial::kTreeRandom:
      RunTreeRandom(&s);
      break;
    case Adversarial::kTreeMoveIntoEachOther:
      RunTreeMoveIntoEachOther(&s);
      break;
    case Adversarial::kTreeMoveIntoDeleted:
      RunTreeMoveIntoDeleted(&s);
      break;
    case Adversarial::kTreeMoveWhileEditingInside:
      RunTreeMoveWhileEditingInside(&s);
      break;
    case Adversarial::kTreeRenameCycleThreeWay:
      RunTreeRenameCycleThreeWay(&s);
      break;
    case Adversarial::kTreeCompactThenMove:
      RunTreeCompactThenMove(&s);
      break;
    case Adversarial::kRelayDropsPermanently:
      RunRelayDropsPermanently(&s);
      break;
    case Adversarial::kRelayReplaysOldCiphertext:
      RunRelayReplaysOldCiphertext(&s);
      break;
    case Adversarial::kClockSkew:
      RunClockSkew(&s);
      break;
    case Adversarial::kRelayStaleView:
      RunRelayStaleView(&s);
      break;
    case Adversarial::kRestartFromLog:
      RunRestartFromLog(&s);
      break;
    case Adversarial::kIndexSegmentBeforeManifest:
      RunIndexSegmentBeforeManifest(&s);
      break;
    case Adversarial::kIndexStaleManifest:
      RunIndexStaleManifest(&s);
      break;
    case Adversarial::kIndexConcurrentCompaction:
      RunIndexConcurrentCompaction(&s);
      break;
    case Adversarial::kIndexForeignModel:
      RunIndexForeignModel(&s);
      break;
    case Adversarial::kIndexCorruptedSegment:
      RunIndexCorruptedSegment(&s);
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
