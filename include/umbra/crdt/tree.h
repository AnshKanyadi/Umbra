// The file-tree CRDT: Kleppmann's move operation.
//
// docs/adr/0003-tree.md argues the choice. What follows is what the code does.
//
// ---------------------------------------------------------------------------
// ONE OPERATION
//
// The tree is a set of (child, parent, name) triples, and the ONLY operation is
// a move. Everything the watcher reports is one:
//
//   create  move a brand new id under a parent
//   rename  move a node under the SAME parent with a different name
//   move    move a node under a different parent
//   delete  move a node under the reserved TRASH node
//
// That is not a trick to save code. A design with separate create and delete
// operations has to answer what a delete concurrent with a move into the
// deleted directory means, and the answer is a special case. Here it is not a
// special case: both are moves, they are ordered by timestamp, and the later
// one wins.
//
// ---------------------------------------------------------------------------
// THE HARD CASE, AND WHY THE LOG IS REPLAYED
//
// Two replicas concurrently move A into B and B into A. Applied naively in
// either order the tree acquires a CYCLE: A and B become each other's ancestor
// and neither is reachable from the root. Both files vanish. Naive designs get
// this wrong by applying both moves and then repairing, or by reparenting one
// node to the root, and the two replicas repair differently.
//
// The fix, from the paper, is that applying an operation is not "append": it is
//
//     UNDO every logged operation with a LATER timestamp, in reverse order
//     DO   the new operation
//     REDO the undone operations, in timestamp order
//
// so the state is a function of the SET of operations ordered by timestamp, and
// nothing else. Two replicas holding the same set agree however they received
// it. Each operation records what it displaced, which is what makes undo exact.
//
// AND THE CYCLE CHECK IS PART OF `DO`. An operation whose effect would make a
// node its own ancestor is IGNORED -- not applied and repaired, not redirected
// to the root, IGNORED, as though it had never been issued. It stays in the log
// because a later replay may reach it in a different state where it is legal.
// See TreeApply::kIgnoredCycle.
//
// ---------------------------------------------------------------------------
// WHAT THIS COSTS
//
// Applying an operation older than ones already seen undoes and redoes
// everything newer, so an operation that arrives k positions out of order costs
// O(k). Operations mostly arrive in order, so k is usually zero; a replica
// rejoining after a long absence pays once, proportional to what it missed.
// That is the trade the paper makes and it is the reason no causal delivery is
// required: a tree operation is NEVER not-ready, whatever order it arrives in,
// which is a strictly stronger property than the text CRDT has.
#ifndef UMBRA_CRDT_TREE_H_
#define UMBRA_CRDT_TREE_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "umbra/change_event.h"
#include "umbra/crdt/op.h"
#include "umbra/crdt/op_id.h"

namespace umbra {

// The vault root. Every reachable node's parent chain ends here.
ObjectId TreeRoot();
// Where deleted nodes go. Reachable from nothing; a node under it is deleted.
ObjectId TreeTrash();
// The reserved object the tree's own operation log is filed under in the oplog,
// so tree operations share the key layout with text operations. See oplog.h.
ObjectId TreeObject();

bool IsTreeRoot(const ObjectId& id);
bool IsTreeTrash(const ObjectId& id);

// One move. This is the whole operation set.
struct TreeOp {
  // The timestamp. Totally ordered by (counter, replica), exactly as text
  // operations are, and for the same reason: the order has to be computable
  // from the operation alone.
  OpId id;

  ObjectId child;
  ObjectId parent;

  // ONE PATH COMPONENT, not a path. A rename touches one node; deriving the
  // full path by walking to the root is what makes a directory move cost a
  // single operation rather than one per descendant.
  //
  // This is also where a filename lives on the wire, so encrypting the payload
  // is what keeps names off the relay. See docs/threat-model.md section 3.
  std::string name;

  // True when the node is a directory. Carried because the watcher knows and
  // the tree cannot tell from the shape alone -- an empty directory and a file
  // are both leaves.
  bool is_dir = false;

  std::string ToString() const;
};

// Closed; -Werror=switch applies.
enum class TreeApply : uint8_t {
  kApplied,
  // Already in the log. Duplicate delivery is normal.
  kDuplicate,
  // The move would have made a node its own ancestor, so it was IGNORED. Not
  // an error: it is the defined outcome for a concurrent move that would create
  // a cycle, and the operation is still logged so a later replay can reconsider
  // it.
  kIgnoredCycle,
  // Structurally impossible: moving the root, moving a node into itself as a
  // direct self-parent, or an empty name for a non-root node.
  kMalformed,
};

const char* TreeApplyName(TreeApply a);

class TreeDoc {
 public:
  TreeDoc();

  // Apply a move from anywhere. NEVER returns "not ready": the algorithm is
  // defined for any arrival order, which is the property that makes tree
  // operations independent of causal delivery.
  TreeApply Apply(const TreeOp& op);

  // Build a move from this replica. Does not apply it.
  TreeOp MakeMove(const ObjectId& child, const ObjectId& parent,
                  const std::string& name, bool is_dir,
                  LamportClock* clock) const;

  // ------------------------------------------------------------- queries
  bool Exists(const ObjectId& id) const;
  bool ParentOf(const ObjectId& id, ObjectId* out) const;
  bool NameOf(const ObjectId& id, std::string* out) const;
  bool IsDir(const ObjectId& id) const;

  // Vault-relative path, '/'-separated. False when the node is missing, is in
  // the trash, or its parent chain does not reach the root.
  bool PathOf(const ObjectId& id, std::string* out) const;

  // Resolve a vault-relative path to a node. Linear in the tree; this is a
  // client-side index in the finished system, and is here so tests and the
  // bridge can ask.
  bool Resolve(const std::string& path, ObjectId* out) const;

  // True when the node's parent chain reaches the trash rather than the root.
  bool IsDeleted(const ObjectId& id) const;

  std::vector<ObjectId> Children(const ObjectId& parent) const;
  // Every live node with a resolvable path, path-sorted. The whole visible
  // vault.
  std::vector<std::pair<std::string, ObjectId>> Listing() const;

  std::size_t NodeCount() const { return nodes_.size(); }
  std::size_t LogSize() const { return log_.size(); }

  // ------------------------------------------------------ log compaction
  //
  // Drop every log entry whose timestamp counter is at or below `through`.
  // docs/adr/0003-tree.md carries the five-part condition the caller must have
  // satisfied; CompactionWatermark below computes the only value that
  // satisfies it. Returns how many entries went.
  //
  // THE WATERMARK IS REMEMBERED, and that is clause 5 of the condition.
  // Dropping the log entry does not drop the operation: a peer or a relay can
  // still hand it back, and re-applying it would undo the entire remaining log
  // to make room for it. Anything at or below the mark is treated as already
  // seen instead.
  std::size_t CompactLog(uint64_t through);
  uint64_t compacted_through() const { return compacted_through_; }

  // THE PREFIX MARK IS NOT DERIVABLE FROM THIS LOG, and an earlier version of
  // this file offered a HaveMarks() that pretended otherwise.
  //
  // Clause 2 of the condition needs "the highest counter from source S for
  // which I hold EVERY operation at or below it". A log can only be asked which
  // counters it holds, and a run of consecutive integers is not the same
  // question: text and tree operations share one Lamport counter space per
  // device, so a device's tree operations are almost never consecutive. The
  // old implementation therefore stopped at the first text-operation counter
  // and reported a mark far below the truth -- and, worse, reported ZERO for a
  // device whose first tree operation was not counter 1, which the watermark
  // read as "this source has produced nothing" and skipped entirely. Operations
  // that were still in flight were then compacted past. Seed 68 of tree-random.
  //
  // The mark is a SYNC quantity: a cursor says "I have fetched everything from
  // S up to counter c", which is exactly the guarantee, and it is true because
  // the fetch is ordered by counter (ADR 0001's key layout). It is supplied by
  // the caller, not computed here.

  // A fingerprint of the VISIBLE tree: every live path and what is at it. Two
  // replicas that have converged produce the same value.
  std::string StateHash() const;

  // Would moving `child` under `parent` make `child` its own ancestor? Exposed
  // because the harness's reference model has to ask the same question
  // independently.
  bool WouldCycle(const ObjectId& child, const ObjectId& parent) const;

 private:
  struct Entry {
    ObjectId parent;
    std::string name;
    bool is_dir = false;
  };

  // What one applied operation displaced, so it can be undone exactly.
  struct LogMove {
    TreeOp op;
    bool had_old = false;  // the child existed before this operation
    Entry old_entry;       // what it was, when had_old
    bool ignored = false;  // the cycle check refused it; undo is a no-op
  };

  void DoOp(const TreeOp& op, LogMove* record);
  void UndoOp(const LogMove& record);

  std::map<ObjectId, Entry> nodes_;
  // Ordered by timestamp. A map rather than a vector because the common
  // operation is "everything after t", which is a range.
  std::map<OpId, LogMove> log_;
  uint64_t compacted_through_ = 0;
};

// One device's report, clause 2 of the condition.
struct DeviceReport {
  ReplicaId device;
  // Contiguous prefix marks: source -> highest counter for which this device
  // holds everything at or below it.
  std::map<ReplicaId, uint64_t> have;
  // This device's Lamport clock. Load-bearing and easy to leave out: without
  // it, a device whose clock is behind the watermark will issue a counter below
  // it and need log entries that are gone.
  uint64_t clock = 0;
};

// Clause 3, computed. Returns 0 -- meaning compact nothing -- whenever any
// enrolled device has not reported, which is the conservative direction and the
// one a withholding relay can force.
//
// `enrolled` is the set the vault knows about. A report from a device that is
// not enrolled is ignored; an enrolled device with no report collapses the
// watermark.
uint64_t CompactionWatermark(const std::vector<ReplicaId>& enrolled,
                             const std::vector<DeviceReport>& reports);

// Encoding, to the same opaque OpPayload text operations use, so the oplog and
// the encryption layer treat both identically. See op.h for why the payload is
// the boundary.
OpPayload EncodeTreeOp(const TreeOp& op);
bool DecodeTreeOp(const OpPayload& payload, TreeOp* out);

constexpr uint8_t kTreeOpEncodingVersion = 1;

}  // namespace umbra

#endif  // UMBRA_CRDT_TREE_H_
