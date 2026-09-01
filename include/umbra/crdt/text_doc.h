// The sequence CRDT: Fugue.
//
// docs/adr/0002-crdt.md argues the choice. What follows is what the code does.
//
// ---------------------------------------------------------------------------
// THE STRUCTURE
//
// Every character is a node in a tree. A node records the node it was inserted
// next to (`parent`) and WHICH SIDE of it (`side`). The document is the
// in-order traversal:
//
//     render(n) = render(left children of n, in sibling order)
//                 ++ n
//                 ++ render(right children of n, in sibling order)
//
// A sentinel root holds the whole document as its right children, so "insert at
// the very beginning" has a node to name and needs no special case.
//
// ---------------------------------------------------------------------------
// THE INSERT RULE, WHICH IS THE WHOLE DESIGN
//
// To insert between two currently adjacent nodes `l` and `r`:
//
//     if l has no right children:  new node is a RIGHT child of l
//     else:                        new node is a LEFT child of r
//
// Two lines, and they are what avoids interleaving. The reason:
//
//   TYPING FORWARD makes a right-chain. Insert `a` between l and r; a has no
//   right children, so `b` becomes a's right child, then `c` becomes b's. The
//   run is a chain hanging off its own first character.
//
//   TYPING BACKWARD makes a left-chain. Insert `c` between l and r -- if l
//   already has right children, c becomes r's LEFT child. Insert `b` between l
//   and c: c is now the right origin, so b becomes c's left child. The run is
//   again a chain, hanging off its own last character.
//
// EITHER WAY A RUN IS A CHAIN, and a chain moves as a unit: the only place a
// concurrent run can be ordered against it is at the chain's head, where the
// sibling comparison happens once. Two concurrent runs therefore come out as
// one whole run then the other. They cannot alternate character by character,
// which is the interleaving anomaly.
//
// This is precisely what RGA does not give. In RGA every character names the
// character it follows, so a run typed BACKWARD anchors every one of its
// characters to the SAME node, they all become siblings, and a concurrent
// backward run's characters sort in among them. See the ADR.
//
// ---------------------------------------------------------------------------
// SIBLING ORDER
//
// Children of one node, on one side, are ordered by OpId ASCENDING.
//
// The direction is a free choice -- it decides only WHICH of two concurrent
// runs lands first, and both answers are equally correct. What is NOT free is
// that the order be TOTAL and computed from the ids alone. OpId ordering is
// (counter, replica); the replica half is what makes it total, and dropping it
// makes sibling order depend on the sequence in which a replica happened to
// learn of the operations. Two replicas with different delivery orders then
// render different documents.
//
// ---------------------------------------------------------------------------
// WHAT THIS COSTS, STATED
//
// One node per character, each holding two OpIds (24 bytes apiece) inline:
// roughly 56 bytes per character of document. A 100 KB note is about 5 MB
// resident while open. Two optimizations are deliberately NOT done here --
// storing a run as one node and splitting it only when something is inserted
// into its middle, and interning replica ids to a small integer. The second is
// a trap worth naming: an interned index must sort the same way the ReplicaId
// it stands for does, or sibling order becomes discovery-order dependent and
// replicas diverge. Both are optimizations of a design whose correctness is the
// point of this phase.
//
// Rendering and index lookup are both a traversal, so both are O(document). An
// order-statistic index would make them O(log n) and is likewise deferred.
#ifndef UMBRA_CRDT_TEXT_DOC_H_
#define UMBRA_CRDT_TEXT_DOC_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "umbra/change_event.h"
#include "umbra/crdt/op.h"
#include "umbra/crdt/op_id.h"

namespace umbra {

// Why an operation could not be applied. Closed; -Werror=switch applies.
enum class ApplyResult : uint8_t {
  // Applied, and the document changed.
  kApplied,
  // Already had it. Duplicate delivery is normal and is not an error: the relay
  // may resend, and a replica may receive the same operation by two paths.
  kDuplicate,
  // The operation names something this replica has not seen yet -- an insert
  // whose parent is unknown, or a delete whose target is unknown. The caller
  // should hold it and retry when more arrives. NOT an error either; it is what
  // out-of-order delivery looks like.
  kNotReady,
  // Structurally impossible: a delete with count 0, an insert with no text, a
  // run whose ids collide with a different existing run. A malformed or
  // hostile operation.
  kMalformed,
};

const char* ApplyResultName(ApplyResult r);

// Where a character sits and whether it is still visible.
struct Node {
  OpId id;
  OpId parent;
  Side side = Side::kRight;
  char32_t value = 0;
  bool deleted = false;

  // Sorted ascending by OpId. Kept as vectors rather than sets because they are
  // almost always tiny -- a node acquires a second child on one side only when
  // two replicas insert at the same spot concurrently -- and a vector of one is
  // cheaper than a node of one in every way that matters.
  std::vector<OpId> left;
  std::vector<OpId> right;
};

class TextDoc {
 public:
  TextDoc() = default;

  // ---------------------------------------------------------------- remote
  //
  // Apply an operation from anywhere, including this replica's own past.
  // Idempotent: applying the same operation twice is kDuplicate and changes
  // nothing. Commutative for concurrent operations, which is what the
  // convergence harness exists to hold to account.
  ApplyResult Apply(const Op& op);

  // ----------------------------------------------------------------- local
  //
  // Produce the operations for an edit expressed in document positions, and
  // apply them here. Positions are in CHARACTERS of the visible document, not
  // bytes and not including deleted nodes.
  //
  // Returns false and produces nothing if the position is out of range or the
  // text is not valid UTF-8.
  bool LocalInsert(std::size_t index, const std::string& utf8,
                   LamportClock* clock, std::vector<Op>* out);
  bool LocalDelete(std::size_t index, std::size_t count, LamportClock* clock,
                   std::vector<Op>* out);

  // --------------------------------------------------------------- reading
  std::string Text() const;              // UTF-8
  std::vector<char32_t> Chars() const;   // visible scalars, in order
  std::vector<OpId> VisibleIds() const;  // the ids behind those scalars
  std::size_t Length() const;            // visible characters

  // Every node ever seen, tombstones included. For tests and compaction.
  std::size_t NodeCount() const { return nodes_.size(); }
  std::size_t TombstoneCount() const;

  // A stable fingerprint of the VISIBLE document. Two replicas that have
  // converged produce the same value; two that have not, do not. Cheaper to
  // compare than the text and exactly as decisive, because it is a hash of it.
  std::string StateHash() const;

  // ------------------------------------------------------------ compaction
  //
  // Drop tombstones that can no longer affect anything. See oplog.h for the
  // watermark and for the safety argument; this is only the mechanism.
  //
  // A tombstone is droppable when it is deleted, its id is at or below the
  // watermark for its replica, AND IT IS A LEAF. The leaf requirement is not
  // an optimization: a tombstone with children is still holding their position
  // in the tree, and removing it would move them. Chains of tombstones
  // therefore collapse from the outside in, over successive compactions.
  //
  // Returns how many nodes were removed.
  std::size_t Compact(const std::map<ReplicaId, uint64_t>& watermark);

  // Test and diagnostic surface.
  const Node* Find(const OpId& id) const;
  bool HasNode(const OpId& id) const { return Find(id) != nullptr; }

 private:
  // Returns nullptr for the root, which has no Node of its own.
  Node* Mutable(const OpId& id);
  void InsertChild(Node* parent_node, const OpId& child, Side side);
  void RemoveChild(Node* parent_node, const OpId& child, Side side);
  const std::vector<OpId>& ChildrenOf(const OpId& id, Side side) const;
  void Walk(const OpId& id, bool emit_self,
            const std::function<void(const Node&)>& fn) const;

  std::map<OpId, Node> nodes_;
  // The root's children. The root has no left children by construction: it is
  // never a right origin, so nothing is ever inserted to its left.
  std::vector<OpId> root_right_;
  static const std::vector<OpId> kNoChildren;
};

}  // namespace umbra

#endif  // UMBRA_CRDT_TEXT_DOC_H_
