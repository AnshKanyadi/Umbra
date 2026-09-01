#include "umbra/crdt/text_doc.h"

#include <sodium.h>
#include <algorithm>

#include "check.h"
#include "utf8.h"

namespace umbra {

const std::vector<OpId> TextDoc::kNoChildren;

const char* ApplyResultName(ApplyResult r) {
  switch (r) {
    case ApplyResult::kApplied:
      return "applied";
    case ApplyResult::kDuplicate:
      return "duplicate";
    case ApplyResult::kNotReady:
      return "not-ready";
    case ApplyResult::kMalformed:
      return "malformed";
  }
  return "unknown";
}

const Node* TextDoc::Find(const OpId& id) const {
  const std::map<OpId, Node>::const_iterator it = nodes_.find(id);
  return it == nodes_.end() ? nullptr : &it->second;
}

Node* TextDoc::Mutable(const OpId& id) {
  const std::map<OpId, Node>::iterator it = nodes_.find(id);
  return it == nodes_.end() ? nullptr : &it->second;
}

const std::vector<OpId>& TextDoc::ChildrenOf(const OpId& id, Side side) const {
  if (IsRoot(id)) {
    // The root has no left children: it is never a right origin, so nothing is
    // ever inserted to its left. Returning the empty vector rather than
    // asserting keeps the traversal uniform.
    return side == Side::kRight ? root_right_ : kNoChildren;
  }
  const Node* n = Find(id);
  if (n == nullptr) return kNoChildren;
  return side == Side::kLeft ? n->left : n->right;
}

void TextDoc::InsertChild(Node* parent_node, const OpId& child, Side side) {
  std::vector<OpId>* v;
  if (parent_node == nullptr) {
    UMBRA_CHECK(side == Side::kRight,
                "nothing may be inserted to the left of the document root");
    v = &root_right_;
  } else {
    v = side == Side::kLeft ? &parent_node->left : &parent_node->right;
  }
  // ASCENDING BY OpId, and the comparison is OpId's own -- (counter, replica).
  // This is the tiebreak the whole design rests on; see text_doc.h.
  const std::vector<OpId>::iterator at =
      std::lower_bound(v->begin(), v->end(), child);
  v->insert(at, child);
}

void TextDoc::RemoveChild(Node* parent_node, const OpId& child, Side side) {
  std::vector<OpId>* v;
  if (parent_node == nullptr) {
    v = &root_right_;
  } else {
    v = side == Side::kLeft ? &parent_node->left : &parent_node->right;
  }
  const std::vector<OpId>::iterator at =
      std::lower_bound(v->begin(), v->end(), child);
  if (at != v->end() && *at == child) v->erase(at);
}

void TextDoc::Walk(const OpId& id, bool emit_self,
                   const std::function<void(const Node&)>& fn) const {
  // Explicit stack, not recursion: a document is user input, and a long
  // left- or right-chain -- which is exactly what typing a paragraph produces
  // -- would be a stack frame per character.
  struct Frame {
    OpId id;
    bool emit_self;
    std::size_t left_i = 0;
    std::size_t right_i = 0;
    bool emitted = false;
  };
  std::vector<Frame> stack;
  stack.push_back(Frame{id, emit_self, 0, 0, false});

  while (!stack.empty()) {
    Frame& f = stack.back();
    const std::vector<OpId>& l = ChildrenOf(f.id, Side::kLeft);
    if (f.left_i < l.size()) {
      const OpId child = l[f.left_i++];
      stack.push_back(Frame{child, true, 0, 0, false});
      continue;
    }
    if (!f.emitted) {
      f.emitted = true;
      if (f.emit_self) {
        const Node* n = Find(f.id);
        if (n != nullptr) fn(*n);
      }
    }
    const std::vector<OpId>& rr = ChildrenOf(f.id, Side::kRight);
    if (f.right_i < rr.size()) {
      const OpId child = rr[f.right_i++];
      stack.push_back(Frame{child, true, 0, 0, false});
      continue;
    }
    stack.pop_back();
  }
}

std::vector<char32_t> TextDoc::Chars() const {
  std::vector<char32_t> out;
  Walk(RootId(), false, [&out](const Node& n) {
    if (!n.deleted) out.push_back(n.value);
  });
  return out;
}

std::vector<OpId> TextDoc::VisibleIds() const {
  std::vector<OpId> out;
  Walk(RootId(), false, [&out](const Node& n) {
    if (!n.deleted) out.push_back(n.id);
  });
  return out;
}

std::string TextDoc::Text() const { return Utf8Encode(Chars()); }

std::size_t TextDoc::Length() const {
  std::size_t n = 0;
  Walk(RootId(), false, [&n](const Node& node) {
    if (!node.deleted) ++n;
  });
  return n;
}

std::size_t TextDoc::TombstoneCount() const {
  std::size_t n = 0;
  for (const std::map<OpId, Node>::value_type& kv : nodes_) {
    if (kv.second.deleted) ++n;
  }
  return n;
}

std::string TextDoc::StateHash() const {
  // Over the VISIBLE text only. Two replicas that agree on what the user sees
  // have converged, even if one still holds a tombstone the other has
  // compacted away -- which is the whole point of allowing compaction to run
  // at different times on different replicas.
  const std::string text = Text();
  const ContentHash h = HashBytes(text.data(), text.size());
  return h.ToHex();
}

bool TextDoc::AlreadyCompacted(const OpId& id) const {
  const std::map<ReplicaId, uint64_t>::const_iterator it =
      compacted_.find(id.replica);
  return it != compacted_.end() && id.counter <= it->second;
}

ApplyResult TextDoc::Apply(const Op& op) {
  // AT OR BELOW THE COMPACTION MARK IS ALREADY SEEN. See Compact in the header:
  // the nodes this operation created may have been dropped, and the mark is
  // only ever set to a point every replica had already received, so there is
  // nothing here that has not already been accounted for.
  if (AlreadyCompacted(op.id)) return ApplyResult::kDuplicate;
  switch (op.kind) {
    case OpKind::kInsert: {
      if (op.text.empty()) return ApplyResult::kMalformed;
      if (op.id.counter == 0) return ApplyResult::kMalformed;
      // Already here? A run is present or absent as a unit -- it is applied
      // atomically below -- so its first id answers for all of it.
      if (Find(op.id) != nullptr) return ApplyResult::kDuplicate;
      // The parent must exist, or this operation is ahead of its cause.
      if (!IsRoot(op.parent) && Find(op.parent) == nullptr) {
        return ApplyResult::kNotReady;
      }
      // Any id in the run already taken by something else means two different
      // operations claim one id. That is not recoverable and not ours to
      // guess at.
      for (std::size_t i = 1; i < op.text.size(); ++i) {
        if (Find(op.id.Plus(i)) != nullptr) return ApplyResult::kMalformed;
      }

      // The first character attaches where the operation says. Every
      // subsequent one is the right child of its predecessor -- the shape the
      // insert rule produces for a left-to-right run, which is why it is
      // implied rather than encoded. See text_doc.h.
      OpId prev = op.parent;
      Side prev_side = op.side;
      for (std::size_t i = 0; i < op.text.size(); ++i) {
        Node n;
        n.id = op.id.Plus(i);
        n.parent = prev;
        n.side = prev_side;
        n.value = op.text[i];
        Node* parent_node = Mutable(n.parent);
        nodes_.emplace(n.id, n);
        InsertChild(parent_node, n.id, n.side);
        prev = n.id;
        prev_side = Side::kRight;
      }
      return ApplyResult::kApplied;
    }
    case OpKind::kDelete: {
      if (op.count == 0) return ApplyResult::kMalformed;
      // Every target must be present, or already compacted away.
      //
      // A DELETE'S OWN ID IS NOT ENOUGH TO DECIDE THIS, and that is the whole
      // reason for the second clause. A delete takes its own clock tick, so its
      // id can sit far above the compaction watermark while its TARGET sits
      // below it. That happens for real: two replicas delete the same character
      // concurrently, one delete becomes everyone's and the character is
      // compacted, the other arrives afterwards from a replica whose clock had
      // run ahead -- naming a node that no longer exists anywhere.
      //
      // Skipping such a target is sound rather than convenient: the watermark
      // means every replica already had the character, so the only way it is
      // gone is that it was deleted and compacted. Deleting it again is a
      // no-op. Found at seed 39 of compact-then-edit, once the sweep was
      // widened past thirty seeds.
      for (uint32_t i = 0; i < op.count; ++i) {
        const OpId t = op.target.Plus(i);
        if (Find(t) == nullptr && !AlreadyCompacted(t)) {
          return ApplyResult::kNotReady;
        }
      }
      bool changed = false;
      for (uint32_t i = 0; i < op.count; ++i) {
        Node* n = Mutable(op.target.Plus(i));
        if (n == nullptr) continue;  // compacted; already accounted for
        if (!n->deleted) {
          n->deleted = true;
          changed = true;
        }
      }
      // Deleting an already-deleted run is a duplicate, not a no-op error:
      // deletion is idempotent and re-delivery is normal.
      return changed ? ApplyResult::kApplied : ApplyResult::kDuplicate;
    }
  }
  return ApplyResult::kMalformed;
}

bool TextDoc::LocalInsert(std::size_t index, const std::string& utf8,
                          LamportClock* clock, std::vector<Op>* out) {
  std::vector<char32_t> chars;
  if (!Utf8Decode(utf8, &chars)) return false;
  if (chars.empty()) return true;

  // THE ORIGINS ARE FOUND IN THE FULL ORDER, TOMBSTONES INCLUDED, and that is
  // not a detail. A deleted character is invisible to the user but still holds
  // a position in the tree, and the insert rule below asks about TREE
  // structure. Using the visible order instead produces a left origin whose
  // right children are all tombstones -- the rule then wants a right origin,
  // and there is none, because the tombstones that would have provided one were
  // skipped. The convergence harness aborted on exactly that.
  //
  // In the full order the situation cannot arise: a node's right subtree is
  // what immediately follows it in an in-order walk, so if the left origin has
  // right children then the next element exists by construction.
  std::vector<OpId> full;
  std::vector<bool> live;
  Walk(RootId(), false, [&](const Node& n) {
    full.push_back(n.id);
    live.push_back(!n.deleted);
  });

  // The insertion point is immediately after the `index`-th visible character:
  // the smallest cut with exactly `index` live nodes before it.
  std::size_t cut = full.size();
  std::size_t seen = 0;
  if (index == 0) {
    cut = 0;
  } else {
    for (std::size_t k = 0; k < full.size(); ++k) {
      if (live[k]) ++seen;
      if (seen == index) {
        cut = k + 1;
        break;
      }
    }
    if (seen < index) return false;  // asked for a position past the end
  }

  const OpId left = cut == 0 ? RootId() : full[cut - 1];
  const bool have_right = cut < full.size();
  const OpId right = have_right ? full[cut] : OpId();

  // THE INSERT RULE. Two lines, and the whole non-interleaving argument rests
  // on them; see text_doc.h.
  OpId parent;
  Side side;
  const std::vector<OpId>& left_rights = ChildrenOf(left, Side::kRight);
  if (left_rights.empty()) {
    parent = left;
    side = Side::kRight;
  } else {
    UMBRA_CHECK(have_right,
                "left origin has right children but there is no right origin");
    parent = right;
    side = Side::kLeft;
  }

  Op op;
  op.kind = OpKind::kInsert;
  op.id = clock->Tick(chars.size());
  op.parent = parent;
  op.side = side;
  op.text = chars;
  const ApplyResult r = Apply(op);
  UMBRA_CHECK(r == ApplyResult::kApplied,
              "a locally generated insert did not apply");
  out->push_back(op);
  return true;
}

bool TextDoc::LocalDelete(std::size_t index, std::size_t count,
                          LamportClock* clock, std::vector<Op>* out) {
  if (count == 0) return true;
  std::vector<OpId> targets;
  targets.reserve(count);
  std::size_t seen = 0;
  Walk(RootId(), false, [&](const Node& n) {
    if (n.deleted) return;
    if (seen >= index && targets.size() < count) targets.push_back(n.id);
    ++seen;
  });
  if (targets.size() != count) return false;

  // Group into maximal runs of consecutive ids from one replica. A deletion
  // that spans several insert runs becomes several operations; one that sits
  // inside a single run is one operation however long it is.
  std::size_t i = 0;
  while (i < targets.size()) {
    std::size_t j = i + 1;
    while (j < targets.size() &&
           targets[j - 1].IsSameReplicaOffset(targets[j], 1)) {
      ++j;
    }
    Op op;
    op.kind = OpKind::kDelete;
    // Its own tick, so the operation has an identity distinct from the
    // characters it removes; see op.h.
    op.id = clock->Tick(1);
    op.target = targets[i];
    op.count = static_cast<uint32_t>(j - i);
    const ApplyResult r = Apply(op);
    UMBRA_CHECK(r == ApplyResult::kApplied || r == ApplyResult::kDuplicate,
                "a locally generated delete did not apply");
    out->push_back(op);
    i = j;
  }
  return true;
}

std::size_t TextDoc::Compact(const std::map<ReplicaId, uint64_t>& watermark) {
  std::size_t removed = 0;
  // Remembered before anything is dropped, and only ever moved forward.
  for (const std::map<ReplicaId, uint64_t>::value_type& kv : watermark) {
    uint64_t& mark = compacted_[kv.first];
    if (kv.second > mark) mark = kv.second;
  }
  // Repeated passes, because removing a leaf tombstone can make its parent a
  // leaf. A chain of tombstones therefore collapses from the outside in, and
  // one call does as much as it can rather than leaving work for the next.
  bool progress = true;
  while (progress) {
    progress = false;
    std::vector<OpId> droppable;
    for (const std::map<OpId, Node>::value_type& kv : nodes_) {
      const Node& n = kv.second;
      if (!n.deleted) continue;
      if (!n.left.empty() || !n.right.empty()) continue;  // still an anchor
      const std::map<ReplicaId, uint64_t>::const_iterator w =
          watermark.find(n.id.replica);
      if (w == watermark.end()) continue;
      if (n.id.counter > w->second) continue;
      droppable.push_back(n.id);
    }
    for (const OpId& id : droppable) {
      const Node* n = Find(id);
      if (n == nullptr) continue;
      Node* parent_node = Mutable(n->parent);
      const Side side = n->side;
      RemoveChild(parent_node, id, side);
      nodes_.erase(id);
      ++removed;
      progress = true;
    }
  }
  return removed;
}

}  // namespace umbra
