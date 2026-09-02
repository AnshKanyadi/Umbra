#include "umbra/crdt/tree.h"

#include <algorithm>
#include <cstring>

#include "check.h"

namespace umbra {
namespace {

ObjectId Reserved(uint8_t tag) {
  ObjectId id;
  // All zero but for the last byte. A random 128-bit object id colliding with
  // one of these is not a risk worth engineering against, and the alternative
  // -- a separate "is reserved" flag on every node -- would be a second source
  // of truth.
  id.bytes[15] = tag;
  return id;
}

void PutU8(uint8_t v, std::string* out) {
  out->push_back(static_cast<char>(v));
}

void PutU32(uint32_t v, std::string* out) {
  for (int i = 0; i < 4; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
}

void PutU64(uint64_t v, std::string* out) {
  for (int i = 0; i < 8; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
}

void PutOpId(const OpId& id, std::string* out) {
  PutU64(id.counter, out);
  out->append(reinterpret_cast<const char*>(id.replica.bytes.data()),
              id.replica.bytes.size());
}

void PutObjectId(const ObjectId& id, std::string* out) {
  out->append(reinterpret_cast<const char*>(id.bytes.data()), id.bytes.size());
}

struct Reader {
  const std::string* s;
  std::size_t pos = 0;
  bool Need(std::size_t n) const { return pos + n <= s->size(); }
  bool U8(uint8_t* v) {
    if (!Need(1)) return false;
    *v = static_cast<uint8_t>((*s)[pos++]);
    return true;
  }
  bool U32(uint32_t* v) {
    if (!Need(4)) return false;
    *v = 0;
    for (int i = 0; i < 4; ++i) {
      *v |= static_cast<uint32_t>(static_cast<unsigned char>((*s)[pos + i]))
            << (8 * i);
    }
    pos += 4;
    return true;
  }
  bool U64(uint64_t* v) {
    if (!Need(8)) return false;
    *v = 0;
    for (int i = 0; i < 8; ++i) {
      *v |= static_cast<uint64_t>(static_cast<unsigned char>((*s)[pos + i]))
            << (8 * i);
    }
    pos += 8;
    return true;
  }
  bool Id(OpId* id) {
    if (!U64(&id->counter)) return false;
    if (!Need(id->replica.bytes.size())) return false;
    std::memcpy(id->replica.bytes.data(), s->data() + pos,
                id->replica.bytes.size());
    pos += id->replica.bytes.size();
    return true;
  }
  bool Obj(ObjectId* id) {
    if (!Need(id->bytes.size())) return false;
    std::memcpy(id->bytes.data(), s->data() + pos, id->bytes.size());
    pos += id->bytes.size();
    return true;
  }
};

// A name is one path component, so a separator in it would make the tree and
// the filesystem disagree about the shape of the vault.
bool NameIsLegal(const std::string& name) {
  if (name.empty()) return false;
  if (name == "." || name == "..") return false;
  return name.find('/') == std::string::npos;
}

}  // namespace

ObjectId TreeRoot() { return Reserved(0); }
ObjectId TreeTrash() { return Reserved(1); }
ObjectId TreeObject() { return Reserved(2); }

bool IsTreeRoot(const ObjectId& id) { return id == TreeRoot(); }
bool IsTreeTrash(const ObjectId& id) { return id == TreeTrash(); }

const char* TreeApplyName(TreeApply a) {
  switch (a) {
    case TreeApply::kApplied:
      return "applied";
    case TreeApply::kDuplicate:
      return "duplicate";
    case TreeApply::kIgnoredCycle:
      return "ignored-cycle";
    case TreeApply::kMalformed:
      return "malformed";
  }
  return "unknown";
}

std::string TreeOp::ToString() const {
  return "move " + id.ToString() + " child=" + child.ToHex().substr(0, 8) +
         " -> parent=" + parent.ToHex().substr(0, 8) + " name=\"" + name +
         "\"" + (is_dir ? " dir" : "");
}

TreeDoc::TreeDoc() = default;

bool TreeDoc::Exists(const ObjectId& id) const {
  return nodes_.find(id) != nodes_.end();
}

bool TreeDoc::ParentOf(const ObjectId& id, ObjectId* out) const {
  const std::map<ObjectId, Entry>::const_iterator it = nodes_.find(id);
  if (it == nodes_.end()) return false;
  *out = it->second.parent;
  return true;
}

bool TreeDoc::NameOf(const ObjectId& id, std::string* out) const {
  const std::map<ObjectId, Entry>::const_iterator it = nodes_.find(id);
  if (it == nodes_.end()) return false;
  *out = it->second.name;
  return true;
}

bool TreeDoc::IsDir(const ObjectId& id) const {
  const std::map<ObjectId, Entry>::const_iterator it = nodes_.find(id);
  return it != nodes_.end() && it->second.is_dir;
}

bool TreeDoc::WouldCycle(const ObjectId& child, const ObjectId& parent) const {
  if (child == parent) return true;
  // Walk up from the prospective parent. If the child is on that path, the move
  // would put the child under itself.
  //
  // BOUNDED BY THE NODE COUNT, and the bound is an assertion rather than a
  // safety net: the tree is acyclic by this very check, so exceeding it means
  // the invariant is already broken and continuing would hang.
  ObjectId cur = parent;
  std::size_t steps = 0;
  while (!IsTreeRoot(cur) && !IsTreeTrash(cur)) {
    if (cur == child) return true;
    const std::map<ObjectId, Entry>::const_iterator it = nodes_.find(cur);
    if (it == nodes_.end()) return false;  // detached; no path to the child
    cur = it->second.parent;
    ++steps;
    UMBRA_CHECK(steps <= nodes_.size() + 2,
                "tree has a cycle; the move check that prevents them failed");
  }
  return false;
}

void TreeDoc::DoOp(const TreeOp& op, LogMove* record) {
  record->op = op;
  const std::map<ObjectId, Entry>::iterator it = nodes_.find(op.child);
  record->had_old = it != nodes_.end();
  if (record->had_old) record->old_entry = it->second;

  // THE CYCLE CHECK. An operation that would make a node its own ancestor is
  // ignored outright -- see the note at the top of tree.h. It is still recorded
  // so that a later undo/redo pass, which may reach it with a different tree,
  // can reconsider it.
  if (WouldCycle(op.child, op.parent)) {
    record->ignored = true;
    return;
  }
  record->ignored = false;

  Entry e;
  e.parent = op.parent;
  e.name = op.name;
  e.is_dir = op.is_dir;
  nodes_[op.child] = e;
}

void TreeDoc::UndoOp(const LogMove& record) {
  if (record.ignored)
    return;  // it changed nothing, so there is nothing to undo
  if (record.had_old) {
    nodes_[record.op.child] = record.old_entry;
  } else {
    nodes_.erase(record.op.child);
  }
}

TreeApply TreeDoc::Apply(const TreeOp& op) {
  if (IsTreeRoot(op.child) || IsTreeTrash(op.child)) {
    return TreeApply::kMalformed;  // the fixed points do not move
  }
  if (op.child == op.parent) return TreeApply::kMalformed;
  if (!NameIsLegal(op.name)) return TreeApply::kMalformed;
  if (log_.find(op.id) != log_.end()) return TreeApply::kDuplicate;

  // UNDO EVERYTHING NEWER, DO, REDO. This is the whole algorithm; see tree.h.
  // The undone set is the tail of the log after op.id, which the map gives as
  // a range.
  std::vector<LogMove> newer;
  std::map<OpId, LogMove>::iterator first = log_.upper_bound(op.id);
  for (std::map<OpId, LogMove>::iterator it = first; it != log_.end(); ++it) {
    newer.push_back(it->second);
  }
  for (std::vector<LogMove>::reverse_iterator it = newer.rbegin();
       it != newer.rend(); ++it) {
    UndoOp(*it);
  }
  log_.erase(first, log_.end());

  LogMove record;
  DoOp(op, &record);
  const bool ignored = record.ignored;
  log_[op.id] = record;

  // Redo in timestamp order. Each one runs its own cycle check again, against
  // the tree as it now is -- which is why an operation ignored once may apply
  // later, and why the log keeps ignored operations.
  for (const LogMove& old : newer) {
    LogMove redone;
    DoOp(old.op, &redone);
    log_[old.op.id] = redone;
  }
  return ignored ? TreeApply::kIgnoredCycle : TreeApply::kApplied;
}

TreeOp TreeDoc::MakeMove(const ObjectId& child, const ObjectId& parent,
                         const std::string& name, bool is_dir,
                         LamportClock* clock) const {
  TreeOp op;
  op.id = clock->Tick(1);
  op.child = child;
  op.parent = parent;
  op.name = name;
  op.is_dir = is_dir;
  return op;
}

bool TreeDoc::IsDeleted(const ObjectId& id) const {
  ObjectId cur = id;
  std::size_t steps = 0;
  while (true) {
    if (IsTreeTrash(cur)) return true;
    if (IsTreeRoot(cur)) return false;
    const std::map<ObjectId, Entry>::const_iterator it = nodes_.find(cur);
    if (it == nodes_.end()) return false;  // detached, not deleted
    cur = it->second.parent;
    ++steps;
    UMBRA_CHECK(steps <= nodes_.size() + 2, "tree has a cycle");
  }
}

bool TreeDoc::PathOf(const ObjectId& id, std::string* out) const {
  if (IsTreeRoot(id)) {
    out->clear();
    return true;
  }
  std::vector<std::string> parts;
  ObjectId cur = id;
  std::size_t steps = 0;
  while (!IsTreeRoot(cur)) {
    if (IsTreeTrash(cur)) return false;  // deleted
    const std::map<ObjectId, Entry>::const_iterator it = nodes_.find(cur);
    if (it == nodes_.end()) return false;  // detached from the root
    parts.push_back(it->second.name);
    cur = it->second.parent;
    ++steps;
    UMBRA_CHECK(steps <= nodes_.size() + 2, "tree has a cycle");
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

bool TreeDoc::Resolve(const std::string& path, ObjectId* out) const {
  if (path.empty()) {
    *out = TreeRoot();
    return true;
  }
  for (const std::map<ObjectId, Entry>::value_type& kv : nodes_) {
    std::string p;
    if (!PathOf(kv.first, &p)) continue;
    if (p == path) {
      *out = kv.first;
      return true;
    }
  }
  return false;
}

std::vector<ObjectId> TreeDoc::Children(const ObjectId& parent) const {
  std::vector<ObjectId> out;
  for (const std::map<ObjectId, Entry>::value_type& kv : nodes_) {
    if (kv.second.parent == parent) out.push_back(kv.first);
  }
  return out;
}

std::vector<std::pair<std::string, ObjectId>> TreeDoc::Listing() const {
  std::vector<std::pair<std::string, ObjectId>> out;
  for (const std::map<ObjectId, Entry>::value_type& kv : nodes_) {
    std::string p;
    if (!PathOf(kv.first, &p)) continue;
    out.emplace_back(p, kv.first);
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::string TreeDoc::StateHash() const {
  // Over the VISIBLE tree only: which live paths exist and what is at each.
  // Nodes in the trash and nodes detached from the root are excluded, because
  // two replicas that agree on what the user can see have converged.
  std::string acc;
  for (const std::pair<std::string, ObjectId>& kv : Listing()) {
    acc += kv.first;
    acc.push_back('\0');
    acc += kv.second.ToHex();
    acc.push_back(IsDir(kv.second) ? 'd' : 'f');
    acc.push_back('\n');
  }
  return HashBytes(acc.data(), acc.size()).ToHex();
}

OpPayload EncodeTreeOp(const TreeOp& op) {
  OpPayload p;
  std::string& out = p.bytes;
  PutU8(kTreeOpEncodingVersion, &out);
  PutOpId(op.id, &out);
  PutObjectId(op.child, &out);
  PutObjectId(op.parent, &out);
  PutU8(op.is_dir ? 1 : 0, &out);
  PutU32(static_cast<uint32_t>(op.name.size()), &out);
  out += op.name;
  return p;
}

bool DecodeTreeOp(const OpPayload& payload, TreeOp* out) {
  Reader r{&payload.bytes, 0};
  uint8_t version = 0;
  if (!r.U8(&version)) return false;
  if (version != kTreeOpEncodingVersion) return false;
  *out = TreeOp();
  if (!r.Id(&out->id)) return false;
  if (out->id.counter == 0) return false;
  if (!r.Obj(&out->child)) return false;
  if (!r.Obj(&out->parent)) return false;
  uint8_t dir = 0;
  if (!r.U8(&dir)) return false;
  if (dir > 1) return false;
  out->is_dir = dir == 1;
  uint32_t n = 0;
  if (!r.U32(&n)) return false;
  if (!r.Need(n)) return false;
  out->name.assign(payload.bytes, r.pos, n);
  r.pos += n;
  if (!NameIsLegal(out->name)) return false;
  return r.pos == payload.bytes.size();
}

}  // namespace umbra
