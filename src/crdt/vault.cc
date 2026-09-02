#include "umbra/crdt/vault.h"

#include <algorithm>
#include <random>

#include "check.h"
#include "utf8.h"

namespace umbra {
namespace {

std::string BaseName(const std::string& path) {
  const std::string::size_type slash = path.rfind('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

ObjectId NewObjectId() {
  ObjectId id;
  std::random_device rd;
  std::uniform_int_distribution<unsigned int> dist(0, 255);
  for (std::size_t i = 0; i < id.bytes.size(); ++i) {
    id.bytes[i] = static_cast<uint8_t>(dist(rd));
  }
  return id;
}

}  // namespace

const char* VaultOutcomeName(VaultOutcome o) {
  switch (o) {
    case VaultOutcome::kOk:
      return "ok";
    case VaultOutcome::kCaseCollision:
      return "case-collision";
    case VaultOutcome::kUnknownPath:
      return "unknown-path";
    case VaultOutcome::kNotUtf8:
      return "not-utf8";
  }
  return "unknown";
}

Vault::Vault(ReplicaId replica) : clock_(replica) {}
Vault::~Vault() = default;

std::string Vault::FoldCase(const std::string& path) {
  std::string out = path;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::size_t Vault::ObjectCount() const { return tree_.Listing().size(); }

bool Vault::ObjectAt(const std::string& path, ObjectId* out) const {
  ObjectId id;
  if (!tree_.Resolve(path, &id)) return false;
  if (IsTreeRoot(id)) return false;
  *out = id;
  return true;
}

bool Vault::PathOf(const ObjectId& id, std::string* out) const {
  return tree_.PathOf(id, out);
}

const TextDoc* Vault::Doc(const ObjectId& id) const {
  const std::map<ObjectId, TextDoc>::const_iterator it = docs_.find(id);
  return it == docs_.end() ? nullptr : &it->second;
}

// A REPLICA THAT APPLIES AN OPERATION HAS SEEN IT, so the clock must move.
// Without this, a vault seeded from its own log or from a peer issues its next
// operation at counter 1 and silently overwrites what it just learned: the
// oplog is keyed by object||replica||counter, so a duplicate counter from the
// same replica is not a conflict, it is a lost write. The first end-to-end run
// lost a file exactly this way -- three tree operations were created, all at
// counter 1, and one survived.
TreeApply Vault::ApplyTreeOp(const TreeOp& op) {
  clock_.Observe(op.id);
  return tree_.Apply(op);
}

ApplyResult Vault::ApplyOp(const ObjectId& id, const Op& op) {
  // LastId, not op.id: a run insert owns a range of counters and a clock told
  // only about the first hands out the second next. op.h says so; this is the
  // second time that has been worth writing down.
  clock_.Observe(LastId(op));
  return docs_[id].Apply(op);
}

bool Vault::FoldedClash(const std::string& path, std::string* existing) const {
  const std::string folded = FoldCase(path);
  for (const std::pair<std::string, ObjectId>& kv : tree_.Listing()) {
    if (kv.first == path) continue;
    if (FoldCase(kv.first) == folded) {
      *existing = kv.first;
      return true;
    }
  }
  return false;
}

// Make sure every directory above `path` exists, creating the ones that do not.
//
// The watcher reports a file, not the directories above it: a `mkdir -p` and a
// write arrive as one create for the file, because the intermediate directories
// were never separately interesting. The tree needs them, so they are made here
// and each one is a tree operation like any other -- which is what lets another
// device merge a concurrent creation of the same folder.
bool Vault::EnsureParents(const std::string& path, ObjectId* parent,
                          std::vector<TreeOp>* ops) {
  ObjectId cur = TreeRoot();
  std::string prefix;
  std::size_t start = 0;
  while (true) {
    const std::size_t slash = path.find('/', start);
    if (slash == std::string::npos) break;
    const std::string component = path.substr(start, slash - start);
    if (component.empty()) return false;
    if (!prefix.empty()) prefix.push_back('/');
    prefix += component;

    ObjectId existing;
    if (tree_.Resolve(prefix, &existing) && !IsTreeRoot(existing)) {
      cur = existing;
    } else {
      const ObjectId dir = NewObjectId();
      const TreeOp op = tree_.MakeMove(dir, cur, component, true, &clock_);
      if (tree_.Apply(op) != TreeApply::kApplied) return false;
      ops->push_back(op);
      cur = dir;
    }
    start = slash + 1;
  }
  *parent = cur;
  return true;
}

// Replace a document's text with `content`, as the smallest edit that gets
// there.
//
// THE DIFF IS A COMMON PREFIX AND SUFFIX TRIM, and that is a deliberate floor
// rather than an attempt at a good diff. It is exactly right for the case that
// dominates -- a person typing, where one contiguous region changed -- and for
// anything else it degrades to replacing the middle, which is correct but
// larger than a real diff would produce. A proper Myers diff would emit fewer
// operations for a reordered paragraph; it would not change what the CRDT does
// with them, so it is an optimization rather than a correctness question.
ChangeOutcome Vault::SetContent(const ObjectId& id,
                                const std::string& content) {
  ChangeOutcome out;
  out.object = id;

  std::vector<char32_t> want;
  if (!Utf8Decode(content, &want)) {
    out.status = VaultOutcome::kNotUtf8;
    return out;
  }
  TextDoc& doc = docs_[id];
  const std::vector<char32_t> have = doc.Chars();

  std::size_t pre = 0;
  while (pre < have.size() && pre < want.size() && have[pre] == want[pre])
    ++pre;
  std::size_t suf = 0;
  while (suf < have.size() - pre && suf < want.size() - pre &&
         have[have.size() - 1 - suf] == want[want.size() - 1 - suf]) {
    ++suf;
  }

  const std::size_t remove = have.size() - pre - suf;
  if (remove > 0) {
    if (!doc.LocalDelete(pre, remove, &clock_, &out.ops)) {
      out.status = VaultOutcome::kUnknownPath;
      return out;
    }
  }
  const std::size_t add = want.size() - pre - suf;
  if (add > 0) {
    std::vector<char32_t> middle(want.begin() + static_cast<long>(pre),
                                 want.begin() + static_cast<long>(pre + add));
    if (!doc.LocalInsert(pre, Utf8Encode(middle), &clock_, &out.ops)) {
      out.status = VaultOutcome::kUnknownPath;
      return out;
    }
  }
  return out;
}

ChangeOutcome Vault::ApplyChange(const ChangeEvent& event,
                                 const std::string& content) {
  ChangeOutcome out;
  switch (event.kind) {
    case ChangeKind::kCreated: {
      std::string clash;
      if (FoldedClash(event.path, &clash)) {
        // SURFACED, NOT MERGED. See the note in vault.h.
        out.status = VaultOutcome::kCaseCollision;
        out.colliding_path = clash;
        return out;
      }
      ObjectId id;
      if (tree_.Resolve(event.path, &id) && !IsTreeRoot(id)) {
        // Already there; treat it as a modify of the same object.
        ChangeOutcome r = SetContent(id, content);
        return r;
      }
      ObjectId parent;
      if (!EnsureParents(event.path, &parent, &out.tree_ops)) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      const std::string name = BaseName(event.path);
      if (name.empty()) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      const ObjectId fresh = NewObjectId();
      const TreeOp op = tree_.MakeMove(fresh, parent, name, false, &clock_);
      if (tree_.Apply(op) != TreeApply::kApplied) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      out.tree_ops.push_back(op);
      docs_[fresh];
      ChangeOutcome r = SetContent(fresh, content);
      r.tree_ops = out.tree_ops;
      return r;
    }
    case ChangeKind::kModified: {
      ObjectId id;
      if (!ObjectAt(event.path, &id)) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      return SetContent(id, content);
    }
    case ChangeKind::kDeleted: {
      ObjectId id;
      if (!ObjectAt(event.path, &id)) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      out.object = id;
      // A DELETE IS A MOVE TO THE TRASH, and that is the whole of it -- no
      // separate operation kind, so a delete concurrent with a move into the
      // deleted directory is two moves ordered by timestamp rather than a
      // special case. See ADR 0003.
      std::string name;
      if (!tree_.NameOf(id, &name)) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      const TreeOp op =
          tree_.MakeMove(id, TreeTrash(), name, tree_.IsDir(id), &clock_);
      if (tree_.Apply(op) != TreeApply::kApplied) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      out.tree_ops.push_back(op);
      // THE TEXT IS LEFT ALONE. Phase 1 emptied the document on delete, which
      // was the only way a flat path map could express "gone". The tree says it
      // now, and saying it twice would mean a restore-from-trash produced an
      // empty file.
      return out;
    }
    case ChangeKind::kMoved: {
      ObjectId id;
      if (!ObjectAt(event.old_path, &id)) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      std::string clash;
      if (FoldedClash(event.path, &clash) && clash != event.old_path) {
        out.status = VaultOutcome::kCaseCollision;
        out.colliding_path = clash;
        return out;
      }
      ObjectId parent;
      if (!EnsureParents(event.path, &parent, &out.tree_ops)) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      const std::string name = BaseName(event.path);
      if (name.empty()) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      // ONE TREE OPERATION AND ZERO TEXT OPERATIONS. The object keeps its
      // identity and its document; only its place in the tree changes. This is
      // the property ADR 0002 established and ADR 0003 keeps.
      const TreeOp op =
          tree_.MakeMove(id, parent, name, tree_.IsDir(id), &clock_);
      const TreeApply r = tree_.Apply(op);
      if (r == TreeApply::kIgnoredCycle) {
        // A local move cannot make a cycle unless the user moved a directory
        // into its own descendant, which the filesystem refuses first. If it
        // happens anyway the tree is right and we are wrong; report it rather
        // than log an operation the tree ignored.
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      if (r != TreeApply::kApplied) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      out.tree_ops.push_back(op);
      out.object = id;
      out.was_pure_move = true;
      return out;
    }
  }
  out.status = VaultOutcome::kUnknownPath;
  return out;
}

}  // namespace umbra
