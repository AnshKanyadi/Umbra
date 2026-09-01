#include "umbra/crdt/vault.h"

#include <algorithm>
#include <random>

#include "check.h"
#include "utf8.h"

namespace umbra {
namespace {

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

bool Vault::ObjectAt(const std::string& path, ObjectId* out) const {
  const std::map<std::string, ObjectId>::const_iterator it =
      by_path_.find(path);
  if (it == by_path_.end()) return false;
  *out = it->second;
  return true;
}

bool Vault::PathOf(const ObjectId& id, std::string* out) const {
  const std::map<ObjectId, std::string>::const_iterator it = path_of_.find(id);
  if (it == path_of_.end()) return false;
  *out = it->second;
  return true;
}

const TextDoc* Vault::Doc(const ObjectId& id) const {
  const std::map<ObjectId, TextDoc>::const_iterator it = docs_.find(id);
  return it == docs_.end() ? nullptr : &it->second;
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
      const std::string folded = FoldCase(event.path);
      const std::map<std::string, std::string>::const_iterator clash =
          by_folded_.find(folded);
      if (clash != by_folded_.end() && clash->second != event.path) {
        // SURFACED, NOT MERGED. See the note in vault.h.
        out.status = VaultOutcome::kCaseCollision;
        out.colliding_path = clash->second;
        return out;
      }
      ObjectId id;
      if (!ObjectAt(event.path, &id)) {
        id = NewObjectId();
        by_path_[event.path] = id;
        by_folded_[folded] = event.path;
        path_of_[id] = event.path;
        docs_[id];
      }
      return SetContent(id, content);
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
      TextDoc& doc = docs_[id];
      const std::size_t n = doc.Length();
      if (n > 0) {
        if (!doc.LocalDelete(0, n, &clock_, &out.ops)) {
          out.status = VaultOutcome::kUnknownPath;
          return out;
        }
      }
      // The path stops resolving. The OBJECT is not forgotten: its document
      // and its id stay, because a delete has to be a fact other devices can
      // learn rather than an absence they have to infer. Removing the object
      // itself is a file-tree operation and belongs to the phase that owns the
      // tree.
      by_path_.erase(event.path);
      by_folded_.erase(FoldCase(event.path));
      return out;
    }
    case ChangeKind::kMoved: {
      ObjectId id;
      if (!ObjectAt(event.old_path, &id)) {
        out.status = VaultOutcome::kUnknownPath;
        return out;
      }
      const std::string folded = FoldCase(event.path);
      const std::map<std::string, std::string>::const_iterator clash =
          by_folded_.find(folded);
      if (clash != by_folded_.end() && clash->second != event.old_path &&
          clash->second != event.path) {
        out.status = VaultOutcome::kCaseCollision;
        out.colliding_path = clash->second;
        return out;
      }
      // A MOVE PRODUCES NO OPERATIONS. The object keeps its identity and its
      // document; only the path it is filed under changes. See vault.h.
      by_path_.erase(event.old_path);
      by_folded_.erase(FoldCase(event.old_path));
      by_path_[event.path] = id;
      by_folded_[folded] = event.path;
      path_of_[id] = event.path;
      out.object = id;
      out.was_pure_move = true;
      return out;
    }
  }
  out.status = VaultOutcome::kUnknownPath;
  return out;
}

}  // namespace umbra
