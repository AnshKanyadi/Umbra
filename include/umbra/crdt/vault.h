// Paths to objects, and watcher events to operations.
//
// ---------------------------------------------------------------------------
// IDENTITY, DECIDED
//
// An object id is OPAQUE and is drawn from entropy. It is not derived from the
// path, not from a hash of the path, and not from anything the relay could
// guess -- docs/threat-model.md §3 puts names inside the confidentiality
// boundary, and an id derived from a name lets a relay confirm a guessed name
// by computing its id.
//
// IDENTITY NEVER DEPENDS ON PATH CASE. `Notes.md` and `notes.md` are two
// objects, always, on every platform. What differs between platforms is whether
// they can both exist:
//
//   Linux, ext4         both exist. Two objects, no ambiguity.
//   macOS, APFS default only one can. The second create arrives as a MODIFY of
//                       the first, or the rename fails outright.
//
// SO A CASE COLLISION IS DETECTED AND SURFACED, NEVER SILENTLY MERGED. When a
// path arrives whose case-folded form matches a DIFFERENT path already in the
// index, this refuses to assign an id and names both paths. Merging them would
// mean a device that can hold both files syncing them into one, and the user
// losing a file to a filesystem property they never chose.
//
// THE FOLD IS ASCII-ONLY, AND THAT IS A STATED LIMIT. `Notes.md` against
// `notes.md` is caught. `Café.md` against `café.md` is NOT: APFS folds the full
// Unicode case table and this does not, so on macOS those two collide on disk
// while this index treats them as unrelated. Doing it properly needs a case
// folding table; ASCII covers the overwhelming majority of markdown filenames
// and the gap is written down rather than papered over.
//
// ---------------------------------------------------------------------------
// A MOVE IS NOT A DELETE PLUS A CREATE
//
// The watcher already does the hard part: it reports kMoved with the object's
// existing identity rather than a delete and a create (src/watcher/reconciler.h).
// This must not undo that. A kMoved changes ONE thing -- which path the object
// is filed under -- and produces NO operations at all. The document is
// untouched, so nothing enters the oplog, nothing is sent, and no other device
// sees the note's history restart.
//
// The alternative would be visible to the user as a note losing its edit
// history because they moved it into a folder.
#ifndef UMBRA_CRDT_VAULT_H_
#define UMBRA_CRDT_VAULT_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "umbra/change_event.h"
#include "umbra/crdt/op.h"
#include "umbra/crdt/op_id.h"
#include "umbra/crdt/text_doc.h"

namespace umbra {

// Closed; -Werror=switch applies.
enum class VaultOutcome : uint8_t {
  kOk,
  // Another path already in the index folds to the same string. Both paths are
  // reported; neither is touched.
  kCaseCollision,
  // A change arrived for a path the index has never seen, where the kind
  // required it to be known (a modify or a delete of an unknown path).
  kUnknownPath,
  // The file's bytes are not valid UTF-8, so it cannot be represented as text.
  // Refused rather than mangled.
  kNotUtf8,
};

const char* VaultOutcomeName(VaultOutcome o);

struct ChangeOutcome {
  VaultOutcome status = VaultOutcome::kOk;
  ObjectId object;
  std::vector<Op> ops;
  // kCaseCollision only: the path already in the index that this one folds to.
  std::string colliding_path;
  // True when the change moved an object without touching its text. Exists so
  // a test can assert the property rather than infer it from ops.empty().
  bool was_pure_move = false;
};

// One device's view of a vault: which paths hold which objects, and the current
// document for each.
class Vault {
 public:
  explicit Vault(ReplicaId replica);
  ~Vault();

  // Turn one watcher change event into operations, applying them locally.
  // `content` is the file's bytes as they now are on disk; it is ignored for
  // kDeleted and kMoved.
  ChangeOutcome ApplyChange(const ChangeEvent& event,
                            const std::string& content);

  // Lookup and inspection.
  bool ObjectAt(const std::string& path, ObjectId* out) const;
  bool PathOf(const ObjectId& id, std::string* out) const;
  const TextDoc* Doc(const ObjectId& id) const;
  std::size_t ObjectCount() const { return by_path_.size(); }

  LamportClock* clock() { return &clock_; }

  // The ASCII fold used for collision detection. Exposed so the test can assert
  // what it does rather than restate it.
  static std::string FoldCase(const std::string& path);

 private:
  ChangeOutcome SetContent(const ObjectId& id, const std::string& content);

  LamportClock clock_;
  std::map<std::string, ObjectId> by_path_;
  std::map<std::string, std::string> by_folded_;  // folded -> exact path
  std::map<ObjectId, std::string> path_of_;
  std::map<ObjectId, TextDoc> docs_;
};

}  // namespace umbra

#endif  // UMBRA_CRDT_VAULT_H_
