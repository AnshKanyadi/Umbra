// Turning "something near these paths changed" into "these objects changed".
//
// THE RECONCILER NEVER TRUSTS AN EVENT. It receives HINTS -- vault-relative
// paths that a backend thinks are interesting -- and answers by looking at the
// filesystem and comparing what it finds against what it last knew. A hint that
// turns out to be wrong costs a stat; a hint that never arrives is the only
// thing that can hide a change, which is why both backends are driven so that
// their failure mode is an EXTRA hint rather than a missing one.
//
// That design is not defensive dressing. It is forced by the backends:
//
//   - FSEvents coalesces, and can report kFSEventStreamEventFlagMustScanSubDirs
//     instead of naming any file at all, meaning "I dropped events, go look".
//   - inotify drops its entire queue on IN_Q_OVERFLOW and tells you only that
//     it happened.
//
// A watcher that treated notifications as facts would have to special-case both
// of those. One that treats them as hints already handles them: the overflow
// path is a hint for the vault root, and the ordinary path is a hint for one
// file. Same code.
//
// ---------------------------------------------------------------------------
// HOW IDENTITY IS DECIDED, WHICH IS THE WHOLE PROBLEM.
//
// Two requirements point in opposite directions:
//
//   1. Moving `a/note.md` to `b/note.md` must PRESERVE the object. The user
//      reorganized; they did not delete a note and write a new one.
//   2. Saving `note.md` in almost any editor writes a temp file and renames it
//      over the original. At the syscall level the original file is UNLINKED
//      and a DIFFERENT INODE takes its place -- so inode identity says the
//      object was destroyed, and path identity says nothing happened.
//
// Neither inode-as-identity nor path-as-identity satisfies both. So:
//
//   PATH IS THE IDENTITY OF A VAULT OBJECT. INODE IS THE EVIDENCE USED TO
//   DECIDE WHETHER TWO PATHS ARE THE SAME OBJECT.
//
// Concretely, over a whole debounce batch, each affected path is classified by
// what happened to the inode sitting at it:
//
//   VACANCY  the inode that was at this path is no longer at this path
//            (deleted, or replaced by a different inode)
//   ARRIVAL  an inode is at this path that was not here before
//
// A path can be both -- that is exactly what an atomic save looks like. Then:
//
//   - An ARRIVAL at P and a VACANCY at Q (P != Q) carrying THE SAME inode is a
//     MOVE. The object keeps its ID. This is requirement 1, and it covers a
//     rename within a directory and a move across directories identically,
//     because at this level they are the same thing.
//   - A path left holding BOTH its own vacancy and its own arrival is a
//     MODIFY. This is requirement 2.
//   - A leftover vacancy is a DELETE; a leftover arrival is a CREATE.
//
// WHAT THIS DELIBERATELY CANNOT DISTINGUISH, stated because it is a real limit
// and not an oversight: a DELETE FOLLOWED BY A CREATE AT THE SAME PATH inside
// one debounce window is reported as a MODIFY. It is not that the reconciler
// gives up -- it is that the two are the same sequence of syscalls. An atomic
// save IS a delete followed by a create at the same path. Any rule that split
// them would split ordinary saves too, and the sync engine would replace a
// file's history on every keystroke-triggered autosave. Reporting a modify is
// the correct answer to both, and a consumer that needs to know the content
// changed has the hash to compare.
//
// THE INODE NUMBER ALONE IS NOT ENOUGH EVIDENCE, and finding that out is the
// reason Hint carries a `renamed` flag.
//
//   - INODE REUSE. Linux hands a freshly deleted file's inode number to a file
//     created immediately afterwards, and gives it the same mtime too. MEASURED
//     on overlayfs, not assumed: 198 of 200 delete-and-create pairs shared BOTH
//     the inode number and the exact nanosecond mtime, and two consecutive
//     writes to one file were seen with a timestamp delta of zero. macOS/APFS
//     recycles far less eagerly, so this was invisible there and the same code
//     reported an unrelated delete-and-create as a MOVE on Linux -- grafting
//     one note's identity onto another's.
//
//     mtime and size were tried as corroborating evidence first and are NOT
//     sufficient: the measurement above is exactly the case they fail on. The
//     information needed is not in the filesystem at all. It is in the
//     notification, so a move additionally requires that at least one of the
//     two paths was reported by the platform as part of a rename. See hint.h.
//   - HARD LINKS. Two paths legitimately share an inode, so an inode turning up
//     at a new name proves nothing -- it never left the old one. Ambiguity is
//     REFUSED rather than guessed, on two independent grounds: an inode with
//     more than one arrival or more than one vacancy in a batch is not paired,
//     and neither is one whose st_nlink exceeds 1 on either side. The paths
//     fall through to create and delete, which is what actually happened.
#ifndef UMBRA_WATCHER_RECONCILER_H_
#define UMBRA_WATCHER_RECONCILER_H_

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "hint.h"
#include "object_id.h"
#include "scan.h"
#include "umbra/change_event.h"

namespace umbra {

class Reconciler {
 public:
  struct Options {
    // Already passed through RealPath by the caller. The reconciler compares
    // this against paths coming out of a backend and must not be the place that
    // discovers they were spelled differently.
    std::string abs_root;

    // Attempts to get a torn-free read of one file before giving up on it for
    // this batch. See ReadFileState.
    int max_read_attempts = 4;

    // Not owned; must outlive the reconciler.
    ObjectIdSource* ids = nullptr;
  };

  explicit Reconciler(Options opts);

  // Census the whole vault and adopt what is there WITHOUT emitting anything.
  // A watcher opening on an existing vault is not reporting that the user just
  // created every note they own. Returns the number of objects adopted.
  std::size_t Prime();

  // Resolve a batch of hints.
  //
  // Duplicates and non-existent paths are fine and are the normal case. A hint
  // naming a directory is expanded over that directory's subtree AND over the
  // snapshot entries underneath it, which is what makes a moved directory's
  // children resolvable -- the children generate no events of their own on
  // either platform. AN EXPANDED PATH INHERITS ITS HINT'S `renamed` FLAG, which
  // is what lets a renamed directory's children be recognized as moves: the
  // rename was reported for the directory, never for them.
  //
  // Paths that could not be read consistently are appended to `retry` and
  // produce NO event this batch. The caller must feed them back in later;
  // dropping them loses a change.
  std::vector<ChangeEvent> Reconcile(const std::vector<Hint>& hints,
                                     std::vector<std::string>* retry);

  // Inspection, for tests and for the report.
  bool Lookup(const std::string& rel, ObjectId* id) const;
  std::size_t Size() const { return snap_.size(); }

 private:
  struct Entry {
    FileState st;
    ObjectId id;
  };

  // Ordered, deliberately: a directory hint is answered with a range query over
  // the paths underneath it, and the ordering also makes the emitted event
  // sequence deterministic, which is what lets the scenario table assert on it.
  using Snapshot = std::map<std::string, Entry>;

  // Adds the hint and everything it covers to `universe`, mapping each path to
  // whether a rename was reported for it. Existing entries are OR-ed, so a path
  // named by both a rename hint and a plain one keeps the rename.
  void ExpandHint(const Hint& h, std::map<std::string, bool>* universe) const;

  Options opts_;
  Snapshot snap_;
};

}  // namespace umbra

#endif  // UMBRA_WATCHER_RECONCILER_H_
