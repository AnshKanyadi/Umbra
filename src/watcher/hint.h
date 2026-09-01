// What a backend reports, and the one piece of platform knowledge that could
// not be reduced to "look at this path".
#ifndef UMBRA_WATCHER_HINT_H_
#define UMBRA_WATCHER_HINT_H_

#include <string>

namespace umbra {

struct Hint {
  // Vault-relative. The empty string means the vault root, which is how "I lost
  // events, rescan everything" is spelled.
  std::string path;

  // THE PLATFORM SAID THIS PATH WAS ONE END OF A RENAME.
  //
  // This bit exists because it had to. The reconciler decides that two paths
  // are the same object by comparing inode numbers, and on Linux THAT IS NOT
  // SUFFICIENT EVIDENCE: a file created immediately after another is deleted
  // gets the same inode number, and -- measured on overlayfs, 198 times out of
  // 200 -- the same nanosecond mtime as well, because the filesystem's
  // timestamp granularity is coarser than the two operations. Two consecutive
  // writes to one file were observed with a delta of ZERO nanoseconds.
  //
  // So an unrelated delete-and-create is INDISTINGUISHABLE from a rename by
  // stat(2) alone on that platform. Nothing about inode numbers, sizes,
  // timestamps or content separates them; the information simply is not in the
  // filesystem. It IS in the notification, and both platforms carry it:
  //
  //   inotify   IN_MOVED_FROM / IN_MOVED_TO / IN_MOVE_SELF
  //   FSEvents  kFSEventStreamEventFlagItemRenamed
  //
  // This is the ONE thing the hint interface carries beyond a path, and it is
  // carried as a BOOLEAN rather than as inotify's rename cookie or FSEvents'
  // old/new pairing. A boolean is what both platforms can honestly supply: the
  // cookie exists only on Linux, only when both ends are inside a watched
  // directory, and FSEvents has no equivalent. The pairing itself is still done
  // by inode, and this bit only says the pairing is ALLOWED to be attempted.
  //
  // WHAT IT COSTS WHEN IT IS ABSENT, stated rather than hidden: after a dropped
  // queue -- IN_Q_OVERFLOW, or FSEvents' MustScanSubDirs -- there is no
  // notification left to carry the bit, so a move that happened during the gap
  // is reported as a delete plus a create. Content survives; the object's
  // identity does not. That is the conservative direction: refusing to infer a
  // move never merges two unrelated objects' histories, and inferring one
  // wrongly does.
  bool renamed = false;

  Hint() = default;
  explicit Hint(std::string p, bool r = false)
      : path(std::move(p)), renamed(r) {}
};

}  // namespace umbra

#endif  // UMBRA_WATCHER_HINT_H_
