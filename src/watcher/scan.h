// Looking at the filesystem: the only place in the watcher that calls stat(2)
// or opens a file.
//
// Everything here is SYNCHRONOUS AND OBSERVATIONAL. It answers "what is at this
// path right now", never "what changed" -- change is reconciler.h's job, and it
// is computed by comparing two answers from here rather than by trusting a
// notification. That split is what makes the watcher robust to the backends
// lying to it, which both of them do: FSEvents coalesces and can demand a
// rescan instead of naming files, and inotify drops the queue on overflow.
#ifndef UMBRA_WATCHER_SCAN_H_
#define UMBRA_WATCHER_SCAN_H_

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "umbra/change_event.h"

namespace umbra {

// What one look at a path found.
//
// dev and ino ARE THE MOVE DETECTOR. A rename preserves them on both platforms;
// an editor's write-temp-and-rename does not. That single distinction is what
// separates "the user moved a note" from "the user saved a note", which are
// otherwise the same sequence of syscalls. See reconciler.h.
struct FileState {
  bool exists = false;
  bool is_dir = false;
  uint64_t dev = 0;
  uint64_t ino = 0;
  uint64_t size = 0;
  int64_t mtime_ns = 0;
  int64_t ctime_ns = 0;
  // Hard link count. THE MOVE DETECTOR CONSULTS THIS BEFORE TRUSTING AN INODE:
  // a file with more than one name shares its inode legitimately, so an inode
  // appearing at a new path proves nothing about where it came from. See
  // reconciler.h.
  uint64_t nlink = 0;
  ContentHash hash;  // meaningful only when exists && !is_dir

  bool SameInode(const FileState& o) const {
    return exists && o.exists && dev == o.dev && ino == o.ino;
  }
};

// Why a look at a path ended the way it did.
//
// Closed; -Werror=switch applies. kAbsent and kUnstable are NORMAL RESULTS and
// not errors: the first is a file that was deleted between the notification and
// the read, which is the ordinary case for an editor's temp file, and the
// second is a file being written while we read it.
enum class ReadOutcome : uint8_t {
  kOk,
  // No such path. Includes a component of the path not existing, which is what
  // a whole directory being removed looks like from a child's point of view.
  kAbsent,
  // The file changed underneath the read, repeatedly, and no consistent
  // snapshot was obtained within the attempt budget. The caller must NOT emit
  // an event from this; it must try again later.
  kUnstable,
  // Present but neither a regular file nor a directory: a symlink, socket,
  // fifo, device. The vault holds markdown files; these are skipped rather than
  // followed. Following one would let a symlink outside the vault be read,
  // hashed and eventually synced, which is a confidentiality bug.
  kNotRegular,
  kIoError,
};

const char* ReadOutcomeName(ReadOutcome o);

// lstat only. Does not open, does not hash. Used where the caller needs
// identity and existence but not content -- directory entries during a walk,
// and the cheap half of the tear check below.
ReadOutcome StatPath(const std::string& abs_path, FileState* out);

// Stat, read, hash, and CHECK THAT NOTHING MOVED UNDER THE READ.
//
// The check: stat, read the whole file, stat again, and require
// (dev, ino, size, mtime_ns, ctime_ns) to be identical across the pair. A
// writer that appended, truncated or replaced the file during the read changes
// at least one of those, and the read is retried.
//
// THIS IS A DETECTOR, NOT A GUARANTEE, AND THE DIFFERENCE IS WORTH STATING. A
// writer that rewrote the same number of bytes within the timestamp granularity
// of the filesystem would pass the check with a torn hash. POSIX offers no way
// to read a file atomically with respect to a concurrent writer; a real
// guarantee needs a filesystem snapshot. What this buys is that the ORDINARY
// tear -- an editor still flushing when the notification arrived -- is caught
// and retried, and the pathological one is bounded by the next event on the
// same file producing a fresh hash.
//
// max_attempts must be >= 1. On kUnstable the caller should requeue the path.
ReadOutcome ReadFileState(const std::string& abs_path, int max_attempts,
                          FileState* out);

// Walk everything under abs_root, calling fn for each entry with its path
// RELATIVE to rel_prefix's root. Directories are reported before their
// children.
//
// Errors on individual entries are skipped rather than aborting the walk: a
// walk that gives up on the first unreadable directory would make one bad
// permission bit hide every change in the vault. A path that vanishes mid-walk
// is likewise skipped, because it does not exist to report on.
//
// Does not follow symlinks and does not descend into them; see kNotRegular.
void WalkSubtree(
    const std::string& abs_root, const std::string& rel_root,
    const std::function<void(const std::string& rel, const FileState& st)>& fn);

// Vault path handling. Vault-relative paths are '/'-separated with no leading
// slash and no "." component; the empty string is the vault root itself.
//
// The second parameter is `suffix` and not `rel` on purpose: callers pass a
// bare directory entry name as often as they pass a relative path, and naming
// it `rel` made clang-tidy's swapped-argument heuristic match every
// `JoinPath(dir_rel, name)` call in the inotify backend.
std::string JoinPath(const std::string& base, const std::string& suffix);

// True when `path` is `prefix` itself or lies underneath it. Used to find the
// snapshot entries a directory-level hint covers -- including the entries of a
// directory that no longer exists, which is how a moved directory's children
// are found at all.
bool IsPathAtOrUnder(const std::string& path, const std::string& prefix);

// Resolve symlinks in the vault root once, at open time.
//
// NOT COSMETIC ON macOS. FSEvents reports the REALPATH of everything it
// notifies about, and the standard temp directory on macOS is /var/folders/...,
// where /var is a symlink to /private/var. A watcher that registered
// /var/folders/x and compared incoming paths against that prefix would match
// none of them and report no changes at all -- silently, since the stream is
// running and healthy. Resolving up front makes both sides of that comparison
// the same string.
ReadOutcome RealPath(const std::string& path, std::string* out);

// True if the name is one the vault syncs. Markdown only in this phase.
bool IsVaultFile(const std::string& rel_path);

}  // namespace umbra

#endif  // UMBRA_WATCHER_SCAN_H_
