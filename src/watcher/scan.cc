#include "scan.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

namespace umbra {
namespace {

// st_mtim on Linux, st_mtimespec on macOS. One #ifdef, isolated to two
// accessors, rather than sprinkled through the file.
int64_t MtimeNs(const struct stat& s) {
#if defined(__APPLE__)
  return static_cast<int64_t>(s.st_mtimespec.tv_sec) * 1000000000 +
         s.st_mtimespec.tv_nsec;
#else
  return static_cast<int64_t>(s.st_mtim.tv_sec) * 1000000000 +
         s.st_mtim.tv_nsec;
#endif
}

int64_t CtimeNs(const struct stat& s) {
#if defined(__APPLE__)
  return static_cast<int64_t>(s.st_ctimespec.tv_sec) * 1000000000 +
         s.st_ctimespec.tv_nsec;
#else
  return static_cast<int64_t>(s.st_ctim.tv_sec) * 1000000000 +
         s.st_ctim.tv_nsec;
#endif
}

ReadOutcome FromErrno(int e) {
  // ENOENT and ENOTDIR are BOTH "absent". ENOTDIR is what a child of a
  // directory that has been replaced by a file, or removed entirely, reports;
  // treating it as an IO error would turn an ordinary delete into a failure.
  if (e == ENOENT || e == ENOTDIR) return ReadOutcome::kAbsent;
  return ReadOutcome::kIoError;
}

void FillFromStat(const struct stat& s, FileState* out) {
  out->exists = true;
  out->is_dir = S_ISDIR(s.st_mode);
  out->dev = static_cast<uint64_t>(s.st_dev);
  out->ino = static_cast<uint64_t>(s.st_ino);
  out->size = static_cast<uint64_t>(s.st_size);
  out->nlink = static_cast<uint64_t>(s.st_nlink);
  out->mtime_ns = MtimeNs(s);
  out->ctime_ns = CtimeNs(s);
}

// Identity for the tear check. Deliberately excludes atime, which our own read
// changes.
bool SameIdentity(const FileState& a, const FileState& b) {
  return a.exists == b.exists && a.dev == b.dev && a.ino == b.ino &&
         a.size == b.size && a.mtime_ns == b.mtime_ns &&
         a.ctime_ns == b.ctime_ns && a.nlink == b.nlink;
}

}  // namespace

const char* ReadOutcomeName(ReadOutcome o) {
  switch (o) {
    case ReadOutcome::kOk:
      return "ok";
    case ReadOutcome::kAbsent:
      return "absent";
    case ReadOutcome::kUnstable:
      return "unstable";
    case ReadOutcome::kNotRegular:
      return "not-regular";
    case ReadOutcome::kIoError:
      return "io-error";
  }
  return "unknown";
}

std::string JoinPath(const std::string& base, const std::string& suffix) {
  if (suffix.empty()) return base;
  if (base.empty()) return suffix;
  if (base.back() == '/') return base + suffix;
  return base + "/" + suffix;
}

bool IsPathAtOrUnder(const std::string& path, const std::string& prefix) {
  // The vault root, spelled "", contains everything.
  if (prefix.empty()) return true;
  if (path.size() < prefix.size()) return false;
  if (path.compare(0, prefix.size(), prefix) != 0) return false;
  if (path.size() == prefix.size()) return true;
  // Guards the "notes" / "notes-archive" case: a prefix match is only a
  // containment when the next character is the separator.
  return path[prefix.size()] == '/';
}

bool IsVaultFile(const std::string& rel_path) {
  // Markdown only, matched case-insensitively on the extension.
  //
  // CASE-INSENSITIVE HERE IS ABOUT THE EXTENSION AND NOT ABOUT THE PATH. macOS
  // filesystems are case-INSENSITIVE by default and Linux ext4 is case-
  // SENSITIVE, so "Notes.md" and "notes.md" are one object on one platform and
  // two on the other. The watcher does not paper over that; see the leaky-
  // abstraction notes in docs/adr/0001-storage.md and the phase report.
  const std::string::size_type dot = rel_path.rfind('.');
  if (dot == std::string::npos) return false;
  std::string ext = rel_path.substr(dot);
  for (char& c : ext) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  if (ext != ".md") return false;

  // An editor's in-progress temp file is not a vault object. These are matched
  // by SHAPE and not by an editor allowlist: the shapes below are what the
  // common editors produce, and a temp file we fail to recognize is not a
  // correctness problem -- it appears, is hashed, and disappears again within
  // one debounce window, which the reconciler resolves to no event at all.
  const std::string::size_type slash = rel_path.rfind('/');
  const std::string name =
      slash == std::string::npos ? rel_path : rel_path.substr(slash + 1);
  return name.empty() || (name[0] != '.' && name[0] != '#');
}

ReadOutcome StatPath(const std::string& abs_path, FileState* out) {
  *out = FileState();
  struct stat s;
  // lstat, not stat: a symlink must be seen AS a symlink so it can be refused.
  if (::lstat(abs_path.c_str(), &s) != 0) return FromErrno(errno);
  if (!S_ISREG(s.st_mode) && !S_ISDIR(s.st_mode))
    return ReadOutcome::kNotRegular;
  FillFromStat(s, out);
  return ReadOutcome::kOk;
}

ReadOutcome ReadFileState(const std::string& abs_path, int max_attempts,
                          FileState* out) {
  if (max_attempts < 1) max_attempts = 1;
  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    FileState before;
    const ReadOutcome pre = StatPath(abs_path, &before);
    if (pre != ReadOutcome::kOk) return pre;
    if (before.is_dir) {
      *out = before;
      return ReadOutcome::kOk;  // directories have no content to hash
    }

    // O_NOFOLLOW: between the lstat above and this open, the path could have
    // been replaced by a symlink. Without it, that race reads a file outside
    // the vault.
    const int fd = ::open(abs_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
      if (errno == ELOOP) return ReadOutcome::kNotRegular;
      return FromErrno(errno);
    }

    std::vector<unsigned char> buf;
    bool io_failed = false;
    unsigned char chunk[65536];
    for (;;) {
      const ssize_t n = ::read(fd, chunk, sizeof(chunk));
      if (n == 0) break;
      if (n < 0) {
        if (errno == EINTR) continue;
        io_failed = true;
        break;
      }
      buf.insert(buf.end(), chunk, chunk + n);
    }
    ::close(fd);
    if (io_failed) return ReadOutcome::kIoError;

    FileState after;
    const ReadOutcome post = StatPath(abs_path, &after);
    if (post != ReadOutcome::kOk) return post;

    // The size recorded before the read must also match what we actually read,
    // which catches a truncate-and-rewrite that restored the original size and
    // timestamps -- rare, but free to check.
    if (SameIdentity(before, after) && after.size == buf.size()) {
      *out = after;
      out->hash = HashBytes(buf.data(), buf.size());
      return ReadOutcome::kOk;
    }
    // Otherwise: something wrote while we read. Try again.
  }
  return ReadOutcome::kUnstable;
}

void WalkSubtree(
    const std::string& abs_root, const std::string& rel_root,
    const std::function<void(const std::string&, const FileState&)>& fn) {
  // Explicit stack rather than recursion: a vault is user-supplied and a deeply
  // nested tree must not be able to overflow ours.
  std::vector<std::pair<std::string, std::string>> stack;  // (abs, rel)
  stack.emplace_back(abs_root, rel_root);

  while (!stack.empty()) {
    const std::string abs = stack.back().first;
    const std::string rel = stack.back().second;
    stack.pop_back();

    FileState st;
    if (StatPath(abs, &st) != ReadOutcome::kOk) continue;
    if (!st.is_dir) {
      fn(rel, st);
      continue;
    }
    fn(rel, st);

    DIR* d = ::opendir(abs.c_str());
    if (d == nullptr) continue;  // unreadable directory: skip, do not abort
    for (;;) {
      errno = 0;
      const struct dirent* e = ::readdir(d);
      if (e == nullptr) break;
      const char* n = e->d_name;
      if (n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0'))) {
        continue;
      }
      stack.emplace_back(JoinPath(abs, n), JoinPath(rel, n));
    }
    ::closedir(d);
  }
}

ReadOutcome RealPath(const std::string& path, std::string* out) {
  char resolved[PATH_MAX];
  if (::realpath(path.c_str(), resolved) == nullptr) return FromErrno(errno);
  out->assign(resolved);
  return ReadOutcome::kOk;
}

}  // namespace umbra
