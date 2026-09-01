// inotify. Compiled on every platform; inert off Linux. See the note at the top
// of backend_fsevents.cc for why both files are always in the source list.
#if defined(UMBRA_BACKEND_INOTIFY)

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "backend.h"
#include "scan.h"

namespace umbra {
namespace {

// INOTIFY IS NOT RECURSIVE AND THIS IS THE LARGEST DIFFERENCE BETWEEN THE TWO
// BACKENDS. FSEvents watches a tree from one registration; inotify watches ONE
// DIRECTORY per watch descriptor, so the whole vault has to be enumerated and
// every directory registered individually, and every directory created later
// has to be registered as it appears.
//
// THAT REGISTRATION IS INHERENTLY RACY. Between a directory being created and
// our inotify_add_watch on it, files can be created inside it and their events
// are simply not delivered -- nobody was listening. The race cannot be closed
// from userspace.
//
// It is CLOSED ANYWAY, by hinting the directory itself the moment we watch it:
// the reconciler answers a directory hint by walking the subtree and comparing
// against its snapshot, so anything that appeared during the gap is found by
// looking rather than by having been told. This is the same mechanism that
// handles queue overflow, and it is the reason the interface reports hints
// rather than events.
const uint32_t kMask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE |
                       IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_MOVE_SELF |
                       IN_DELETE_SELF | IN_EXCL_UNLINK;

class InotifyBackend : public WatchBackend {
 public:
  ~InotifyBackend() override { Stop(); }

  bool Start(const std::string& abs_root, HintSink sink) override {
    if (fd_ >= 0) return false;
    root_ = abs_root;
    sink_ = std::move(sink);

    fd_ = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd_ < 0) return false;
    if (::pipe(stop_pipe_) != 0) {
      ::close(fd_);
      fd_ = -1;
      return false;
    }
    ::fcntl(stop_pipe_[0], F_SETFL, O_NONBLOCK);

    AddWatchTree(std::string());
    if (wd_to_rel_.empty()) {  // could not even watch the root
      ::close(stop_pipe_[0]);
      ::close(stop_pipe_[1]);
      ::close(fd_);
      fd_ = -1;
      return false;
    }

    thread_ = std::thread([this] { Loop(); });
    return true;
  }

  void Stop() override {
    if (fd_ < 0) return;
    // One byte on the pipe wakes poll(). Writing rather than closing: closing
    // the read end from here would race the thread's own use of it.
    const char b = 'x';
    ssize_t ignored = ::write(stop_pipe_[1], &b, 1);
    (void)ignored;
    if (thread_.joinable()) thread_.join();

    ::close(stop_pipe_[0]);
    ::close(stop_pipe_[1]);
    ::close(fd_);
    fd_ = -1;
    wd_to_rel_.clear();
    rel_to_wd_.clear();
    sink_ = nullptr;
  }

  const char* Name() const override { return "inotify"; }

 private:
  // Registers `rel` and every directory beneath it, and hints each one so the
  // gap described above is covered by a scan.
  void AddWatchTree(const std::string& rel) {
    std::vector<std::string> dirs;
    WalkSubtree(JoinPath(root_, rel), rel,
                [&dirs](const std::string& r, const FileState& st) {
                  if (st.is_dir) dirs.push_back(r);
                });
    for (const std::string& d : dirs) AddWatch(d);
  }

  void AddWatch(const std::string& rel) {
    if (rel_to_wd_.count(rel) != 0) return;
    const int wd =
        ::inotify_add_watch(fd_, JoinPath(root_, rel).c_str(), kMask);
    // Failure is not fatal. ENOSPC here means max_user_watches is exhausted --
    // see the note in Loop() -- and ENOENT means the directory was removed
    // between the walk and now, which is ordinary.
    if (wd < 0) return;
    wd_to_rel_[wd] = rel;
    rel_to_wd_[rel] = wd;
  }

  void DropWatchTree(const std::string& rel) {
    std::vector<std::string> gone;
    for (const std::map<std::string, int>::value_type& kv : rel_to_wd_) {
      if (IsPathAtOrUnder(kv.first, rel)) gone.push_back(kv.first);
    }
    for (const std::string& r : gone) {
      const int wd = rel_to_wd_[r];
      ::inotify_rm_watch(fd_, wd);
      wd_to_rel_.erase(wd);
      rel_to_wd_.erase(r);
    }
  }

  void Loop() {
    // The buffer must hold at least one event with the longest name the
    // filesystem allows, or read() returns EINVAL forever.
    std::vector<char> buf(64 * 1024);
    for (;;) {
      struct pollfd fds[2];
      fds[0].fd = fd_;
      fds[0].events = POLLIN;
      fds[0].revents = 0;
      fds[1].fd = stop_pipe_[0];
      fds[1].events = POLLIN;
      fds[1].revents = 0;

      const int n = ::poll(fds, 2, -1);
      if (n < 0) {
        if (errno == EINTR) continue;
        return;
      }
      if ((fds[1].revents & POLLIN) != 0) return;
      if ((fds[0].revents & POLLIN) == 0) continue;

      for (;;) {
        const ssize_t len = ::read(fd_, buf.data(), buf.size());
        if (len < 0) {
          if (errno == EINTR) continue;
          break;  // EAGAIN: drained
        }
        if (len == 0) break;
        Dispatch(buf.data(), static_cast<size_t>(len));
        break;
      }
    }
  }

  void Dispatch(const char* data, size_t len) {
    size_t off = 0;
    while (off + sizeof(struct inotify_event) <= len) {
      const struct inotify_event* e =
          reinterpret_cast<const struct inotify_event*>(data + off);
      off += sizeof(struct inotify_event) + e->len;

      // THE KERNEL QUEUE OVERFLOWED and the events it dropped are gone. wd is
      // -1 here, so there is not even a directory to narrow it to. Hint the
      // vault root and let the reconciler census everything.
      if ((e->mask & IN_Q_OVERFLOW) != 0) {
        // No rename bit here, and there cannot be one: the events that carried
        // it are exactly the events the kernel threw away. See hint.h.
        sink_(Hint(std::string()));
        continue;
      }

      const std::map<int, std::string>::const_iterator it =
          wd_to_rel_.find(e->wd);
      if (it == wd_to_rel_.end()) continue;
      const std::string dir_rel = it->second;

      if ((e->mask & IN_IGNORED) != 0) {
        // The kernel has released this watch: the directory was deleted or
        // unmounted. Forget it, or the descriptor number is later reused for a
        // different directory and events are attributed to the wrong path.
        rel_to_wd_.erase(dir_rel);
        wd_to_rel_.erase(e->wd);
        continue;
      }

      // A watched directory itself moved or was deleted. The path we know it by
      // is stale, so drop the subtree's watches and hint the old location; the
      // destination arrives separately as IN_MOVED_TO in the PARENT's watch,
      // and the reconciler pairs the two by inode.
      if ((e->mask & (IN_MOVE_SELF | IN_DELETE_SELF)) != 0) {
        DropWatchTree(dir_rel);
        sink_(Hint(dir_rel, (e->mask & IN_MOVE_SELF) != 0));
        continue;
      }

      const std::string name =
          e->len > 0 ? std::string(e->name) : std::string();
      const std::string rel = name.empty() ? dir_rel : JoinPath(dir_rel, name);
      // THE RENAME BIT. Both halves of a rename carry it and each arrives as
      // its own event; the reconciler pairs them by inode. See hint.h for why
      // the cookie that would pair them here is deliberately not used.
      const bool renamed = (e->mask & (IN_MOVED_FROM | IN_MOVED_TO)) != 0;

      if ((e->mask & IN_ISDIR) != 0) {
        if ((e->mask & (IN_CREATE | IN_MOVED_TO)) != 0) {
          // Watch it, then hint it. The order does not close the race -- see
          // the comment on kMask -- the hint does.
          AddWatchTree(rel);
        } else if ((e->mask & (IN_DELETE | IN_MOVED_FROM)) != 0) {
          DropWatchTree(rel);
        }
      }
      sink_(Hint(rel, renamed));
    }
  }

  int fd_ = -1;
  int stop_pipe_[2] = {-1, -1};
  std::thread thread_;
  std::string root_;
  HintSink sink_;
  // Touched only from Start/Stop and from the backend thread, never
  // concurrently: Start populates before the thread exists and Stop joins
  // before clearing.
  std::map<int, std::string> wd_to_rel_;
  std::map<std::string, int> rel_to_wd_;
};

}  // namespace

std::unique_ptr<WatchBackend> MakePlatformBackend() {
  return std::unique_ptr<WatchBackend>(new InotifyBackend());
}

}  // namespace umbra

#else
namespace umbra {
namespace {
const int kInotifyBackendNotOnThisPlatform = 0;
}
int InotifyBackendPlatformProbe() { return kInotifyBackendNotOnThisPlatform; }
}  // namespace umbra
#endif  // UMBRA_BACKEND_INOTIFY
