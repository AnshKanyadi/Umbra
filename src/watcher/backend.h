// The one interface the two platform watchers meet.
//
// IT IS DELIBERATELY NARROW: a backend reports a PATH and nothing else. No
// kind, no cookie, no old/new pair, no ordering promise. Everything a platform
// API offers beyond "look here" is dropped at this boundary on purpose.
//
// That is not throwing away information for the sake of symmetry. It is that
// the extra information the two APIs offer is DIFFERENT information, and
// neither is trustworthy on its own:
//
//   - inotify pairs a rename with a cookie shared by IN_MOVED_FROM and
//     IN_MOVED_TO. The pair is only delivered when BOTH ends are inside a
//     watched directory; a file moved in from outside the vault arrives as
//     IN_MOVED_TO with a cookie whose partner never comes.
//   - FSEvents has no cookie. With kFSEventStreamCreateFlagFileEvents it offers
//     ItemRenamed on both paths, in one batch or in two, with no marker saying
//     which two belong together.
//
// An interface that tried to expose "a rename" as a PAIR would therefore be
// exposing two different things under one name. So the pairing is not exposed:
// both platforms are reduced to a path plus a single boolean saying that the
// path was one end of a rename, and the reconciler recovers WHICH path it was
// paired with from the inode. See hint.h for why that boolean could not also be
// dropped, and reconciler.h for what is done with it.
#ifndef UMBRA_WATCHER_BACKEND_H_
#define UMBRA_WATCHER_BACKEND_H_

#include <functional>
#include <memory>
#include <string>

#include "hint.h"

namespace umbra {

// Called from the backend's own thread. Must be cheap and must not block: on
// Linux it runs between reads of the inotify fd, and blocking it makes the
// kernel queue overflow, which loses events.
using HintSink = std::function<void(const Hint&)>;

class WatchBackend {
 public:
  virtual ~WatchBackend() = default;

  // abs_root must already be a realpath. Returns false if the platform
  // machinery could not be established at all.
  virtual bool Start(const std::string& abs_root, HintSink sink) = 0;

  // Idempotent, and safe to call from a thread other than the one Start was
  // called on. Returns once the backend's thread has stopped and the sink is
  // guaranteed not to be called again -- the watcher destroys state the sink
  // touches immediately afterwards.
  virtual void Stop() = 0;

  virtual const char* Name() const = 0;
};

// FSEvents on macOS, inotify on Linux. Never null: CMakeLists.txt fails to
// configure on a platform with neither, so there is no third case to return
// nothing for.
std::unique_ptr<WatchBackend> MakePlatformBackend();

}  // namespace umbra

#endif  // UMBRA_WATCHER_BACKEND_H_
