// FSEvents. Compiled on every platform; inert off macOS.
//
// Both backend translation units are compiled everywhere and each is empty off
// its own platform, rather than the file list changing per platform. The point
// is that `#if` is confined to the top of two files and CMakeLists.txt names
// the same sources on both, so a build for one platform still parses the
// other's file list -- which is where an unnoticed typo would otherwise live
// until somebody built on the other OS.
#if defined(UMBRA_BACKEND_FSEVENTS)

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

#include <mutex>
#include <string>
#include <utility>

#include "backend.h"
#include "scan.h"

namespace umbra {
namespace {

// `final` and a non-virtual teardown; see the note on InotifyBackend in
// backend_inotify.cc for why a destructor must not call a virtual Stop().
class FseventsBackend final : public WatchBackend {
 public:
  ~FseventsBackend() override { StopImpl(); }

  bool Start(const std::string& abs_root, HintSink sink) override {
    std::lock_guard<std::mutex> lock(mu_);
    if (stream_ != nullptr) return false;
    root_ = abs_root;
    sink_ = std::move(sink);

    CFStringRef path = CFStringCreateWithCString(nullptr, abs_root.c_str(),
                                                 kCFStringEncodingUTF8);
    if (path == nullptr) return false;
    CFArrayRef paths = CFArrayCreate(
        nullptr,
        reinterpret_cast<const void**>(const_cast<CFStringRef*>(&path)), 1,
        &kCFTypeArrayCallBacks);
    CFRelease(path);
    if (paths == nullptr) return false;

    FSEventStreamContext ctx = {};
    ctx.info = this;

    // LATENCY IS 0.01s AND NOT SOMETHING LARGER, even though FSEvents will
    // happily coalesce for us. Coalescing has to happen in ONE place or the two
    // platforms debounce differently, and the place is VaultWatcher, which is
    // shared. What FSEvents is asked for here is prompt delivery; deciding what
    // a burst means is not its job.
    //
    // kFSEventStreamCreateFlagFileEvents: per-file paths rather than the
    // containing directory. Without it every hint would be a directory and
    // every batch would walk one.
    //
    // kFSEventStreamCreateFlagNoDefer: deliver the FIRST event of a burst
    // immediately rather than after the latency window. With it, the watcher's
    // own quiet period starts when the user's save starts.
    //
    // kFSEventStreamCreateFlagWatchRoot: report when the vault directory itself
    // is moved or replaced, which is otherwise silent.
    stream_ = FSEventStreamCreate(nullptr, &FseventsBackend::Callback, &ctx,
                                  paths, kFSEventStreamEventIdSinceNow, 0.01,
                                  kFSEventStreamCreateFlagFileEvents |
                                      kFSEventStreamCreateFlagNoDefer |
                                      kFSEventStreamCreateFlagWatchRoot);
    CFRelease(paths);
    if (stream_ == nullptr) return false;

    // A DISPATCH QUEUE AND NOT A CFRunLoop THREAD. The run-loop scheduling calls
    // are deprecated, and this project builds with -Werror; more usefully, a
    // serial queue gives an ordering guarantee and a way to FLUSH on shutdown
    // (the dispatch_sync in Stop) that a run loop would need extra signalling
    // for.
    queue_ = dispatch_queue_create("dev.umbra.fsevents", DISPATCH_QUEUE_SERIAL);
    FSEventStreamSetDispatchQueue(stream_, queue_);
    if (!FSEventStreamStart(stream_)) {
      FSEventStreamInvalidate(stream_);
      FSEventStreamRelease(stream_);
      stream_ = nullptr;
      dispatch_release(queue_);
      queue_ = nullptr;
      return false;
    }
    return true;
  }

  void Stop() override { StopImpl(); }

  const char* Name() const override { return "fsevents"; }

 private:
  void StopImpl() {
    FSEventStreamRef stream = nullptr;
    dispatch_queue_t queue = nullptr;
    {
      std::lock_guard<std::mutex> lock(mu_);
      stream = stream_;
      queue = queue_;
      stream_ = nullptr;
      queue_ = nullptr;
      sink_ = nullptr;  // a callback already in flight sees this and returns
    }
    if (stream != nullptr) {
      FSEventStreamStop(stream);
      FSEventStreamInvalidate(stream);
      FSEventStreamRelease(stream);
    }
    if (queue != nullptr) {
      // THE BARRIER THAT MAKES Stop()'s CONTRACT TRUE. Invalidate stops new
      // callbacks being scheduled but says nothing about one already running on
      // the queue. Draining the serial queue means that when this returns, no
      // callback is executing, which is what lets the watcher tear down the
      // state the sink writes into.
      //
      // dispatch_sync_f AND NOT dispatch_sync WITH A BLOCK. `^{}` is a Clang
      // extension; the function-pointer form is plain C and costs nothing here.
      // It does not make this file portable to gcc -- CoreServices.h itself uses
      // blocks in MDItem.h, so no amount of care in our own code compiles this
      // translation unit under gcc -- but it keeps the one Clang extension we
      // would have introduced ourselves out of the tree.
      dispatch_sync_f(queue, nullptr, &FseventsBackend::DrainBarrier);
      dispatch_release(queue);
    }
  }

  // Does nothing. Its only purpose is to be the last thing on the queue.
  static void DrainBarrier(void*) {}

  static void Callback(ConstFSEventStreamRef, void* info, size_t count,
                       void* event_paths, const FSEventStreamEventFlags flags[],
                       const FSEventStreamEventId[]) {
    static_cast<FseventsBackend*>(info)->Deliver(
        count, static_cast<char**>(event_paths), flags);
  }

  void Deliver(size_t count, char** paths,
               const FSEventStreamEventFlags flags[]) {
    HintSink sink;
    std::string root;
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (!sink_) return;
      sink = sink_;
      root = root_;
    }

    for (size_t i = 0; i < count; ++i) {
      const FSEventStreamEventFlags f = flags[i];

      // "I DROPPED EVENTS." Both of these mean the stream cannot tell us what
      // changed, only that something did. Hinting the vault root makes the
      // reconciler census everything, which is the only correct response and is
      // the same code path as an ordinary hint.
      if ((f & kFSEventStreamEventFlagMustScanSubDirs) != 0 ||
          (f & kFSEventStreamEventFlagUserDropped) != 0 ||
          (f & kFSEventStreamEventFlagKernelDropped) != 0 ||
          (f & kFSEventStreamEventFlagRootChanged) != 0) {
        // No rename bit: the events that carried it are the ones that were
        // dropped. See hint.h for what that costs.
        sink(Hint(std::string()));
        continue;
      }

      const bool renamed = (f & kFSEventStreamEventFlagItemRenamed) != 0;

      const std::string abs(paths[i]);
      // FSEvents reports realpaths. The root was realpath'd at Open for exactly
      // this comparison; see RealPath in scan.h for what goes wrong otherwise.
      if (abs == root) {
        sink(Hint(std::string(), renamed));
        continue;
      }
      if (abs.size() <= root.size() + 1) continue;
      if (abs.compare(0, root.size(), root) != 0) continue;
      if (abs[root.size()] != '/') continue;
      sink(Hint(abs.substr(root.size() + 1), renamed));
    }
  }

  mutable std::mutex mu_;
  FSEventStreamRef stream_ = nullptr;
  dispatch_queue_t queue_ = nullptr;
  std::string root_;
  HintSink sink_;
};

}  // namespace

std::unique_ptr<WatchBackend> MakePlatformBackend() {
  return std::unique_ptr<WatchBackend>(new FseventsBackend());
}

}  // namespace umbra

#else
namespace umbra {
// Keeps the translation unit non-empty off macOS.
namespace {
const int kFseventsBackendNotOnThisPlatform = 0;
}
int FseventsBackendPlatformProbe() { return kFseventsBackendNotOnThisPlatform; }
}  // namespace umbra
#endif  // UMBRA_BACKEND_FSEVENTS
