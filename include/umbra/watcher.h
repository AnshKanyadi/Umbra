// The vault watcher: a directory tree of markdown files in, a stream of
// normalized change events out.
//
// WHAT IT IS RESPONSIBLE FOR
//   - noticing that the tree changed, on macOS and on Linux
//   - collapsing the several filesystem operations one user save produces into
//     ONE logical change
//   - deciding which object each change is about, including across renames and
//     moves
//   - hashing the resulting content
//
// WHAT IT IS NOT RESPONSIBLE FOR, and must not become responsible for: CRDT
// operations, encryption, key handling, the relay, or persistence. It reports
// what happened on disk. Everything downstream is a later phase, and the
// boundary is ChangeEvent.
#ifndef UMBRA_WATCHER_H_
#define UMBRA_WATCHER_H_

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "umbra/change_event.h"

namespace umbra {

// Internal. Declared, never defined here: WatcherOptions::backend exists so the
// test suite can drive the watcher with a scripted event source, and the
// definition lives under src/watcher/. Leave it null in every other caller.
class WatchBackend;
class ObjectIdSource;

// Closed; -Werror=switch applies.
enum class WatchStatus : uint8_t {
  kOk,
  kRootNotFound,
  kRootNotDirectory,
  // The platform machinery refused to start: an FSEvents stream that would not
  // schedule, or an inotify instance that could not be created. On Linux the
  // usual cause is /proc/sys/fs/inotify/max_user_instances.
  kBackendFailed,
};

const char* WatchStatusName(WatchStatus s);

struct WatcherOptions {
  // The vault. Resolved with realpath() at Open; see RealPath in
  // src/watcher/scan.h for why that is load-bearing rather than tidy.
  std::string root;

  // DEBOUNCE. One user save is several filesystem operations -- an editor
  // writes a temp file, fsyncs it, renames it over the original, and may touch
  // the containing directory -- and each one is a separate notification. These
  // two numbers are what turn that burst back into one change.
  //
  // quiet_period: flush once nothing new has been heard for this long. It is
  // the whole debounce for an ordinary save.
  //
  // max_delay: flush anyway once the OLDEST unflushed hint is this old. Without
  // it, a file being written continuously -- a long paste, a sync from another
  // tool, a log being appended -- would reset the quiet period forever and the
  // watcher would never report anything. A debounce with no upper bound is a
  // debounce that can starve.
  std::chrono::milliseconds quiet_period{40};
  std::chrono::milliseconds max_delay{400};

  // How many times to re-read a file that is changing underneath the read
  // before giving up on it for this batch and retrying in the next one.
  int max_read_attempts = 4;

  // Called from the watcher's own thread, once per flush, with at least one
  // event. NEVER called with an empty vector: a flush that resolves to no
  // change -- which is the common case for an editor's temp-file churn --
  // produces no call at all.
  //
  // It runs on the thread that would otherwise be reconciling, so a slow
  // callback delays the next batch. It does not lose events; hints accumulate
  // while it runs.
  std::function<void(const std::vector<ChangeEvent>&)> on_change;

  // Null means the platform backend. Not owned; must outlive the watcher.
  WatchBackend* backend = nullptr;

  // Null means a random source. Not owned; must outlive the watcher.
  ObjectIdSource* ids = nullptr;
};

class VaultWatcher {
 public:
  // Censuses the vault and ADOPTS what is already there without reporting it.
  // A watcher opening on an existing vault is not announcing that the user just
  // wrote every note they own.
  static WatchStatus Open(const WatcherOptions& opts,
                          std::unique_ptr<VaultWatcher>* out);

  virtual ~VaultWatcher() = default;

  // Stops the backend, joins the watcher thread, and returns. After this
  // returns the change callback will not be called again. Idempotent; the
  // destructor calls it.
  virtual void Stop() = 0;

  // Blocks until every hint received so far has been reconciled and no flush is
  // in progress, or until `timeout` elapses. Returns true if it reached that
  // state.
  //
  // FOR TESTS, and honest about what it is: it observes the watcher's own
  // bookkeeping, so it can only promise that what the watcher HAS HEARD has
  // been processed. It cannot promise the kernel has finished telling us about
  // a write that happened a moment ago -- no API on either platform offers
  // that, which is why the live-backend tests poll for an expected event rather
  // than assert once after a fixed sleep.
  virtual bool WaitForIdle(std::chrono::milliseconds timeout) = 0;

  // Number of objects currently known. Test and diagnostic surface.
  virtual std::size_t ObjectCount() const = 0;

  // The backend actually in use: "fsevents", "inotify" or "manual".
  virtual const char* BackendName() const = 0;
};

}  // namespace umbra

#endif  // UMBRA_WATCHER_H_
