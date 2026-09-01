#include "umbra/watcher.h"

#include <sys/stat.h>

#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>
#include <utility>

#include "backend.h"
#include "hint.h"
#include "object_id.h"
#include "reconciler.h"
#include "scan.h"

namespace umbra {
namespace {

using Clock = std::chrono::steady_clock;

// `final` and a non-virtual teardown; see the note on InotifyBackend in
// backend_inotify.cc for why a destructor must not call a virtual Stop().
class VaultWatcherImpl final : public VaultWatcher {
 public:
  explicit VaultWatcherImpl(const WatcherOptions& opts) : opts_(opts) {}
  ~VaultWatcherImpl() override { StopImpl(); }

  WatchStatus Init(const std::string& abs_root) {
    if (opts_.ids == nullptr) {
      owned_ids_ = MakeRandomObjectIdSource();
      ids_ = owned_ids_.get();
    } else {
      ids_ = opts_.ids;
    }

    Reconciler::Options ropts;
    ropts.abs_root = abs_root;
    ropts.max_read_attempts = opts_.max_read_attempts;
    ropts.ids = ids_;
    reconciler_.reset(new Reconciler(ropts));
    reconciler_->Prime();
    object_count_ = reconciler_->Size();

    if (opts_.backend == nullptr) {
      owned_backend_ = MakePlatformBackend();
      backend_ = owned_backend_.get();
    } else {
      backend_ = opts_.backend;
    }
    backend_name_ = backend_->Name();

    // THE WORKER IS STARTED BEFORE THE BACKEND. Starting the backend first
    // would let hints arrive with nothing to drain them; they would sit in
    // pending_ until the worker existed, which is harmless, but the reverse
    // ordering also makes Stop's teardown order the exact mirror, and a
    // start/stop pair that is not a mirror is where use-after-free lives.
    running_ = true;
    worker_ = std::thread([this] { Run(); });

    const bool ok =
        backend_->Start(abs_root, [this](const Hint& h) { OnHint(h); });
    if (!ok) {
      StopWorker();
      return WatchStatus::kBackendFailed;
    }
    return WatchStatus::kOk;
  }

  void Stop() override { StopImpl(); }

  bool WaitForIdle(std::chrono::milliseconds timeout) override {
    std::unique_lock<std::mutex> lock(mu_);
    const Clock::time_point deadline = Clock::now() + timeout;
    // Idle means: nothing waiting, nothing being worked on, and at least one
    // flush cycle has completed since the last hint arrived.
    return idle_cv_.wait_until(
        lock, deadline, [this] { return pending_.empty() && !flushing_; });
  }

  std::size_t ObjectCount() const override {
    // Read from the worker's structure, so it is taken under the same lock the
    // worker publishes it with.
    std::lock_guard<std::mutex> lock(mu_);
    return object_count_;
  }

  const char* BackendName() const override {
    return backend_name_.empty() ? "none" : backend_name_.c_str();
  }

 private:
  // Non-virtual, so the destructor can call it without dispatching on a
  // partially destroyed object.
  void StopImpl() {
    if (backend_ != nullptr) {
      // Backend first, and it does not return until its thread is joined and
      // no callback is in flight. Only then is it safe to tear down the state
      // OnHint writes into.
      backend_->Stop();
      backend_ = nullptr;
    }
    StopWorker();
  }

  void OnHint(const Hint& h) {
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (!running_) return;
      const Clock::time_point now = Clock::now();
      if (pending_.empty()) oldest_ = now;
      newest_ = now;
      // OR-ed, not overwritten. Two hints for one path inside a window -- an
      // IN_MOVED_TO followed by an IN_MODIFY, say -- must not let the plain one
      // erase the rename evidence the other carried.
      pending_[h.path] = pending_[h.path] || h.renamed;
    }
    work_cv_.notify_one();
  }

  void Run() {
    for (;;) {
      std::map<std::string, bool> batch;
      {
        std::unique_lock<std::mutex> lock(mu_);
        // Wait for work, or for shutdown.
        work_cv_.wait(lock, [this] { return !running_ || !pending_.empty(); });
        if (!running_ && pending_.empty()) return;

        // THE DEBOUNCE. Sleep until either the stream has been quiet for
        // quiet_period, or the oldest hint has waited max_delay -- whichever
        // comes first. Each new hint moves `newest_` forward and this loop
        // re-evaluates, which is what makes a burst collapse into one batch.
        for (;;) {
          if (!running_) break;
          const Clock::time_point now = Clock::now();
          const Clock::time_point quiet_at = newest_ + opts_.quiet_period;
          const Clock::time_point forced_at = oldest_ + opts_.max_delay;
          const Clock::time_point wake =
              quiet_at < forced_at ? quiet_at : forced_at;
          if (now >= wake) break;
          work_cv_.wait_until(lock, wake);
        }
        if (!running_ && pending_.empty()) return;

        batch.swap(pending_);
        flushing_ = true;
      }

      std::vector<Hint> hints;
      hints.reserve(batch.size());
      for (const std::map<std::string, bool>::value_type& kv : batch) {
        hints.emplace_back(kv.first, kv.second);
      }
      std::vector<std::string> retry;
      const std::vector<ChangeEvent> events =
          reconciler_->Reconcile(hints, &retry);

      {
        std::lock_guard<std::mutex> lock(mu_);
        object_count_ = reconciler_->Size();
        // A path that could not be read consistently goes back on the queue. It
        // is re-hinted rather than dropped: dropping it loses a change with no
        // way to notice, and the next batch's fresh read is the only thing that
        // can resolve it.
        //
        // NOT DURING SHUTDOWN, THOUGH, AND THAT GUARD IS NOT COSMETIC. Stop()
        // drains what is already queued before joining, so a file still being
        // written while the watcher is closing would be re-queued by every
        // pass, refill the queue it was just drained from, and the join would
        // never return. The change is not lost -- the next Open censuses the
        // vault and finds it -- and a Stop that hangs is worse than a hint
        // deferred to the next run.
        for (const std::string& r : retry) {
          if (!running_) break;
          if (pending_.empty()) oldest_ = Clock::now();
          newest_ = Clock::now();
          // emplace, not assignment: a retried path keeps whatever rename
          // evidence it already had and gains none, so an existing entry must
          // be left alone rather than overwritten with false.
          pending_.emplace(r, false);
        }
        flushing_ = false;
      }
      idle_cv_.notify_all();
      if (!retry.empty()) work_cv_.notify_one();

      // OUTSIDE THE LOCK. The callback is user code; running it under mu_ would
      // let a callback that touched this watcher deadlock, and would block the
      // backend's sink for as long as it ran.
      if (!events.empty() && opts_.on_change) opts_.on_change(events);
    }
  }

  void StopWorker() {
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (!running_) return;
      running_ = false;
    }
    work_cv_.notify_all();
    idle_cv_.notify_all();
    if (worker_.joinable()) worker_.join();
  }

  WatcherOptions opts_;
  std::string backend_name_;

  std::unique_ptr<ObjectIdSource> owned_ids_;
  ObjectIdSource* ids_ = nullptr;
  std::unique_ptr<WatchBackend> owned_backend_;
  WatchBackend* backend_ = nullptr;
  // Touched only by the worker thread after Init returns.
  std::unique_ptr<Reconciler> reconciler_;

  mutable std::mutex mu_;
  std::condition_variable work_cv_;
  std::condition_variable idle_cv_;
  bool running_ = false;
  bool flushing_ = false;
  // path -> whether a rename was reported for it. See hint.h.
  std::map<std::string, bool> pending_;
  Clock::time_point oldest_;
  Clock::time_point newest_;
  std::size_t object_count_ = 0;
  std::thread worker_;
};

}  // namespace

const char* WatchStatusName(WatchStatus s) {
  switch (s) {
    case WatchStatus::kOk:
      return "ok";
    case WatchStatus::kRootNotFound:
      return "root-not-found";
    case WatchStatus::kRootNotDirectory:
      return "root-not-directory";
    case WatchStatus::kBackendFailed:
      return "backend-failed";
  }
  return "unknown";
}

WatchStatus VaultWatcher::Open(const WatcherOptions& opts,
                               std::unique_ptr<VaultWatcher>* out) {
  std::string abs_root;
  if (RealPath(opts.root, &abs_root) != ReadOutcome::kOk) {
    return WatchStatus::kRootNotFound;
  }
  FileState st;
  if (StatPath(abs_root, &st) != ReadOutcome::kOk) {
    return WatchStatus::kRootNotFound;
  }
  if (!st.is_dir) return WatchStatus::kRootNotDirectory;

  std::unique_ptr<VaultWatcherImpl> w(new VaultWatcherImpl(opts));
  const WatchStatus s = w->Init(abs_root);
  if (s != WatchStatus::kOk) return s;
  *out = std::move(w);
  return WatchStatus::kOk;
}

}  // namespace umbra
