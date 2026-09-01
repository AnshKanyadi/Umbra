#include "backend_manual.h"

#include <utility>

namespace umbra {

bool ManualBackend::Start(const std::string& abs_root, HintSink sink) {
  (void)abs_root;
  std::lock_guard<std::mutex> lock(mu_);
  sink_ = std::move(sink);
  running_ = true;
  return true;
}

void ManualBackend::Stop() {
  std::lock_guard<std::mutex> lock(mu_);
  running_ = false;
  sink_ = nullptr;
}

void ManualBackend::Emit(const std::string& rel_path, bool renamed) {
  // The sink is copied out and called with the lock RELEASED. Calling it under
  // the lock would let a sink that emits again deadlock, and the watcher's sink
  // takes its own lock -- two locks in an order this class cannot see.
  HintSink sink;
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (!running_) return;
    sink = sink_;
  }
  if (sink) sink(Hint(rel_path, renamed));
}

bool ManualBackend::Running() const {
  std::lock_guard<std::mutex> lock(mu_);
  return running_;
}

}  // namespace umbra
