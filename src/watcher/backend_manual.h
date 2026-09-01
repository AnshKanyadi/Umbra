// A backend that reports exactly what a test tells it to.
//
// WHY THIS EXISTS RATHER THAN TESTING EVERYTHING THROUGH THE REAL ONE. The
// scenario table in test/watcher_test.cc asserts on the EVENTS A SEQUENCE OF
// FILESYSTEM OPERATIONS PRODUCES. Driven through a real backend, every row of
// that table would also be asserting that FSEvents or inotify delivered a
// notification within some timeout -- so a row could fail for a reason that has
// nothing to do with the behaviour it names, and the failure would be a
// timeout rather than a description of what went wrong.
//
// So the table performs REAL filesystem operations in a REAL temp directory --
// the reconciler stats and reads actual files, and the inode evidence it
// reasons from is the kernel's -- and supplies the hints itself, in the shape
// the platform backend would have supplied them. The platform backends are then
// covered separately by tests that assert the thing only they can be asked
// about: that a real change produces a hint at all.
//
// That split is the reason a table row is a description of behaviour rather
// than a timing experiment.
#ifndef UMBRA_WATCHER_BACKEND_MANUAL_H_
#define UMBRA_WATCHER_BACKEND_MANUAL_H_

#include <memory>
#include <mutex>
#include <string>

#include "backend.h"

namespace umbra {

class ManualBackend : public WatchBackend {
 public:
  bool Start(const std::string& abs_root, HintSink sink) override;
  void Stop() override;
  const char* Name() const override { return "manual"; }

  // Deliver a hint as the platform backend would. Safe from any thread.
  // `renamed` is what FSEvents' ItemRenamed and inotify's MOVED_FROM/MOVED_TO
  // set; see hint.h.
  void Emit(const std::string& rel_path, bool renamed = false);

  bool Running() const;

 private:
  mutable std::mutex mu_;
  HintSink sink_;
  bool running_ = false;
};

}  // namespace umbra

#endif  // UMBRA_WATCHER_BACKEND_MANUAL_H_
