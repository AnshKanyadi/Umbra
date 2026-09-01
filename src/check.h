// Aborting on a violated invariant.
//
// This project builds -fno-exceptions and returns failure by value. That covers
// everything a CALLER could act on. It does not cover the other kind of
// failure: an invariant this code is responsible for maintaining has been
// found broken, and there is no correct way to continue.
//
// Those abort, loudly, with the file and line. A sync engine that carries on
// past a broken invariant writes the consequences into the user's notes and
// into every device it talks to, and the damage is not undone by noticing
// later.
#ifndef UMBRA_CHECK_H_
#define UMBRA_CHECK_H_

#include <cstdio>
#include <cstdlib>

namespace umbra {
namespace internal {

// Not inline-able away and not returning: the compiler is told this ends the
// program so the call sites need no unreachable-path handling.
[[noreturn]] inline void Die(const char* file, int line, const char* what) {
  // The (void) casts are the deliberate, greppable form of ignoring a return
  // value, and cert-err33-c is right to want them here even though nothing
  // could be done with either result: the process is about to abort, and a
  // failed write to stderr does not change that. Silencing the check by
  // disabling it would also silence it everywhere it matters.
  (void)std::fprintf(stderr, "umbra: fatal at %s:%d: %s\n", file, line, what);
  (void)std::fflush(stderr);
  std::abort();
}

}  // namespace internal
}  // namespace umbra

// UMBRA_CHECK is COMPILED IN EVERY BUILD, including release. It is not assert:
// assert disappears under NDEBUG, and an invariant worth stating is worth
// checking in the configuration users actually run. Where a check is too
// expensive for that, it belongs in a test, not behind NDEBUG.
#define UMBRA_CHECK(cond, what)                           \
  do {                                                    \
    if (!(cond)) {                                        \
      ::umbra::internal::Die(__FILE__, __LINE__, (what)); \
    }                                                     \
  } while (0)

#define UMBRA_DIE(what) ::umbra::internal::Die(__FILE__, __LINE__, (what))

#endif  // UMBRA_CHECK_H_
