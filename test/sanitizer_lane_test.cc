// The sanitizer lanes assert, at compile time, that their sanitizer is on.
//
// PORTED FROM basalt's test/sanitizer_lane_test.cc, mechanism intact. It is
// ported rather than referenced because it must be compiled INTO each of this
// repo's lane binaries with that lane's flags -- it is a property of how the
// binary was built, and there is nothing to link against that could report it.
//
// The hazard it exists for: a lane found GREEN after quietly losing the only
// thing it was checking. A -fsanitize flag dropped by a CMake edit leaves
// umbra-asan building, running and passing while checking nothing at all. A
// green build does not verify a sanitizer lane; this file is what does.
//
// So the flag is not trusted; it is asserted. Each lane defines its own
// UMBRA_EXPECT_* macro, the build is probed for the sanitizer that macro names,
// and the two must agree or the lane fails to BUILD. That is stronger than any
// runtime canary, because it cannot be reached by a test that was skipped, and
// it cannot be reached by a binary that failed to run.
//
// ---------------------------------------------------------------------------
// HOW A SANITIZER IS DETECTED, AND WHY IT TAKES THREE MECHANISMS.
//
// basalt's file was clang-only until it was run under gcc, and all four of its
// lanes failed to build at once: `__has_feature` is a clang extension that gcc
// did not adopt until 14, and under gcc 13 a `#else #define HAS_FEATURE(f) 0`
// fallback made every probe answer "no sanitizer".
//
//   A FALLBACK THAT ANSWERS "NO" CANNOT TELL "ABSENT" FROM "UNDETECTABLE".
//   There it answered "no" for lanes that had the sanitizer, which is loud.
//   Reverse the polarity of one assertion -- which is exactly what the control
//   lane does -- and the same fallback is SILENT. basalt's uninstrumented lane
//   passed under gcc 13 for that reason, vacuously, unable to detect a
//   sanitizer it had accidentally acquired.
//
// So detection is per-sanitizer, and each answers from what that toolchain
// actually exposes. The three columns below were measured on this machine, not
// assumed; see docs/adr/ and the phase report for the probe.
//
//   AddressSanitizer   clang: __has_feature(address_sanitizer)
//                      gcc:   __SANITIZE_ADDRESS__          (present, gcc 16.1)
//   ThreadSanitizer    clang: __has_feature(thread_sanitizer)
//                      gcc:   __SANITIZE_THREAD__
//   UBSan              clang and gcc >= 14: __has_feature(...)
//                      gcc < 14:            NOTHING. See below.
//
// UBSAN IS THE ONE THE COMPILER WILL NOT ANSWER IN GENERAL.
// `__SANITIZE_UNDEFINED__` is ABSENT under `-fsanitize=undefined` on gcc 16.1
// -- verified directly, not inherited as a claim -- as it is on gcc 13, so it
// is not a version gap that waiting fixes. gcc >= 14 answers through
// `__has_feature` instead, and gcc 16.1 was measured doing so. gcc 13, which is
// what ubuntu-latest's `gcc` still resolves to, answers through neither. For
// that toolchain the BUILD SYSTEM is the witness, through
// UMBRA_UBSAN_FLAGS_ADDED.
//
// THAT DEFINE IS A WEAKER KIND OF EVIDENCE AND IS TREATED AS ONE. It is a claim
// by CMake rather than an observation of the compiler, so it is emitted inside
// the SAME add_compile_options() argument list as -fsanitize=undefined itself:
// dropping the flag while keeping the claim means deleting one token from the
// middle of a list whose remaining tokens are right beside it. See the UBSan
// branch in CMakeLists.txt.
//
// And where the compiler CAN see UBSan -- clang, gcc >= 14 -- the two are
// required to AGREE. That is a tripwire on the define itself: a
// UMBRA_UBSAN_FLAGS_ADDED that has drifted away from the flag fails the build,
// in either direction. gcc 13 cannot run that cross-check, which is stated here
// rather than left to be assumed.
#include <gtest/gtest.h>

#if defined(__has_feature)
#define UMBRA_HAS_FEATURE(f) __has_feature(f)
#define UMBRA_HAS_FEATURE_AVAILABLE 1
#else
// NOT a silent 0. A toolchain with neither __has_feature nor the gcc macros
// cannot be probed at all, and the lanes below must not pass by defaulting.
// This pairs with the #error further down, which is what stops the default
// from being reached quietly.
#define UMBRA_HAS_FEATURE(f) 0
#define UMBRA_HAS_FEATURE_AVAILABLE 0
#endif

#if UMBRA_HAS_FEATURE(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define UMBRA_ASAN_ON 1
#else
#define UMBRA_ASAN_ON 0
#endif

#if UMBRA_HAS_FEATURE(thread_sanitizer) || defined(__SANITIZE_THREAD__)
#define UMBRA_TSAN_ON 1
#else
#define UMBRA_TSAN_ON 0
#endif

#if defined(UMBRA_UBSAN_FLAGS_ADDED)
#define UMBRA_UBSAN_CLAIMED 1
#else
#define UMBRA_UBSAN_CLAIMED 0
#endif

#if UMBRA_HAS_FEATURE(undefined_behavior_sanitizer) || UMBRA_UBSAN_CLAIMED
#define UMBRA_UBSAN_ON 1
#else
#define UMBRA_UBSAN_ON 0
#endif

// A toolchain that exposes no probe at all is REFUSED OUTRIGHT rather than
// allowed to answer "absent" for everything. Both gcc and clang satisfy one of
// these; a third compiler that satisfies neither must be taught how to answer
// before any of its lanes mean anything. This is the line that turns the
// fallback above from a silent default into a build failure.
#if !UMBRA_HAS_FEATURE_AVAILABLE && !defined(__GNUC__)
#error "no sanitizer probe for this compiler: teach it before trusting a lane"
#endif

#if defined(UMBRA_EXPECT_ASAN)
static_assert(UMBRA_ASAN_ON,
              "umbra-asan lane was built WITHOUT AddressSanitizer");
#endif
#if defined(UMBRA_EXPECT_UBSAN)
static_assert(UMBRA_UBSAN_ON,
              "umbra-ubsan lane was built WITHOUT UndefinedBehaviorSanitizer");
#endif
#if defined(UMBRA_EXPECT_TSAN)
static_assert(UMBRA_TSAN_ON,
              "umbra-tsan lane was built WITHOUT ThreadSanitizer");
#endif

// THE DEFINE IS CHECKED AGAINST THE COMPILER WHEREVER THE COMPILER CAN ANSWER.
// This is what keeps UMBRA_UBSAN_FLAGS_ADDED honest: it fires if the define
// outlives the flag, and it fires if the flag is added without the define.
// Preprocessor, not static_assert: __has_feature and defined() are legal only
// in a preprocessor expression, and writing them in a C++ one compiles to
// something else entirely on the toolchains where it compiles at all.
#if UMBRA_HAS_FEATURE_AVAILABLE
#if UMBRA_HAS_FEATURE(undefined_behavior_sanitizer) != UMBRA_UBSAN_CLAIMED
#error \
    "UMBRA_UBSAN_FLAGS_ADDED and -fsanitize=undefined have drifted apart; they are emitted from one add_compile_options() call and must arrive together"
#endif
#endif

// The plain umbra-test lane asserts the CONVERSE: it must run with NO
// sanitizer. Without this, a build that silently sanitized everything would
// make umbra-test and umbra-asan the same lane, and the control that makes the
// other three attributable would be one of them counted twice.
#if defined(UMBRA_EXPECT_NO_SANITIZER)
static_assert(!UMBRA_ASAN_ON && !UMBRA_TSAN_ON && !UMBRA_UBSAN_ON,
              "umbra-test lane was built WITH a sanitizer; it is meant to be "
              "the uninstrumented control for the other three");
#endif

// Exactly one expectation macro must be defined, or a lane is running with no
// declared identity at all -- which is the state a new lane is in on the day
// somebody adds it to CMakeLists.txt and forgets the define.
namespace {
constexpr int kExpectationsDefined = 0
#if defined(UMBRA_EXPECT_ASAN)
                                     + 1
#endif
#if defined(UMBRA_EXPECT_UBSAN)
                                     + 1
#endif
#if defined(UMBRA_EXPECT_TSAN)
                                     + 1
#endif
#if defined(UMBRA_EXPECT_NO_SANITIZER)
                                     + 1
#endif
    ;
static_assert(kExpectationsDefined == 1,
              "exactly one UMBRA_EXPECT_* macro must be defined by the lane");
}  // namespace

TEST(SanitizerLane, DeclaresExactlyOneExpectation) {
  EXPECT_EQ(kExpectationsDefined, 1);
}
