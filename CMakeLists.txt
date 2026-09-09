# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ansh Kanyadi
#
# umbra -- a self-hostable end-to-end-encrypted sync engine for folders of
# markdown files.
#
# NO NETWORK AT BUILD TIME. There is no FetchContent, no ExternalProject and no
# download step, and there must never be one: a build step that reaches the
# network fails in exactly the situation where "it builds from a clean clone"
# matters most, which is a stranger checking our work. The two dependencies are
# both already on disk by the time cmake runs:
#
#   third_party/basalt      a git SUBMODULE, pinned to a commit.
#                           `git submodule update --init` is a CHECKOUT step,
#                           not a build step; it happens before this file runs
#                           and its failure is legible.
#   third_party/googletest  a VENDORED TREE, upstream's v1.17.0 unmodified.
#                           See its VERSION file for the pin and for why it is a
#                           separate copy from basalt's rather than a reach
#                           through the submodule.
#   third_party/libsodium   a VENDORED TREE, upstream's 1.0.22 unmodified.
#                           It ships autotools and no CMake, so its build
#                           description is third_party/libsodium.cmake -- OUTSIDE
#                           the tree, so that `configure` never runs and the tree
#                           never changes. See both files.
cmake_minimum_required(VERSION 3.16)
project(umbra CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(UMBRA_IS_TOP_LEVEL ON)
else()
  set(UMBRA_IS_TOP_LEVEL OFF)
endif()
option(UMBRA_BUILD_TESTS "Build the test suite" ${UMBRA_IS_TOP_LEVEL})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# THE SUBMODULE IS CHECKED FOR HERE so the failure is one sentence rather than a
# missing-file error from inside a subdirectory nobody expected to be empty. A
# fresh `git clone` without `--recursive` leaves that directory present and
# EMPTY, which add_subdirectory reports in terms of CMakeLists.txt rather than
# in terms of the submodule.
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/basalt/CMakeLists.txt")
  message(FATAL_ERROR
          "third_party/basalt is empty. It is a git submodule and this build "
          "does not fetch it:\n"
          "    git submodule update --init --recursive")
endif()

# ------------------------------------------------------------------- lanes
#
# One build directory per lane, one sanitizer per build directory. The lanes are
# not variations on a theme: the uninstrumented lane is the CONTROL that makes
# the other three mean something, which is why it asserts it has NO sanitizer
# just as firmly as they assert they have one (test/sanitizer_lane_test.cc).
set(UMBRA_SANITIZER "none" CACHE STRING "none | address | undefined | thread")
set_property(CACHE UMBRA_SANITIZER PROPERTY STRINGS none address undefined thread)

# Sanitizer flags are set GLOBALLY, and set HERE -- before the vendored
# googletest and before the basalt submodule are added -- so that the framework
# and the dependency are instrumented too. add_compile_options at this scope
# propagates into every subdirectory added AFTER it, and the ordering below is
# load-bearing for that reason.
#
# Half-instrumented ASan is worse than none: it reports the halves it can see
# and stays quiet about the rest, which reads as a clean run.
if(UMBRA_SANITIZER STREQUAL "address")
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address)
  set(UMBRA_SANITIZER_DEFINE UMBRA_EXPECT_ASAN=1)
elseif(UMBRA_SANITIZER STREQUAL "undefined")
  # -fno-sanitize-recover=all is load-bearing. Without it UBSan PRINTS a
  # diagnostic and carries on, the process exits 0, and the lane is green with
  # undefined behaviour in its own log. A lane that reports a defect by writing
  # it down and passing anyway is decoration.
  #
  # -DUMBRA_UBSAN_FLAGS_ADDED IS IN THIS ARGUMENT LIST ON PURPOSE, and it is the
  # one place in this file where a -D is not an accident.
  #
  # gcc < 14 publishes no macro for UBSan that can be relied on --
  # __SANITIZE_UNDEFINED__ is absent under -fsanitize=undefined on 16.1 as well
  # as on 13, measured, so it is not a version gap that waiting fixes -- and
  # ubuntu-latest's `gcc` is still 13. Under that compiler the lane's own guard
  # cannot see the sanitizer and the build system has to be the witness.
  #
  # A WITNESS THAT CAN DRIFT FROM WHAT IT WITNESSES IS WORTHLESS, so it is not a
  # separate add_compile_definitions() a few lines away: it is a token in the
  # SAME list as -fsanitize=undefined. Removing the flag and leaving the claim
  # means deleting one word from the middle of this list.
  #
  # test/sanitizer_lane_test.cc holds the pair to account on every toolchain
  # that can see UBSan for itself, so drift here fails the build under clang and
  # under gcc >= 14 even though gcc 13 cannot catch it.
  add_compile_options(-fsanitize=undefined -DUMBRA_UBSAN_FLAGS_ADDED=1
                      -fno-sanitize-recover=all
                      -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=undefined)
  set(UMBRA_SANITIZER_DEFINE UMBRA_EXPECT_UBSAN=1)
elseif(UMBRA_SANITIZER STREQUAL "thread")
  add_compile_options(-fsanitize=thread -g)
  add_link_options(-fsanitize=thread)
  set(UMBRA_SANITIZER_DEFINE UMBRA_EXPECT_TSAN=1)
elseif(UMBRA_SANITIZER STREQUAL "none")
  set(UMBRA_SANITIZER_DEFINE UMBRA_EXPECT_NO_SANITIZER=1)
else()
  message(FATAL_ERROR
          "UMBRA_SANITIZER must be none|address|undefined|thread, got '${UMBRA_SANITIZER}'")
endif()

# ------------------------------------------------------------ our own flags
#
# -Werror=switch is named explicitly even though -Werror already implies it. It
# is not a style preference: it is the mechanism that makes ChangeKind CLOSED.
# The watcher switches over that enum to decide what to emit, and removing this
# turns "somebody added a change kind and forgot to classify it" from a build
# failure into a change the sync engine silently drops.
#
# -fno-exceptions -fno-rtti: matching basalt, which Umbra links. The watcher
# reports failure by return value; a violated precondition aborts. Mixing an
# exceptions build of this code with a no-exceptions basalt across a
# translation-unit boundary is the kind of ODR problem that presents as
# something far stranger than a build error.
set(UMBRA_CXX_FLAGS -Wall -Wextra -Werror -Werror=switch -fno-exceptions -fno-rtti)

# --------------------------------------------------------------- basalt
#
# BASALT_BUILD_TESTS IS FORCED OFF, and that is not only about build time: with
# it on, basalt would add ITS vendored googletest, this file would add OURS, and
# two `gtest` targets in one build is a configure error. The assertion below
# makes that a stated invariant rather than a thing that happens to hold.
#
# basalt is added AFTER the sanitizer block above, so a sanitizer lane
# instruments the dependency too. It is added BEFORE our googletest only for
# readability; neither order matters between them.
set(BASALT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/basalt EXCLUDE_FROM_ALL)

# ------------------------------------------------------------------ libsodium
#
# Included AFTER the sanitizer block for the same reason basalt and googletest
# are: a lane that does not instrument its crypto library is a lane that would
# stay quiet about a defect there. include() rather than add_subdirectory()
# because the file describes a tree it does not live in.
include(third_party/libsodium.cmake)
if(TARGET gtest)
  message(FATAL_ERROR
          "basalt defined a `gtest` target, so BASALT_BUILD_TESTS did not take. "
          "Adding ours next would be a duplicate-target configure error.")
endif()

# ---------------------------------------------------------------- the library
#
# The watcher owns a backend thread, so pthreads is a real dependency and is
# resolved BEFORE the target that links it rather than after. CMake would
# tolerate the reverse -- imported targets resolve at generate time -- but a
# reader should not have to know that to believe the file.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# THE WIRE FORMAT IS NOT THE RELAY. A client has to speak the protocol, so it
# needs these types; it must not therefore link the relay's store and its TCP
# server. The library used to link the whole umbra_relay archive to reach
# wire.h, which put a listening server inside libumbra.a and made the public
# header include/umbra/sync/client.h depend on the relay's include path -- the
# library-only CI job caught it as a missing wire.h.
#
# umbra_wire depends on nothing. Not on basalt, not on sodium, not on umbra.
# It is defined HERE, above its first consumer, because a target named in
# target_link_libraries before it exists does not propagate its include path
# and the failure looks like a missing header rather than a missing target.
add_library(umbra_wire STATIC relay/wire.cc)
target_include_directories(umbra_wire PUBLIC relay)
target_compile_options(umbra_wire PRIVATE ${UMBRA_CXX_FLAGS})

add_library(umbra STATIC
  src/crdt/op_id.cc
  src/crdt/op.cc
  src/crdt/utf8.cc
  src/crdt/text_doc.cc
  src/crdt/tree.cc
  src/crdt/oplog.cc
  src/crdt/vault.cc
  src/crypto/keys.cc
  src/crypto/aead.cc
  src/sync/report.cc
  src/sync/client.cc
  src/ai/answer.cc
  src/ai/chunk.cc
  src/ai/embed.cc
  src/ai/embed_hashing.cc
  src/ai/embed_ollama.cc
  src/ai/hnsw.cc
  src/ai/index.cc
  src/ai/keyspace.cc
  src/ai/manifest.cc
  src/ai/segment.cc
  src/sync/enroll.cc
  src/sync/tcp_transport.cc
  src/watcher/content_hash.cc
  src/watcher/object_id.cc
  src/watcher/scan.cc
  src/watcher/reconciler.cc
  src/watcher/watcher.cc
  # BOTH BACKENDS ARE NAMED ON BOTH PLATFORMS. Each is an inert translation unit
  # off its own platform, guarded by one #if at the top of the file. The file
  # list therefore does not vary by platform, so a build on either OS still
  # parses the other's entry -- which is where a typo would otherwise wait until
  # somebody built on the other one.
  src/watcher/backend_fsevents.cc
  src/watcher/backend_inotify.cc
)
add_library(umbra::umbra ALIAS umbra)
target_include_directories(umbra
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>
  PRIVATE src src/watcher src/crdt src/crypto src/sync src/ai)
target_compile_options(umbra PRIVATE ${UMBRA_CXX_FLAGS})
# sodium is PRIVATE: BLAKE2b is how ContentHash is computed, which is an
# implementation detail of this library. A consumer of <umbra/change_event.h>
# gets a 32-byte digest and no libsodium headers.
target_link_libraries(umbra PUBLIC basalt::basalt Threads::Threads)
target_link_libraries(umbra PRIVATE umbra::sodium)
target_link_libraries(umbra PUBLIC umbra_wire)

# THE BACKEND IS CHOSEN HERE AND NOT WITH #ifdef INSIDE ONE FILE. Both backend
# sources are compiled on both platforms; each is a no-op translation unit off
# its own platform (see the guard at the top of each). The selection that
# matters -- which one MakePlatformBackend returns -- is a compile definition,
# so a platform with neither backend gets a build failure naming the platform
# rather than a watcher that silently observes nothing.
if(APPLE)
  target_compile_definitions(umbra PRIVATE UMBRA_BACKEND_FSEVENTS=1)
  target_link_libraries(umbra PUBLIC "-framework CoreServices")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(umbra PRIVATE UMBRA_BACKEND_INOTIFY=1)
else()
  message(FATAL_ERROR
          "no vault watcher backend for '${CMAKE_SYSTEM_NAME}'. FSEvents and "
          "inotify are the two that exist; see src/watcher/backend.h.")
endif()

include(GNUInstallDirs)
install(TARGETS umbra ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/umbra DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(NOT UMBRA_BUILD_TESTS)
  return()
endif()

# ------------------------------------------------------------- harness-side
#
# The scripted backend lives under src/ so it is built with the same flags and
# covered by the same sanitizers as the code it stands in for, but it is a
# SEPARATE ARCHIVE and never links into `umbra`. A shipped library must not
# contain a backend whose events come from whoever calls Emit.
add_library(umbra_testing STATIC src/watcher/backend_manual.cc)
target_include_directories(umbra_testing PUBLIC src src/watcher src/crdt)
target_link_libraries(umbra_testing PUBLIC umbra)
target_compile_options(umbra_testing PRIVATE ${UMBRA_CXX_FLAGS})

# ---------------------------------------------------------------- googletest
#
# gmock is not built: we do not use it, and building it doubles the framework's
# compile time in every one of four lanes. This is a build-config choice and NOT
# a modification of the vendored tree, which is upstream's complete tree at the
# pinned commit.
set(BUILD_GMOCK   OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

# The library is built -fno-exceptions -fno-rtti. GoogleTest must be told the
# same thing, in the same terms, or its inline code and ours disagree about
# GTEST_HAS_EXCEPTIONS across a translation-unit boundary -- an ODR violation
# that would present as something far stranger than a build error.
add_subdirectory(third_party/googletest "${CMAKE_BINARY_DIR}/googletest" EXCLUDE_FROM_ALL)
target_compile_options(gtest      PRIVATE -fno-exceptions -fno-rtti)
target_compile_options(gtest_main PRIVATE -fno-exceptions -fno-rtti)
target_compile_definitions(gtest      PUBLIC GTEST_HAS_EXCEPTIONS=0 GTEST_HAS_RTTI=0)
target_compile_definitions(gtest_main PUBLIC GTEST_HAS_EXCEPTIONS=0 GTEST_HAS_RTTI=0)

# ----------------------------------------------------------------- binaries
enable_testing()

# ONE TEST BINARY, RUN BY ALL FOUR LANES INCLUDING umbra-tsan.
#
# basalt needs a separate TSan harness because its unit suite is single-threaded
# and a green TSan run over it would report the absence of threads as the
# absence of races. UMBRA'S SUITE HAS THE OPPOSITE PROPERTY: the watcher owns a
# backend thread and a debounce timer, and every scenario in
# test/watcher_test.cc drives real filesystem events across that thread boundary
# into the test's own thread. There is nothing to build separately, so there is
# no second harness to keep honest.
add_executable(umbra_test
  test/sanitizer_lane_test.cc
  test/watcher_test.cc
  test/crdt_test.cc
  test/tree_test.cc
  test/crypto_test.cc
  test/answer_test.cc
  test/chunk_test.cc
  test/embed_test.cc
  test/index_test.cc
  test/enroll_test.cc
  test/replicate_test.cc
  test/relay_test.cc
  test/oplog_test.cc
  test/converge_test.cc
)
# umbra::sodium is linked into the TEST but not exposed by the library.
#
# The parameter test asserts that the shipped Argon2id settings equal
# libsodium's own MODERATE constants, which means it has to see them. Asserting
# against numbers copied into the test would assert that two copies of a number
# match, which is not the claim being made.
# umbra_relay explicitly: relay_test.cc runs a real store and a real server, so
# the test binary needs the half the client does not.
target_link_libraries(umbra_test PRIVATE umbra_testing umbra_sim umbra_relay
                                         umbra::sodium gtest_main)
target_include_directories(umbra_test PRIVATE src src/watcher src/crdt src/crypto src/sync src/ai)
target_compile_options(umbra_test PRIVATE ${UMBRA_CXX_FLAGS})
target_compile_definitions(umbra_test PRIVATE ${UMBRA_SANITIZER_DEFINE})
# The chunking fixtures are read at run time rather than embedded, so a person
# can add one without touching the build. UMBRA_FIXTURES overrides it.
target_compile_definitions(umbra_test PRIVATE
  UMBRA_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/chunking")
add_test(NAME umbra_test COMMAND umbra_test)

# ------------------------------------------------------------------- relay
#
# A SEPARATE ARCHIVE THAT DOES NOT LINK THE CRDTS OR THE CRYPTO, and the
# separation is the design rather than tidiness: the relay must not be able to
# understand an operation, so it must not be able to CALL anything that could.
# If a future change makes relay/ need umbra::umbra, that is the moment to ask
# why.
add_library(umbra_relay STATIC relay/store.cc relay/server.cc)
target_include_directories(umbra_relay PUBLIC relay)
target_link_libraries(umbra_relay PUBLIC umbra_wire basalt::basalt)
target_compile_options(umbra_relay PRIVATE ${UMBRA_CXX_FLAGS})

# The vault state both binaries read: salt, epoch wraps, device key, passphrase.
# One copy, because umbra_ai deriving its own keys from a constant is exactly
# the bug this library exists to make impossible.
add_library(umbra_cmd_state STATIC cmd/vault_state.cc)
target_include_directories(umbra_cmd_state PUBLIC cmd)
target_link_libraries(umbra_cmd_state PUBLIC umbra)
target_compile_options(umbra_cmd_state PRIVATE ${UMBRA_CXX_FLAGS})

add_executable(umbra_sync cmd/sync_main.cc)
target_link_libraries(umbra_sync PRIVATE umbra umbra_cmd_state)
target_include_directories(umbra_sync PRIVATE src src/watcher src/crdt src/crypto src/sync src/ai)
target_compile_options(umbra_sync PRIVATE ${UMBRA_CXX_FLAGS})

add_executable(umbra_ai cmd/ai_main.cc)
target_link_libraries(umbra_ai PRIVATE umbra umbra::sodium umbra_cmd_state)
target_include_directories(umbra_ai PRIVATE src src/watcher src/crdt src/crypto src/sync src/ai)
target_compile_options(umbra_ai PRIVATE ${UMBRA_CXX_FLAGS})

add_executable(umbra_relay_bin cmd/relay_main.cc)
set_target_properties(umbra_relay_bin PROPERTIES OUTPUT_NAME umbra_relay)
target_link_libraries(umbra_relay_bin PRIVATE umbra_relay Threads::Threads)
target_compile_options(umbra_relay_bin PRIVATE ${UMBRA_CXX_FLAGS})

# ------------------------------------------------------ convergence harness
#
# A separate archive and a separate binary, so the sweep can run as its own CI
# lane over a wide seed range without the unit suite paying for it, and so the
# unit suite can run a narrow range of the SAME code on every push.
add_library(umbra_sim STATIC sim/sim.cc)
target_include_directories(umbra_sim PUBLIC sim PRIVATE src src/crdt)
target_link_libraries(umbra_sim PUBLIC umbra)
target_compile_options(umbra_sim PRIVATE ${UMBRA_CXX_FLAGS})

add_executable(umbra_converge cmd/converge_main.cc)
target_link_libraries(umbra_converge PRIVATE umbra_sim)
target_compile_options(umbra_converge PRIVATE ${UMBRA_CXX_FLAGS})
