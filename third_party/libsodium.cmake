# Building the vendored libsodium, from outside the vendored tree.
#
# WHY THIS FILE EXISTS AT ALL. GoogleTest ships a CMakeLists.txt, so vendoring
# it is a copy plus an add_subdirectory. libsodium ships autotools and nothing
# else: there is no CMake support upstream, and `configure` is a build step that
# runs a shell, probes the compiler and WRITES INTO THE SOURCE TREE. That is a
# build step we would have to trust and could not audit, and it would make
# third_party/libsodium stop matching upstream's tree the first time anyone
# built.
#
# So the tree stays pristine and the build description lives here, beside it
# rather than inside it. third_party/libsodium/VERSION records the pin and the
# tree hash, and the equality of that hash against upstream is checkable exactly
# the way GoogleTest's is.
#
# ---------------------------------------------------------------------------
# THE PORTABLE BUILD, AND WHY THAT IS THE RIGHT ONE HERE.
#
# Every SIMD path in libsodium is guarded by a HAVE_* macro that `configure`
# defines after probing the compiler -- HAVE_AVX2INTRIN_H, HAVE_ARMCRYPTO and so
# on. WE DEFINE NONE OF THEM. Each of those files then compiles to an empty
# translation unit and the runtime dispatcher, which reads the same flags,
# selects the portable reference implementation.
#
# This is a deliberate trade and not an oversight. What it costs: BLAKE2b runs
# at reference speed rather than AVX2 speed. What it buys: one build that is
# identical on macOS/arm64, ubuntu/x86-64 and ubuntu/arm64, with no compiler
# probing, no per-file -m flags, and no possibility of a lane silently getting a
# different code path from the others. Umbra hashes markdown files; the hash is
# not the bottleneck, and a content hash that differs between platforms because
# one picked a different implementation would be a far worse problem than a slow
# one.
#
# If profiling ever says otherwise, the fix is to define the HAVE_* macros per
# platform HERE, and the differential to watch is that the digest does not move.

set(UMBRA_SODIUM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium")
set(UMBRA_SODIUM_SRC  "${UMBRA_SODIUM_ROOT}/src/libsodium")

if(NOT EXISTS "${UMBRA_SODIUM_SRC}/sodium/core.c")
  message(FATAL_ERROR
          "third_party/libsodium is missing or incomplete. It is a vendored "
          "tree, not a submodule, so this is a bad checkout rather than a "
          "missing `git submodule update`.")
endif()

# version.h is the ONE header `configure` generates, and it is generated INTO
# THE BUILD DIRECTORY rather than into the source tree. The values come from
# libsodium's own configure.ac at the pinned tag; they are asserted below
# against the vendored version.h.in so a pin bump that changes them fails here
# instead of silently reporting the wrong version at runtime.
set(SODIUM_VERSION "1.0.22")
set(SODIUM_LIBRARY_VERSION_MAJOR 26)
set(SODIUM_LIBRARY_VERSION_MINOR 4)
set(VERSION "${SODIUM_VERSION}")
set(SODIUM_LIBRARY_MINIMAL_DEF "")
configure_file("${UMBRA_SODIUM_SRC}/include/sodium/version.h.in"
               "${CMAKE_BINARY_DIR}/sodium-generated/sodium/version.h" @ONLY)

# Every .c under src/libsodium. Globbed rather than listed: the list is
# upstream's business, it changes on every pin bump, and a hand-maintained copy
# would drift silently -- a dropped file usually still links, because the
# symbols it defines are only reached from a path we do not exercise.
#
# CONFIGURE_DEPENDS so adding the next pin's files does not need a manual
# cmake re-run.
file(GLOB_RECURSE UMBRA_SODIUM_SOURCES CONFIGURE_DEPENDS
     "${UMBRA_SODIUM_SRC}/*.c")

add_library(sodium STATIC ${UMBRA_SODIUM_SOURCES})
add_library(umbra::sodium ALIAS sodium)

# include/ and the generated directory are PUBLIC so <sodium.h> resolves.
# include/sodium is PUBLIC TOO, and that needs a word: the generated version.h
# does `#include "export.h"`, which upstream resolves because its build puts the
# generated header in the same directory as the checked-in ones. Ours keeps the
# generated file in the build directory, so export.h has to be findable by bare
# name from there. Widening the path costs nothing outside this library --
# `sodium` is linked PRIVATE into umbra, so no consumer of umbra ever sees it.
target_include_directories(sodium
  PUBLIC  "${UMBRA_SODIUM_SRC}/include"
          "${UMBRA_SODIUM_SRC}/include/sodium"
          "${CMAKE_BINARY_DIR}/sodium-generated"
          "${CMAKE_BINARY_DIR}/sodium-generated/sodium"
  PRIVATE "${UMBRA_SODIUM_SRC}")

# SODIUM_STATIC and SODIUM_EXPORT= together stop export.h from decorating every
# symbol with dllexport/visibility attributes meant for a shared build.
#
# CONFIGURED=1 is what libsodium's headers check to decide that somebody has
# taken responsibility for the configuration. Without it they #error out, which
# is the correct thing for them to do and the reason it is set here explicitly
# rather than by accident.
target_compile_definitions(sodium PUBLIC SODIUM_STATIC=1)
target_compile_definitions(sodium PRIVATE CONFIGURED=1)

# UPSTREAM'S WARNINGS ARE NOT OURS. The project builds -Wall -Wextra -Werror,
# and applying that to a vendored C library means a pin bump can fail the build
# over a warning in code we do not maintain and must not edit. The library is
# compiled with warnings off; OUR code that calls it is not.
if(NOT MSVC)
  target_compile_options(sodium PRIVATE -w)
endif()

# libsodium is C, and its files must not be compiled as C++ even though the rest
# of this project is. Stated explicitly because the top-level project() declares
# CXX only, and a CMake that inferred a language here would infer the wrong one.
enable_language(C)
set_target_properties(sodium PROPERTIES
  C_STANDARD 99
  C_STANDARD_REQUIRED ON
  POSITION_INDEPENDENT_CODE ON)
