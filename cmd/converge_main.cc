// The convergence sweep, as a command.
//
// Runs a range of seeds against every schedule shape and reports. Exits
// non-zero if any seed fails, and names it, because a failing seed is the whole
// output that matters: it replays exactly.
#include <chrono>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <csignal>

#include "sim.h"

namespace {

// WHAT IS RUNNING RIGHT NOW, so that a crash says so.
//
// A defect that trips an internal invariant aborts inside the schedule, and
// without this the sweep dies having printed nothing -- the operator gets a
// stack trace and no seed, which is the one thing they needed. Found while
// deliberately breaking the causal readiness check: the harness detected the
// defect and then could not say where.
struct Current {
  volatile std::sig_atomic_t active = 0;
  unsigned long long seed = 0;
  const char* schedule = "";
  std::size_t replicas = 0;
  std::size_t steps = 0;
};
Current g_current;

extern "C" void OnFatalSignal(int sig) {
  if (g_current.active != 0) {
    // Only async-signal-safe calls here: write(2) on a preformatted buffer.
    char buf[256];
    const int n = std::snprintf(
        buf, sizeof(buf),
        "\nCRASH seed=%llu schedule=%s replicas=%zu steps=%zu\n"
        "  replay: umbra_converge --from %llu --to %llu --only %s "
        "--replicas %zu --steps %zu\n",
        g_current.seed, g_current.schedule, g_current.replicas,
        g_current.steps, g_current.seed, g_current.seed + 1,
        g_current.schedule, g_current.replicas, g_current.steps);
    if (n > 0) {
      const ssize_t w = ::write(2, buf, static_cast<std::size_t>(n));
      (void)w;
    }
  }
  std::signal(sig, SIG_DFL);
  std::raise(sig);
}

uint64_t ParseU64(const char* s, uint64_t fallback) {
  if (s == nullptr || *s == '\0') return fallback;
  char* end = nullptr;
  const unsigned long long v = std::strtoull(s, &end, 10);
  if (end == s || *end != '\0') return fallback;
  return static_cast<uint64_t>(v);
}

void Usage() {
  std::fprintf(
      stderr,
      "usage: umbra_converge [--from N] [--to N] [--replicas N]\n"
      "                      [--steps N] [--only SCHEDULE] [-v]\n"
      "\n"
      "  --from/--to   seed range, inclusive of from, exclusive of to\n"
      "  --only        run one schedule shape by name\n"
      "\n"
      "A failing seed is printed with everything needed to replay it.\n");
}

}  // namespace

int main(int argc, char** argv) {
  uint64_t from = 0;
  uint64_t to = 200;
  umbra::sim::Config cfg;
  const char* only = nullptr;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    const char* next = (i + 1 < argc) ? argv[i + 1] : nullptr;
    if (a == "--from" && next != nullptr) {
      from = ParseU64(next, from);
      ++i;
    } else if (a == "--to" && next != nullptr) {
      to = ParseU64(next, to);
      ++i;
    } else if (a == "--replicas" && next != nullptr) {
      cfg.replicas = static_cast<std::size_t>(ParseU64(next, cfg.replicas));
      ++i;
    } else if (a == "--steps" && next != nullptr) {
      cfg.steps = static_cast<std::size_t>(ParseU64(next, cfg.steps));
      ++i;
    } else if (a == "--only" && next != nullptr) {
      only = next;
      ++i;
    } else if (a == "-v" || a == "--verbose") {
      cfg.verbose = true;
    } else {
      Usage();
      return 2;
    }
  }
  if (cfg.replicas < 2) {
    std::fprintf(stderr, "at least two replicas are needed to converge\n");
    return 2;
  }

  std::signal(SIGABRT, OnFatalSignal);
  std::signal(SIGSEGV, OnFatalSignal);

  const auto started = std::chrono::steady_clock::now();
  std::size_t run = 0;
  std::size_t failed = 0;
  std::size_t total_ops = 0;
  std::size_t total_deliveries = 0;
  std::size_t total_crashes = 0;

  for (uint64_t seed = from; seed < to; ++seed) {
    for (std::size_t k = 0; k < umbra::sim::kAdversarialCount; ++k) {
      const umbra::sim::Adversarial adv =
          static_cast<umbra::sim::Adversarial>(k);
      const char* name = umbra::sim::AdversarialName(adv);
      if (only != nullptr && std::strcmp(only, name) != 0) continue;
      g_current.seed = static_cast<unsigned long long>(seed);
      g_current.schedule = name;
      g_current.replicas = cfg.replicas;
      g_current.steps = cfg.steps;
      g_current.active = 1;
      const umbra::sim::Result r = umbra::sim::RunSchedule(seed, cfg, adv);
      g_current.active = 0;
      ++run;
      total_ops += r.ops;
      total_deliveries += r.deliveries;
      total_crashes += r.crashes;
      if (!r.ok) {
        ++failed;
        std::printf("FAIL seed=%llu schedule=%s replicas=%zu steps=%zu\n",
                    static_cast<unsigned long long>(seed), name, cfg.replicas,
                    cfg.steps);
        std::printf("  %s\n", r.failure.c_str());
        std::printf(
            "  replay: umbra_converge --from %llu --to %llu --only %s "
            "--replicas %zu --steps %zu\n",
            static_cast<unsigned long long>(seed),
            static_cast<unsigned long long>(seed + 1), name, cfg.replicas,
            cfg.steps);
      } else if (cfg.verbose) {
        std::printf("ok   seed=%llu schedule=%-26s ops=%zu text=%zu\n",
                    static_cast<unsigned long long>(seed), name, r.ops,
                    r.final_text.size());
      }
    }
  }

  const auto elapsed = std::chrono::steady_clock::now() - started;
  const double secs =
      std::chrono::duration_cast<std::chrono::duration<double>>(elapsed)
          .count();
  std::printf(
      "%zu schedules, seeds [%llu,%llu), %zu replicas, %zu ops, %zu deliveries,"
      " %zu crashes, %.2fs\n",
      run, static_cast<unsigned long long>(from),
      static_cast<unsigned long long>(to), cfg.replicas, total_ops,
      total_deliveries, total_crashes, secs);
  if (failed != 0) {
    std::printf("%zu FAILED\n", failed);
    return 1;
  }
  std::printf("all converged and matched the reference model\n");
  return 0;
}
