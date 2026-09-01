// A narrow slice of the convergence sweep, inside the unit suite.
//
// The wide sweep is umbra_converge and has its own CI lane. This exists so that
// the harness itself is exercised by every ordinary `umbra_test` run, including
// under the sanitizers -- a harness that only runs in one lane is a harness
// whose own use-after-frees nobody finds.
#include <gtest/gtest.h>

#include "sim.h"

namespace umbra {
namespace sim {
namespace {

Config SmallConfig() {
  Config c;
  c.replicas = 4;
  c.steps = 120;
  return c;
}

TEST(Converge, RandomSchedules) {
  const Config cfg = SmallConfig();
  for (uint64_t seed = 0; seed < 25; ++seed) {
    const Result r = RunSchedule(seed, cfg, Adversarial::kNone);
    ASSERT_TRUE(r.ok) << "seed " << seed << "\n" << r.failure;
  }
}

class AdversarialSchedule : public ::testing::TestWithParam<std::size_t> {};

TEST_P(AdversarialSchedule, Converges) {
  const Config cfg = SmallConfig();
  const Adversarial adv = static_cast<Adversarial>(GetParam());
  for (uint64_t seed = 0; seed < 15; ++seed) {
    const Result r = RunSchedule(seed, cfg, adv);
    ASSERT_TRUE(r.ok) << AdversarialName(adv) << " seed " << seed << "\n"
                      << r.failure;
  }
}

std::string ScheduleName(const ::testing::TestParamInfo<std::size_t>& info) {
  std::string n = AdversarialName(static_cast<Adversarial>(info.param));
  for (char& c : n) {
    if (c == '-') c = '_';
  }
  return n;
}

INSTANTIATE_TEST_SUITE_P(Shapes, AdversarialSchedule,
                         ::testing::Range(std::size_t{1}, kAdversarialCount),
                         ScheduleName);

// Same seed, same answer, twice. Without this the harness could be reporting
// green because it is doing something different each run.
TEST(Converge, IsReproducible) {
  const Config cfg = SmallConfig();
  for (uint64_t seed = 100; seed < 105; ++seed) {
    const Result a = RunSchedule(seed, cfg, Adversarial::kNone);
    const Result b = RunSchedule(seed, cfg, Adversarial::kNone);
    ASSERT_TRUE(a.ok);
    EXPECT_EQ(a.final_text, b.final_text)
        << "seed " << seed << " is not stable";
    EXPECT_EQ(a.ops, b.ops);
    EXPECT_EQ(a.deliveries, b.deliveries);
    EXPECT_EQ(a.crashes, b.crashes);
  }
}

}  // namespace
}  // namespace sim
}  // namespace umbra
