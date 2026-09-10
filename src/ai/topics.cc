#include "umbra/ai/topics.h"

#include "umbra/ai/embed.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <set>

namespace umbra {
namespace ai {
namespace {

// SPHERICAL K-MEANS, because the index ranks by cosine and so must this.
//
// Assignment is by largest dot product and a centre is the normalised mean of
// its members, which is k-means on the unit sphere. Using Euclidean distance
// here would group by vector magnitude as well as direction and would disagree
// with what Search calls near -- two answers to "what is close" inside one
// system is how a store starts lying quietly.
float Dot(const float* a, const float* b, uint32_t dim) {
  float s = 0.0f;
  for (uint32_t i = 0; i < dim; ++i) s += a[i] * b[i];
  return s;
}

// FURTHEST-FIRST SEEDING, DETERMINISTICALLY.
//
// k-means++ samples proportionally to distance and needs a random source; the
// deterministic limit of it is to take the furthest point every time. Same
// index, same map, every run -- which matters because a topic map that
// reshuffled itself between two identical runs would look like the vault had
// changed.
std::vector<uint32_t> Seed(const std::vector<const float*>& points,
                           uint32_t dim, uint32_t k) {
  std::vector<uint32_t> chosen;
  if (points.empty()) return chosen;
  chosen.push_back(0);  // enumeration order is stable, so this is stable
  std::vector<float> best(points.size(), -2.0f);
  while (chosen.size() < k) {
    const float* last = points[chosen.back()];
    uint32_t furthest = 0;
    float furthest_score = 2.0f;
    for (std::size_t i = 0; i < points.size(); ++i) {
      const float sim = Dot(points[i], last, dim);
      if (sim > best[i]) best[i] = sim;
      // The point least similar to anything already chosen.
      if (best[i] < furthest_score) {
        furthest_score = best[i];
        furthest = static_cast<uint32_t>(i);
      }
    }
    if (std::find(chosen.begin(), chosen.end(), furthest) != chosen.end())
      break;
    chosen.push_back(furthest);
  }
  return chosen;
}

}  // namespace

const char* TopicStatusName(TopicStatus s) {
  switch (s) {
    case TopicStatus::kOk:
      return "ok";
    case TopicStatus::kNotEnoughChunks:
      return "not-enough-chunks";
    case TopicStatus::kBadArgument:
      return "bad-argument";
  }
  return "unknown";
}

uint32_t DefaultTopicCount(uint32_t chunks) {
  if (chunks < 4) return chunks < 2 ? 0 : 2;
  const double k = std::sqrt(static_cast<double>(chunks) / 2.0);
  uint32_t rounded = static_cast<uint32_t>(k + 0.5);
  if (rounded < 2) rounded = 2;
  if (rounded > 20) rounded = 20;
  return rounded;
}

TopicStatus BuildTopicMap(const Index& index, const TopicOptions& options,
                          TopicMap* out) {
  if (out == nullptr) return TopicStatus::kBadArgument;
  *out = TopicMap();

  // Copied out of the segments, because the pointers a callback hands over are
  // only valid during the call and k-means needs many passes.
  // The dimension is not published by Index, so it is taken from the manifest's
  // view of what this index holds. Every segment in one index shares it -- the
  // model identity is part of the index identity (ADR 0007) -- so the first
  // one answers for all of them.
  uint32_t dim = 0;
  std::vector<float> flat;
  std::vector<SegmentEntry> entries;
  index.ForEachLiveVector([&](const Index::LiveVector& v) {
    if (dim == 0) dim = v.dimension;
    if (v.dimension != dim) return;  // cannot happen; not worth trusting
    flat.insert(flat.end(), v.vector, v.vector + dim);
    entries.push_back(*v.entry);
  });
  if (dim == 0) return TopicStatus::kNotEnoughChunks;
  const uint32_t n = static_cast<uint32_t>(entries.size());
  if (n < 2) return TopicStatus::kNotEnoughChunks;

  std::vector<const float*> points(n);
  for (uint32_t i = 0; i < n; ++i) points[i] = flat.data() + (i * dim);

  uint32_t k = options.k != 0 ? options.k : DefaultTopicCount(n);
  if (k < 2) return TopicStatus::kNotEnoughChunks;
  if (k > n) k = n;

  std::vector<std::vector<float>> centres;
  for (uint32_t idx : Seed(points, dim, k)) {
    centres.push_back(std::vector<float>(points[idx], points[idx] + dim));
  }
  k = static_cast<uint32_t>(centres.size());
  if (k < 2) return TopicStatus::kNotEnoughChunks;

  std::vector<uint32_t> assign(n, 0);
  uint32_t iterations = 0;
  for (; iterations < options.max_iterations; ++iterations) {
    bool moved = false;
    for (uint32_t i = 0; i < n; ++i) {
      uint32_t best = 0;
      float best_sim = -2.0f;
      for (uint32_t c = 0; c < k; ++c) {
        const float sim = Dot(points[i], centres[c].data(), dim);
        if (sim > best_sim) {
          best_sim = sim;
          best = c;
        }
      }
      if (assign[i] != best) {
        assign[i] = best;
        moved = true;
      }
    }
    if (!moved) break;
    std::vector<std::vector<float>> next(k, std::vector<float>(dim, 0.0f));
    std::vector<uint32_t> counts(k, 0);
    for (uint32_t i = 0; i < n; ++i) {
      const uint32_t c = assign[i];
      ++counts[c];
      for (uint32_t d = 0; d < dim; ++d) next[c][d] += points[i][d];
    }
    for (uint32_t c = 0; c < k; ++c) {
      // AN EMPTY GROUP KEEPS ITS OLD CENTRE rather than being dropped or
      // re-seeded at random. Dropping it would change k underneath the caller;
      // re-seeding would make the result depend on where the emptiness
      // happened. It simply attracts nothing and is reported with zero chunks.
      if (counts[c] == 0) continue;
      Normalise(&next[c]);
      centres[c] = next[c];
    }
  }

  // ONE LAST ASSIGNMENT AGAINST THE FINAL CENTRES.
  //
  // The loop assigns, then moves the centres, so on exit `assign` was computed
  // against the centres as they were one step earlier. Reporting that pairing
  // would put chunks in a group that is no longer their nearest -- which showed
  // up as two subjects sharing no vocabulary at all landing three-and-one in
  // each other's groups.
  for (uint32_t i = 0; i < n; ++i) {
    uint32_t best = 0;
    float best_sim = -2.0f;
    for (uint32_t c = 0; c < k; ++c) {
      const float sim = Dot(points[i], centres[c].data(), dim);
      if (sim > best_sim) {
        best_sim = sim;
        best = c;
      }
    }
    assign[i] = best;
  }

  // Build the report. Members carry their similarity to the centre, which is
  // both the ordering for examples and the cohesion when averaged.
  struct Build {
    double similarity_sum = 0.0;
    uint32_t chunks = 0;
    std::set<std::string> objects;
    std::vector<TopicExample> examples;
  };
  std::vector<Build> built(k);
  for (uint32_t i = 0; i < n; ++i) {
    const uint32_t c = assign[i];
    Build& b = built[c];
    const float sim = Dot(points[i], centres[c].data(), dim);
    ++b.chunks;
    b.similarity_sum += sim;
    b.objects.insert(std::string(
        reinterpret_cast<const char*>(entries[i].object.bytes.data()),
        entries[i].object.bytes.size()));
    TopicExample e;
    e.object = entries[i].object;
    e.start = entries[i].start;
    e.end = entries[i].end;
    e.heading_path = entries[i].heading_path;
    e.similarity = sim;
    b.examples.push_back(e);
  }

  double weighted = 0.0;
  for (uint32_t c = 0; c < k; ++c) {
    Build& b = built[c];
    Topic t;
    t.chunks = b.chunks;
    t.notes = static_cast<uint32_t>(b.objects.size());
    t.cohesion = b.chunks == 0
                     ? 0.0f
                     : static_cast<float>(b.similarity_sum /
                                          static_cast<double>(b.chunks));
    weighted += b.similarity_sum;
    std::sort(b.examples.begin(), b.examples.end(),
              [](const TopicExample& x, const TopicExample& y) {
                if (x.similarity != y.similarity) {
                  return x.similarity > y.similarity;
                }
                // A total order, so equal similarities do not reorder between
                // runs.
                if (x.object.bytes != y.object.bytes) {
                  return x.object.bytes < y.object.bytes;
                }
                return x.start < y.start;
              });
    if (b.examples.size() > options.examples_per_topic) {
      b.examples.resize(options.examples_per_topic);
    }
    t.examples = b.examples;
    out->topics.push_back(t);
  }

  std::sort(out->topics.begin(), out->topics.end(),
            [](const Topic& a, const Topic& b) {
              if (a.chunks != b.chunks) return a.chunks > b.chunks;
              return a.cohesion > b.cohesion;
            });

  std::set<std::string> all_objects;
  for (const SegmentEntry& e : entries) {
    all_objects.insert(
        std::string(reinterpret_cast<const char*>(e.object.bytes.data()),
                    e.object.bytes.size()));
  }
  out->chunks = n;
  out->notes = static_cast<uint32_t>(all_objects.size());
  out->k = k;
  out->iterations = iterations;
  out->cohesion = static_cast<float>(weighted / static_cast<double>(n));
  return TopicStatus::kOk;
}

}  // namespace ai
}  // namespace umbra
