#include "hnsw.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <queue>

namespace umbra {
namespace ai {
namespace {

// SplitMix64, the same generator the convergence harness uses. Integer in,
// integer out, no library RNG: std::uniform_int_distribution is
// implementation-defined and would make the graph depend on which standard
// library built it.
class Rng {
 public:
  explicit Rng(uint64_t seed) : state_(seed) {}
  uint64_t Next() {
    uint64_t z = (state_ += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }

 private:
  uint64_t state_;
};

// THE SEED COMES FROM THE DATA, NOT FROM A CLOCK OR A DEVICE. Textbook HNSW
// draws node levels from a random source, which makes the graph different on
// every run and the segment bytes different with it. Hashing the vectors gives
// a seed that is stable for the same input and unrelated for different input,
// so two builds of the same segment agree and two different segments do not
// share a layout.
uint64_t SeedFrom(const float* vectors, uint32_t count, uint32_t dimension) {
  uint8_t digest[8];
  crypto_generichash(
      digest, sizeof(digest), reinterpret_cast<const unsigned char*>(vectors),
      static_cast<unsigned long long>(count) * dimension * sizeof(float),
      nullptr, 0);
  uint64_t v = 0;
  for (std::size_t i = 0; i < sizeof(digest); ++i) v = (v << 8) | digest[i];
  // Never zero: SplitMix64 is fine with a zero state, but a zero seed reads
  // like "unseeded" to anyone debugging this later.
  return v == 0 ? 0x9E3779B97F4A7C15ull : v;
}

// A TOTAL ORDER, TIES INCLUDED. Ordering only by score leaves equal-scoring
// candidates in whatever order the heap happened to produce, which depends on
// the standard library's sift implementation. That is the classic way a build
// that is called deterministic stops being one, and it shows up as two devices
// disagreeing about the fifth result rather than as an error.
struct Nearer {
  bool operator()(const Neighbour& a, const Neighbour& b) const {
    if (a.score != b.score) return a.score < b.score;  // max-heap on score
    return a.id > b.id;                                // lower id wins ties
  }
};
struct Further {
  bool operator()(const Neighbour& a, const Neighbour& b) const {
    if (a.score != b.score) return a.score > b.score;  // min-heap on score
    return a.id < b.id;
  }
};

bool SortNearer(const Neighbour& a, const Neighbour& b) {
  if (a.score != b.score) return a.score > b.score;
  return a.id < b.id;
}

}  // namespace

uint32_t HnswGraph::SlotsFor(uint32_t level, const HnswParams& p) {
  // Layer zero is twice as wide, which is what keeps the base layer navigable
  // once the upper layers have thinned out.
  return (2u * p.m) + (level * p.m);
}

uint32_t HnswGraph::AdjacencyOffset(uint32_t node) const {
  return offsets_[node];
}

// WHERE ONE NODE'S SLOTS FOR ONE LAYER BEGIN, in one place. This arithmetic was
// written out at three call sites and the segment writer needs it as well;
// three copies of an offset calculation is three chances for one of them to
// drift and produce a graph that reads its neighbours from the wrong node.
uint32_t HnswGraph::LayerBase(uint32_t node, uint32_t layer) const {
  const uint32_t within =
      (layer == 0) ? 0u : (2u * params_.m) + ((layer - 1) * params_.m);
  return offsets_[node] + within;
}

uint32_t HnswGraph::LayerWidth(uint32_t layer) const {
  return (layer == 0) ? 2u * params_.m : params_.m;
}

double HnswGraph::Score(const float* a, uint32_t b) const {
  const float* v = vectors_ + (static_cast<std::size_t>(b) * dimension_);
  // Double accumulator: over 768 terms a float one loses enough precision to
  // reorder near-ties, so the ranking would change when someone enabled
  // vectorisation.
  double sum = 0.0;
  for (uint32_t i = 0; i < dimension_; ++i) {
    sum += static_cast<double>(a[i]) * static_cast<double>(v[i]);
  }
  return sum;
}

// A STAMP ARRAY, NOT A FRESH BITSET PER CALL. The first version allocated and
// zeroed a `vector<bool>` of one bit per node on every layer of every search,
// which is O(n) work to answer a query that touches O(log n) nodes -- and it
// showed: 320 microseconds for four thousand vectors, most of it spent zeroing
// memory the search never read. The caller owns a stamp buffer and each visit
// writes the current stamp, so "visited" is a comparison and clearing is an
// increment.
std::vector<Neighbour> HnswGraph::SearchLayer(const float* query,
                                              uint32_t entry, uint32_t ef,
                                              uint32_t layer,
                                              std::vector<uint32_t>* stamps,
                                              uint32_t stamp) const {
  std::priority_queue<Neighbour, std::vector<Neighbour>, Nearer> candidates;
  std::priority_queue<Neighbour, std::vector<Neighbour>, Further> results;

  Neighbour start;
  start.id = entry;
  start.score = static_cast<float>(Score(query, entry));
  (*stamps)[entry] = stamp;
  candidates.push(start);
  results.push(start);

  while (!candidates.empty()) {
    const Neighbour c = candidates.top();
    candidates.pop();
    if (!results.empty() && c.score < results.top().score &&
        results.size() >= ef) {
      break;
    }
    if (layer > levels_[c.id]) continue;
    const uint32_t base = LayerBase(c.id, layer);
    const uint32_t width = LayerWidth(layer);
    for (uint32_t i = 0; i < width; ++i) {
      const uint32_t n = adjacency_[base + i];
      if (n == UINT32_MAX) break;  // slots are filled from the front
      if ((*stamps)[n] == stamp) continue;
      (*stamps)[n] = stamp;
      Neighbour cand;
      cand.id = n;
      cand.score = static_cast<float>(Score(query, n));
      if (results.size() < ef || cand.score > results.top().score) {
        candidates.push(cand);
        results.push(cand);
        if (results.size() > ef) results.pop();
      }
    }
  }

  std::vector<Neighbour> out;
  out.reserve(results.size());
  while (!results.empty()) {
    out.push_back(results.top());
    results.pop();
  }
  std::sort(out.begin(), out.end(), SortNearer);
  return out;
}

void HnswGraph::Connect(uint32_t node, uint32_t layer,
                        const std::vector<Neighbour>& candidates) {
  const uint32_t width = LayerWidth(layer);
  const uint32_t base = LayerBase(node, layer);

  // THE NEIGHBOUR HEURISTIC, NOT SIMPLY THE TOP M. Taking the M nearest gives a
  // graph where every node points into the same dense cluster and long edges
  // never get made, so a search that starts on the wrong side of the space has
  // no way across. A candidate is kept only if it is nearer to the node than to
  // any neighbour already kept, which is what preserves those long edges.
  std::vector<Neighbour> kept;
  for (const Neighbour& c : candidates) {
    if (c.id == node) continue;
    if (kept.size() >= width) break;
    bool dominated = false;
    const float* cv = vectors_ + (static_cast<std::size_t>(c.id) * dimension_);
    for (const Neighbour& k : kept) {
      if (static_cast<float>(Score(cv, k.id)) > c.score) {
        dominated = true;
        break;
      }
    }
    if (!dominated) kept.push_back(c);
  }
  // If the heuristic was too strict to fill the slots, top up in order. An
  // under-connected node is a node the search cannot leave.
  for (const Neighbour& c : candidates) {
    if (kept.size() >= width) break;
    if (c.id == node) continue;
    bool already = false;
    for (const Neighbour& k : kept) {
      if (k.id == c.id) already = true;
    }
    if (!already) kept.push_back(c);
  }

  for (uint32_t i = 0; i < width; ++i) {
    adjacency_[base + i] = (i < kept.size()) ? kept[i].id : UINT32_MAX;
  }

  // Back-links, with pruning when the other end is full. Without these the
  // graph is directed and whole regions become unreachable from the entry
  // point.
  for (const Neighbour& k : kept) {
    if (layer > levels_[k.id]) continue;
    const uint32_t kbase = LayerBase(k.id, layer);
    uint32_t filled = 0;
    while (filled < width && adjacency_[kbase + filled] != UINT32_MAX) ++filled;
    if (filled < width) {
      adjacency_[kbase + filled] = node;
      continue;
    }
    // Full: rebuild that node's list from its current neighbours plus this one,
    // keeping the nearest by the same rule.
    std::vector<Neighbour> merged;
    const float* kv = vectors_ + (static_cast<std::size_t>(k.id) * dimension_);
    for (uint32_t i = 0; i < width; ++i) {
      const uint32_t n = adjacency_[kbase + i];
      if (n == UINT32_MAX) break;
      Neighbour m;
      m.id = n;
      m.score = static_cast<float>(Score(kv, n));
      merged.push_back(m);
    }
    Neighbour self;
    self.id = node;
    self.score = static_cast<float>(Score(kv, node));
    merged.push_back(self);
    std::sort(merged.begin(), merged.end(), SortNearer);
    for (uint32_t i = 0; i < width; ++i) {
      adjacency_[kbase + i] = (i < merged.size()) ? merged[i].id : UINT32_MAX;
    }
  }
}

HnswGraph HnswGraph::Build(const float* vectors, uint32_t count,
                           uint32_t dimension, const HnswParams& params) {
  HnswGraph g;
  g.vectors_ = vectors;
  g.count_ = count;
  g.dimension_ = dimension;
  g.params_ = params;
  if (count == 0) return g;

  Rng rng(SeedFrom(vectors, count, dimension));
  // Probability 1/m of climbing a level, drawn as an integer comparison so no
  // float reaches a layout decision.
  const uint64_t climb = (params.m > 1) ? (UINT64_MAX / params.m) : 0;

  g.levels_.resize(count, 0);
  g.offsets_.resize(count, 0);
  uint32_t total = 0;
  for (uint32_t i = 0; i < count; ++i) {
    uint32_t level = 0;
    while (level + 1 < params.max_level && rng.Next() < climb) ++level;
    g.levels_[i] = static_cast<uint8_t>(level);
    g.offsets_[i] = total;
    total += SlotsFor(level, params);
  }
  g.adjacency_.assign(total, UINT32_MAX);

  g.entry_ = 0;
  uint32_t entry_level = g.levels_[0];
  for (uint32_t i = 1; i < count; ++i) {
    if (g.levels_[i] > entry_level) {
      entry_level = g.levels_[i];
      g.entry_ = i;
    }
  }

  // One stamp buffer for the whole build rather than one per layer per insert.
  std::vector<uint32_t> stamps(count, 0);
  uint32_t stamp = 0;

  // Insert in index order. The order is part of the input, so it is part of
  // what makes the build reproducible.
  for (uint32_t i = 0; i < count; ++i) {
    if (i == g.entry_) continue;
    const float* v = vectors + (static_cast<std::size_t>(i) * dimension);
    uint32_t ep = g.entry_;
    const uint32_t my_level = g.levels_[i];

    // Descend from the top to one above this node's level, greedily.
    for (uint32_t layer = entry_level; layer > my_level; --layer) {
      const std::vector<Neighbour> found =
          g.SearchLayer(v, ep, 1, layer, &stamps, ++stamp);
      if (!found.empty()) ep = found[0].id;
      if (layer == 0) break;
    }
    // Connect at every layer this node lives in.
    for (uint32_t layer = std::min(my_level, entry_level) + 1; layer-- > 0;) {
      const std::vector<Neighbour> found =
          g.SearchLayer(v, ep, params.ef_construction, layer, &stamps, ++stamp);
      g.Connect(i, layer, found);
      if (!found.empty()) ep = found[0].id;
    }
  }
  return g;
}

HnswGraph HnswGraph::FromParts(const float* vectors, uint32_t count,
                               uint32_t dimension, uint32_t entry,
                               std::vector<uint8_t> levels,
                               std::vector<uint32_t> adjacency,
                               const HnswParams& params) {
  HnswGraph g;
  g.vectors_ = vectors;
  g.count_ = count;
  g.dimension_ = dimension;
  g.entry_ = entry;
  g.params_ = params;
  g.levels_ = std::move(levels);
  g.adjacency_ = std::move(adjacency);
  g.offsets_.resize(count, 0);
  uint32_t total = 0;
  for (uint32_t i = 0; i < count; ++i) {
    g.offsets_[i] = total;
    total += SlotsFor(g.levels_[i], params);
  }
  return g;
}

std::vector<Neighbour> HnswGraph::Search(const float* query, uint32_t k,
                                         uint32_t ef,
                                         const std::vector<bool>* skip,
                                         Scratch* scratch) const {
  if (count_ == 0 || k == 0) return {};
  if (ef < k) ef = k;

  Scratch owned;
  Scratch* sc = (scratch != nullptr) ? scratch : &owned;
  if (sc->stamps.size() < count_) sc->stamps.assign(count_, 0);
  // The stamp counter wrapping would make a stale entry read as visited and
  // silently truncate a search, so it resets the buffer when it comes round.
  if (sc->stamp > UINT32_MAX - 4) {
    sc->stamps.assign(sc->stamps.size(), 0);
    sc->stamp = 0;
  }
  std::vector<uint32_t>& stamps = sc->stamps;
  uint32_t& stamp = sc->stamp;
  uint32_t ep = entry_;
  const uint32_t top = levels_[entry_];
  for (uint32_t layer = top; layer > 0; --layer) {
    const std::vector<Neighbour> found =
        SearchLayer(query, ep, 1, layer, &stamps, ++stamp);
    if (!found.empty()) ep = found[0].id;
  }
  // A DELETED NODE IS STILL TRAVERSED. Its edges may be the only path to its
  // neighbours, and the graph cannot be rewired without rebuilding the segment
  // -- which is what compaction is for. So `skip` filters the RESULT and never
  // the traversal.
  const std::vector<Neighbour> found =
      SearchLayer(query, ep, ef, 0, &stamps, ++stamp);
  std::vector<Neighbour> out;
  out.reserve(k);
  for (const Neighbour& n : found) {
    if (skip != nullptr && n.id < skip->size() && (*skip)[n.id]) continue;
    out.push_back(n);
    if (out.size() >= k) break;
  }
  return out;
}

std::vector<Neighbour> HnswGraph::BruteForce(
    const float* query, uint32_t k, const std::vector<bool>* skip) const {
  std::vector<Neighbour> all;
  all.reserve(count_);
  for (uint32_t i = 0; i < count_; ++i) {
    if (skip != nullptr && i < skip->size() && (*skip)[i]) continue;
    Neighbour n;
    n.id = i;
    n.score = static_cast<float>(Score(query, i));
    all.push_back(n);
  }
  std::sort(all.begin(), all.end(), SortNearer);
  if (all.size() > k) all.resize(k);
  return all;
}

}  // namespace ai
}  // namespace umbra
