// A small HNSW, built to be deterministic.
//
// ---------------------------------------------------------------------------
// WHY THE GRAPH IS BUILT HERE RATHER THAN LINKED IN
//
// The interesting part of a vector store is the part that decides which
// neighbours a node keeps, and handing that to a dependency would leave this
// project with an index whose behaviour nobody here can explain. It is also
// small: the algorithm is a few hundred lines and the hard parts are the
// invariants, not the volume.
//
// ---------------------------------------------------------------------------
// DETERMINISM, AND WHAT IT DOES AND DOES NOT COVER
//
// Segment bytes must be identical for identical INPUT VECTORS. That is what
// item 5's "same input, same segments, byte for byte" means here, and it is
// achievable. It is NOT the same as requiring identical bytes for identical
// note text: vectors are floating point and inference is not reproducible
// across machines (see include/umbra/ai/embed.h), which is fine because Phase 5
// copies segments rather than rebuilding them.
//
// So construction excludes every source of variation it can control:
//
//   - THE LEVEL RNG IS SEEDED FROM THE VECTORS. Textbook HNSW draws node levels
//     from a random source; a random source makes the graph different every
//     run. The seed here is a hash of the input, so the same input builds the
//     same graph and two different inputs do not share a layout.
//   - EVERY TIE BREAKS ON NODE INDEX. Two candidates at the same distance would
//     otherwise be ordered by whatever the container did, which depends on the
//     standard library. A comparator that is not a total order is the classic
//     way a "deterministic" build stops being one.
//   - DISTANCES ARE ACCUMULATED IN DOUBLE. Over 768 terms a float accumulator
//     loses enough to reorder near-ties, so a ranking would change when someone
//     enabled vectorisation.
#ifndef UMBRA_AI_HNSW_H_
#define UMBRA_AI_HNSW_H_

#include <cstdint>
#include <string>
#include <vector>

#include "umbra/ai/embed.h"

namespace umbra {
namespace ai {

struct HnswParams {
  // Neighbours kept per node per layer. 16 is the usual starting point and
  // costs 16 * 4 bytes per node per layer.
  uint32_t m = 16;
  // Candidate list width during construction. Higher is a better graph and a
  // slower build; it does not affect query cost.
  uint32_t ef_construction = 200;
  // A ceiling on levels, so a pathological draw cannot make the graph deep.
  uint32_t max_level = 16;
};

// An immutable graph over a fixed set of vectors. Built once, searched many
// times, and serialised into a segment exactly as built.
class HnswGraph {
 public:
  // `vectors` is count * dimension floats, unit length, row major. Nothing is
  // copied: the caller owns the storage and must outlive the graph.
  static HnswGraph Build(const float* vectors, uint32_t count,
                         uint32_t dimension, const HnswParams& params);

  // Rebuild from serialised adjacency, for a segment being read back.
  static HnswGraph FromParts(const float* vectors, uint32_t count,
                             uint32_t dimension, uint32_t entry,
                             std::vector<uint8_t> levels,
                             std::vector<uint32_t> adjacency,
                             const HnswParams& params);

  // Scratch the caller owns and reuses. One entry per node; searching many
  // segments for one query, or many queries in a row, should allocate once
  // rather than once per call. Grown as needed, so a default-constructed one is
  // fine to pass.
  struct Scratch {
    std::vector<uint32_t> stamps;
    uint32_t stamp = 0;
  };

  // Nearest `k` by cosine similarity, using a beam of `ef`. `skip` is consulted
  // for every candidate before it is returned; a node it rejects is still
  // traversed, because a deleted node's edges are the only path to its
  // neighbours in a graph that cannot be rewired.
  std::vector<Neighbour> Search(const float* query, uint32_t k, uint32_t ef,
                                const std::vector<bool>* skip,
                                Scratch* scratch) const;

  // Exhaustive scan. The thing recall is measured against, and the fallback for
  // a segment too small for a graph to be worth building.
  std::vector<Neighbour> BruteForce(const float* query, uint32_t k,
                                    const std::vector<bool>* skip) const;

  uint32_t count() const { return count_; }
  uint32_t dimension() const { return dimension_; }
  uint32_t entry() const { return entry_; }
  const std::vector<uint8_t>& levels() const { return levels_; }
  const std::vector<uint32_t>& adjacency() const { return adjacency_; }

  // Slots per node across every layer it appears in, including the wider layer
  // zero. Exposed because the segment writer lays bytes out with the same
  // arithmetic and the two must not drift.
  static uint32_t SlotsFor(uint32_t level, const HnswParams& p);
  uint32_t AdjacencyOffset(uint32_t node) const;
  // Where one node's slots for one layer begin, and how many there are. Public
  // because the segment writer lays bytes out with the same arithmetic; two
  // copies of it would be two chances to drift.
  uint32_t LayerBase(uint32_t node, uint32_t layer) const;
  uint32_t LayerWidth(uint32_t layer) const;

 private:
  const float* vectors_ = nullptr;
  uint32_t count_ = 0;
  uint32_t dimension_ = 0;
  uint32_t entry_ = 0;
  HnswParams params_;
  // Level of each node, and a flat adjacency array. Flat rather than nested so
  // that serialising it is a memcpy and reading it back needs no allocation
  // per node.
  std::vector<uint8_t> levels_;
  std::vector<uint32_t> offsets_;
  std::vector<uint32_t> adjacency_;

  double Score(const float* a, uint32_t b) const;
  // `stamps` is scratch owned by the caller: one entry per node, compared
  // against `stamp` to mean visited. See the note in the .cc for why this is
  // not a fresh bitset per call.
  std::vector<Neighbour> SearchLayer(const float* query, uint32_t entry,
                                     uint32_t ef, uint32_t layer,
                                     std::vector<uint32_t>* stamps,
                                     uint32_t stamp) const;
  std::vector<Neighbour> Select(uint32_t node,
                                const std::vector<Neighbour>& candidates,
                                uint32_t width) const;
  void Connect(uint32_t node, uint32_t layer,
               const std::vector<Neighbour>& candidates);
};

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_HNSW_H_
