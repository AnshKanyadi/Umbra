// Where ObjectIds come from.
//
// Behind an interface for ONE reason: the tests need identities they can
// predict, and the vault needs identities the relay cannot. Those are opposite
// requirements and neither should be compromised to serve the other.
#ifndef UMBRA_WATCHER_OBJECT_ID_H_
#define UMBRA_WATCHER_OBJECT_ID_H_

#include <memory>

#include "umbra/change_event.h"

namespace umbra {

class ObjectIdSource {
 public:
  virtual ~ObjectIdSource() = default;
  virtual ObjectId Next() = 0;
};

// Draws from the platform entropy source.
//
// std::random_device IS NOT PROMISED TO BE A CSPRNG by the standard, and on
// some implementations it is a PRNG with a fixed seed. On the two platforms
// this project builds for it reads from the kernel's entropy pool, which is
// adequate for an identifier whose only security property is that the relay
// cannot correlate it with a filename. THE CRYPTO PHASE SHOULD REPLACE THIS
// with the same CSPRNG that generates key material, at which point this comment
// becomes the record of what was there before.
std::unique_ptr<ObjectIdSource> MakeRandomObjectIdSource();

// Counts up from `first`, big-endian in the last 8 bytes. TESTS ONLY: an ID
// that is a counter is exactly what the threat model forbids on the wire.
std::unique_ptr<ObjectIdSource> MakeSequentialObjectIdSource(uint64_t first);

}  // namespace umbra

#endif  // UMBRA_WATCHER_OBJECT_ID_H_
