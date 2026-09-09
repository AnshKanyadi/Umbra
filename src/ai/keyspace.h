// Key ranges for the index manifest.
//
// This exists as its own header for one reason: the prefix upper bound was
// wrong, the bug was invisible on one platform and fatal on another, and it
// cannot be reached from the outside on demand -- it depends on a
// content-addressed segment id happening to begin with 0xFF, which is about one
// segment in two hundred and fifty six. A test that waited for that to happen
// would be a test that usually proves nothing.
//
// So the arithmetic lives here where a test can call it with the exact input
// that breaks it.
#ifndef UMBRA_AI_KEYSPACE_H_
#define UMBRA_AI_KEYSPACE_H_

#include <cstdint>
#include <string>

namespace umbra {
namespace ai {

// The smallest key strictly greater than every key beginning with `prefix`.
//
// THE OBVIOUS ANSWER IS WRONG. Appending 0xFF gives a bound that excludes every
// key whose next byte is 0xFF, which for the index's object keys -- 'o' ||
// object || segment || slot -- means every segment whose id starts with 0xFF is
// invisible to the scan that finds an object's previous chunks. Deleting or
// re-indexing that object then leaves those slots live and answering queries.
//
// Returns empty when the prefix is all 0xFF and therefore has no successor.
// A caller must read that as "scan to the end", not as "scan nothing".
std::string PrefixUpperBound(const std::string& prefix);

}  // namespace ai
}  // namespace umbra

#endif  // UMBRA_AI_KEYSPACE_H_
