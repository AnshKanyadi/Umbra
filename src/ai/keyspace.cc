#include "keyspace.h"

namespace umbra {
namespace ai {

std::string PrefixUpperBound(const std::string& prefix) {
  std::string out = prefix;
  while (!out.empty()) {
    const uint8_t last = static_cast<uint8_t>(out.back());
    if (last != 0xFF) {
      out.back() = static_cast<char>(last + 1);
      return out;
    }
    out.pop_back();
  }
  return std::string();
}

}  // namespace ai
}  // namespace umbra
