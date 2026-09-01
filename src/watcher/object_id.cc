#include "object_id.h"

#include <random>

namespace umbra {
namespace {

class RandomSource : public ObjectIdSource {
 public:
  ObjectId Next() override {
    ObjectId id;
    for (std::size_t i = 0; i < id.bytes.size(); ++i) {
      id.bytes[i] = static_cast<uint8_t>(dist_(rd_));
    }
    return id;
  }

 private:
  std::random_device rd_;
  // uniform_int_distribution<uint8_t> is not permitted by the standard; the
  // smallest allowed integer type is used and narrowed explicitly above.
  std::uniform_int_distribution<unsigned int> dist_{0, 255};
};

class SequentialSource : public ObjectIdSource {
 public:
  explicit SequentialSource(uint64_t first) : next_(first) {}

  ObjectId Next() override {
    ObjectId id;
    const uint64_t v = next_++;
    for (int i = 0; i < 8; ++i) {
      id.bytes[8 + i] = static_cast<uint8_t>((v >> (56 - (8 * i))) & 0xff);
    }
    return id;
  }

 private:
  uint64_t next_;
};

}  // namespace

std::unique_ptr<ObjectIdSource> MakeRandomObjectIdSource() {
  return std::unique_ptr<ObjectIdSource>(new RandomSource());
}

std::unique_ptr<ObjectIdSource> MakeSequentialObjectIdSource(uint64_t first) {
  return std::unique_ptr<ObjectIdSource>(new SequentialSource(first));
}

}  // namespace umbra
