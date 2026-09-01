#include "umbra/crdt/op.h"

#include <cstring>

#include "check.h"

namespace umbra {
namespace {

void PutU8(uint8_t v, std::string* out) {
  out->push_back(static_cast<char>(v));
}

// Little-endian, fixed width. Fixed rather than varint: the encoding must be
// canonical, and a varint has a second spelling for the same number unless the
// decoder rejects non-minimal forms, which is one more thing to get right for a
// few bytes.
void PutU32(uint32_t v, std::string* out) {
  for (int i = 0; i < 4; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
}

void PutU64(uint64_t v, std::string* out) {
  for (int i = 0; i < 8; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
}

void PutOpId(const OpId& id, std::string* out) {
  PutU64(id.counter, out);
  out->append(reinterpret_cast<const char*>(id.replica.bytes.data()),
              id.replica.bytes.size());
}

struct Reader {
  const std::string* s;
  std::size_t pos = 0;

  bool Need(std::size_t n) const { return pos + n <= s->size(); }
  bool U8(uint8_t* v) {
    if (!Need(1)) return false;
    *v = static_cast<uint8_t>((*s)[pos++]);
    return true;
  }
  bool U32(uint32_t* v) {
    if (!Need(4)) return false;
    *v = 0;
    for (int i = 0; i < 4; ++i) {
      *v |= static_cast<uint32_t>(static_cast<unsigned char>((*s)[pos + i]))
            << (8 * i);
    }
    pos += 4;
    return true;
  }
  bool U64(uint64_t* v) {
    if (!Need(8)) return false;
    *v = 0;
    for (int i = 0; i < 8; ++i) {
      *v |= static_cast<uint64_t>(static_cast<unsigned char>((*s)[pos + i]))
            << (8 * i);
    }
    pos += 8;
    return true;
  }
  bool Id(OpId* id) {
    if (!U64(&id->counter)) return false;
    if (!Need(id->replica.bytes.size())) return false;
    std::memcpy(id->replica.bytes.data(), s->data() + pos,
                id->replica.bytes.size());
    pos += id->replica.bytes.size();
    return true;
  }
};

}  // namespace

const char* OpKindName(OpKind k) {
  switch (k) {
    case OpKind::kInsert:
      return "insert";
    case OpKind::kDelete:
      return "delete";
  }
  return "unknown";
}

std::string Op::ToString() const {
  std::string s = std::string(OpKindName(kind)) + " " + id.ToString();
  if (kind == OpKind::kInsert) {
    s += " under " + parent.ToString() + (side == Side::kLeft ? " L" : " R") +
         " x" + std::to_string(text.size());
  } else {
    s += " x" + std::to_string(count);
  }
  return s;
}

OpId LastId(const Op& op) {
  switch (op.kind) {
    case OpKind::kInsert:
      UMBRA_CHECK(!op.text.empty(), "an insert with no text has no last id");
      return op.id.Plus(op.text.size() - 1);
    case OpKind::kDelete:
      // A delete creates nothing, so it occupies only its own id.
      return op.id;
  }
  return op.id;
}

OpPayload EncodeOp(const Op& op) {
  OpPayload p;
  std::string& out = p.bytes;
  PutU8(kOpEncodingVersion, &out);
  PutU8(static_cast<uint8_t>(op.kind), &out);
  PutOpId(op.id, &out);
  switch (op.kind) {
    case OpKind::kInsert:
      PutOpId(op.parent, &out);
      PutU8(static_cast<uint8_t>(op.side), &out);
      PutU32(static_cast<uint32_t>(op.text.size()), &out);
      for (char32_t c : op.text) PutU32(static_cast<uint32_t>(c), &out);
      break;
    case OpKind::kDelete:
      PutU32(op.count, &out);
      break;
  }
  return p;
}

bool DecodeOp(const OpPayload& payload, Op* out) {
  Reader r{&payload.bytes, 0};
  uint8_t version = 0;
  if (!r.U8(&version)) return false;
  if (version != kOpEncodingVersion) return false;

  uint8_t kind = 0;
  if (!r.U8(&kind)) return false;
  if (kind > static_cast<uint8_t>(OpKind::kDelete)) return false;
  *out = Op();
  out->kind = static_cast<OpKind>(kind);

  if (!r.Id(&out->id)) return false;
  // counter 0 is the root, which is not an operation.
  if (out->id.counter == 0) return false;

  switch (out->kind) {
    case OpKind::kInsert: {
      if (!r.Id(&out->parent)) return false;
      uint8_t side = 0;
      if (!r.U8(&side)) return false;
      if (side > static_cast<uint8_t>(Side::kRight)) return false;
      out->side = static_cast<Side>(side);
      uint32_t n = 0;
      if (!r.U32(&n)) return false;
      if (n == 0) return false;  // an insert of nothing is not an operation
      // A length that would need more bytes than remain is a truncated or
      // hostile payload; refuse before allocating for it.
      if (!r.Need(static_cast<std::size_t>(n) * 4)) return false;
      out->text.reserve(n);
      for (uint32_t i = 0; i < n; ++i) {
        uint32_t c = 0;
        if (!r.U32(&c)) return false;
        if (c > 0x10FFFF) return false;
        if (c >= 0xD800 && c <= 0xDFFF) return false;
        out->text.push_back(static_cast<char32_t>(c));
      }
      break;
    }
    case OpKind::kDelete:
      if (!r.U32(&out->count)) return false;
      if (out->count == 0) return false;
      break;
  }
  // Trailing bytes mean the payload is not what this decoder thinks it is.
  return r.pos == payload.bytes.size();
}

}  // namespace umbra
