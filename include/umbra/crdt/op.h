// The operations, and the byte encoding they travel and persist as.
//
// THE ENCODING BOUNDARY IS THE POINT OF THIS FILE. Encryption is a later phase,
// and the requirement is that adding it changes no CRDT logic. That is met by
// making the byte string the ONLY thing anything outside the CRDT ever sees:
//
//     Op  --EncodeOp-->  OpPayload (bytes)  --> oplog / relay
//     Op  <--DecodeOp--  OpPayload (bytes)  <-- oplog / relay
//
// An OpPayload is opaque. The oplog stores one, the relay forwards one, and
// neither looks inside. When encryption lands it wraps the payload at that
// boundary -- AEAD in, AEAD out -- and no code in text_doc.cc or anywhere else
// in this directory changes, because none of it has ever seen a payload.
//
// The one thing that must NOT be inside the payload is anything the sync
// protocol needs in the clear to route or order the operation. That is exactly
// the oplog key: object, replica, counter (see oplog.h). Those stay outside the
// payload today so that they can stay outside it when the payload is
// ciphertext, which is why the key is not simply "the encoded op".
#ifndef UMBRA_CRDT_OP_H_
#define UMBRA_CRDT_OP_H_

#include <cstdint>
#include <string>
#include <vector>

#include "umbra/crdt/op_id.h"

namespace umbra {

// Which side of its parent a node sits on. See text_doc.h for what this means
// and why the tree has sides at all.
enum class Side : uint8_t { kLeft = 0, kRight = 1 };

// A CLOSED enum; -Werror=switch is what makes adding a kind a build failure
// until every switch has classified it.
enum class OpKind : uint8_t { kInsert = 0, kDelete = 1 };

const char* OpKindName(OpKind k);

// One operation.
//
// INSERT carries a RUN of characters, not one character. The run occupies
// `id`, `id`+1, ... `id`+n-1 -- consecutive counters from one replica -- and its
// internal shape is implied rather than encoded: each character after the first
// is the right child of the one before it. That is not a compression trick, it
// is what the insert rule produces anyway when a run is typed left to right,
// so encoding it would be storing a derivable fact.
//
// DELETE names a run too: `id` through `id`+count-1. A deletion of a span that
// crosses several insert runs becomes several delete operations, one per
// maximal group of consecutive ids from one replica.
struct Op {
  OpKind kind = OpKind::kInsert;

  // Insert: the id of the run's FIRST character.
  // Delete: the id of the first character to remove.
  OpId id;

  // Insert only. The node this run's first character attaches to, and which
  // side of it. RootId() for the start of the document.
  OpId parent;
  Side side = Side::kRight;

  // Insert: the run's text, as Unicode scalar values. Not UTF-8 bytes: a node
  // holds a whole character so that no concurrent operation can ever split one.
  // See text_doc.h.
  std::vector<char32_t> text;

  // Delete: how many consecutive ids to remove. Always >= 1.
  uint32_t count = 0;

  // How many ids this operation consumes. An insert consumes one per
  // character; a delete consumes none, because it creates nothing.
  uint64_t IdSpan() const {
    return kind == OpKind::kInsert ? static_cast<uint64_t>(text.size()) : 0;
  }

  std::string ToString() const;
};

// Opaque bytes. Everything outside the CRDT handles operations as these.
struct OpPayload {
  std::string bytes;

  bool empty() const { return bytes.empty(); }
};

// Canonical, deterministic, versioned.
//
// DETERMINISM IS REQUIRED, not merely nice: two replicas that encoded the same
// operation differently would store different bytes under the same oplog key,
// and a future integrity check over the log would report a divergence that does
// not exist. There is exactly one encoding of any Op.
OpPayload EncodeOp(const Op& op);

// Returns false on anything malformed: a truncated buffer, an unknown version,
// an unknown kind, a delete with count 0, an insert with no text, or a
// character outside the Unicode scalar range. A malformed payload is a
// hostile or corrupt one and is refused rather than guessed at.
bool DecodeOp(const OpPayload& payload, Op* out);

// The version byte every payload starts with. Bumping it is how a future
// encoding change announces itself; a decoder that does not know a version
// refuses the payload rather than misreading it.
constexpr uint8_t kOpEncodingVersion = 1;

}  // namespace umbra

#endif  // UMBRA_CRDT_OP_H_
