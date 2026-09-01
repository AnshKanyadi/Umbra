// The normalized change event: what the vault watcher hands to everything
// downstream of it.
//
// THIS TYPE IS THE BOUNDARY. Above it there are inotify cookies, FSEvents
// flags, temp files, editor save strategies and inode numbers; below it there
// is an object identity, a kind, and a digest of the bytes. Nothing about which
// backend produced the event survives the crossing, and neither does anything
// about HOW the user's editor happened to write the file.
//
// NO CRDT OPS AND NO CIPHERTEXT PASS THROUGH HERE. A change event says that an
// object now has certain content; deciding what operation that implies, and
// encrypting anything, are later phases and different types.
#ifndef UMBRA_CHANGE_EVENT_H_
#define UMBRA_CHANGE_EVENT_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace umbra {

// The opaque per-file identity the relay sees.
//
// It is NOT derived from the path, and that is a threat-model requirement
// rather than an implementation convenience: docs/threat-model.md puts file
// paths and directory structure inside the confidentiality boundary, so an ID
// the relay can correlate with a name -- including by observing that the same
// name always produces the same ID -- would leak the thing the design is
// protecting. IDs are drawn from an entropy source and the path-to-ID mapping
// lives only on the client.
//
// 128 bits. Random IDs collide at ~2^64 objects by the birthday bound, which is
// not a bound this application can reach.
struct ObjectId {
  std::array<uint8_t, 16> bytes{};

  bool operator==(const ObjectId& o) const { return bytes == o.bytes; }
  bool operator!=(const ObjectId& o) const { return !(*this == o); }
  bool operator<(const ObjectId& o) const { return bytes < o.bytes; }

  // Lowercase hex, 32 characters. For logs and for test failure messages; it is
  // not a wire format.
  std::string ToHex() const;
};

// A digest of a file's contents: unkeyed BLAKE2b-256, via libsodium's
// crypto_generichash.
//
// THE SAME FUNCTION NAMES BLOBS. ADR 0001 makes the encrypted vector-index
// segment store content-addressed, so this digest is not only a change detector
// -- a collision there means one segment silently standing in for another,
// which is an integrity failure rather than a missed sync. That is why it is a
// cryptographic hash and why the choice is not a local one.
//
// BLAKE2b rather than SHA-256: libsodium is already the dependency the rest of
// the crypto design needs, crypto_generichash is its recommended general hash,
// and it is faster than SHA-256 on the platforms this targets without needing
// hardware support to be so.
//
// The digest is computed over the bytes AS THEY ARE ON DISK -- plaintext, at
// this layer. Where content addressing is applied to a segment it is applied to
// the CIPHERTEXT, for the reason ADR 0001 gives: hashing plaintext would make
// the name a fingerprint of the content, which is the leak the threat model
// rules out for paths.
struct ContentHash {
  std::array<uint8_t, 32> bytes{};

  bool operator==(const ContentHash& o) const { return bytes == o.bytes; }
  bool operator!=(const ContentHash& o) const { return !(*this == o); }

  // All-zero. What a kDeleted event carries, because there is no content to
  // describe. A real digest of empty input is NOT zero, so this is
  // distinguishable from "hashed an empty file".
  static ContentHash Zero() { return ContentHash{}; }
  bool IsZero() const;

  std::string ToHex() const;
};

// Digest of an arbitrary byte range. See the warning on ContentHash.
ContentHash HashBytes(const void* data, std::size_t len);

// A CLOSED enum. -Werror=switch is set project-wide precisely so that adding a
// kind here fails every switch that has not classified it, rather than letting
// the sync engine silently drop a change it does not recognize. Do not add a
// `default:` arm to any switch over this type.
enum class ChangeKind : uint8_t {
  // The object did not exist in the last known state and does now.
  kCreated,
  // The object existed and its CONTENT DIGEST CHANGED. A write that leaves the
  // bytes identical produces no event at all.
  kModified,
  // The object existed and does not now.
  kDeleted,
  // The object existed at `old_path` and now exists at `path`, with identity
  // preserved. See ChangeEvent::hash for what a move says about content.
  kMoved,
};

// Human-readable, for test failures and logs. Total over ChangeKind.
const char* ChangeKindName(ChangeKind k);

struct ChangeEvent {
  ChangeKind kind = ChangeKind::kCreated;

  // Stable across kMoved. This is the whole point of having an ID that is not
  // the path.
  ObjectId id;

  // The digest of the content AFTER the change. ContentHash::Zero() for
  // kDeleted.
  //
  // A kMoved event carries a real digest, and it is NOT a promise that the
  // content is unchanged: a file moved and edited inside one debounce window
  // produces a single kMoved whose hash differs from the one the consumer last
  // recorded. Consumers compare rather than assume.
  ContentHash hash;

  // Vault-relative, '/'-separated, no leading slash. CLIENT-SIDE ONLY -- this
  // field exists because the watcher is the component that owns the path-to-ID
  // mapping, and it must never be serialized towards a relay.
  std::string path;

  // kMoved only; empty otherwise.
  std::string old_path;
};

}  // namespace umbra

#endif  // UMBRA_CHANGE_EVENT_H_
