// The operation log, in Basalt.
//
// ADR 0001 put the op log in Basalt because it is small, ordered, append-heavy
// state with real churn. This is that decision made concrete.
//
// ---------------------------------------------------------------------------
// THE KEY, AND WHY IT IS NOT SIMPLY THE ENCODED OPERATION
//
//     object_id (16)  ||  replica_id (16)  ||  counter (8, BIG-endian)
//
// Big-endian on purpose: Basalt orders keys by bytes, so a big-endian counter
// makes byte order and numeric order the same thing, and "everything from
// replica R after counter C" becomes one range scan rather than a filter over
// the whole object.
//
// EVERYTHING THE SYNC PROTOCOL NEEDS TO ROUTE OR ORDER AN OPERATION IS IN THE
// KEY, AND NOTHING ELSE IS. That is the shape encryption needs: the value is an
// OpPayload, already opaque to everything outside the CRDT, and when it becomes
// ciphertext the relay can still address and order operations without being
// able to read one. If the counter lived only inside the encoded operation, a
// relay could not answer "what have I not seen" without decrypting, and the
// design would have to be reopened.
//
// The object id is in the key rather than being a separate column family
// because a vault is one Basalt instance and a scan bounded by object prefix is
// what "open this note" needs.
//
// ---------------------------------------------------------------------------
// WHAT A COMMIT MUST CONTAIN, WHICH THE HARNESS ESTABLISHED
//
// THE LOG MUST BE CAUSALLY CLOSED: every operation in it has its dependencies
// in it too. Not merely ordered -- closed. Replay buffers operations that
// arrive before their parents, so ORDER inside the log does not matter, but a
// dependency that was never written at all is one replay can never satisfy and
// the document cannot be rebuilt.
//
// The consequence for callers: an operation this replica produced and the
// remote operations it was built on top of go down in ONE BATCH. Basalt's
// WriteBatch is atomic, which is why it is the unit here rather than one key
// per operation. The convergence harness found this the hard way -- see the
// note on Sim::Originate in sim/sim.cc.
//
// AND AN OPERATION MUST BE DURABLE BEFORE IT IS PUBLISHED. A replica that sends
// first and logs second, then crashes, rebuilds its Lamport clock from a log
// that is missing what it already sent -- and reissues those ids for different
// content. Also found by the harness.
#ifndef UMBRA_CRDT_OPLOG_H_
#define UMBRA_CRDT_OPLOG_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "umbra/change_event.h"
#include "umbra/crdt/op.h"
#include "umbra/crdt/op_id.h"
#include "umbra/crdt/text_doc.h"
#include "umbra/crdt/tree.h"
#include "umbra/crypto/keys.h"

namespace umbra {

// Closed; -Werror=switch applies.
enum class LogStatus : uint8_t {
  kOk,
  kOpenFailed,
  kWriteFailed,
  kReadFailed,
  // A stored payload did not decode. The log is corrupt or was written by
  // something else; it is refused rather than skipped, because silently
  // dropping an operation is how a replica diverges without anybody noticing.
  kCorrupt,
  // Replay could not satisfy every operation's dependencies. The log is not
  // causally closed; see the note above.
  kNotClosed,
};

const char* LogStatusName(LogStatus s);

// The key layout, exposed because the sync protocol and the tests both need to
// build and parse one, and two implementations of a wire format is one too
// many.
constexpr std::size_t kOpLogKeyBytes = 16 + 16 + 8;
std::string MakeOpLogKey(const ObjectId& object, const ReplicaId& replica,
                         uint64_t counter);
bool ParseOpLogKey(const std::string& key, ObjectId* object, ReplicaId* replica,
                   uint64_t* counter);

// An operation as the log stores it: an identity for the key, and bytes.
//
// THE LOG DOES NOT KNOW WHAT KIND OF OPERATION IT IS HOLDING, and that is the
// point. Text operations and tree operations both reduce to this, so both get
// the same key layout, the same atomic batching and -- when it lands -- the
// same encryption, without the log growing a switch over kinds.
struct LoggedOp {
  OpId id;
  OpPayload payload;
};

// The envelope a stored value carries outside the ciphertext.
//
// Only the epoch, and only because the reader has to know WHICH KEY GENERATION
// sealed the payload before it can open it. Four bytes in the clear, which the
// threat model already concedes -- a relay can count rotations, and knowing a
// vault rotated is not knowing anything about its contents.
constexpr std::size_t kEnvelopeBytes = 4;

// An operation exactly as it is stored: still sealed, with the epoch that
// sealed it.
//
// PUSHED TO A RELAY VERBATIM, and that is not an optimization. Decrypting and
// re-sealing would draw a fresh nonce, so the same operation would produce
// different bytes on every push and the relay could not recognise a repeat. A
// client that crashed mid-push would then store the operation twice under
// different ciphertext, and idempotency -- the thing that makes a crashed push
// safe to simply retry -- would be gone.
struct StoredBlob {
  OpId id;
  uint32_t epoch = 0;
  std::string sealed;
};

class OpLog {
 public:
  // Without keys: payloads are stored as-is. Used by tests that are about the
  // log rather than about the crypto, and by nothing else.
  static LogStatus Open(const std::string& dir, std::unique_ptr<OpLog>* out);

  // WITH KEYS, WHICH IS THE REAL CONFIGURATION. Every payload is sealed on the
  // way in and opened on the way out, and NOTHING ELSE IN THE SYSTEM CHANGES:
  // the CRDTs hand this an opaque OpPayload and get one back, exactly as they
  // did before there was any encryption. `keys` is not owned and must outlive
  // the log.
  static LogStatus OpenEncrypted(const std::string& dir, const VaultKeys* keys,
                                 std::unique_ptr<OpLog>* out);
  ~OpLog();

  // The one write path. Everything below encodes to this.
  LogStatus AppendRaw(const ObjectId& object, const std::vector<LoggedOp>& ops);
  // The one read path.
  LogStatus ReadRaw(const ObjectId& object, std::vector<LoggedOp>* out) const;

  // One atomic batch. Callers put an operation and everything it depends on in
  // the same call; see above.
  LogStatus Append(const ObjectId& object, const std::vector<Op>& ops);

  // Tree operations are filed under the reserved TreeObject(), so the vault's
  // shape is one more object in the same log with the same key layout.
  LogStatus AppendTree(const std::vector<TreeOp>& ops);
  LogStatus ReadTree(std::vector<TreeOp>* out) const;
  // Rebuild the tree. There is no causally-closed requirement here: tree
  // operations are never not-ready, so any order works and a missing parent
  // leaves a node detached rather than stuck. See ADR 0003.
  LogStatus ReplayTree(TreeDoc* tree,
                       std::map<ReplicaId, uint64_t>* high_water) const;

  // Everything stored for one object, in (replica, counter) order -- which is
  // NOT apply order, and does not need to be.
  LogStatus ReadObject(const ObjectId& object, std::vector<Op>* out) const;

  // Rebuild a document. Buffers operations whose dependencies have not been
  // seen yet and drains until nothing moves; returns kNotClosed if anything is
  // left, which means the log is missing something it refers to.
  //
  // Also returns the highest counter seen per replica, which is what a
  // recovered replica must load its Lamport clock from -- see the note about
  // reissued ids above.
  LogStatus Replay(const ObjectId& object, TextDoc* doc,
                   std::map<ReplicaId, uint64_t>* high_water) const;

  // The sync cursor: everything from one replica strictly after `after`.
  LogStatus ReadFrom(const ObjectId& object, const ReplicaId& replica,
                     uint64_t after, std::vector<Op>* out) const;

  // Stored form, undecrypted, from one source after a counter. What push uses.
  LogStatus ReadStoredFrom(const ObjectId& object, const ReplicaId& replica,
                           uint64_t after, std::vector<StoredBlob>* out) const;

  // Which replicas have written to this object, and how far one has got.
  bool SourcesFor(const ObjectId& object, std::vector<ReplicaId>* out) const;
  bool HighestFrom(const ObjectId& object, const ReplicaId& replica,
                   uint64_t* out) const;

  // ----------------------------------------------------------- cursors
  //
  // Durable, in the same store as the log, because a cursor that survived a
  // crash differently from the operations it describes would be worse than no
  // cursor at all. Keyed under a reserved prefix so they cannot collide with an
  // operation.
  bool GetCursor(const ObjectId& object, const ReplicaId& source,
                 uint64_t* out) const;
  bool SetCursor(const ObjectId& object, const ReplicaId& source,
                 uint64_t value);

  // Basalt's Write never blocks on I/O; this is the durability point. An
  // operation is not published until this has returned for the batch that
  // holds it.
  LogStatus Sync();

 private:
  OpLog();
  // Every read goes through here, which is where decryption happens. See the
  // note in oplog.cc: having three readers is how two of them ended up handing
  // ciphertext to a decoder.
  LogStatus ReadBounded(const ObjectId& object, const std::string& lo,
                        const std::string& hi_exclusive,
                        std::vector<LoggedOp>* out) const;
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace umbra

#endif  // UMBRA_CRDT_OPLOG_H_
