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

class OpLog {
 public:
  static LogStatus Open(const std::string& dir, std::unique_ptr<OpLog>* out);
  ~OpLog();

  // One atomic batch. Callers put an operation and everything it depends on in
  // the same call; see above.
  LogStatus Append(const ObjectId& object, const std::vector<Op>& ops);

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

  // Basalt's Write never blocks on I/O; this is the durability point. An
  // operation is not published until this has returned for the batch that
  // holds it.
  LogStatus Sync();

 private:
  OpLog();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace umbra

#endif  // UMBRA_CRDT_OPLOG_H_
