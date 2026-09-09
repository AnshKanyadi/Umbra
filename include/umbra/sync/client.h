// The sync client: cursors, chain verification, backpressure.
//
// ---------------------------------------------------------------------------
// THE CURSOR IS THE PREFIX MARK
//
// ADR 0003's compaction condition needs "I hold everything from S at or below
// counter c". A cursor is exactly that claim, and it is true because of two
// things together:
//
//   1. Fetch is ordered by counter. The relay's key layout makes a range scan
//      ascending, and the client checks it rather than trusting it.
//   2. Every operation names its predecessor, so a skipped one is visible.
//      Ordering alone is not enough -- counters are 7.5 to 18 per cent dense
//      per object, so a hole is ambiguous without the chain. ADR 0001,
//      "Ordering is not completeness".
//
// THE CURSOR ADVANCES ONLY ACROSS A VERIFIED CHAIN. On any break it stops where
// it was and the fetch reports it. That is what makes a withheld operation safe
// rather than silently lost: the mark stays truthful, so the watermark stays
// low, so nothing is compacted that anyone still needs.
//
// ---------------------------------------------------------------------------
// RESUMABLE AND BOUNDED
//
// A fetch is a loop of windows. Each window is applied and its cursor written
// before the next is asked for, so a client that dies mid-sync resumes from the
// last verified operation and never has to start over. A device rejoining after
// a month walks the backlog in windows of kFetchWindow and never holds more
// than that; the relay caps it again on its own side, because neither party
// trusts the other's bound.
#ifndef UMBRA_SYNC_CLIENT_H_
#define UMBRA_SYNC_CLIENT_H_

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "umbra/crdt/oplog.h"
#include "umbra/crdt/text_doc.h"
#include "umbra/crdt/tree.h"
#include "umbra/crypto/keys.h"
#include "umbra/sync/report.h"
#include "wire.h"

namespace umbra {
namespace sync {

// How many operations one fetch window holds. Small enough that a month of
// backlog is many bounded steps rather than one unbounded one.
constexpr uint32_t kFetchWindow = 64;

// Closed; -Werror=switch applies.
enum class SyncStatus : uint8_t {
  kOk,
  // The transport failed. Retryable, and the cursor has not moved.
  kUnreachable,
  // The relay answered with something that does not decode. Not retryable
  // against this relay.
  kBadResponse,
  // THE CHAIN BROKE. The relay served an operation whose predecessor this
  // client has not reached, which means it skipped one. The cursor is left
  // where it was and nothing was applied. Not an error the client can fix; it
  // is the relay misbehaving, and it is reported so a user can be told.
  kChainBroken,
  // The relay served operations out of counter order.
  kOutOfOrder,
  // A payload did not open. Wrong epoch, tampering, or a ciphertext moved to a
  // different key.
  kAuthFailed,
  // A sealed report did not open, or claimed to be from a device other than the
  // one it was filed under.
  kBadReport,
  kLocalError,
};

const char* SyncStatusName(SyncStatus s);

// What the client talks to. Abstract so the harness can substitute a relay that
// drops, reorders, replays and lies, which is the only way to test that the
// client survives one.
class Transport {
 public:
  virtual ~Transport() = default;
  virtual bool Push(const relay::PushRequest& req) = 0;
  virtual bool Fetch(const relay::FetchRequest& req,
                     relay::BlobsResponse* out) = 0;
  virtual bool PutReport(const relay::PutReportRequest& req) = 0;
  virtual bool GetReports(const relay::GetReportsRequest& req,
                          relay::ReportsResponse* out) = 0;
  virtual bool PutEnvelope(const relay::PutEnvelopeRequest& req) = 0;
  virtual bool GetEnvelopes(const relay::GetEnvelopesRequest& req,
                            relay::EnvelopesResponse* out) = 0;
  virtual bool PutSegment(const relay::PutSegmentRequest& req) = 0;
  virtual bool GetSegment(const relay::GetSegmentRequest& req,
                          relay::SegmentResponse* out) = 0;
  virtual bool ListSegments(const relay::ListSegmentsRequest& req,
                            relay::SegmentListResponse* out) = 0;
};

// A real one, over TCP.
std::unique_ptr<Transport> NewTcpTransport(const std::string& host,
                                           uint16_t port,
                                           int timeout_seconds = 30);

struct FetchStats {
  std::size_t fetched = 0;
  std::size_t applied = 0;
  std::size_t duplicates = 0;
  std::size_t windows = 0;
  uint64_t cursor_before = 0;
  uint64_t cursor_after = 0;
};

class Client {
 public:
  // `keys`, `log` and `transport` are not owned and must outlive this.
  Client(const relay::VaultId& vault, const ReplicaId& self, VaultKeys* keys,
         OpLog* log, Transport* transport);

  // Send everything from `object` that this device has produced and not yet
  // pushed. Idempotent: the relay stores a repeated blob once, so a client that
  // crashed mid-push simply pushes again.
  SyncStatus PushObject(const ObjectId& object, std::size_t* pushed);

  // Pull from one source, verifying the chain, applying as it goes, writing the
  // cursor after each window. `apply` is called for each verified payload in
  // order; returning false stops the fetch without advancing past that point.
  SyncStatus FetchObject(const ObjectId& object, const ReplicaId& source,
                         const std::function<bool(const OpPayload&)>& apply,
                         FetchStats* stats);

  // Cursors, durable in the oplog's store.
  uint64_t Cursor(const ObjectId& object, const ReplicaId& source) const;

  // Publish this device's compaction report, sealed. `have` is built from the
  // cursors, which is what makes it a claim this device can honestly make.
  // Enrolment. The client does not interpret an envelope; it moves bytes
  // between a device and the relay and the crypto in enroll.h does the rest.
  SyncStatus PublishEnvelope(const std::array<uint8_t, 32>& tag,
                             const std::string& body);
  SyncStatus CollectEnvelopes(std::vector<relay::Envelope>* out);

  // SEALED INDEX SEGMENTS, PUSHED AND PULLED IN PIECES. The client stitches;
  // the relay never holds a whole one in memory and never sees inside it. A
  // pull that stops partway resumes from the offset it reached rather than
  // starting again, which matters when a segment is tens of megabytes over a
  // link that drops.
  // The id is raw bytes here rather than ai::SegmentId ON PURPOSE: the sync
  // layer moves opaque blobs and must not depend on the layer that gives them
  // meaning. Phase 3's relay does not link the CRDTs for the same reason.
  SyncStatus PushSegment(const std::array<uint8_t, 32>& id,
                         const std::string& sealed);
  SyncStatus PullSegment(const std::array<uint8_t, 32>& id,
                         std::string* sealed);
  SyncStatus ListSegments(std::vector<std::array<uint8_t, 32>>* ids,
                          std::vector<uint64_t>* sizes);

  SyncStatus PublishReport(uint64_t clock, const std::vector<ObjectId>& objects,
                           const ReplicaId& tree_object_source_hint);

  // Collect every device's report and compute the watermark. Reports that do
  // not open, or that claim a device other than the one they were filed under,
  // are DROPPED rather than failing the whole collection: a relay that stores
  // one bad report must not be able to stop compaction reasoning entirely.
  SyncStatus CollectReports(const std::vector<ReplicaId>& enrolled,
                            uint64_t* watermark, std::size_t* refused);

  // Is the relay serving a stale view? True when some device's own report says
  // it has produced past what this client's cursor for it has reached.
  //
  // DETECTION, NOT PREVENTION. Threat model §5.6: a relay that withholds
  // indefinitely holds compaction hostage and there is nothing the protocol can
  // do about it beyond telling the user.
  bool RelayLooksStale(const std::vector<ReplicaId>& enrolled,
                       std::string* why);

 private:
  SyncStatus LoadCursor(const ObjectId& object, const ReplicaId& source,
                        uint64_t* out) const;
  SyncStatus StoreCursor(const ObjectId& object, const ReplicaId& source,
                         uint64_t value);

  relay::VaultId vault_;
  ReplicaId self_;
  VaultKeys* keys_;
  OpLog* log_;
  Transport* transport_;
  mutable std::map<std::pair<ObjectId, ReplicaId>, uint64_t> cursor_cache_;
  std::map<ReplicaId, DeviceReport> last_reports_;
};

}  // namespace sync
}  // namespace umbra

#endif  // UMBRA_SYNC_CLIENT_H_
