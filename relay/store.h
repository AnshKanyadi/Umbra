// The relay's storage, and the whole of what a relay does.
//
// IT HOLDS NO KEYS AND DECRYPTS NOTHING. This header includes no crypto and no
// CRDT; the archive it builds into links neither. A payload is a string of
// bytes that arrives, is filed under four routing fields, and is handed back on
// request. If every payload were replaced with random noise of the same length,
// nothing here would behave differently -- which is the property being claimed
// and the reason the separation is enforced by the build rather than by
// intention.
//
// Storage is Basalt, keyed `vault || object || replica || counter(BE)`. That is
// ADR 0001's oplog key with the vault prepended, so a range scan answers a
// fetch cursor directly and the relay never needs an index it would have to
// understand to maintain.
#ifndef UMBRA_RELAY_STORE_H_
#define UMBRA_RELAY_STORE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "wire.h"

namespace umbra {
namespace relay {

// Closed; -Werror=switch applies.
enum class StoreStatus : uint8_t {
  kOk,
  kOpenFailed,
  kWriteFailed,
  kReadFailed,
  // The request did not decode, or asked for something outside its bounds. The
  // relay answers with an error and keeps the connection; a malformed request
  // is a bug or an attack and neither is a reason to lose the others.
  kBadRequest,
};

const char* StoreStatusName(StoreStatus s);

// How many blobs one fetch may return, whatever the client asks for.
//
// THE CAP IS THE RELAY'S, NOT THE CLIENT'S, and it is what keeps a small VPS
// alive: a client asking for four billion blobs gets this many. The client has
// its own, smaller bound for its own memory (see sync/client.h); this one
// exists because the relay cannot trust the client either.
constexpr uint32_t kMaxFetchBlobs = 512;

class Store {
 public:
  static StoreStatus Open(const std::string& dir, std::unique_ptr<Store>* out);
  ~Store();

  // Idempotent. Pushing the same blob twice stores it once, because a client
  // that crashed mid-push must be able to simply push again.
  StoreStatus Push(const PushRequest& req);

  // Strictly after `after`, in ascending counter order, at most
  // min(limit, kMaxFetchBlobs).
  StoreStatus Fetch(const FetchRequest& req, BlobsResponse* out);

  StoreStatus PutReport(const PutReportRequest& req);
  StoreStatus GetReports(const GetReportsRequest& req, ReportsResponse* out);

  // SEALED INDEX SEGMENTS, in pieces. The relay stores bytes under a name it
  // does not interpret; it never reassembles one, never verifies the content
  // hash, and cannot tell a segment from any other blob of the same size.
  StoreStatus PutSegment(const PutSegmentRequest& req);
  StoreStatus GetSegment(const GetSegmentRequest& req, SegmentResponse* out);
  StoreStatus ListSegments(const ListSegmentsRequest& req,
                           SegmentListResponse* out);

  // Enrolment envelopes. Opaque to the relay in both directions.
  StoreStatus PutEnvelope(const PutEnvelopeRequest& req);
  StoreStatus GetEnvelopes(const GetEnvelopesRequest& req,
                           EnvelopesResponse* out);

  // Durability. Basalt's Write never blocks on I/O; a relay that answered OK
  // before this returned would be promising something it had not done.
  StoreStatus Sync();

  // Diagnostics for the operator and for tests. Counting is all the relay can
  // do with what it holds.
  std::size_t BlobCount() const;

 private:
  Store();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Handle one request frame body and produce one response frame. The single
// entry point a server loop needs, and the reason the server and the store can
// be tested apart.
std::string HandleRequest(Store* store, const std::string& request_body);

}  // namespace relay
}  // namespace umbra

#endif  // UMBRA_RELAY_STORE_H_
