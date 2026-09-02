// The relay wire protocol.
//
// THE RELAY MUST NOT NEED TO UNDERSTAND AN OPERATION TO ROUTE IT, and this file
// is where that is either true or false. Every request carries, in the clear,
// exactly the four things routing needs -- vault, object, replica, counter --
// and one opaque blob. The relay never decodes the blob, has no key that could,
// and would behave identically if the blob were random bytes.
//
// Those four fields are the oplog key from ADR 0001 plus the vault. They are
// already conceded to the relay in the threat model (§3, §5.3, §5.5), so putting
// them in the clear costs nothing that was not already spent, and it is what
// lets a range fetch happen without decryption.
//
// FRAMING: every message is a 4-byte little-endian length followed by that many
// bytes. The length excludes itself. A frame larger than kMaxFrameBytes is
// refused before it is read, so a hostile peer cannot make either side allocate
// without bound -- that applies to the CLIENT reading a relay's response just as
// much as the other way round, because the relay is the hostile party here.
#ifndef UMBRA_RELAY_WIRE_H_
#define UMBRA_RELAY_WIRE_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace umbra {
namespace relay {

// THE RELAY HAS ITS OWN ID TYPE AND DOES NOT SHARE THE CRDT'S, which is not
// duplication for its own sake. `umbra::ObjectId` and `umbra::ReplicaId` live in
// headers that also declare operations, documents and keys; including them here
// would put the vocabulary of things the relay must not understand within reach
// of the code that must not understand them. Sixteen opaque bytes is the entire
// contract, and this is what that looks like when it is enforced by the type
// system rather than by resolve.
struct Id16 {
  std::array<uint8_t, 16> bytes{};
  bool operator==(const Id16& o) const { return bytes == o.bytes; }
  bool operator!=(const Id16& o) const { return !(*this == o); }
  bool operator<(const Id16& o) const { return bytes < o.bytes; }
  std::string ToHex() const;
};

using ObjectId = Id16;
using ReplicaId = Id16;

// 8 MiB. Large enough for a batch of operations over a fat pipe, small enough
// that a hostile frame length cannot exhaust a small VPS.
constexpr uint32_t kMaxFrameBytes = 8u * 1024 * 1024;

// A household, not a fleet. Enrolment envelopes are a handful per vault and a
// relay claiming more than this is either broken or trying to make a client
// allocate on its say-so.
constexpr uint32_t kMaxEnvelopes = 256;

// A vault is identified by an opaque 16-byte id, like everything else the relay
// sees. It is NOT derived from the passphrase or from any key: a relay hosting
// several vaults must be able to tell them apart without that telling it
// anything about them.
using VaultId = Id16;

// Closed; -Werror=switch applies.
enum class Op : uint8_t {
  kPush = 1,          // client -> relay: store these blobs
  kFetch = 2,         // client -> relay: give me blobs after a cursor
  kPutReport = 3,     // client -> relay: store my sealed compaction report
  kGetReports = 4,    // client -> relay: give me every device's sealed report
  kPutEnvelope = 5,   // client -> relay: hold this enrolment envelope
  kGetEnvelopes = 6,  // client -> relay: give me every envelope in this vault
  kOk = 100,          // relay -> client
  kBlobs = 101,       // relay -> client
  kReports = 102,     // relay -> client
  kEnvelopes = 104,   // relay -> client
  kError = 103,       // relay -> client
};

const char* OpName(Op o);

// One stored item. The relay treats `payload` as bytes and nothing else.
struct Blob {
  ObjectId object;
  ReplicaId replica;
  uint64_t counter = 0;
  // Epoch is in the clear because a reader must know which key generation
  // sealed the payload before it can open it; see oplog.h. The relay does not
  // use it for anything.
  uint32_t epoch = 0;
  std::string payload;
};

struct PushRequest {
  VaultId vault;
  std::vector<Blob> blobs;
};

struct FetchRequest {
  VaultId vault;
  ObjectId object;
  ReplicaId replica;
  // Strictly after this counter. Zero fetches from the beginning.
  uint64_t after = 0;
  // BOUNDED, and the bound is the client's. A device rejoining after a month
  // must not ask for the whole backlog at once; it walks the cursor in windows.
  uint32_t limit = 0;
};

struct BlobsResponse {
  std::vector<Blob> blobs;
  // True when the relay has more beyond what it returned. Advisory only: a
  // client that trusted it would be trusting the relay, so it is used to decide
  // whether to ask again and never to decide that a fetch is complete.
  bool more = false;
};

// A device's compaction report, sealed under the epoch key. The relay stores
// and returns it verbatim; it cannot read it and cannot forge one.
struct SealedReport {
  ReplicaId device;
  uint32_t epoch = 0;
  std::string sealed;
};

// AN OPAQUE ENVELOPE. The relay does not know a request from a grant: both are
// bytes under a 32-byte tag it never interprets. It cannot even tell which
// direction an enrolment is going, only that one is happening -- which is
// recorded in docs/threat-model.md rather than claimed away.
struct Envelope {
  std::array<uint8_t, 32> tag{};
  std::string body;
};

struct PutEnvelopeRequest {
  VaultId vault;
  Envelope envelope;
};

struct GetEnvelopesRequest {
  VaultId vault;
};

struct EnvelopesResponse {
  std::vector<Envelope> envelopes;
};

struct PutReportRequest {
  VaultId vault;
  SealedReport report;
};

struct GetReportsRequest {
  VaultId vault;
};

struct ReportsResponse {
  std::vector<SealedReport> reports;
};

// Encoding. Every Encode produces a complete frame including its length prefix.
std::string EncodePush(const PushRequest& r);
std::string EncodeFetch(const FetchRequest& r);
std::string EncodePutReport(const PutReportRequest& r);
std::string EncodeGetReports(const GetReportsRequest& r);
std::string EncodePutEnvelope(const PutEnvelopeRequest& r);
std::string EncodeGetEnvelopes(const GetEnvelopesRequest& r);
std::string EncodeEnvelopes(const EnvelopesResponse& r);
std::string EncodeOk();
std::string EncodeBlobs(const BlobsResponse& r);
std::string EncodeReports(const ReportsResponse& r);
std::string EncodeError(const std::string& message);

// Decoding a frame BODY (the length prefix already stripped). Every one returns
// false on anything malformed rather than guessing.
bool PeekOp(const std::string& body, Op* out);
bool DecodePush(const std::string& body, PushRequest* out);
bool DecodeFetch(const std::string& body, FetchRequest* out);
bool DecodePutReport(const std::string& body, PutReportRequest* out);
bool DecodeGetReports(const std::string& body, GetReportsRequest* out);
bool DecodeBlobs(const std::string& body, BlobsResponse* out);
bool DecodeReports(const std::string& body, ReportsResponse* out);
bool DecodePutEnvelope(const std::string& body, PutEnvelopeRequest* out);
bool DecodeGetEnvelopes(const std::string& body, GetEnvelopesRequest* out);
bool DecodeEnvelopes(const std::string& body, EnvelopesResponse* out);
bool DecodeError(const std::string& body, std::string* message);

}  // namespace relay
}  // namespace umbra

#endif  // UMBRA_RELAY_WIRE_H_
