#include "wire.h"

#include <cstring>

namespace umbra {
namespace relay {
namespace {

void PutU8(uint8_t v, std::string* out) {
  out->push_back(static_cast<char>(v));
}

void PutU32(uint32_t v, std::string* out) {
  for (int i = 0; i < 4; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
}

void PutU64(uint64_t v, std::string* out) {
  for (int i = 0; i < 8; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
}

void PutBytes(const uint8_t* p, std::size_t n, std::string* out) {
  out->append(reinterpret_cast<const char*>(p), n);
}

void PutString(const std::string& s, std::string* out) {
  PutU32(static_cast<uint32_t>(s.size()), out);
  *out += s;
}

// Wraps a body in its length prefix. Every Encode ends here, so no caller can
// forget it.
std::string Frame(const std::string& body) {
  std::string out;
  out.reserve(4 + body.size());
  PutU32(static_cast<uint32_t>(body.size()), &out);
  out += body;
  return out;
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
  bool Bytes(uint8_t* p, std::size_t n) {
    if (!Need(n)) return false;
    std::memcpy(p, s->data() + pos, n);
    pos += n;
    return true;
  }
  bool Str(std::string* out) {
    uint32_t n = 0;
    if (!U32(&n)) return false;
    // A LENGTH IS NOT A PROMISE. Checking it against what remains before
    // reserving is what stops a hostile length from allocating gigabytes, and
    // the relay is the hostile party as often as the client is.
    if (!Need(n)) return false;
    out->assign(*s, pos, n);
    pos += n;
    return true;
  }
  bool Done() const { return pos == s->size(); }
};

}  // namespace

std::string Id16::ToHex() const {
  static const char kHex[] = "0123456789abcdef";
  std::string s;
  s.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    s.push_back(kHex[b >> 4]);
    s.push_back(kHex[b & 0x0f]);
  }
  return s;
}

const char* OpName(Op o) {
  switch (o) {
    case Op::kPush:
      return "push";
    case Op::kFetch:
      return "fetch";
    case Op::kPutReport:
      return "put-report";
    case Op::kGetReports:
      return "get-reports";
    case Op::kPutEnvelope:
      return "put-envelope";
    case Op::kGetEnvelopes:
      return "get-envelopes";
    case Op::kPutSegment:
      return "put-segment";
    case Op::kGetSegment:
      return "get-segment";
    case Op::kListSegments:
      return "list-segments";
    case Op::kOk:
      return "ok";
    case Op::kBlobs:
      return "blobs";
    case Op::kReports:
      return "reports";
    case Op::kEnvelopes:
      return "envelopes";
    case Op::kSegment:
      return "segment";
    case Op::kSegmentList:
      return "segment-list";
    case Op::kError:
      return "error";
  }
  return "unknown";
}

namespace {

void PutBlob(const Blob& b, std::string* out) {
  PutBytes(b.object.bytes.data(), b.object.bytes.size(), out);
  PutBytes(b.replica.bytes.data(), b.replica.bytes.size(), out);
  PutU64(b.counter, out);
  PutU32(b.epoch, out);
  PutString(b.payload, out);
}

bool GetBlob(Reader* r, Blob* b) {
  if (!r->Bytes(b->object.bytes.data(), b->object.bytes.size())) return false;
  if (!r->Bytes(b->replica.bytes.data(), b->replica.bytes.size())) return false;
  if (!r->U64(&b->counter)) return false;
  if (!r->U32(&b->epoch)) return false;
  if (!r->Str(&b->payload)) return false;
  // A counter of zero is the tree root's sentinel and is never a real
  // operation, so it is refused rather than stored.
  return b->counter != 0;
}

}  // namespace

std::string EncodePush(const PushRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kPush), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  PutU32(static_cast<uint32_t>(r.blobs.size()), &b);
  for (const Blob& blob : r.blobs) PutBlob(blob, &b);
  return Frame(b);
}

std::string EncodeFetch(const FetchRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kFetch), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  PutBytes(r.object.bytes.data(), r.object.bytes.size(), &b);
  PutBytes(r.replica.bytes.data(), r.replica.bytes.size(), &b);
  PutU64(r.after, &b);
  PutU32(r.limit, &b);
  return Frame(b);
}

std::string EncodePutReport(const PutReportRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kPutReport), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  PutBytes(r.report.device.bytes.data(), r.report.device.bytes.size(), &b);
  PutU32(r.report.epoch, &b);
  PutString(r.report.sealed, &b);
  return Frame(b);
}

std::string EncodeGetReports(const GetReportsRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kGetReports), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  return Frame(b);
}

std::string EncodeOk() {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kOk), &b);
  return Frame(b);
}

std::string EncodeBlobs(const BlobsResponse& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kBlobs), &b);
  PutU8(r.more ? 1 : 0, &b);
  PutU32(static_cast<uint32_t>(r.blobs.size()), &b);
  for (const Blob& blob : r.blobs) PutBlob(blob, &b);
  return Frame(b);
}

std::string EncodeReports(const ReportsResponse& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kReports), &b);
  PutU32(static_cast<uint32_t>(r.reports.size()), &b);
  for (const SealedReport& s : r.reports) {
    PutBytes(s.device.bytes.data(), s.device.bytes.size(), &b);
    PutU32(s.epoch, &b);
    PutString(s.sealed, &b);
  }
  return Frame(b);
}

std::string EncodeError(const std::string& message) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kError), &b);
  PutString(message, &b);
  return Frame(b);
}

bool PeekOp(const std::string& body, Op* out) {
  if (body.empty()) return false;
  const uint8_t v = static_cast<uint8_t>(body[0]);
  switch (static_cast<Op>(v)) {
    case Op::kPush:
    case Op::kFetch:
    case Op::kPutReport:
    case Op::kGetReports:
    case Op::kPutEnvelope:
    case Op::kGetEnvelopes:
    case Op::kPutSegment:
    case Op::kGetSegment:
    case Op::kListSegments:
    case Op::kOk:
    case Op::kBlobs:
    case Op::kReports:
    case Op::kEnvelopes:
    case Op::kSegment:
    case Op::kSegmentList:
    case Op::kError:
      *out = static_cast<Op>(v);
      return true;
  }
  return false;
}

bool DecodePush(const std::string& body, PushRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kPush) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  uint32_t n = 0;
  if (!r.U32(&n)) return false;
  // Bound the count against what is left before reserving, for the same reason
  // Str does.
  if (n > body.size()) return false;
  out->blobs.resize(n);
  for (uint32_t i = 0; i < n; ++i) {
    if (!GetBlob(&r, &out->blobs[i])) return false;
  }
  return r.Done();
}

bool DecodeFetch(const std::string& body, FetchRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kFetch) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  if (!r.Bytes(out->object.bytes.data(), out->object.bytes.size()))
    return false;
  if (!r.Bytes(out->replica.bytes.data(), out->replica.bytes.size()))
    return false;
  if (!r.U64(&out->after)) return false;
  if (!r.U32(&out->limit)) return false;
  return r.Done();
}

bool DecodePutReport(const std::string& body, PutReportRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kPutReport) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  if (!r.Bytes(out->report.device.bytes.data(),
               out->report.device.bytes.size())) {
    return false;
  }
  if (!r.U32(&out->report.epoch)) return false;
  if (!r.Str(&out->report.sealed)) return false;
  return r.Done();
}

bool DecodeGetReports(const std::string& body, GetReportsRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kGetReports) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  return r.Done();
}

bool DecodeBlobs(const std::string& body, BlobsResponse* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kBlobs) return false;
  uint8_t more = 0;
  if (!r.U8(&more)) return false;
  if (more > 1) return false;
  out->more = more == 1;
  uint32_t n = 0;
  if (!r.U32(&n)) return false;
  if (n > body.size()) return false;
  out->blobs.resize(n);
  for (uint32_t i = 0; i < n; ++i) {
    if (!GetBlob(&r, &out->blobs[i])) return false;
  }
  return r.Done();
}

bool DecodeReports(const std::string& body, ReportsResponse* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kReports) return false;
  uint32_t n = 0;
  if (!r.U32(&n)) return false;
  if (n > body.size()) return false;
  out->reports.resize(n);
  for (uint32_t i = 0; i < n; ++i) {
    SealedReport& s = out->reports[i];
    if (!r.Bytes(s.device.bytes.data(), s.device.bytes.size())) return false;
    if (!r.U32(&s.epoch)) return false;
    if (!r.Str(&s.sealed)) return false;
  }
  return r.Done();
}

bool DecodeError(const std::string& body, std::string* message) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kError) return false;
  if (!r.Str(message)) return false;
  return r.Done();
}

std::string EncodePutEnvelope(const PutEnvelopeRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kPutEnvelope), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  PutBytes(r.envelope.tag.data(), r.envelope.tag.size(), &b);
  PutString(r.envelope.body, &b);
  return Frame(b);
}

bool DecodePutEnvelope(const std::string& body, PutEnvelopeRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kPutEnvelope) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  if (!r.Bytes(out->envelope.tag.data(), out->envelope.tag.size()))
    return false;
  if (!r.Str(&out->envelope.body)) return false;
  return r.Done();
}

std::string EncodeGetEnvelopes(const GetEnvelopesRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kGetEnvelopes), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  return Frame(b);
}

bool DecodeGetEnvelopes(const std::string& body, GetEnvelopesRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kGetEnvelopes) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  return r.Done();
}

std::string EncodeEnvelopes(const EnvelopesResponse& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kEnvelopes), &b);
  PutU32(static_cast<uint32_t>(r.envelopes.size()), &b);
  for (const Envelope& e : r.envelopes) {
    PutBytes(e.tag.data(), e.tag.size(), &b);
    PutString(e.body, &b);
  }
  return Frame(b);
}

bool DecodeEnvelopes(const std::string& body, EnvelopesResponse* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kEnvelopes) return false;
  uint32_t n = 0;
  if (!r.U32(&n)) return false;
  // BOUND BEFORE RESERVING. A relay that claims four billion envelopes must
  // not be able to make a client allocate for them.
  if (n > kMaxEnvelopes) return false;
  out->envelopes.clear();
  out->envelopes.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    Envelope e;
    if (!r.Bytes(e.tag.data(), e.tag.size())) return false;
    if (!r.Str(&e.body)) return false;
    out->envelopes.push_back(e);
  }
  return r.Done();
}

std::string EncodePutSegment(const PutSegmentRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kPutSegment), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  PutBytes(r.segment.data(), r.segment.size(), &b);
  PutU64(r.offset, &b);
  PutU64(r.total, &b);
  PutString(r.chunk, &b);
  return Frame(b);
}

bool DecodePutSegment(const std::string& body, PutSegmentRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kPutSegment) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  if (!r.Bytes(out->segment.data(), out->segment.size())) return false;
  if (!r.U64(&out->offset) || !r.U64(&out->total)) return false;
  if (!r.Str(&out->chunk)) return false;
  // BOUNDS BEFORE ANYTHING ELSE. A piece that claims to sit past the end of the
  // segment it belongs to, or a segment larger than this will ever move, is
  // refused rather than stored and puzzled over later.
  if (out->total > kMaxSegmentBytes) return false;
  if (out->offset > out->total) return false;
  if (out->chunk.size() > kSegmentChunkBytes) return false;
  if (out->offset + out->chunk.size() > out->total) return false;
  return r.Done();
}

std::string EncodeGetSegment(const GetSegmentRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kGetSegment), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  PutBytes(r.segment.data(), r.segment.size(), &b);
  PutU64(r.offset, &b);
  return Frame(b);
}

bool DecodeGetSegment(const std::string& body, GetSegmentRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kGetSegment) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  if (!r.Bytes(out->segment.data(), out->segment.size())) return false;
  if (!r.U64(&out->offset)) return false;
  return r.Done();
}

std::string EncodeSegment(const SegmentResponse& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kSegment), &b);
  PutU8(r.found ? 1u : 0u, &b);
  PutU64(r.offset, &b);
  PutU64(r.total, &b);
  PutString(r.chunk, &b);
  return Frame(b);
}

bool DecodeSegment(const std::string& body, SegmentResponse* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kSegment) return false;
  uint8_t found = 0;
  if (!r.U8(&found)) return false;
  out->found = found != 0;
  if (!r.U64(&out->offset) || !r.U64(&out->total)) return false;
  if (!r.Str(&out->chunk)) return false;
  if (out->total > kMaxSegmentBytes) return false;
  if (out->chunk.size() > kSegmentChunkBytes) return false;
  if (out->offset + out->chunk.size() > out->total) return false;
  return r.Done();
}

std::string EncodeListSegments(const ListSegmentsRequest& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kListSegments), &b);
  PutBytes(r.vault.bytes.data(), r.vault.bytes.size(), &b);
  PutBytes(r.after.data(), r.after.size(), &b);
  PutU32(r.limit, &b);
  return Frame(b);
}

bool DecodeListSegments(const std::string& body, ListSegmentsRequest* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kListSegments) return false;
  if (!r.Bytes(out->vault.bytes.data(), out->vault.bytes.size())) return false;
  if (!r.Bytes(out->after.data(), out->after.size())) return false;
  if (!r.U32(&out->limit)) return false;
  return r.Done();
}

std::string EncodeSegmentList(const SegmentListResponse& r) {
  std::string b;
  PutU8(static_cast<uint8_t>(Op::kSegmentList), &b);
  PutU32(static_cast<uint32_t>(r.segments.size()), &b);
  for (const SegmentEntryWire& e : r.segments) {
    PutBytes(e.segment.data(), e.segment.size(), &b);
    PutU64(e.bytes, &b);
  }
  return Frame(b);
}

bool DecodeSegmentList(const std::string& body, SegmentListResponse* out) {
  Reader r{&body, 0};
  uint8_t op = 0;
  if (!r.U8(&op) || static_cast<Op>(op) != Op::kSegmentList) return false;
  uint32_t n = 0;
  if (!r.U32(&n)) return false;
  // Bound before reserving: a relay claiming four billion segments must not be
  // able to make a client allocate for them.
  if (n > kMaxSegmentsListed) return false;
  out->segments.clear();
  out->segments.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    SegmentEntryWire e;
    if (!r.Bytes(e.segment.data(), e.segment.size())) return false;
    if (!r.U64(&e.bytes)) return false;
    if (e.bytes > kMaxSegmentBytes) return false;
    out->segments.push_back(e);
  }
  return r.Done();
}

}  // namespace relay
}  // namespace umbra
