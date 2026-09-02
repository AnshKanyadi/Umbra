#include "umbra/sync/report.h"

#include <cstring>

#include "umbra/crypto/aead.h"

namespace umbra {
namespace {

constexpr uint8_t kReportVersion = 1;

void PutU8(uint8_t v, std::string* out) {
  out->push_back(static_cast<char>(v));
}

void PutU32(uint32_t v, std::string* out) {
  for (int i = 0; i < 4; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
}

void PutU64(uint64_t v, std::string* out) {
  for (int i = 0; i < 8; ++i) PutU8(static_cast<uint8_t>(v >> (8 * i)), out);
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
  bool Rep(ReplicaId* r) {
    if (!Need(r->bytes.size())) return false;
    std::memcpy(r->bytes.data(), s->data() + pos, r->bytes.size());
    pos += r->bytes.size();
    return true;
  }
};

// The associated data: the device the report claims to be from, and the epoch.
// Binding both is what stops a relay misattributing a report; see report.h.
SealContext ContextFor(const ReplicaId& device, Epoch epoch) {
  SealContext ctx;
  ctx.epoch = epoch;
  ctx.op.replica = device;
  // counter stays zero: a report is not an operation and must not collide with
  // one in the binding.
  return ctx;
}

}  // namespace

std::string EncodeDeviceReport(const DeviceReport& r) {
  std::string out;
  PutU8(kReportVersion, &out);
  out.append(reinterpret_cast<const char*>(r.device.bytes.data()),
             r.device.bytes.size());
  PutU64(r.clock, &out);
  PutU32(static_cast<uint32_t>(r.have.size()), &out);
  // std::map iterates in key order, so the encoding is canonical without
  // sorting here.
  for (const std::map<ReplicaId, uint64_t>::value_type& kv : r.have) {
    out.append(reinterpret_cast<const char*>(kv.first.bytes.data()),
               kv.first.bytes.size());
    PutU64(kv.second, &out);
  }
  return out;
}

bool DecodeDeviceReport(const std::string& bytes, DeviceReport* out) {
  Reader r{&bytes, 0};
  uint8_t v = 0;
  if (!r.U8(&v) || v != kReportVersion) return false;
  *out = DeviceReport();
  if (!r.Rep(&out->device)) return false;
  if (!r.U64(&out->clock)) return false;
  uint32_t n = 0;
  if (!r.U32(&n)) return false;
  if (n > bytes.size()) return false;  // a length is not a promise
  ReplicaId last;
  bool have_last = false;
  for (uint32_t i = 0; i < n; ++i) {
    ReplicaId who;
    uint64_t mark = 0;
    if (!r.Rep(&who)) return false;
    if (!r.U64(&mark)) return false;
    // STRICTLY ASCENDING, because the encoding is canonical and two orderings
    // of one report would be two different ciphertexts for one fact.
    if (have_last && !(last < who)) return false;
    last = who;
    have_last = true;
    // A zero mark is omitted on the wire; see the watermark computation.
    if (mark == 0) return false;
    out->have[who] = mark;
  }
  return r.pos == bytes.size();
}

CryptoStatus SealDeviceReport(const VaultKeys& keys, Epoch epoch,
                              const DeviceReport& r, std::string* sealed) {
  SecretKey k;
  const CryptoStatus s = keys.ContentKey(epoch, &k);
  if (s != CryptoStatus::kOk) return s;
  *sealed = Seal(k, ContextFor(r.device, epoch), EncodeDeviceReport(r));
  return CryptoStatus::kOk;
}

CryptoStatus OpenDeviceReport(const VaultKeys& keys, Epoch epoch,
                              const ReplicaId& claimed_device,
                              const std::string& sealed, DeviceReport* out) {
  SecretKey k;
  const CryptoStatus s = keys.ContentKey(epoch, &k);
  if (s != CryptoStatus::kOk) return s;
  std::string plain;
  const CryptoStatus o =
      Open(k, ContextFor(claimed_device, epoch), sealed, &plain);
  if (o != CryptoStatus::kOk) return o;
  if (!DecodeDeviceReport(plain, out)) return CryptoStatus::kAuthFailed;
  // The sealed contents must agree with the envelope. A relay that swapped the
  // envelope's device id fails the AEAD; one that could somehow not would fail
  // here.
  if (!(out->device == claimed_device)) return CryptoStatus::kAuthFailed;
  return CryptoStatus::kOk;
}

}  // namespace umbra
