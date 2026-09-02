#include "umbra/sync/enroll.h"

#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace umbra {
namespace sync {
namespace {

void PutU32(std::string* s, uint32_t v) {
  for (int i = 3; i >= 0; --i)
    s->push_back(static_cast<char>((v >> (i * 8)) & 0xFF));
}

bool GetU32(const std::string& s, std::size_t* off, uint32_t* out) {
  if (*off + 4 > s.size()) return false;
  uint32_t v = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    v = (v << 8) | static_cast<uint8_t>(s[*off + i]);
  }
  *off += 4;
  *out = v;
  return true;
}

template <std::size_t N>
bool GetBytes(const std::string& s, std::size_t* off,
              std::array<uint8_t, N>* out) {
  if (*off + N > s.size()) return false;
  std::memcpy(out->data(), s.data() + *off, N);
  *off += N;
  return true;
}

constexpr uint8_t kRequestVersion = 1;
constexpr uint8_t kGrantVersion = 1;

}  // namespace

std::string EncodeEnrollRequest(const EnrollRequest& r) {
  std::string out;
  out.push_back(static_cast<char>(kRequestVersion));
  out.append(reinterpret_cast<const char*>(r.device_public.data()),
             r.device_public.size());
  return out;
}

bool DecodeEnrollRequest(const std::string& in, EnrollRequest* out) {
  if (in.size() != 1 + kPublicKeyBytes) return false;
  if (static_cast<uint8_t>(in[0]) != kRequestVersion) return false;
  std::size_t off = 1;
  return GetBytes(in, &off, &out->device_public);
}

std::string EncodeEnrollGrant(const EnrollGrant& g) {
  std::string out;
  out.push_back(static_cast<char>(kGrantVersion));
  out.append(reinterpret_cast<const char*>(g.to.data()), g.to.size());
  out.append(reinterpret_cast<const char*>(g.from.data()), g.from.size());
  PutU32(&out, g.epoch);
  out.append(reinterpret_cast<const char*>(g.salt.data()), g.salt.size());
  out.append(reinterpret_cast<const char*>(g.vault.data()), g.vault.size());
  PutU32(&out, static_cast<uint32_t>(g.sealed_epoch.size()));
  out.append(g.sealed_epoch);
  return out;
}

bool DecodeEnrollGrant(const std::string& in, EnrollGrant* out) {
  if (in.empty() || static_cast<uint8_t>(in[0]) != kGrantVersion) return false;
  std::size_t off = 1;
  if (!GetBytes(in, &off, &out->to)) return false;
  if (!GetBytes(in, &off, &out->from)) return false;
  if (!GetU32(in, &off, &out->epoch)) return false;
  if (!GetBytes(in, &off, &out->salt)) return false;
  if (!GetBytes(in, &off, &out->vault)) return false;
  uint32_t n = 0;
  if (!GetU32(in, &off, &n)) return false;
  // Bound before reserving: this arrives from a relay.
  if (n > in.size() - off) return false;
  out->sealed_epoch.assign(in, off, n);
  off += n;
  return off == in.size();
}

std::string PairingCode(const std::array<uint8_t, kPublicKeyBytes>& a,
                        const std::array<uint8_t, kPublicKeyBytes>& b) {
  if (sodium_init() < 0) return "------";
  // SORTED, so both sides compute the same code without either needing to know
  // which of them is the one joining.
  const bool a_first =
      std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
  const std::array<uint8_t, kPublicKeyBytes>& lo = a_first ? a : b;
  const std::array<uint8_t, kPublicKeyBytes>& hi = a_first ? b : a;

  static const char kContext[] = "umbra enrol sas";
  crypto_generichash_state st;
  crypto_generichash_init(&st, nullptr, 0, 4);
  crypto_generichash_update(&st,
                            reinterpret_cast<const unsigned char*>(kContext),
                            sizeof(kContext) - 1);
  crypto_generichash_update(&st, lo.data(), lo.size());
  crypto_generichash_update(&st, hi.data(), hi.size());
  uint8_t digest[4];
  crypto_generichash_final(&st, digest, sizeof(digest));

  uint32_t v = 0;
  for (std::size_t i = 0; i < sizeof(digest); ++i) v = (v << 8) | digest[i];
  // 20 bits, rendered as six digits with a space in the middle. See the header
  // for why twenty bits is the right ceiling for something a person compares.
  v %= 1000000u;
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%03u %03u", v / 1000u, v % 1000u);
  return std::string(buf);
}

std::string DeviceLabel(const ReplicaId& r) { return r.Short(); }

}  // namespace sync
}  // namespace umbra
