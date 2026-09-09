// A Transport over TCP.
//
// It reconnects on demand rather than holding a socket open forever: a sync
// client on a laptop spends most of its life asleep, and a connection that
// survived a suspend would be a connection that fails at the worst moment
// instead of at the cheapest one.
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <string>

#include "umbra/sync/client.h"

namespace umbra {
namespace sync {
namespace {

bool ReadExactly(int fd, char* p, std::size_t n, int timeout_seconds) {
  std::size_t got = 0;
  while (got < n) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    const int pr = ::poll(&pfd, 1, timeout_seconds * 1000);
    if (pr <= 0) return false;
    const ssize_t r = ::read(fd, p + got, n - got);
    if (r == 0) return false;
    if (r < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    got += static_cast<std::size_t>(r);
  }
  return true;
}

bool WriteAll(int fd, const std::string& s) {
  std::size_t sent = 0;
  while (sent < s.size()) {
    const ssize_t w = ::write(fd, s.data() + sent, s.size() - sent);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    sent += static_cast<std::size_t>(w);
  }
  return true;
}

uint32_t GetU32Le(const char* p) {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i) {
    v |= static_cast<uint32_t>(static_cast<unsigned char>(p[i])) << (8 * i);
  }
  return v;
}

class TcpTransport : public Transport {
 public:
  TcpTransport(const std::string& host, uint16_t port, int timeout)
      : host_(host), port_(port), timeout_(timeout) {}

  bool Push(const relay::PushRequest& req) override {
    std::string body;
    if (!RoundTrip(relay::EncodePush(req), &body)) return false;
    relay::Op op;
    return relay::PeekOp(body, &op) && op == relay::Op::kOk;
  }

  bool Fetch(const relay::FetchRequest& req,
             relay::BlobsResponse* out) override {
    std::string body;
    if (!RoundTrip(relay::EncodeFetch(req), &body)) return false;
    return relay::DecodeBlobs(body, out);
  }

  bool PutReport(const relay::PutReportRequest& req) override {
    std::string body;
    if (!RoundTrip(relay::EncodePutReport(req), &body)) return false;
    relay::Op op;
    return relay::PeekOp(body, &op) && op == relay::Op::kOk;
  }

  bool GetReports(const relay::GetReportsRequest& req,
                  relay::ReportsResponse* out) override {
    std::string body;
    if (!RoundTrip(relay::EncodeGetReports(req), &body)) return false;
    return relay::DecodeReports(body, out);
  }

  bool PutEnvelope(const relay::PutEnvelopeRequest& req) override {
    std::string body;
    if (!RoundTrip(relay::EncodePutEnvelope(req), &body)) return false;
    relay::Op op;
    return relay::PeekOp(body, &op) && op == relay::Op::kOk;
  }

  bool GetEnvelopes(const relay::GetEnvelopesRequest& req,
                    relay::EnvelopesResponse* out) override {
    std::string body;
    if (!RoundTrip(relay::EncodeGetEnvelopes(req), &body)) return false;
    return relay::DecodeEnvelopes(body, out);
  }

  bool PutSegment(const relay::PutSegmentRequest& req) override {
    std::string body;
    if (!RoundTrip(relay::EncodePutSegment(req), &body)) return false;
    relay::Op op;
    return relay::PeekOp(body, &op) && op == relay::Op::kOk;
  }

  bool GetSegment(const relay::GetSegmentRequest& req,
                  relay::SegmentResponse* out) override {
    std::string body;
    if (!RoundTrip(relay::EncodeGetSegment(req), &body)) return false;
    return relay::DecodeSegment(body, out);
  }

  bool ListSegments(const relay::ListSegmentsRequest& req,
                    relay::SegmentListResponse* out) override {
    std::string body;
    if (!RoundTrip(relay::EncodeListSegments(req), &body)) return false;
    return relay::DecodeSegmentList(body, out);
  }

 private:
  int Connect() {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const std::string port_s = std::to_string(port_);
    if (::getaddrinfo(host_.c_str(), port_s.c_str(), &hints, &res) != 0) {
      return -1;
    }
    int fd = -1;
    for (struct addrinfo* a = res; a != nullptr; a = a->ai_next) {
      fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
      if (fd < 0) continue;
      if (::connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
      ::close(fd);
      fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd >= 0) {
      int one = 1;
      (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return fd;
  }

  bool RoundTrip(const std::string& frame, std::string* body) {
    const int fd = Connect();
    if (fd < 0) return false;
    bool ok = WriteAll(fd, frame);
    if (ok) {
      char header[4];
      ok = ReadExactly(fd, header, 4, timeout_);
      if (ok) {
        const uint32_t len = GetU32Le(header);
        // THE CLIENT BOUNDS THE RELAY'S RESPONSE TOO. The relay is the hostile
        // party; a length it chose must not be able to make this allocate.
        if (len == 0 || len > relay::kMaxFrameBytes) {
          ok = false;
        } else {
          body->resize(len);
          ok = ReadExactly(fd, &(*body)[0], len, timeout_);
        }
      }
    }
    ::close(fd);
    return ok;
  }

  std::string host_;
  uint16_t port_;
  int timeout_;
};

}  // namespace

std::unique_ptr<Transport> NewTcpTransport(const std::string& host,
                                           uint16_t port, int timeout_seconds) {
  return std::unique_ptr<Transport>(
      new TcpTransport(host, port, timeout_seconds));
}

}  // namespace sync
}  // namespace umbra
