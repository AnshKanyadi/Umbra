// The Ollama backend: HTTP to a local inference server.
//
// WHY A HAND-ROLLED CLIENT AND NOT A LIBRARY. The relay already speaks TCP
// without a dependency (relay/server.cc) and the surface needed here is one
// POST to one host with one JSON shape. Adding libcurl to a project whose whole
// argument is that it does not send your notes anywhere is a poor trade: it is
// a large dependency, it is a TLS stack, and the one thing this connection must
// never be is remote.
//
// THE CONNECTION IS TO LOOPBACK AND IS CHECKED. A backend host that is not a
// loopback address is refused rather than dialled, because "point it at a
// server" is exactly how a local-first tool quietly becomes a service that
// uploads your vault. See the note on Loopback below.
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "umbra/ai/embed.h"

namespace umbra {
namespace ai {
namespace {

constexpr std::size_t kMaxResponseBytes = 64u * 1024 * 1024;

// A LOCAL-FIRST TOOL MUST NOT BE ONE FLAG AWAY FROM AN UPLOADER. Only loopback
// is accepted. If someone genuinely wants a model on another machine, that is a
// deliberate change here with a comment explaining what it costs, not a host
// string in a config file.
bool Loopback(const std::string& host) {
  if (host == "localhost") return true;
  struct in_addr v4;
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    const uint32_t a = ntohl(v4.s_addr);
    return (a >> 24) == 127u;
  }
  struct in6_addr v6;
  if (::inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
    static const uint8_t kLoop[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1};
    return std::memcmp(v6.s6_addr, kLoop, sizeof(kLoop)) == 0;
  }
  return false;
}

std::string JsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (std::size_t i = 0; i < s.size(); ++i) {
    const uint8_t c = static_cast<uint8_t>(s[i]);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  return out;
}

// A NUMBER SCANNER, NOT A JSON PARSER. The response shape is fixed and known:
// {"embeddings":[[f,...],[f,...]]}. Pulling the floats out of the nested arrays
// is all that is needed, and a general parser here would be more code and more
// places to be wrong. It is strict about structure so that a response of a
// different shape fails rather than yielding a plausible-looking short vector.
bool ParseEmbeddings(const std::string& body, std::size_t expect_rows,
                     std::vector<Vector>* out) {
  const std::string key = "\"embeddings\"";
  std::size_t at = body.find(key);
  if (at == std::string::npos) return false;
  at = body.find('[', at);
  if (at == std::string::npos) return false;
  ++at;  // past the outer [

  out->clear();
  while (at < body.size()) {
    while (at < body.size() &&
           (body[at] == ' ' || body[at] == ',' || body[at] == '\n' ||
            body[at] == '\r' || body[at] == '\t')) {
      ++at;
    }
    if (at >= body.size()) return false;
    if (body[at] == ']') break;  // end of the outer array
    if (body[at] != '[') return false;
    ++at;
    Vector v;
    while (at < body.size() && body[at] != ']') {
      while (at < body.size() &&
             (body[at] == ' ' || body[at] == ',' || body[at] == '\n' ||
              body[at] == '\r' || body[at] == '\t')) {
        ++at;
      }
      if (at < body.size() && body[at] == ']') break;
      const char* start = body.c_str() + at;
      char* stop = nullptr;
      const double d = std::strtod(start, &stop);
      if (stop == start) return false;
      if (!std::isfinite(d)) return false;
      v.push_back(static_cast<float>(d));
      at += static_cast<std::size_t>(stop - start);
    }
    if (at >= body.size()) return false;
    ++at;  // past the inner ]
    out->push_back(v);
  }
  if (out->size() != expect_rows) return false;
  return true;
}

class OllamaEmbedder : public Embedder {
 public:
  OllamaEmbedder(std::string model, std::string host, uint16_t port)
      : model_(std::move(model)), host_(std::move(host)), port_(port) {}

  EmbedStatus Probe() {
    // THE DIMENSION IS DISCOVERED, NOT CONFIGURED. A configured width that
    // disagrees with the backend writes short or long vectors into segments and
    // nothing notices until search is wrong.
    std::vector<Vector> got;
    const EmbedStatus s = Post({"umbra dimension probe"}, &got);
    if (s != EmbedStatus::kOk) return s;
    if (got.size() != 1 || got[0].empty()) return EmbedStatus::kBadResponse;
    descriptor_.family = model_;
    descriptor_.version = "resolved-by-backend";
    descriptor_.dimension = static_cast<uint32_t>(got[0].size());
    descriptor_.quantisation = "unknown";
    descriptor_.pooling = "backend";
    descriptor_.normalised = true;
    id_ = ComputeModelId(descriptor_);
    return EmbedStatus::kOk;
  }

  EmbedStatus EmbedDocuments(const std::vector<std::string>& texts,
                             std::vector<Vector>* out) override {
    if (texts.empty()) {
      out->clear();
      return EmbedStatus::kOk;
    }
    const EmbedStatus s = Post(texts, out);
    if (s != EmbedStatus::kOk) return s;
    for (Vector& v : *out) {
      if (v.size() != descriptor_.dimension) return EmbedStatus::kBadResponse;
      if (!Normalise(&v)) return EmbedStatus::kDegenerateVector;
    }
    return EmbedStatus::kOk;
  }

  EmbedStatus EmbedQuery(const std::string& text, Vector* out) override {
    std::vector<Vector> got;
    const EmbedStatus s = Post({QueryPrefix() + text}, &got);
    if (s != EmbedStatus::kOk) return s;
    if (got.size() != 1 || got[0].size() != descriptor_.dimension) {
      return EmbedStatus::kBadResponse;
    }
    *out = got[0];
    if (!Normalise(out)) return EmbedStatus::kDegenerateVector;
    return EmbedStatus::kOk;
  }

  uint32_t dimension() const override { return descriptor_.dimension; }
  const EmbeddingModelId& id() const override { return id_; }
  const ModelDescriptor& descriptor() const override { return descriptor_; }

 private:
  // THE ASYMMETRY LIVES HERE so no caller has to remember it. Getting it wrong
  // costs recall and raises nothing.
  std::string QueryPrefix() const {
    if (model_.find("bge") != std::string::npos) {
      return "Represent this sentence for searching relevant passages: ";
    }
    if (model_.find("e5") != std::string::npos) return "query: ";
    if (model_.find("nomic") != std::string::npos) return "search_query: ";
    return std::string();
  }
  std::string DocumentPrefix() const {
    if (model_.find("e5") != std::string::npos) return "passage: ";
    if (model_.find("nomic") != std::string::npos) return "search_document: ";
    return std::string();
  }

  EmbedStatus Post(const std::vector<std::string>& texts,
                   std::vector<Vector>* out) {
    if (!Loopback(host_)) return EmbedStatus::kUnreachable;

    std::string body = "{\"model\":\"";
    body += JsonEscape(model_);
    body += "\",\"input\":[";
    const std::string prefix = DocumentPrefix();
    for (std::size_t i = 0; i < texts.size(); ++i) {
      if (i != 0) body += ",";
      body += "\"";
      body += JsonEscape(prefix + texts[i]);
      body += "\"";
    }
    body += "]}";

    std::string response;
    const EmbedStatus s = RoundTrip(body, &response);
    if (s != EmbedStatus::kOk) return s;
    if (response.find("\"error\"") != std::string::npos) {
      if (response.find("not found") != std::string::npos) {
        return EmbedStatus::kNoSuchModel;
      }
      return EmbedStatus::kBadResponse;
    }
    if (!ParseEmbeddings(response, texts.size(), out)) {
      return EmbedStatus::kBadResponse;
    }
    return EmbedStatus::kOk;
  }

  EmbedStatus RoundTrip(const std::string& body, std::string* response) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const std::string port_s = std::to_string(port_);
    if (::getaddrinfo(host_.c_str(), port_s.c_str(), &hints, &res) != 0) {
      return EmbedStatus::kUnreachable;
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
    if (fd < 0) return EmbedStatus::kUnreachable;

    std::string request = "POST /api/embed HTTP/1.1\r\nHost: ";
    request += host_;
    request += ":";
    request += port_s;
    request += "\r\nContent-Type: application/json\r\nConnection: close\r\n";
    request += "Content-Length: ";
    request += std::to_string(body.size());
    request += "\r\n\r\n";
    request += body;

    std::size_t sent = 0;
    while (sent < request.size()) {
      const ssize_t n =
          ::send(fd, request.data() + sent, request.size() - sent, 0);
      if (n <= 0) {
        ::close(fd);
        return EmbedStatus::kUnreachable;
      }
      sent += static_cast<std::size_t>(n);
    }

    std::string raw;
    char buf[16384];
    for (;;) {
      const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
      if (n < 0) {
        ::close(fd);
        return EmbedStatus::kUnreachable;
      }
      if (n == 0) break;
      if (raw.size() + static_cast<std::size_t>(n) > kMaxResponseBytes) {
        // The backend is local and trusted less than it is convenient. A
        // response that will not fit a bound is refused rather than grown.
        ::close(fd);
        return EmbedStatus::kBadResponse;
      }
      raw.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);

    const std::size_t head = raw.find("\r\n\r\n");
    if (head == std::string::npos) return EmbedStatus::kBadResponse;
    *response = raw.substr(head + 4);
    return EmbedStatus::kOk;
  }

  std::string model_;
  std::string host_;
  uint16_t port_;
  ModelDescriptor descriptor_;
  EmbeddingModelId id_;
};

}  // namespace

std::unique_ptr<Embedder> NewOllamaEmbedder(const std::string& model,
                                            const std::string& host,
                                            uint16_t port,
                                            EmbedStatus* status) {
  std::unique_ptr<OllamaEmbedder> e(new OllamaEmbedder(model, host, port));
  const EmbedStatus s = e->Probe();
  if (status != nullptr) *status = s;
  if (s != EmbedStatus::kOk) return nullptr;
  return std::unique_ptr<Embedder>(e.release());
}

}  // namespace ai
}  // namespace umbra
