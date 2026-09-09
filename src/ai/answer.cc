#include "umbra/ai/answer.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <set>

namespace umbra {
namespace ai {
namespace {

constexpr std::size_t kMaxResponseBytes = 16u * 1024 * 1024;

// The same rule as the embedder: a local-first tool must not be one config
// string away from shipping the user's notes somewhere.
bool Loopback(const std::string& host) {
  if (host == "localhost") return true;
  struct in_addr v4;
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    return (ntohl(v4.s_addr) >> 24) == 127u;
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

// Pulls one JSON string field out by name and unescapes it. Same reasoning as
// the embedder's number scanner: the shape is fixed and known, and a general
// parser would be more code with more places to be wrong.
bool ExtractString(const std::string& body, const std::string& field,
                   std::string* out) {
  const std::string key = "\"" + field + "\"";
  std::size_t at = body.find(key);
  if (at == std::string::npos) return false;
  at = body.find(':', at + key.size());
  if (at == std::string::npos) return false;
  ++at;
  while (at < body.size() && (body[at] == ' ' || body[at] == '\n')) ++at;
  if (at >= body.size() || body[at] != '"') return false;
  ++at;
  out->clear();
  while (at < body.size()) {
    const char c = body[at];
    if (c == '"') {
      return true;
    }
    if (c == '\\') {
      if (at + 1 >= body.size()) return false;
      const char n = body[at + 1];
      switch (n) {
        case 'n':
          out->push_back('\n');
          break;
        case 'r':
          out->push_back('\r');
          break;
        case 't':
          out->push_back('\t');
          break;
        case '"':
          out->push_back('"');
          break;
        case '\\':
          out->push_back('\\');
          break;
        case 'u': {
          if (at + 5 >= body.size()) return false;
          unsigned code = 0;
          if (std::sscanf(body.c_str() + at + 2, "%4x", &code) != 1) {
            return false;
          }
          // Enough for the control characters an escape actually carries here.
          // A surrogate pair would need more; a model reply containing one is
          // dropped rather than mangled.
          if (code < 0x80) {
            out->push_back(static_cast<char>(code));
          } else if (code < 0x800) {
            out->push_back(static_cast<char>(0xC0 | (code >> 6)));
            out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
          } else if (code < 0xD800 || code > 0xDFFF) {
            out->push_back(static_cast<char>(0xE0 | (code >> 12)));
            out->push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out->push_back(static_cast<char>(0x80 | (code & 0x3F)));
          }
          at += 4;
          break;
        }
        default:
          out->push_back(n);
      }
      at += 2;
      continue;
    }
    out->push_back(c);
    ++at;
  }
  return false;
}

class OllamaGenerator : public Generator {
 public:
  OllamaGenerator(std::string model, std::string host, uint16_t port)
      : model_(std::move(model)), host_(std::move(host)), port_(port) {}

  bool Generate(const std::string& system, const std::string& user,
                std::string* out) override {
    if (!Loopback(host_)) return false;
    std::string body = "{\"model\":\"";
    body += JsonEscape(model_);
    body += "\",\"stream\":false,\"options\":{\"temperature\":0},";
    body += "\"messages\":[{\"role\":\"system\",\"content\":\"";
    body += JsonEscape(system);
    body += "\"},{\"role\":\"user\",\"content\":\"";
    body += JsonEscape(user);
    body += "\"}]}";

    std::string response;
    if (!RoundTrip("/api/chat", body, &response)) return false;
    // {"message":{"role":"assistant","content":"..."}}
    return ExtractString(response, "content", out);
  }

  const std::string& model() const override { return model_; }

 private:
  bool RoundTrip(const std::string& path, const std::string& body,
                 std::string* response) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const std::string port_s = std::to_string(port_);
    if (::getaddrinfo(host_.c_str(), port_s.c_str(), &hints, &res) != 0) {
      return false;
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
    if (fd < 0) return false;

    std::string request = "POST " + path + " HTTP/1.1\r\nHost: " + host_ + ":" +
                          port_s +
                          "\r\nContent-Type: application/json\r\nConnection: "
                          "close\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\n\r\n" + body;
    std::size_t sent = 0;
    while (sent < request.size()) {
      const ssize_t n =
          ::send(fd, request.data() + sent, request.size() - sent, 0);
      if (n <= 0) {
        ::close(fd);
        return false;
      }
      sent += static_cast<std::size_t>(n);
    }
    std::string raw;
    char buf[16384];
    for (;;) {
      const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
      if (n < 0) {
        ::close(fd);
        return false;
      }
      if (n == 0) break;
      if (raw.size() + static_cast<std::size_t>(n) > kMaxResponseBytes) {
        ::close(fd);
        return false;
      }
      raw.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    const std::size_t head = raw.find("\r\n\r\n");
    if (head == std::string::npos) return false;
    *response = raw.substr(head + 4);
    return true;
  }

  std::string model_;
  std::string host_;
  uint16_t port_;
};

class ScriptedGenerator : public Generator {
 public:
  explicit ScriptedGenerator(std::string reply)
      : reply_(std::move(reply)), name_("scripted") {}
  bool Generate(const std::string&, const std::string&,
                std::string* out) override {
    *out = reply_;
    return true;
  }
  const std::string& model() const override { return name_; }

 private:
  std::string reply_;
  std::string name_;
};

}  // namespace

const char* AnswerStatusName(AnswerStatus s) {
  switch (s) {
    case AnswerStatus::kAnswered:
      return "answered";
    case AnswerStatus::kNoPassages:
      return "no-passages";
    case AnswerStatus::kUngrounded:
      return "ungrounded";
    case AnswerStatus::kRetrievalFailed:
      return "retrieval-failed";
    case AnswerStatus::kGenerationFailed:
      return "generation-failed";
  }
  return "unknown";
}

std::unique_ptr<Generator> NewOllamaGenerator(const std::string& model,
                                              const std::string& host,
                                              uint16_t port) {
  return std::unique_ptr<Generator>(new OllamaGenerator(model, host, port));
}

std::unique_ptr<Generator> NewScriptedGenerator(const std::string& reply) {
  return std::unique_ptr<Generator>(new ScriptedGenerator(reply));
}

const char* SystemPrompt() {
  // WRITTEN TO BE READ BY THE USER AS WELL AS THE MODEL. If the answering rules
  // are going to be enforced by a prompt, the prompt has to be somewhere a
  // person can check them rather than buried in a string literal nobody prints.
  return "You answer questions about the user's own notes.\n"
         "\n"
         "Rules:\n"
         "1. Use ONLY the numbered passages provided. They are the whole of "
         "what "
         "you know here.\n"
         "2. Cite every claim with the passage number in square brackets, like "
         "[2]. A sentence with no citation is not acceptable.\n"
         "3. If the passages do not contain the answer, say exactly that and "
         "stop. "
         "Do not fill the gap from general knowledge, and do not guess.\n"
         "4. Do not invent passage numbers. Only the numbers shown exist.\n"
         "5. Be brief. The user can read the passages themselves.";
}

std::string BuildPrompt(const std::string& query,
                        const std::vector<Passage>& passages) {
  std::string out = "Question: ";
  out += query;
  out += "\n\nPassages:\n";
  for (std::size_t i = 0; i < passages.size(); ++i) {
    out += "\n[";
    out += std::to_string(i + 1);
    out += "] ";
    if (!passages[i].heading_path.empty()) {
      out += passages[i].heading_path;
      out += "\n";
    }
    out += passages[i].text;
    out += "\n";
  }
  out += "\nAnswer using only these passages, citing each claim.";
  return out;
}

std::vector<uint32_t> ParseCitations(const std::string& text,
                                     uint32_t passage_count) {
  std::set<uint32_t> found;
  for (std::size_t i = 0; i + 1 < text.size(); ++i) {
    if (text[i] != '[') continue;
    std::size_t j = i + 1;
    uint32_t value = 0;
    uint32_t digits = 0;
    while (j < text.size() && text[j] >= '0' && text[j] <= '9' && digits < 4) {
      value = (value * 10) + static_cast<uint32_t>(text[j] - '0');
      ++j;
      ++digits;
    }
    if (digits == 0 || j >= text.size() || text[j] != ']') continue;
    // A NUMBER OUTSIDE THE RANGE IS IGNORED, NOT TRUSTED. A model that invents
    // [9] when six passages were shown must not be able to make that resolve to
    // anything; the citation simply does not count, which is what makes an
    // answer built on invented citations come back as ungrounded.
    if (value >= 1 && value <= passage_count) found.insert(value - 1);
  }
  return std::vector<uint32_t>(found.begin(), found.end());
}

IndexStatus Retrieve(const Index& index, Embedder* embedder,
                     const DocumentSource& source, const std::string& query,
                     const AnswerOptions& options, std::vector<Passage>* out,
                     std::vector<Passage>* near_misses) {
  out->clear();
  if (near_misses != nullptr) near_misses->clear();
  if (embedder == nullptr) return IndexStatus::kBadArgument;

  Vector q;
  if (embedder->EmbedQuery(query, &q) != EmbedStatus::kOk) {
    return IndexStatus::kBadArgument;
  }
  std::vector<SearchHit> hits;
  // Retrieve more than are wanted, because the floor and the link demotion
  // both discard, and discarding down to nothing when a fifth hit would have
  // served is a worse failure than a slightly slower search.
  const uint32_t wide = options.k * 3;
  const IndexStatus s = index.Search(q, wide, options.ef, &hits);
  if (s != IndexStatus::kOk) return s;

  std::vector<Passage> kept;
  std::vector<Passage> misses;
  std::vector<Passage> demoted;
  const float best = hits.empty() ? 0.0f : hits[0].score;
  for (const SearchHit& h : hits) {
    Passage p;
    p.object = h.object;
    p.start = h.start;
    p.end = h.end;
    p.heading_path = h.heading_path;
    p.score = h.score;
    p.kind = h.kind;
    p.link_ratio = h.link_ratio;

    std::string document;
    if (source && source(h.object, &document) && h.end <= document.size() &&
        h.start < h.end) {
      p.text = document.substr(h.start, h.end - h.start);
      p.resolved = true;
    }

    // THE RELATIVE FLOOR ONLY MEANS ANYTHING WHEN THE BEST SCORE IS POSITIVE.
    // It is a fraction of the best hit, and multiplying a NEGATIVE best by a
    // fraction gives a number ABOVE it -- so on a query where everything is
    // negatively correlated, a floor meant to keep the top results discarded
    // all of them. "Fifty-five per cent of the best" is not a statement about a
    // best that is below zero, and the honest reading is that there is nothing
    // to be a fraction of.
    const bool relative_applies = best > 0.0f;
    if (h.score < options.min_score ||
        (relative_applies && h.score < best * options.relative_floor)) {
      if (misses.size() < 3) misses.push_back(p);
      continue;
    }
    // A PASSAGE THAT CANNOT BE RESOLVED IS NEVER CITED. The note may have been
    // deleted or shortened since it was indexed; putting a range in front of
    // the model that no longer exists would produce a citation that goes
    // nowhere, which is worse than one fewer passage.
    if (!p.resolved) continue;
    if (p.link_ratio >= options.demote_link_ratio) {
      demoted.push_back(p);
      continue;
    }
    kept.push_back(p);
    if (kept.size() >= options.k) break;
  }
  // A map of contents is rarely the answer, but it is better than nothing.
  for (const Passage& p : demoted) {
    if (kept.size() >= options.k) break;
    if (kept.empty()) kept.push_back(p);
  }
  out->swap(kept);
  if (near_misses != nullptr) near_misses->swap(misses);
  return IndexStatus::kOk;
}

AnswerResult Answer(const Index& index, Embedder* embedder,
                    Generator* generator, const DocumentSource& source,
                    const std::string& query, const AnswerOptions& options) {
  AnswerResult r;
  const IndexStatus s = Retrieve(index, embedder, source, query, options,
                                 &r.passages, &r.near_misses);
  if (s != IndexStatus::kOk) {
    r.status = AnswerStatus::kRetrievalFailed;
    return r;
  }
  if (r.passages.empty()) {
    // NOTHING IS SAID BEYOND WHAT IS KNOWN. No answer is generated at all --
    // not even a hedged one, because a hedged answer from a model that was
    // given nothing is still a model talking about a vault it cannot see.
    r.status = AnswerStatus::kNoPassages;
    r.text =
        "Nothing in the vault is close enough to that question to answer "
        "from.";
    return r;
  }
  if (generator == nullptr) {
    r.status = AnswerStatus::kAnswered;
    return r;
  }
  std::string text;
  if (!generator->Generate(SystemPrompt(), BuildPrompt(query, r.passages),
                           &text)) {
    r.status = AnswerStatus::kGenerationFailed;
    return r;
  }
  r.text = text;
  r.cited = ParseCitations(text, static_cast<uint32_t>(r.passages.size()));
  // AN ANSWER THAT CITES NOTHING IS MARKED, NOT DISCARDED AND NOT ACCEPTED.
  // Discarding it hides that the model had something to say; accepting it
  // silently is the failure this whole file exists to prevent. The caller is
  // told and can decide what to show.
  r.status =
      r.cited.empty() ? AnswerStatus::kUngrounded : AnswerStatus::kAnswered;
  return r;
}

}  // namespace ai
}  // namespace umbra
