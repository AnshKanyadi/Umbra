#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace umbra {
namespace relay {
namespace {

bool ReadExactly(int fd, char* p, std::size_t n, int timeout_seconds) {
  std::size_t got = 0;
  while (got < n) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    const int pr = ::poll(&pfd, 1, timeout_seconds * 1000);
    if (pr <= 0) return false;  // timeout or error: drop the connection
    const ssize_t r = ::read(fd, p + got, n - got);
    if (r == 0) return false;  // peer closed
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

}  // namespace

Server::Server(Store* store, const ServerOptions& opts)
    : store_(store), opts_(opts) {}

Server::~Server() {
  if (listen_fd_ >= 0) ::close(listen_fd_);
}

bool Server::Start() {
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) return false;
  int yes = 1;
  (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(opts_.port);
  if (::inet_pton(AF_INET, opts_.bind.c_str(), &addr.sin_addr) != 1) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) != 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::listen(listen_fd_, 16) != 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  struct sockaddr_in actual;
  socklen_t len = sizeof(actual);
  if (::getsockname(listen_fd_, reinterpret_cast<struct sockaddr*>(&actual),
                    &len) == 0) {
    bound_port_ = ntohs(actual.sin_port);
  }
  running_ = true;
  return true;
}

void Server::Stop() { running_ = false; }

void Server::HandleConnection(int fd) {
  int one = 1;
  (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  while (running_) {
    char header[4];
    if (!ReadExactly(fd, header, 4, opts_.idle_timeout_seconds)) break;
    const uint32_t len = GetU32Le(header);
    // REFUSED BEFORE IT IS READ. A hostile length must not be able to make the
    // relay allocate; this is the small-VPS bound, not politeness.
    if (len == 0 || len > kMaxFrameBytes) {
      (void)WriteAll(fd, EncodeError("frame too large"));
      break;
    }
    std::string body;
    body.resize(len);
    if (!ReadExactly(fd, &body[0], len, opts_.idle_timeout_seconds)) break;

    const std::string reply = HandleRequest(store_, body);
    if (!WriteAll(fd, reply)) break;
  }
  ::close(fd);
  --live_connections_;
}

void Server::Run() {
  // SIGPIPE would kill the process when a client vanishes mid-write. Ignored
  // once, here, rather than checked at every write.
  ::signal(SIGPIPE, SIG_IGN);
  while (running_) {
    struct pollfd pfd;
    pfd.fd = listen_fd_;
    pfd.events = POLLIN;
    pfd.revents = 0;
    const int pr = ::poll(&pfd, 1, 200);  // 200ms so Stop() is noticed promptly
    if (pr <= 0) continue;
    const int fd = ::accept(listen_fd_, nullptr, nullptr);
    if (fd < 0) continue;
    if (live_connections_.load() >= opts_.max_connections) {
      // Accepted and closed rather than queued, so the client finds out now.
      ::close(fd);
      continue;
    }
    ++live_connections_;
    std::thread(&Server::HandleConnection, this, fd).detach();
  }
  // Give in-flight connections a moment to finish rather than yanking the
  // store out from under them.
  for (int i = 0; i < 50 && live_connections_.load() > 0; ++i) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 20 * 1000 * 1000;
    ::nanosleep(&ts, nullptr);
  }
}

}  // namespace relay
}  // namespace umbra
