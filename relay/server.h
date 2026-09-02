// A TCP server around Store. No TLS.
//
// NO TLS IS A DELIBERATE OMISSION AND NOT A GAP TO FILL LATER WITH AN APOLOGY.
// The relay is assumed hostile (threat model §2), so a channel that
// authenticates the relay to the client protects against nobody the design
// worries about. What TLS would protect against is the weaker adversary of §2 --
// a network observer -- who otherwise sees the same routing fields the relay
// sees. Terminating TLS in front of this, with any reverse proxy, is the
// intended deployment and costs nothing here; embedding it would mean shipping
// certificate handling in a binary whose whole claim is that it holds no
// secrets.
#ifndef UMBRA_RELAY_SERVER_H_
#define UMBRA_RELAY_SERVER_H_

#include <atomic>
#include <cstdint>
#include <string>

#include "store.h"

namespace umbra {
namespace relay {

struct ServerOptions {
  uint16_t port = 9000;
  // 0.0.0.0 by default: the point is to be reachable. Bind to 127.0.0.1 when
  // something else terminates TLS on the same host.
  std::string bind = "0.0.0.0";
  // A hard cap, because a small VPS is the target. Connections beyond it are
  // accepted and closed rather than queued, so a client learns immediately.
  int max_connections = 64;
  // Seconds. A connection that sends nothing is dropped, so a peer that opens
  // sockets and stops cannot hold them forever.
  int idle_timeout_seconds = 120;
  bool verbose = false;
};

class Server {
 public:
  Server(Store* store, const ServerOptions& opts);
  ~Server();

  // Binds and listens. Returns false if the port cannot be taken.
  bool Start();
  // The port actually bound, which differs from the requested one when 0 was
  // asked for. Tests use that to avoid racing for a fixed port.
  uint16_t port() const { return bound_port_; }

  // Serves until Stop(). Blocks.
  void Run();
  // Safe from another thread and from a signal handler.
  void Stop();

 private:
  void HandleConnection(int fd);

  Store* store_;
  ServerOptions opts_;
  int listen_fd_ = -1;
  uint16_t bound_port_ = 0;
  std::atomic<bool> running_{false};
  std::atomic<int> live_connections_{0};
};

}  // namespace relay
}  // namespace umbra

#endif  // UMBRA_RELAY_SERVER_H_
