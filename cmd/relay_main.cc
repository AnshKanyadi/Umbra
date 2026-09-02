// The relay, as a command.
//
//     umbra_relay --dir /var/lib/umbra --port 9000
//
// Two flags, both with defaults. It holds no keys, needs no configuration file,
// and there is nothing to tune: the point of item 2 is that someone can run this
// on a small VPS without reading a spec.
#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "server.h"
#include "store.h"

namespace {

umbra::relay::Server* g_server = nullptr;

extern "C" void OnSignal(int) {
  if (g_server != nullptr) g_server->Stop();
}

void Usage() {
  std::fprintf(
      stderr,
      "umbra_relay -- stores and forwards ciphertext\n"
      "\n"
      "  --dir PATH    where to keep it (default ./umbra-relay-data)\n"
      "  --port N      TCP port (default 9000, 0 picks a free one)\n"
      "  --bind ADDR   default 0.0.0.0\n"
      "  -v            log each connection\n"
      "\n"
      "It holds no keys and can decrypt nothing. Put a TLS-terminating\n"
      "proxy in front of it if you want the network hidden too; the\n"
      "relay itself is assumed hostile by the design either way.\n");
}

}  // namespace

int main(int argc, char** argv) {
  std::string dir = "./umbra-relay-data";
  umbra::relay::ServerOptions opts;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    const char* next = (i + 1 < argc) ? argv[i + 1] : nullptr;
    if (a == "--dir" && next != nullptr) {
      dir = next;
      ++i;
    } else if (a == "--port" && next != nullptr) {
      opts.port = static_cast<uint16_t>(std::atoi(next));
      ++i;
    } else if (a == "--bind" && next != nullptr) {
      opts.bind = next;
      ++i;
    } else if (a == "-v" || a == "--verbose") {
      opts.verbose = true;
    } else {
      Usage();
      return 2;
    }
  }

  std::unique_ptr<umbra::relay::Store> store;
  if (umbra::relay::Store::Open(dir, &store) !=
      umbra::relay::StoreStatus::kOk) {
    std::fprintf(stderr, "cannot open %s\n", dir.c_str());
    return 1;
  }

  umbra::relay::Server server(store.get(), opts);
  if (!server.Start()) {
    std::fprintf(stderr, "cannot bind %s:%u\n", opts.bind.c_str(),
                 static_cast<unsigned>(opts.port));
    return 1;
  }
  g_server = &server;
  ::signal(SIGINT, OnSignal);
  ::signal(SIGTERM, OnSignal);

  std::printf("umbra_relay listening on %s:%u, data in %s\n", opts.bind.c_str(),
              static_cast<unsigned>(server.port()), dir.c_str());
  std::fflush(stdout);
  server.Run();
  std::printf("stopped\n");
  return 0;
}
