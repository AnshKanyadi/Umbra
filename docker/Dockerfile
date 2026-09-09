# A device, or a relay. One image, three containers.
#
# WHY THIS EXISTS. Every "two device" test before this was two directories on
# one machine: one kernel, one clock, one filesystem, one loopback interface.
# That hid everything network-shaped -- DNS, real TCP, latency, loss -- and it
# hid the question of whether a device is a host or a folder, which it answered
# wrongly for two phases. Containers on a bridge network are the cheapest thing
# that is genuinely separate.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# iproute2 is not decoration: tc netem lives there, and adding latency and loss
# is half the point of running this on a real network stack.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      build-essential cmake python3 iproute2 iputils-ping dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The submodules come in with the source. There is no network at build time,
# which is a property of the CMakeLists this must not quietly break.
COPY . /src
# UMBRA_BUILD_TESTS stays ON, which looks wrong and is not: the three command
# line binaries are declared AFTER the early return at CMakeLists.txt:254, so
# turning tests off removes the relay along with them. Only the three targets
# are built, so googletest is configured and never compiled. Worth fixing when
# packaging is on the table; not worth a layout change today.
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /build --target umbra_relay_bin umbra_sync umbra_ai -j "$(nproc)" \
 && mkdir -p /opt/umbra \
 && cp /build/umbra_relay /build/umbra_sync /build/umbra_ai /opt/umbra/ \
 && rm -rf /build /src

ENV PATH="/opt/umbra:${PATH}"
WORKDIR /work
CMD ["sleep", "infinity"]
