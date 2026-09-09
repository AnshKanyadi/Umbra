# What runs on every push

Twelve lanes: three sanitizers plus a control, across macOS and Ubuntu, under
clang and gcc. A library-only build proves the client does not drag the relay's
server into it.

Chunk boundaries are checked under both char signedness settings on one machine,
because char is signed on x86 and unsigned on ARM.
