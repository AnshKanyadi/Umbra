# The relay

The relay stores bytes it cannot read. It cannot order operations, it cannot
understand them, and the build enforces that: the relay binary links only
Basalt, never the CRDT or the crypto.

## What it learns anyway

Ciphertext sizes, message timing, how many devices are active, and roughly how
large the vault is. None of that is hidden and all of it is written down.
