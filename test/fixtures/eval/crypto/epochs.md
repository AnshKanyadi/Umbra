# Epoch keys

An epoch key is random, not derived. A derived key would be computable by a
device that knows the root, and every device that has ever been enrolled knows
the root, so revocation would be theatre.

Epoch keys are stored wrapped under the root key. That is what makes
passphrase-only recovery possible when every device is gone.

## Rotation

Rotation generates a new epoch key and seals it to the devices that remain.
Writes move forward to the new epoch; reads of older epochs keep working for
anyone who holds those keys.
