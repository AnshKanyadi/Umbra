# Removing a device

Revoking a device rotates the epoch key. The removed device can no longer read
anything written after the rotation.

## What it keeps

Everything it already had. The files are on its disk in plaintext, its local log
is intact, and it still holds every epoch key it was ever given, so it can still
read anything on the relay sealed under those epochs.

Revocation moves writes forward. It does not reach backwards, and a tool that
implied otherwise would be lying at the worst possible moment.
