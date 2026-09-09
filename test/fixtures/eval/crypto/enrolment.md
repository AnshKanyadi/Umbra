# Letting a device in

A sealed box gives confidentiality and not authenticity: the ciphertext does not
say who sealed it. Anyone who can reach the relay can seal a grant to a joining
device's public key.

## The pairing code

Both devices display six digits derived from both public keys, sorted. The
joining device is the one that checks, because that is where a substituted key
shows up. Twenty bits is a deliberate ceiling: the attack is online and
one-shot, in front of a user looking at two screens.
