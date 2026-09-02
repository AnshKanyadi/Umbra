# ADR 0004: Enrolment is authenticated by a pairing code the user compares

- Status: accepted
- Date: 2026-09-02
- Depends on: [docs/threat-model.md](../threat-model.md) §6,
  [ADR 0001](0001-storage.md)

## Context

Phase 2 built the half of enrolment that keeps a joining device's epoch key
secret: `VaultKeys::SealEpochToDevice` puts the key in an anonymous sealed box
addressed to the device's public key. `keys.h` describes that box accurately,
including the part that matters here:

> Anonymous sealed box: only the holder of the matching secret key can open it,
> **and the ciphertext does not say who sealed it.**

Anyone can seal to a public key. That is what "anonymous" means. So a relay --
or anyone who can write to it -- can answer a joining device's request with its
own grant, sealed to that device's **real** public key, carrying its own epoch
key. The grant decrypts. Nothing is malformed. The device is now enrolled in the
attacker's vault, syncing notes the attacker can read, while the user believes
it joined theirs.

Confidentiality was never the missing piece. Authenticity was.

`test/enroll_test.cc` asserts both halves of this: that the forged grant really
does open, so the attack is not hypothetical, and that the pairing code differs.

## Options considered

**(a) Sign the grant with the enrolling device's key.** A signature proves the
grant came from the holder of some key. The joining device has no way to know
which key is legitimate, so this is trust-on-first-use with extra steps: an
attacker signs with its own key and the device believes it just as readily.

**(b) Derive the envelope key from a long pairing code the user types.** A
128-bit code typed by hand is secure and nobody will do it. A short one is
brute-forceable **offline** by the relay, which holds the ciphertext, so the
code's length becomes the whole security of the vault.

**(c) A short authentication string over keys already exchanged.** Both devices
display digits derived from both public keys. The user compares. An attacker
must substitute a key *before* it can see which digits that produces, and the
honest device has already displayed the honest digits, so there is nothing to
search for afterwards.

## Decision

**(c).** Six digits, from the first 20 bits of
`BLAKE2b("umbra enrol sas" || lo || hi)` where `lo` and `hi` are the two public
keys sorted, so each side computes the same value without knowing which of them
is joining (`src/sync/enroll.cc`).

Twenty bits is a deliberate ceiling and not a target. It is the number a person
will actually compare, and it is sound *here* because:

- the attack is **online and one-shot** — one try, per enrolment, in front of a
  user looking at two screens;
- the code authenticates keys that have already been exchanged, rather than
  being a secret anything is derived from, so there is no offline search.

It would be indefensible in option (b), where the same twenty bits would be a
key.

## Where the check happens, and why only there

**The joining device checks. The approving device only displays.**

Only one of the two can do the checking, and it must be the one that *receives*
the grant, because that is where a substituted key appears. If a relay puts its
own key in front of the joining device, the relay seals the grant, so the
grant's `from` field holds the relay's key and the digits the joining device
computes are not the digits the approving device showed.

Putting the check on the approving device instead would catch nothing: that
device would compare its own honest code against a user who read the honest code
off the other screen, and approve.

The comparison is made **by the program**, against digits the user types
(`--code NNNNNN`), rather than being an instruction to look carefully. "I
compared it" and "it matched" cannot then come apart.

## What the joining device is told out of band

The vault id, as `--vault HEX`. It cannot derive it: the id comes from the root
key, the root key comes from the passphrase **and** the vault's salt, and the
salt is what enrolment delivers. Without it a joining device knocks on a vault
of its own that nobody else is in.

This is not a leak. The relay sees the vault id on every request ever made
against that vault.

## The enrolled set does not come from the relay

Revocation seals the new epoch key to the devices that remain. The obvious place
to get that list is the relay -- every grant envelope names the device it was
sealed to -- and it is the wrong place, because the relay controls it.

Hiding a grant would be survivable: a device simply does not get the new key and
stops syncing, which is visible. **Replaying one is not.** A relay that re-serves
a grant it saw before puts the removed device back in the list, and the very
command the user ran to remove it seals the new epoch key to it. The revocation
would report success and do the opposite of what it said.

So the list is kept locally, in `.umbra/enrolled`: this device approved these
devices, so this device knows. The relay is never consulted.

The residual limit, stated: **a device can only revoke devices it approved
itself.** If two devices have each let others in, neither holds the whole list,
and `--revoke` says so and names the device to run it on rather than rotating
against a list it knows is partial. A shared authenticated roster -- sealed
under the epoch key the way device reports are, so the relay can carry it
without being able to write it -- is the way to close that, and is not built.

## Consequences

**The residual risk is stated, not defaulted away.** If the user does not
compare, this is trust-on-first-use through the relay and a hostile relay can
enrol itself. The program will not enrol without a code, and the threat model
says so in §6 rather than leaving it implied.

**Revocation now means something.** Before this, `umbra_sync` derived the epoch
key from the root with `OverwriteEpochForBootstrap`, which `keys.h` explicitly
warns against: a removed device knows the root, so it could compute every future
epoch key and rotation would be theatre. Epoch keys are now random, as designed,
which forces them to be **stored** -- wrapped under the root, which is the same
mechanism that makes passphrase-only recovery work when every device is gone.

**Adopting the salt must precede wrapping the epoch key.** The root is derived
from the passphrase and the salt; wrapping under a root the device is about to
stop having produces a vault it cannot open on its next run. The first
implementation did exactly that. Enrolment therefore runs Argon2id a second
time, once, on the one invocation that enrols.

**The relay learns that an enrolment happened.** Envelopes are opaque to it --
it cannot tell a request from a grant -- but their appearance is visible.
Recorded in threat model §5.8 rather than claimed away.
