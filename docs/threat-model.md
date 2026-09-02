# Threat model

This document states what Umbra protects, what it does not, and who it assumes
is hostile. It is written before the protocol and the crypto so that those are
designed against a stated adversary rather than measured against one afterwards.

Everything below is a constraint on later phases. Where a decision has been made
it is stated as made. Where a limit exists it is stated as a limit, in the
place a reader would look for a reassurance.

## 1. What Umbra is

A sync engine for a folder of markdown files, self-hosted. One user, several
devices. A relay server passes data between those devices. The user's notes are
encrypted on each device before they reach the relay and are decrypted only on
another of that user's devices.

Sharing between users is **out of scope**. Not deferred — out of scope. Every
design decision here assumes one key holder, and several of them would have to
be reopened to add a second.

## 2. The adversary

**The relay is hostile.** This is the central assumption and it is not
hypothetical hedging. A self-hostable system is one people host on hardware they
rent, borrow, or were given access to, so the realistic cases are:

- the relay is operated by a stranger, because the user picked a public
  instance;
- the relay is operated by the user and has been compromised;
- the relay's operator has been served a subpoena and is complying with it.

These are the same adversary for our purposes: someone with full read access to
everything stored, full visibility of everything transiting, the ability to
retain all of it indefinitely, and the ability to lie about it. A relay that
returns stale data, drops messages, reorders them, or serves one device a
different history from another is behaving within its capabilities.

**The relay stores and forwards ciphertext only.** It never holds a key. There
is no server-side search, no server-side rendering, no server-side conflict
resolution, and no feature that would require any of those, because each would
require plaintext.

Also in scope, at lower priority:

- **A network observer** between a device and the relay. Sees less than the
  relay does; treated as a strictly weaker adversary and not modelled
  separately.
- **A stolen device.** Addressed by the key hierarchy in §4 and by revocation
  in §7, with the limits stated there.

Explicitly **not** in scope:

- An attacker with code execution on a device while the vault is unlocked. At
  that point the plaintext is on that machine and no protocol property survives.
- A malicious editor, plugin, or backup tool with read access to the vault
  directory. Umbra watches a plain folder of markdown files; anything that can
  read that folder has the plaintext, by design.
- Traffic analysis by a global passive adversary correlating multiple users
  across relays.

## 3. What is confidential

**File contents.** The obvious one.

**File paths and file names.** Less obvious, and the reason for most of the
design's complexity. A vault's directory structure is content: `clients/acme/`
names a customer, `2026-02-medical/` names a subject, and a filename is very
often a summary of the file. A system that encrypted note bodies and left a
directory listing in the clear would be protecting the least sensitive half.

So:

- Each file has an **opaque object ID**, unrelated to its path and not derived
  from it. The relay addresses objects by that ID and learns nothing from it.
- The **path-to-ID mapping is client-side only**. It is part of the encrypted
  state; the relay never holds a decryptable copy.
- **Directory structure does not exist on the relay.** There are no folders
  server-side, only objects. The tree is reconstructed on a device from
  decrypted metadata.

An object ID must therefore not be a hash of the path. That would let the relay
confirm a guessed filename by computing its ID — which is the same leak, only
requiring the relay to ask a question rather than read an answer.

## 4. Key hierarchy

```
  passphrase
      |  Argon2id
      v
  root key  ------------------------------------------.
      |                                                |
      |  derives                                       | wraps
      v                                                v
  vault keys (content, metadata, index)          device keypairs
```

**A passphrase, stretched with Argon2id, produces the root key.** Argon2id
because the passphrase is the weakest link and the only defence available is
making each guess expensive in both time and memory. Parameters are a later
decision; that they are tuned against a GPU attacker and not against a laptop
is a requirement now.

**Per-device keypairs sit beneath the root key.** Each device has its own
keypair; the root key wraps them. A device holds its own private key and the
material it needs to participate, not the passphrase.

Two properties this buys, both of which are requirements and not
side effects:

- **The passphrase alone recovers a vault with no surviving device.** A user
  whose laptop and phone are both gone, holding only the passphrase and whatever
  the relay still stores, can decrypt. This is the reason the root key derives
  from the passphrase rather than being generated randomly and wrapped by it —
  the latter would need a copy of the wrapped root key to survive, and "the
  backup you did not make" is the most common way people lose data.
- **Device keys rotate without changing the passphrase.** Removing a device must
  not require every other device to be re-enrolled and must not require the user
  to memorize something new. Rotation replaces device-level material and the
  keys used for future writes; the passphrase and the root key are untouched.

The consequence, stated plainly: **the passphrase is a single point of failure
in both directions.** Forgetting it loses the vault, and disclosing it loses the
vault. There is no recovery path that does not amount to storing the passphrase
somewhere, and Umbra does not provide one.

## 5. What the relay learns anyway

This is the section that matters. A design that encrypts contents and names
still leaks, and the leaks below are real. For each: whether Umbra mitigates it,
how, or that it does not.

### 5.1 Ciphertext sizes — **not mitigated**

The relay sees the byte length of every object it stores. AEAD ciphertext is
approximately plaintext-sized, so the relay learns each note's approximate
length and every change in that length over time.

This is a genuine leak. A 40-byte note and a 200-kilobyte note are
distinguishable, and a note that grows by roughly the same amount every weekday
is recognizable as a journal. Padding to fixed-size buckets would reduce it and
is **not implemented and not planned for the first release**: the effective
choice is between a small number of buckets, which wastes a large multiple of
storage and bandwidth on a corpus of mostly-small markdown files, and a large
number, which leaks nearly as much as the exact size. Neither is a good enough
trade to pay for by default.

Stated as a limit rather than softened: **an operator who knows the approximate
size of a document can tell whether you are storing it.**

### 5.2 Message timing — **not mitigated**

The relay sees when each device connects and when each write arrives. Over time
that is a record of when the user works, when they sleep, what time zone they
are in, when they travel, and when they stop using the vault.

Umbra does not add cover traffic and does not delay writes to obscure this. Cover
traffic that is convincing has to run when the user is asleep, and a sync engine
whose whole value is that changes arrive promptly cannot also delay them. This
is a design decision against mitigation, not an oversight.

### 5.3 Number of active devices — **not mitigated**

The relay authenticates devices individually and therefore knows how many there
are, when a new one is enrolled, and when one stops appearing. Device identity
has to be distinguishable to the relay for revocation to mean anything — a relay
that cannot tell devices apart cannot refuse a removed one — so this leak is
bought deliberately, in exchange for §7.

### 5.4 Approximate total vault size — **not mitigated**

The sum of §5.1, plus the object count. The relay knows roughly how much you
have written and how many notes it is spread across. Deletion is visible as
such: the relay sees an object stop being updated and, once garbage collected,
sees it removed.

### 5.5 Activity patterns over time — **not mitigated**

The relay can correlate across all of the above. Which object IDs change
together in one sync is visible, and that is a structural fingerprint: notes
edited in the same session are related, and an object that changes every time
another changes is plausibly linked to it. Over months this reveals which notes
are active, which are archived, and roughly how the vault is organized — without
revealing a single name.

**Object IDs are stable for the life of an object**, which is what makes this
correlation possible over time. Rotating them per write would break it, and
would also break the relay's ability to garbage collect superseded versions and
a new device's ability to fetch an object it has not seen. That trade has been
made in favour of stable IDs, and the leak is the price.

### 5.6 Withholding, and what it costs — **partially mitigated**

A relay cannot read, forge or reorder anything. It can **refuse to hand things
over**, and that is worth its own entry because it is the attack the rest of the
design is most exposed to.

Two shapes, and they are not equally dangerous:

**Omitting an operation from the middle of a range — detected.** Every operation
carries, inside its encrypted payload, the counter of the previous operation from
the same device for the same object (ADR 0001, "Ordering is not completeness").
A client accepts an operation only when that back-pointer equals its cursor, so a
skipped operation is unambiguous and the cursor refuses to advance. Without this
a relay could induce a client to believe it held something it did not, and the
client would then seal that false belief honestly — **authentication makes a
report un-forgeable, it does not make it true.**

**Withholding everything newer — not prevented, and it is a denial of service.**
A relay that serves a correct but stale view, claiming to have nothing newer when
it does, cannot corrupt anything: the cursor does not move, the prefix mark stays
truthful, and log compaction stays conservative. What it can do is **hold
compaction hostage indefinitely**, because the watermark is a minimum over what
every device has received. The tree log then grows without bound on every device,
which is the cost ADR 0003 accepts in exchange for its safety condition.

It is **detectable but not preventable**. A device's own report says how far it
has produced, so a client that holds a device's report claiming counter 57 while
its own cursor for that device sits at 41 knows the relay is stale. Detection
tells the user their relay is misbehaving; it does not get them their data. The
answer to a relay that withholds is to host a different one, which is the point
of the whole system being self-hostable.

### 5.8 That an enrolment is happening — **not mitigated**

Enrolment envelopes sit on the relay next to the operations. The relay sees a
new 32-byte tag appear, sees a second envelope appear addressed to a tag derived
from it, and sees a new device begin publishing reports shortly afterwards. It
learns that a device joined, and when.

It does not learn the epoch key, which is sealed to a public key it does not
hold, and it does not learn the passphrase, which never leaves a device. What it
learns is that the household grew, which is the same class of fact as §5.3 and
is not separable from having an enrolment mechanism at all.

### 5.7 Summary

| What the relay learns | Mitigated? | How, or why not |
|---|---|---|
| File contents | Yes | Encrypted client-side; the relay holds no key |
| File and directory names | Yes | Opaque object IDs; path mapping is client-side only |
| Directory structure | Yes | No server-side tree; objects only |
| Ciphertext size per object | **No** | Padding rejected as too costly for a markdown corpus |
| Per-message timing | **No** | Cover traffic and delay both defeat the product's purpose |
| Number of active devices | **No** | Device identity must be distinguishable for revocation |
| Approximate total vault size | **No** | Follows from per-object sizes and object count |
| Which objects change together | **No** | Follows from stable object IDs, which are required |
| Long-term activity patterns | **No** | Follows from timing and correlation above |
| Whether a client is missing an operation | Yes | Encrypted back-pointer chain; the cursor refuses to advance across a gap |
| Whether the relay is withholding everything newer | **Detected, not prevented** | A denial of service that holds log compaction hostage; see §5.6 |
| That a device enrolled, and when | **No** | Inseparable from having an enrolment mechanism; see §5.8 |
| Who sealed an enrolment grant | **Detected, not prevented** | A pairing code the user compares; see §6a |

Five of the first nine rows are "no". That ratio is what an encrypted-blob store
against a hostile relay actually looks like, and a document that reported
otherwise would be describing a different system.

The last two rows are integrity rather than confidentiality, and they are stated
here because the same adversary produces both.

## 6. Enrolment, and the one thing the user has to do

A sealed box gives confidentiality and **not** authenticity. `keys.h` says so in
its own comment: the ciphertext "does not say who sealed it". Anyone who can
reach the relay can seal a grant to a joining device's real public key, and that
grant decrypts perfectly. The joining device would then be enrolled in the
attacker's vault while the user believes it joined theirs.

So enrolment ends in a comparison the user makes:

```
joining device                     enrolling device
--------------                     ----------------
umbra_sync --enrol --vault ID      umbra_sync --approve DEVICE
  pairing code 649 260               pairing code 649 260
                                   
umbra_sync --enrol --code 649260
```

Both devices display six digits derived from **both public keys**, sorted so the
two sides compute the same value. The joining device is the one that checks,
because the joining device is where a substituted key shows up: a relay that put
its own key in front of it sealed the grant itself, so the `from` key in the
grant is the relay's and the digits do not match. The check is made by the
program against digits the user types, not left as an instruction to look
carefully, so "I compared it" and "it matched" cannot come apart.

**Twenty bits is a deliberate ceiling.** Six digits is one guess in a million.
That holds because the attack is online and one-shot -- the attacker gets one
try, in front of a user looking at two screens -- and because the code
authenticates keys that have already been exchanged rather than being a secret
anything is derived from. It would not hold if the code could be attacked
offline.

**If the user does not compare, this is trust-on-first-use through the relay,**
and a hostile relay can enrol itself into the vault. That is the honest
statement of the residual risk. It is not defaulted away, and the program does
not enrol without a code.

What an interceptor gets from watching an enrolment: two public keys, a vault
id it already had, a salt that is public by construction, and a sealed epoch key
it cannot open. Not the passphrase, which never leaves a device, and not the
epoch key.


## 7. Revocation, and what it cannot do

**The list of devices to re-key is local, never the relay's.** A relay that
replayed an old grant envelope could otherwise put a removed device back into
the set that gets the new epoch key, and the command the user ran to remove it
would seal the key to it. See [ADR 0004](adr/0004-enrolment.md). The cost is
that a device can only revoke devices it approved itself; it says so rather than
rotating against a list it knows is partial.

Removing a device rotates keys so that **writes made after the rotation cannot
be read by the removed device**. That is the whole of the guarantee.

**Ciphertext the relay has already served cannot be recalled.** Concretely:

- Any data the removed device already holds, it keeps. It is on that device.
- Any data the removed device already fetched from the relay, it keeps, whether
  or not it was decrypted at the time.
- If the relay is hostile or was compromised, it may have handed out everything
  it had before the rotation, and rotation does not reach that copy.
- Revocation depends on the relay refusing the removed device's credentials. A
  **hostile relay will not enforce this**, and the removed device retains
  whatever it can still fetch under old credentials.

So revocation is only meaningful against a device that has stopped being able to
reach the relay, or a relay that is honest about enforcing it. Against a stolen
device that already synced the vault, rotation protects **future** notes and
nothing else. Against an attacker who has both the device and the passphrase, it
protects nothing.

Anything a device could read before the rotation should be treated as
permanently disclosed to whoever holds that device.

## 8. Integrity and rollback

The relay can withhold data, serve old data, or serve different data to
different devices. Encryption alone does not prevent any of these — a hostile
relay that returns yesterday's version of a note is not breaking ciphertext, it
is choosing what to send.

Authenticated encryption prevents the relay from forging or modifying a version.
It does not prevent replay of a genuine earlier version, and it does not prevent
withholding. Detecting those needs the operation log to be verifiable in
sequence, so that a device can tell that it is being served a prefix of history
rather than all of it.

**This is a stated open problem, not a solved one.** The design phase that
specifies the operation log owes an answer, and the acceptance criterion is that
a device can distinguish "nothing has changed" from "the relay is not telling
me what changed". Until then, Umbra defends confidentiality against a hostile
relay and only partially defends freshness.

## 9. Non-goals

- **Deniability.** The relay knows a vault exists, whose account it belongs to,
  and roughly how big it is. Umbra does not offer hidden volumes.
- **Anonymity.** The relay sees the connecting IP address unless the user puts
  something in front of it. Umbra does not.
- **Protection from the vault directory itself.** Plaintext markdown on a local
  disk is the point of the product. Full-disk encryption is the user's
  responsibility.
- **Protecting against the user's own backups.** A backup tool copying the vault
  folder copies plaintext.

## 10. Terms this document will not use

No claim in this repository will describe the cryptography as "military-grade",
"unbreakable", "bank-level", or "zero-knowledge". The first three mean nothing.
The fourth means something specific and different from what Umbra does, and
using it as a synonym for "encrypted client-side" is a claim the design does not
support.

What Umbra does is stated in §2 through §8, including the parts that are
uncomfortable.
