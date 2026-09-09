# Using Umbra on one machine

Build Umbra from a clean checkout, turn a folder of markdown into a vault, index
it, and ask it questions. Everything here runs locally: the notes, the model and
the index never leave the machine.

Written for macOS. Nothing is assumed to be installed.

## Read this before you point it at real notes

Two things are worth knowing before you start: where the keys live, and what
that means if you ever restore or move the vault.

**Umbra writes into your vault folder, but not its device key.** Creating a
vault adds `<vault>/.umbra/` holding `salt`, `epochs` and `log/`. All three are
safe to sync: an Argon2id salt is public by construction, the epoch keys are
wrapped under a root only your passphrase derives, and the log is sealed. They
stay in the vault on purpose — they are what lets your passphrase recover the
vault when every device is gone, so a backup of the folder is a real backup.

This machine's **device key** is the one plaintext secret, and it is deliberately
kept somewhere else:

```
~/Library/Application Support/Umbra/devices/<name derived from the vault path>
```

A vault folder is the sort of thing iCloud or Obsidian Sync watches, and a
copied private key makes two machines into one device. Override the location
with `--state-dir PATH`, which both `umbra_sync` and `umbra_ai` accept and which
names the directory itself.

**What this changes about restoring.** Restoring a vault folder onto a new Mac
no longer brings the identity with it. The passphrase still decrypts everything,
but that machine is not a member of the vault until you enrol it from a device
that is. Same if you move or rename the vault: the identity is filed under the
old path, and Umbra will say so and stop rather than quietly minting a new one.
If you still have the old state directory, point at it with `--state-dir` and
nothing needs re-enrolling.

Only two commands ever make an identity: `umbra_sync --create` and
`umbra_sync --enrol`. Everything else fails and explains when there is none.

**The index is sealed with your vault's keys.** `umbra_ai` reads the salt and
the wrapped epoch keys from `<vault>/.umbra`, exactly as `umbra_sync` does, so
an index is worth what the passphrase is worth. That means two things in
practice: you must create the vault before you can index it, and every
`umbra_ai` command takes a passphrase the same way `umbra_sync` does —
`--pass-file`, `UMBRA_PASSPHRASE`, or a prompt.

It also means every invocation pays Argon2id, about half a second.

## 1. Prerequisites

Xcode command line tools, for a compiler:

```sh
xcode-select --install
```

Homebrew, if you do not have it:

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

CMake, to build:

```sh
brew install cmake
```

Ollama, to embed. Two ways, and they start differently — pick one:

- **The app**, from <https://ollama.com/download>. Open it once; it runs a
  server in the background and puts `ollama` on your `PATH` at
  `/usr/local/bin/ollama`. This is what ollama.com gives you and what this page
  was tested against.
- **The formula**, `brew install ollama`, then `brew services start ollama`.

Either way it serves on `127.0.0.1:11434`, which is where Umbra looks. The two
are not interchangeable once installed: `brew services start ollama` does
nothing for an app install, and vice versa.

Pull the embedding model. `nomic-embed-text` is the one Umbra's own evaluation
chose; it is 274 MB and runs on the CPU:

```sh
ollama pull nomic-embed-text
```

Check it answers before going further:

```sh
curl -s http://127.0.0.1:11434/api/tags | grep nomic-embed-text
```

Docker is **not** needed for anything on this page. It is needed only to run the
multi-device tests in `docker/`.

## 2. Build

```sh
git clone --recursive https://github.com/AnshKanyadi/Umbra.git
cd Umbra
```

`--recursive` matters: Basalt, libsodium and googletest are submodules, and the
build refuses to configure without them rather than reaching for the network. If
you already cloned without it:

```sh
git submodule update --init --recursive
```

Configure and build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

That produces `build/umbra_ai`, `build/umbra_sync` and `build/umbra_relay`.

Optionally, check the build is sound before trusting it with anything:

```sh
./build/umbra_test
```

## 3. Create a vault

A vault is a folder of markdown plus an `.umbra` directory holding its salt and
its wrapped keys. Use a **copy** of your notes:

```sh
cp -R ~/Documents/MyObsidianVault ~/Desktop/umbra-test-vault
```

Put the passphrase in a file rather than typing it on the command line, because
an argument vector is visible to `ps` and to your shell history:

```sh
printf 'a long passphrase you will remember\n' > ~/.umbra-pass
chmod 600 ~/.umbra-pass
```

Create it:

```sh
./build/umbra_sync --dir ~/Desktop/umbra-test-vault --pass-file ~/.umbra-pass --create
```

This prints the vault id, this device's id, and then attempts one sync round. On
one machine with no relay running it says so, and that is expected:

```
  cannot reach the relay at 127.0.0.1:9000. Nothing was pushed or pulled this round.
round 1: 8 local changes, 0 pushed, 0 applied, 0 written, 0 devices
```

The vault is created and the command exits 0. Every other `umbra_sync` mode
exits non-zero when it cannot reach a relay, because a sync that reached nobody
is a failed sync; `--create` is the exception, because it was asked for a vault
and made one.

Key derivation is Argon2id and runs on every invocation. On an idle M-series Mac
in a Release build it is about 0.5s; on a busy one it was 3.2s in the same
binary, so do not read a slow first run as a problem. A debug build is far
slower again.

You do not need a relay to index and search. It is needed only to sync a second
device, which is not this page.

## 4. Index it

Step 3 is not optional any more: the index is sealed with the vault's keys, so
there has to be a vault first.

```sh
./build/umbra_ai \
  --vault ~/Desktop/umbra-test-vault \
  --index ~/Desktop/umbra-index \
  --model nomic-embed-text \
  --pass-file ~/.umbra-pass \
  --build
```

It walks the folder for `.md` files, splits each into chunks on heading and
paragraph boundaries, embeds every chunk through Ollama, and writes sealed
segments under `~/Desktop/umbra-index/segments`.

It reports how long chunking, embedding and indexing took, how many vectors it
holds, and how large the index is relative to the source. Embedding is the slow
part and it is bounded by Ollama, not by Umbra — about 25-45 chunks a second
through `nomic-embed-text` on a laptop.

Two things the numbers will show that are worth expecting:

- **Not every file becomes a vector.** Files inside dot-directories are skipped,
  so Obsidian's own `.obsidian/` and `.trash/` are ignored. Empty notes produce
  no chunk. A vault of four notes where one is empty reports `4 files` and three
  objects.
- **The index is much larger than the source, and that ratio is misleading on a
  small vault.** Each vector is 768 floats — about 3 KB — regardless of how
  short the note is. On 354 bytes of markdown the index is 33x the source; on a
  real vault it settles near 5-6x.

Re-running `--build` over an unchanged vault adds no vectors: segments are
content addressed, so an unchanged note produces the same segment and is
recognised rather than duplicated. The store file still grows by a kilobyte or
two per run, which compaction reclaims.

To merge the many small segments a first build produces into fewer large ones:

```sh
./build/umbra_ai \
  --vault ~/Desktop/umbra-test-vault \
  --index ~/Desktop/umbra-index \
  --model nomic-embed-text \
  --pass-file ~/.umbra-pass \
  --compact
```

**Compact when you are done indexing for a while, not between builds.** A
`--build` after a `--compact` re-adds every note as its own segment and
tombstones the copies inside the compacted one, so the index roughly doubles and
then settles. It is correct and it is wasted work. Build, build, build, then
compact.

## 5. Search it

```sh
./build/umbra_ai \
  --vault ~/Desktop/umbra-test-vault \
  --index ~/Desktop/umbra-index \
  --model nomic-embed-text \
  --pass-file ~/.umbra-pass \
  --ask 'what did I decide about the budget'
```

You get passages with a cosine score and a citation, best first:

```
answered in 0.06s

[1]  0.6440  Umbra's test vault/Welcome.md:0-203
```

The two numbers are **byte offsets into the file**, not line numbers — chunking
works in bytes so it stays independent of the model (`include/umbra/ai/chunk.h`).
`0-203` is the first 203 bytes.

Below a relevance floor of 0.60 Umbra declines to answer rather than returning
the nearest thing it has, and prints what it rejected so the floor is visible:

```
no-passages in 0.05s

Nothing in the vault is close enough to that question to answer from.

nearest, below the floor of 0.60:
  0.5201  Umbra's test vault/more testing.md:2-116
```

**On a small vault you will see that a lot,** including for queries that look
like an obvious match — a note titled "Distributed Systems" scored 0.52 against
the query `distributed systems`. The floor was chosen against a 3000-note corpus
where 0.60 separates useful from noise; with a handful of notes there is little
for a score to stand out against. Lower it:

```sh
./build/umbra_ai \
  --vault ~/Desktop/umbra-test-vault \
  --index ~/Desktop/umbra-index \
  --model nomic-embed-text \
  --pass-file ~/.umbra-pass \
  --floor 0.45 \
  --ask 'distributed systems'
```

To get prose rather than passages, name a chat model Ollama has. The answer is
grounded in the retrieved passages and cites them:

```sh
ollama pull llama3.2:3b
./build/umbra_ai \
  --vault ~/Desktop/umbra-test-vault \
  --index ~/Desktop/umbra-index \
  --model nomic-embed-text \
  --pass-file ~/.umbra-pass \
  --generator llama3.2:3b \
  --ask 'what is this vault about'
```

Every sentence carries a `[n]` pointing at the passage it came from, and the
passages are listed underneath. Expect a few seconds rather than a few
milliseconds — 4.5s for the above, all of it the chat model.

What the index holds, at any point:

```sh
./build/umbra_ai \
  --vault ~/Desktop/umbra-test-vault \
  --index ~/Desktop/umbra-index \
  --model nomic-embed-text \
  --pass-file ~/.umbra-pass \
  --stats
```

## If something goes wrong

**`cannot reach a local Ollama for nomic-embed-text`** — Ollama is not running,
or not on 11434. Open Ollama.app, or `brew services start ollama` for a formula
install, then check `curl -s http://127.0.0.1:11434/api/tags`. If that lists
models but not `nomic-embed-text`, `ollama pull nomic-embed-text`.

**`third_party/basalt is empty`** at configure time — the submodules are not
checked out. `git submodule update --init --recursive`.

**`no markdown under <dir>`** — the vault path is wrong, or the folder has no
`.md` files. Umbra indexes `.md` only and skips dotfiles and dot-directories.

**`cannot reach the relay`** from `umbra_sync` — expected on one machine with no
relay. Nothing on this page needs one.

**`<dir> is not a vault yet`** from `umbra_ai` — run `umbra_sync --create` on
the vault first. The keys that seal an index live in `<vault>/.umbra`.

**`cannot open this vault with that passphrase`** — the passphrase does not
match the one the vault was created with. There is no recovery for a forgotten
passphrase; that is the point of it.

**`cannot open the index: segment-lost`** on an index that used to work — it was
built by a version of `umbra_ai` that derived its own keys rather than the
vault's. Those segments were sealed under a key that was never secret. Delete
the index directory and rebuild it.

**`no device identity on this machine for the vault at ...`** — this machine
has no device key for that vault. Nothing is lost; the message explains the two
ways forward. Most often the vault was moved or renamed, in which case
`--state-dir` pointed at the old directory restores it without re-enrolling.

**`cannot open the index at <dir>: model-mismatch`** — you changed `--model`.
An index is bound to the model that built it, because vectors from two models
are not comparable, and it refuses to open rather than mixing them. Use a
separate `--index` directory per model.

## Known limits

- **A vault rename orphans the device identity.** The state directory is named
  from the vault's path, so moving the folder means re-enrolling unless you pass
  `--state-dir`. Filing the key under something stabler — the macOS Keychain is
  the obvious candidate, and the right home for a private key regardless — would
  fix this. It is platform-specific and a real dependency, so it belongs behind
  the same `--state-dir` seam as another place to look rather than a rewrite of
  how identity works.
- **There is no watcher wired into `umbra_ai`.** Re-run `--build` after you
  have written notes; unchanged notes cost a re-embed but do not duplicate
  anything.
- **An interrupted segment transfer restarts from the beginning.** See
  ADR 0008; it costs at most one segment.
