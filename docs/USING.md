# Using Umbra on one machine

Build Umbra from a clean checkout, turn a folder of markdown into a vault, index
it, and ask it questions. Everything here runs locally: the notes, the model and
the index never leave the machine.

Written for macOS. Nothing is assumed to be installed.

## Read this before you point it at real notes

Two things are true today and neither is obvious from the commands.

**Umbra writes one file into your vault folder.** Indexing creates
`<vault>/.umbra/device`, a keypair that is this device's identity, mode 0600.
Creating a vault also writes `<vault>/.umbra/salt` and `<vault>/.umbra/epochs`.
If the folder is an Obsidian vault that something else syncs, that hidden folder
syncs with it.

**The AI index is not meaningfully encrypted at rest.** `umbra_ai` is a driver
for measuring the index, not a finished product, and it derives its keys from a
passphrase constant in the source with a fixed salt (`cmd/ai_main.cc`, `KeysFor`).
Anyone with the binary can open an index it wrote. The sealing is real and the
format is the real one; the *key* is not a secret. Point it at a copy of your
notes, keep the `--index` directory somewhere you would be comfortable leaving
plaintext, and do not treat it as protected storage yet.

Vaults made by `umbra_sync` are different: those keys come from a passphrase you
choose, and that path is the real one.

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

```sh
./build/umbra_ai \
  --vault ~/Desktop/umbra-test-vault \
  --index ~/Desktop/umbra-index \
  --model nomic-embed-text \
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
  --stats
```

## Keeping it current

There is no watcher wired into `umbra_ai` yet. Re-run `--build` after you have
written notes; unchanged notes cost a re-embed but do not duplicate anything.

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

**`cannot open the index at <dir>: model-mismatch`** — you changed `--model`.
An index is bound to the model that built it, because vectors from two models
are not comparable, and it refuses to open rather than mixing them. Use a
separate `--index` directory per model.
