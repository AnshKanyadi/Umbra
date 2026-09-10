# ADR 0010: The embedding model runs in process, through llama.cpp

- Status: accepted
- Date: 2026-09-10
- Depends on: [ADR 0007](0007-embeddings.md)

## Context

Phase 6 is a desktop app for someone who cannot use a terminal. Search needs an
embedding model on every query and on every note indexed, so if the model comes
from a daemon the user has to install, the app does not work on first launch —
and "install this other thing first" is where that user stops.

So the model has to come with the binary. The question was which runtime.

## The decision turns on the tokenizer, not the tensors

Both ONNX Runtime and llama.cpp can execute a sentence-transformer. They differ
in what else you need.

**ONNX Runtime is a tensor runtime.** It takes token ids and returns tensors. A
sentence-transformer needs BERT WordPiece tokenization with the model's exact
vocabulary, and ONNX Runtime does not do that. It would come from
`onnxruntime-extensions`, or the Rust `tokenizers` crate, or a hand-written
tokenizer — a second dependency with its own build system, and one where being
subtly wrong is the dangerous case. A tokenizer that splits *almost* correctly
produces vectors that are plausible, wrong, and silent: search gets worse and
nothing reports an error. This project has spent a lot of effort on failures
that look like successes; adding another one at the bottom of the stack is
exactly the wrong trade.

**llama.cpp carries the tokenizer.** It is inside the GGUF and inside the
library. The load log says so: `init_tokenizer: initializing tokenizer for type
3`. Nothing else is needed and there is no second vocabulary to keep in step.

It is also one CMake project with no Python in the build, which is what the
no-network build discipline in CMakeLists.txt requires. ONNX Runtime built from
source is a large, Python-assisted build; the prebuilt binaries are a downloaded
artefact, which is the thing that discipline exists to avoid.

## What was measured before committing

macOS arm64, CPU only, all-MiniLM-L6-v2 as a 43.8 MB GGUF:

| | llama.cpp, in process | Ollama daemon |
|---|---|---|
| throughput | **82–113 chunks/s** | 70 chunks/s |
| model load | 0.04s (mmap) | n/a |
| peak RSS | 91 MB including weights | separate process |
| binary size | 0.9 MB → 5.3 MB | 0.9 MB |
| network | none | HTTP to localhost |

Indexing and search were verified **with Ollama quit** and `127.0.0.1:11434`
refusing connections.

**The vectors agree with Ollama's all-minilm to 1e-4**, which is float rounding
rather than a difference in model or pooling. That matters more than the speed:
it means an index built either way is readable by the other, and every retrieval
number measured before this change still holds.

## Where the 43.8 MB of weights live

**Downloaded on first run, pinned by SHA-256, hosted in this project's own
GitHub Release.** Not in git, not in LFS.

```
sha256  797b70c4edf85907fe0a49eb85811256f65fa0f7bf52166b147fd16be2be4662
bytes   45949216
```

The hash is pinned in source and verified after download; a mismatch deletes the
file and fails loudly. That is the same discipline as pinning a submodule to a
commit — the difference between vendoring GoogleTest's 251 text files and
putting a 44 MB binary in history is that git can diff, merge and compress the
first and can do none of those for the second.

**Why not in git.** A GGUF is already compressed, so git stores it whole and
forever. The repository's history is 68 MB today; this would roughly double it
on the first commit and again on every model change, and every clone and every
CI checkout would pay for a file the build never reads.

**Why not LFS.** GitHub's free tier is 1 GB of storage *and* 1 GB of bandwidth a
month. At 43.8 MB per clone that is about twenty-three clones a month before it
bills, which for a project hoping to be popular is either a bill that scales
with success or a broken clone. LFS also makes `git clone` fail confusingly for
anyone without git-lfs installed, which is a bad first impression for a
contributor.

**Why the project's own release rather than Hugging Face.** A pinned third-party
URL is a dependency on someone else's retention policy. Release assets are
served by the same host as the repository and are not metered like LFS.

At runtime the file goes beside the device key, in the per-machine state
directory rather than in the vault:

```
~/Library/Application Support/Umbra/models/all-minilm-797b70c4.gguf
```

Named by its hash, so changing the pin downloads a new file rather than silently
overwriting one. A 44 MB download with a progress bar is an ordinary thing to
see during onboarding; it is not an ordinary thing to see during `git clone`.

Developers who already have the weights can skip all of it: `--model <path>`
takes any GGUF, including the blob Ollama has already downloaded.

## What had to bend for the CI matrix

Measured across the lanes rather than assumed.

**Nothing bent for `-Werror`, `-fno-exceptions` or `-fno-rtti`.** Those flags are
applied `PRIVATE` per target, so llama.cpp compiles with its own. And its C API
catches `std::exception` internally, so a corrupt GGUF returns null rather than
throwing across a `-fno-exceptions` boundary — that one bends on their side and
already had.

**`LLAMA_CURL=OFF` is required.** On, it pulls libcurl into a build that
deliberately has no network dependency.

**UBSan is the one that bends on ours.** GGML trips on the first embed:

```
ggml/src/ggml.c:7419: applying non-zero offset 96 to null pointer
```

`nullptr + 96`, a common C idiom for an offset from a null base — benign in
practice, undefined by the standard, and fatal here because the build runs
`-fno-sanitize-recover=all`.

It is **not suppressed**, because a suppression weakens the check over our own
code to accommodate a dependency our tests never call. Instead llama.cpp lives
in `umbra_local_embed`, a separate target that `umbra_test` does not link, so
the sanitizer lanes never contain GGML. Verified: the instrumented test binary
has zero `ggml` symbols and 289 tests pass under UBSan.

**ASan and TSan are clean.** Both were run by hand over a real index build with
the local embedder: ASan 53 chunks/s, TSan 12 chunks/s, no reports. GGML's
thread pool does not trip TSan on this workload.

**The coverage this gives up, stated plainly:** the embedding path is not
sanitizer-tested in CI. A clean-lane step compiles `umbra_ai` on all three
platforms so the integration cannot rot, but it is not instrumented.

## Consequences

- **CPU only, deliberately.** Metal is faster and adds a shader library that has
  to be located inside an app bundle. At 82 chunks/s a 3000-note vault indexes
  in about three minutes, which is what the daemon it replaces took. Revisit
  when that is the bottleneck.
- **Mean pooling, not CLS.** It is what sentence-transformers does and what the
  vectors in every existing index were made with. CLS on the same weights gives
  different numbers that look just as reasonable.
- **Truncation at 512 tokens.** A normal chunk caps at 1536 bytes, about 380
  tokens, and fits. An oversized chunk — chunk.h makes a code block larger than
  the budget into a single chunk of whatever size — is truncated rather than
  refused, because dropping it would take a real passage out of the index.
- **Ollama is still supported** and is still how generated answers work. This
  replaces it for embedding only.
- **The dependency is not small.** A shallow clone of llama.cpp is 172 MB and it
  adds about 60 seconds to a clean build. That cost lands on every contributor
  and every CI lane.
