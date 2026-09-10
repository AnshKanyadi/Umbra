// umbra_ai: build an index over a folder, query it, and measure it.
//
// This is the tool the numbers in the phase report come from. It is a driver,
// not a product: it takes a folder of markdown, chunks it, embeds it through
// whichever backend is configured, and reports what that cost.
//
// WHY THE MEASUREMENTS LIVE IN A BINARY RATHER THAN A TEST. A test that
// depended on a model being installed would be skipped in CI and would
// therefore rot; a test that asserted a throughput number would fail on a
// slower machine for no defect. The numbers belong in a report with the machine
// named, and the tool that produces them belongs where anyone can rerun it.
#include <dirent.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "umbra/ai/answer.h"
#include "umbra/ai/chunk.h"
#include "umbra/ai/embed.h"
#include "umbra/ai/index.h"
#include "umbra/ai/manifest.h"
#include "umbra/ai/topics.h"
#include "umbra/crdt/op.h"
#include "umbra/crdt/oplog.h"
#include "umbra/crypto/keys.h"
#include "umbra/sync/client.h"
#include "vault_state.h"

namespace {

using namespace umbra;
using namespace umbra::ai;

double Since(const std::chrono::steady_clock::time_point& t) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - t)
      .count();
}

bool ReadWholeFile(const std::string& path, std::string* out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  std::stringstream ss;
  ss << f.rdbuf();
  *out = ss.str();
  return true;
}

// Sorted, so two runs over one folder index in the same order and the segment
// ids are comparable between them. readdir order is not specified.
void ListMarkdown(const std::string& root, const std::string& prefix,
                  std::vector<std::string>* out) {
  DIR* d = ::opendir((root + "/" + prefix).c_str());
  if (d == nullptr) return;
  std::vector<std::string> names;
  struct dirent* e = nullptr;
  while ((e = ::readdir(d)) != nullptr) {
    const std::string name = e->d_name;
    if (name == "." || name == ".." || name[0] == '.') continue;
    names.push_back(name);
  }
  ::closedir(d);
  std::sort(names.begin(), names.end());
  for (const std::string& name : names) {
    const std::string rel = prefix.empty() ? name : prefix + "/" + name;
    struct stat st;
    if (::stat((root + "/" + rel).c_str(), &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      ListMarkdown(root, rel, out);
    } else if (rel.size() > 3 && rel.compare(rel.size() - 3, 3, ".md") == 0) {
      out->push_back(rel);
    }
  }
}

// A stable object id from a path, so re-running the tool over one folder
// updates the same objects rather than duplicating them. A real vault takes
// these from the tree CRDT, where they are drawn from entropy; here the folder
// is the source of truth and the path is the only stable name there is.
ObjectId ObjectForPath(const std::string& rel) {
  ObjectId id;
  uint8_t digest[16];
  crypto_generichash(digest, sizeof(digest),
                     reinterpret_cast<const unsigned char*>(rel.data()),
                     rel.size(), nullptr, 0);
  std::memcpy(id.bytes.data(), digest, id.bytes.size());
  return id;
}

uint64_t DirectoryBytes(const std::string& dir) {
  uint64_t total = 0;
  DIR* d = ::opendir(dir.c_str());
  if (d == nullptr) return 0;
  struct dirent* e = nullptr;
  while ((e = ::readdir(d)) != nullptr) {
    const std::string name = e->d_name;
    if (name == "." || name == "..") continue;
    struct stat st;
    const std::string p = dir + "/" + name;
    if (::stat(p.c_str(), &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      total += DirectoryBytes(p);
    } else {
      total += static_cast<uint64_t>(st.st_size);
    }
  }
  ::closedir(d);
  return total;
}

// THE VAULT'S KEYS, NOT THIS TOOL'S OWN.
//
// This used to derive a root from a passphrase constant in this file with a
// fixed salt and weak Argon2id parameters, and then derive the epoch key from
// that root. Two deliberate compromises, both of them defensible for what this
// once was and neither survivable now that it is pointed at real notes:
//
//  - The constant passphrase and fixed salt made an index at rest openable by
//    anyone holding this binary. The sealing was real, the format was real, and
//    the key was not a secret -- against the project's one headline claim.
//  - The DERIVED epoch key was worse in a quieter way. keys.h says an epoch key
//    must be random precisely so a removed device, which knows the root, cannot
//    compute future ones. A derived epoch key means revocation buys nothing:
//    the removed device recomputes the next content key and reads every segment
//    written after it was removed.
//
// The reason for both was the same: the driver had no vault to read keys from,
// and it wanted its measurements not to be drowned by nine seconds of Argon2id
// per run. It has a vault now -- the one whose notes it is indexing -- so it
// reads the salt and the wrapped epoch keys from `<vault>/.umbra`, exactly as
// cmd/sync_main.cc does, through the same code (cmd/vault_state.h).
//
// The cost is a real one and worth stating: every invocation pays Argon2id at
// the default parameters, about half a second, and an index built by the old
// binary cannot be opened by this one. There is no migration and there should
// not be: those indexes were sealed under a key that was never secret.
struct Options;
VaultKeys VaultKeysFor(const Options& o);

struct Options;
ReplicaId ReplicaFor(const Options& o);

std::unique_ptr<Embedder> MakeEmbedder(const std::string& model,
                                       uint32_t hashing_dim) {
  if (model == "hashing") return NewHashingEmbedder(hashing_dim);
#if defined(UMBRA_HAVE_LLAMA)
  // A PATH MEANS A LOCAL MODEL, no daemon and no network. Phase 6 needs search
  // to work on a machine where nothing has been installed; this is that path.
  // The descriptor is declared to match what the Ollama backend records for the
  // same weights, because the vectors agree to 1e-4 and an index built either
  // way must stay readable by the other.
  if (model.find('/') != std::string::npos ||
      model.rfind(".gguf") != std::string::npos) {
    ModelDescriptor d;
    d.family = "all-minilm";
    d.version = "resolved-by-backend";
    d.quantisation = "unknown";
    d.pooling = "backend";
    d.normalised = true;
    EmbedStatus st = EmbedStatus::kOk;
    std::unique_ptr<Embedder> local = NewLocalEmbedder(model, d, &st);
    if (local == nullptr) {
      std::fprintf(stderr, "cannot load the model at %s: %s\n", model.c_str(),
                   EmbedStatusName(st));
      std::exit(1);
    }
    return local;
  }
#endif
  EmbedStatus st = EmbedStatus::kOk;
  std::unique_ptr<Embedder> e =
      NewOllamaEmbedder(model, "127.0.0.1", 11434, &st);
  if (e == nullptr) {
    std::fprintf(stderr, "cannot reach a local Ollama for %s: %s\n",
                 model.c_str(), EmbedStatusName(st));
    std::exit(1);
  }
  return e;
}

void Usage() {
  std::fprintf(
      stderr,
      "umbra_ai --vault DIR --index DIR [--model NAME] COMMAND\n"
      "\n"
      "  --build              chunk, embed and index the vault\n"
      "                       add --compact to merge segments after\n"
      "  --ask QUESTION       retrieve and answer\n"
      "  --eval FILE          run a question set and report\n"
      "  --stats              what the index holds\n"
      "  --topics [K]         group every chunk and say what is in the vault\n"
      "  --compact            merge segments and drop tombstones\n"
      "  --push               publish this index to the relay\n"
      "  --pull               fetch the index from the relay\n"
      "\n"
      "  --relay HOST:PORT    where the vault's relay is\n"
      "  --pass-file PATH     the vault passphrase, or UMBRA_PASSPHRASE,\n"
      "                       or a prompt. Never an argument.\n"
      "  --state-dir PATH     where this machine keeps its device key\n"
      "\n"
      "  --model NAME         all-minilm, nomic-embed-text, a path to a\n"
      "                       .gguf for a local model with no daemon, or\n"
      "                       hashing for the deterministic stand-in\n"
      "  --generator NAME     an Ollama chat model for --ask\n"
      "  --floor F            the relevance floor, cosine\n");
}

struct Options {
  std::string vault;
  std::string index_dir;
  std::string relay;
  bool push = false;
  bool pull = false;
  std::string model = "all-minilm";
  std::string generator;
  std::string question;
  std::string eval_file;
  float floor = 0.60f;
  bool build = false;
  bool stats = false;
  bool compact = false;
  // Never a --pass flag: an argument vector is visible in `ps`.
  // Taken verbatim when given: the directory holding this machine's key.
  std::string state_dir;
  bool topics = false;
  uint32_t topic_k = 0;
  std::string pass_file;
};

VaultKeys VaultKeysFor(const Options& o) {
  std::string pass;
  if (!cmdstate::ResolvePassphrase(o.pass_file, &pass)) std::exit(2);
  VaultKeys keys;
  const cmdstate::OpenVaultStatus st =
      cmdstate::OpenVaultKeys(o.vault, pass, &keys);
  if (st == cmdstate::OpenVaultStatus::kNotAVault) {
    std::fprintf(stderr,
                 "%s is not a vault yet. Create it first:\n"
                 "  umbra_sync --dir %s --pass-file FILE --create\n",
                 o.vault.c_str(), o.vault.c_str());
    std::exit(1);
  }
  if (st != cmdstate::OpenVaultStatus::kOk) {
    std::fprintf(stderr, "cannot open this vault with that passphrase\n");
    std::exit(1);
  }
  return keys;
}

ReplicaId ReplicaFor(const Options& o) {
  // NEVER MINTS. umbra_ai is not one of the two commands that may make a device
  // a member of a vault -- creating and joining are umbra_sync's -- so a
  // missing identity here is a state to explain, not one to paper over. An
  // invented replica id would sign manifest operations as a device the vault
  // has never enrolled, and every peer would carry them as a stranger's.
  //
  // main() refuses every command without a --vault, so there is always a vault
  // to anchor to.
  DeviceKeyPair d;
  if (!cmdstate::RequireDeviceKeys(
          o.vault, cmdstate::StateDirFor(o.vault, o.state_dir), &d)) {
    std::exit(1);
  }
  return d.Replica();
}

int Build(const Options& o) {
  std::vector<std::string> files;
  ListMarkdown(o.vault, "", &files);
  if (files.empty()) {
    std::fprintf(stderr, "no markdown under %s\n", o.vault.c_str());
    return 1;
  }
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  if (Index::Open(o.index_dir, &keys, keys.current(), e->id(), e->dimension(),
                  ReplicaFor(o), &index) != IndexStatus::kOk) {
    std::fprintf(stderr, "cannot open the index at %s\n", o.index_dir.c_str());
    return 1;
  }

  std::printf("model %s dim %u id %s\n", o.model.c_str(), e->dimension(),
              e->id().Short().c_str());
  std::printf("%zu files\n", files.size());

  const auto t0 = std::chrono::steady_clock::now();
  double chunk_seconds = 0;
  double embed_seconds = 0;
  double index_seconds = 0;
  uint64_t source_bytes = 0;
  std::size_t chunks_total = 0;
  std::size_t skipped = 0;

  for (std::size_t i = 0; i < files.size(); ++i) {
    std::string body;
    if (!ReadWholeFile(o.vault + "/" + files[i], &body)) continue;
    source_bytes += body.size();
    const ObjectId object = ObjectForPath(files[i]);

    const auto c0 = std::chrono::steady_clock::now();
    std::vector<Chunk> chunks;
    const ChunkStatus cs = ChunkMarkdown(object, body, &chunks);
    chunk_seconds += Since(c0);
    if (cs != ChunkStatus::kOk) {
      ++skipped;
      continue;
    }
    if (chunks.empty()) continue;
    chunks_total += chunks.size();

    std::vector<std::string> texts;
    texts.reserve(chunks.size());
    for (const Chunk& c : chunks) texts.push_back(c.text);

    const auto e0 = std::chrono::steady_clock::now();
    std::vector<Vector> vs;
    if (e->EmbedDocuments(texts, &vs) != EmbedStatus::kOk) {
      std::fprintf(stderr, "embedding failed on %s\n", files[i].c_str());
      return 1;
    }
    embed_seconds += Since(e0);

    const auto i0 = std::chrono::steady_clock::now();
    if (index->PutObject(object, chunks, vs) != IndexStatus::kOk) {
      std::fprintf(stderr, "indexing failed on %s\n", files[i].c_str());
      return 1;
    }
    index_seconds += Since(i0);

    if ((i + 1) % 200 == 0) {
      std::printf("  %zu/%zu files, %zu chunks, %.1fs\n", i + 1, files.size(),
                  chunks_total, Since(t0));
      std::fflush(stdout);
    }
  }

  // COMPACTION IS NOT PART OF A BUILD, because it is O(the whole index) and a
  // build can be one file. Measured: reindexing a single note into a
  // 13,838-vector index costs 0.14s to chunk, embed and store -- and 103s if a
  // compaction follows it, because merging 145 segments rebuilds the entire
  // graph. Running it automatically would destroy the incremental property the
  // store was designed for.
  //
  // So it is an explicit command (--compact), and the operator decides when to
  // pay for it. See ADR 0005 on why compaction is all-or-nothing today.
  double compact_seconds = 0;
  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  if (o.compact) {
    const auto k0 = std::chrono::steady_clock::now();
    (void)index->Compact(8, 20, &merged, &reclaimed);
    compact_seconds = Since(k0);
  }

  const double total = Since(t0);
  const IndexStats st = index->Stats();
  const uint64_t disk = DirectoryBytes(o.index_dir);

  std::printf(
      "\n"
      "source        %llu bytes over %zu files (%zu unchunkable)\n"
      "chunks        %zu, %.1f per file, %llu bytes per chunk\n"
      "chunking      %.2fs\n"
      "embedding     %.2fs  (%.0f chunks/s)\n"
      "indexing      %.2fs\n"
      "compaction    %.2fs  (%u segments merged, %u reclaimed)\n"
      "total         %.2fs\n"
      "\n"
      "segments      %u holding %u vectors (%u dead)\n"
      "index on disk %llu bytes, %.2fx the source\n"
      "vector data   %llu bytes of that is raw float32\n",
      static_cast<unsigned long long>(source_bytes), files.size(), skipped,
      chunks_total,
      files.empty() ? 0.0
                    : static_cast<double>(chunks_total) /
                          static_cast<double>(files.size()),
      static_cast<unsigned long long>(
          chunks_total == 0 ? 0 : source_bytes / chunks_total),
      chunk_seconds, embed_seconds,
      embed_seconds > 0 ? static_cast<double>(chunks_total) / embed_seconds : 0,
      index_seconds, compact_seconds, merged, reclaimed, total, st.segments,
      st.vectors, st.tombstoned, static_cast<unsigned long long>(disk),
      source_bytes == 0
          ? 0.0
          : static_cast<double>(disk) / static_cast<double>(source_bytes),
      static_cast<unsigned long long>(static_cast<uint64_t>(st.vectors) *
                                      e->dimension() * 4));
  return 0;
}

DocumentSource VaultSource(const std::string& root,
                           const std::vector<std::string>& files) {
  std::map<std::string, std::string> by_object;
  for (const std::string& rel : files) {
    const ObjectId id = ObjectForPath(rel);
    by_object[std::string(reinterpret_cast<const char*>(id.bytes.data()),
                          id.bytes.size())] = rel;
  }
  const std::string base = root;
  return [by_object, base](const ObjectId& o, std::string* out) {
    const std::string key(reinterpret_cast<const char*>(o.bytes.data()),
                          o.bytes.size());
    const std::map<std::string, std::string>::const_iterator it =
        by_object.find(key);
    if (it == by_object.end()) return false;
    return ReadWholeFile(base + "/" + it->second, out);
  };
}

std::string PathOf(const std::string& root,
                   const std::vector<std::string>& files, const ObjectId& o) {
  for (const std::string& rel : files) {
    if (ObjectForPath(rel) == o) return rel;
  }
  (void)root;
  return "(unknown)";
}

int Ask(const Options& o) {
  std::vector<std::string> files;
  ListMarkdown(o.vault, "", &files);
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, keys.current(), e->id(), e->dimension(),
                    ReplicaFor(o), &index);
    if (s != IndexStatus::kOk) {
      std::fprintf(stderr, "cannot open the index at %s: %s\n",
                   o.index_dir.c_str(), IndexStatusName(s));
      return 1;
    }
  }
  std::unique_ptr<Generator> gen;
  if (!o.generator.empty()) {
    gen = NewOllamaGenerator(o.generator, "127.0.0.1", 11434);
  }
  AnswerOptions opts;
  opts.min_score = o.floor;

  const auto t0 = std::chrono::steady_clock::now();
  const AnswerResult r = Answer(*index, e.get(), gen.get(),
                                VaultSource(o.vault, files), o.question, opts);
  const double seconds = Since(t0);

  std::printf("%s in %.2fs\n\n", AnswerStatusName(r.status), seconds);
  if (!r.text.empty()) {
    if (r.status == AnswerStatus::kUngrounded) {
      // THE MARK IS NOT SUBTLE. An ungrounded answer that looks like a grounded
      // one is the whole failure mode.
      std::printf(
          "!! UNGROUNDED: the model cited none of the passages below.\n"
          "!! Treat this as the model talking, not the vault.\n\n");
    }
    if (r.status == AnswerStatus::kNoAnswerInPassages) {
      std::printf(
          "!! NOT ANSWERED: the model read the passages below and said they "
          "do not\n"
          "!! answer this. Anything after this line is what it found, not an "
          "answer.\n\n");
    }
    std::printf("%s\n\n", r.text.c_str());
  }
  // WHAT SHARE OF THE VAULT THIS ANSWER SAW, always, before the passages.
  //
  // "6 of 6 passages" reads as nothing at all when the question was about one
  // thing, and reads as an indictment when it was "summarize these notes" --
  // which is the case the guards cannot catch, because a summary of six chunks
  // is a true summary of six chunks. The line does not decide anything. It
  // takes the sentence the answer was silently making, that these passages
  // stand for the vault, and puts the numbers next to it.
  if (!r.passages.empty() && r.vault_passages > 0) {
    std::printf(
        "drawn from %zu of %u passages, across %u note(s) in the vault\n",
        r.passages.size(), r.vault_passages, r.vault_notes);
  }
  // THE SHAPE OF THE SCORES, PRINTED. An absolute score cannot be read on its
  // own: 0.71 is a strong hit in one query and the top of an undifferentiated
  // cluster in another. The spread is what tells them apart, so it is shown
  // rather than left for a user to infer from six numbers.
  if (r.passages.size() > 1) {
    const float top = r.passages.front().score;
    const float bottom = r.passages.back().score;
    std::printf("retrieval  top %.3f, %zu passages within %.3f%s\n", top,
                r.passages.size(), top - bottom,
                (top - bottom) < 0.05f ? "  (barely told apart)" : "");
  }
  for (std::size_t i = 0; i < r.passages.size(); ++i) {
    const Passage& p = r.passages[i];
    const bool cited = std::find(r.cited.begin(), r.cited.end(),
                                 static_cast<uint32_t>(i)) != r.cited.end();
    std::printf("[%zu]%s %.4f  %s:%u-%u%s%s\n", i + 1, cited ? "*" : " ",
                p.score, PathOf(o.vault, files, p.object).c_str(), p.start,
                p.end, p.heading_path.empty() ? "" : "  ",
                p.heading_path.c_str());
  }
  if (r.status == AnswerStatus::kNoPassages && !r.near_misses.empty()) {
    std::printf("\nnearest, below the floor of %.2f:\n", opts.min_score);
    for (const Passage& p : r.near_misses) {
      std::printf("  %.4f  %s:%u-%u\n", p.score,
                  PathOf(o.vault, files, p.object).c_str(), p.start, p.end);
    }
  }
  return 0;
}

// A question set: one question per line, then a tab, then a substring that must
// appear in a cited passage for the retrieval to count as correct.
//
// A SUBSTRING RATHER THAN A FILE NAME, deliberately. "the right file" is a much
// weaker claim than "the passage that actually says it", and the whole argument
// for byte ranges is that the second is what a citation should mean.
int Eval(const Options& o) {
  std::ifstream f(o.eval_file);
  if (!f) {
    std::fprintf(stderr, "cannot read %s\n", o.eval_file.c_str());
    return 1;
  }
  std::vector<std::string> files;
  ListMarkdown(o.vault, "", &files);
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, keys.current(), e->id(), e->dimension(),
                    ReplicaFor(o), &index);
    if (s != IndexStatus::kOk) {
      std::fprintf(stderr, "cannot open the index at %s: %s\n",
                   o.index_dir.c_str(), IndexStatusName(s));
      return 1;
    }
  }
  AnswerOptions opts;
  opts.min_score = o.floor;
  opts.k = 5;
  const DocumentSource source = VaultSource(o.vault, files);

  std::size_t asked = 0;
  std::size_t hit_at_1 = 0;
  std::size_t hit_at_3 = 0;
  std::size_t hit_at_5 = 0;
  double mrr = 0;
  std::size_t refusals = 0;
  std::size_t expected_refusals = 0;
  std::size_t correct_refusals = 0;
  double seconds = 0;

  std::string line;
  std::printf("%-4s %-44s %5s %5s %5s  %s\n", "rank", "question", "top", "gap",
              "sd", "expected");
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') continue;
    const std::size_t tab = line.find('\t');
    if (tab == std::string::npos) continue;
    const std::string question = line.substr(0, tab);
    const std::string want = line.substr(tab + 1);
    // A question marked NONE is expected to be refused: the vault does not
    // contain the answer and answering it would be the failure mode.
    const bool expect_none = (want == "NONE");
    if (expect_none) ++expected_refusals;

    std::vector<Passage> passages;
    RetrievalShape shape;
    const auto t0 = std::chrono::steady_clock::now();
    if (Retrieve(*index, e.get(), source, question, opts, &passages, nullptr,
                 &shape) != IndexStatus::kOk) {
      continue;
    }
    seconds += Since(t0);
    ++asked;

    if (passages.empty()) {
      ++refusals;
      if (expect_none) ++correct_refusals;
      std::printf("%-4s %-44s %5.3f %5.3f %5.2f  %s\n",
                  expect_none ? "ok" : "MISS", question.substr(0, 44).c_str(),
                  shape.best, shape.Gap(), shape.Standout(), want.c_str());
      continue;
    }
    if (expect_none) {
      std::printf("%-4s %-44s %5.3f %5.3f %5.2f  %s\n", "BAD",
                  question.substr(0, 44).c_str(), shape.best, shape.Gap(),
                  shape.Standout(), "answered what it cannot answer");
      continue;
    }
    std::size_t rank = 0;
    for (std::size_t i = 0; i < passages.size(); ++i) {
      if (passages[i].text.find(want) != std::string::npos) {
        rank = i + 1;
        break;
      }
    }
    if (rank == 1) ++hit_at_1;
    if (rank >= 1 && rank <= 3) ++hit_at_3;
    if (rank >= 1 && rank <= 5) ++hit_at_5;
    if (rank >= 1) mrr += 1.0 / static_cast<double>(rank);
    std::printf("%-4s %-44s %5.3f %5.3f %5.2f  %s\n",
                rank == 0 ? "MISS" : std::to_string(rank).c_str(),
                question.substr(0, 44).c_str(), shape.best, shape.Gap(),
                shape.Standout(), want.substr(0, 30).c_str());
  }

  const std::size_t answerable = asked - expected_refusals;
  std::printf(
      "\n"
      "model            %s\n"
      "floor            %.2f\n"
      "questions        %zu (%zu answerable, %zu expected to be refused)\n"
      "hit@1            %zu/%zu\n"
      "hit@3            %zu/%zu\n"
      "hit@5            %zu/%zu\n"
      "MRR              %.3f\n"
      "refusals         %zu, of which %zu were correct\n"
      "retrieval        %.1f ms per question\n",
      o.model.c_str(), static_cast<double>(opts.min_score), asked, answerable,
      expected_refusals, hit_at_1, answerable, hit_at_3, answerable, hit_at_5,
      answerable, answerable == 0 ? 0.0 : mrr / static_cast<double>(answerable),
      refusals, correct_refusals,
      asked == 0 ? 0.0 : seconds * 1000.0 / static_cast<double>(asked));
  return 0;
}

// ------------------------------------------------------------- replication
//
// PUSH AND PULL GO THROUGH THE PHASE 3 CLIENT, not a second transport. Manifest
// operations travel in the oplog under IndexObject() with the same chain, the
// same cursor and the same ordering guarantees the tree and text operations
// get; segment bytes travel as blobs the relay stores under a name it does not
// interpret.

// The vault id and keys a driver uses. Derived, as everywhere else in this
// tool, because it has no enrolment channel.
struct RelayHandle {
  VaultKeys keys;
  relay::VaultId vault;
  std::unique_ptr<OpLog> log;
  std::unique_ptr<sync::Transport> transport;
  std::unique_ptr<sync::Client> client;
  ReplicaId me;
};

bool OpenRelay(const Options& o, VaultKeys keys, RelayHandle* h) {
  if (o.relay.empty()) {
    std::fprintf(stderr, "--push and --pull need --relay HOST:PORT\n");
    return false;
  }
  const std::size_t colon = o.relay.rfind(':');
  if (colon == std::string::npos) {
    std::fprintf(stderr, "--relay wants HOST:PORT\n");
    return false;
  }
  const std::string host = o.relay.substr(0, colon);
  const uint16_t port =
      static_cast<uint16_t>(std::atoi(o.relay.c_str() + colon + 1));

  h->keys = keys;
  const SecretKey vid = DeriveSubkey(h->keys.root(), 1, "umbVault");
  std::memcpy(h->vault.bytes.data(), vid.data(), h->vault.bytes.size());
  h->me = ReplicaFor(o);

  if (OpLog::OpenEncrypted(o.index_dir + "/oplog", &h->keys, &h->log) !=
      LogStatus::kOk) {
    std::fprintf(stderr, "cannot open the index oplog\n");
    return false;
  }
  h->transport = sync::NewTcpTransport(host, port);
  h->client.reset(new sync::Client(h->vault, h->me, &h->keys, h->log.get(),
                                   h->transport.get()));
  return true;
}

int Push(const Options& o) {
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, keys.current(), e->id(), e->dimension(),
                    ReplicaFor(o), &index);
    if (s != IndexStatus::kOk) {
      std::fprintf(stderr, "cannot open the index: %s\n", IndexStatusName(s));
      return 1;
    }
  }
  RelayHandle h;
  if (!OpenRelay(o, keys, &h)) return 1;

  const auto t0 = std::chrono::steady_clock::now();

  // THE OPERATIONS FIRST, THEN THE BYTES. A peer that has the operations and
  // not the bytes knows it is incomplete and says so; a peer that has bytes
  // nobody has vouched for cannot tell whether they belong to this vault.
  const std::vector<ManifestOp> ops = index->TakePending();
  // THE RAW LAYER, THE SAME ONE TREE OPERATIONS USE. A manifest operation is
  // not a text operation and must not be smuggled through Op, whose `text` is a
  // vector of code points rather than a bag of bytes. AppendRaw takes an opaque
  // payload and gives it the encryption, the chain and the cursor that every
  // other operation in this project gets.
  std::vector<LoggedOp> raw;
  raw.reserve(ops.size());
  for (const ManifestOp& op : ops) {
    LoggedOp l;
    l.id = op.id;
    l.payload.bytes = EncodeManifestOp(op);
    raw.push_back(l);
  }
  if (!raw.empty() && h.log->AppendRaw(IndexObject(), raw) != LogStatus::kOk) {
    std::fprintf(stderr, "cannot record the manifest operations\n");
    return 1;
  }
  if (!raw.empty() && h.log->Sync() != LogStatus::kOk) return 1;
  std::size_t pushed_ops = 0;
  if (h.client->PushObject(IndexObject(), &pushed_ops) !=
      sync::SyncStatus::kOk) {
    std::fprintf(stderr, "cannot push manifest operations\n");
    return 1;
  }
  // A REPORT, SO A PULLER CAN FIND THIS DEVICE. The relay does not index who
  // has written what; a client learns the other devices from their sealed
  // reports, exactly as the Phase 3 sync client does. Without this a puller has
  // nobody to fetch manifest operations from and quietly concludes the vault
  // has no index.
  (void)h.client->PublishReport(1, {IndexObject()}, h.me);
  const double op_seconds = Since(t0);

  const auto b0 = std::chrono::steady_clock::now();
  std::size_t pushed_segments = 0;
  uint64_t pushed_bytes = 0;
  std::vector<std::array<uint8_t, 32>> already;
  (void)h.client->ListSegments(&already, nullptr);
  std::set<std::string> have;
  for (const std::array<uint8_t, 32>& id : already) {
    have.insert(
        std::string(reinterpret_cast<const char*>(id.data()), id.size()));
  }
  for (const SegmentId& id : index->SegmentIds()) {
    const std::string key(reinterpret_cast<const char*>(id.bytes.data()),
                          id.bytes.size());
    // ALREADY THERE MEANS ALREADY THERE. Segments are content addressed, so a
    // relay that has one has exactly this one -- re-uploading would move tens
    // of megabytes to arrive at the byte-identical result.
    if (have.count(key) != 0) continue;
    std::string sealed;
    if (!ReadWholeFile(o.index_dir + "/segments/" + id.Hex() + ".seg",
                       &sealed)) {
      continue;
    }
    if (h.client->PushSegment(id.bytes, sealed) != sync::SyncStatus::kOk) {
      std::fprintf(stderr, "cannot push segment %s\n", id.Short().c_str());
      return 1;
    }
    ++pushed_segments;
    pushed_bytes += sealed.size();
  }
  const double byte_seconds = Since(b0);

  std::printf(
      "pushed %zu manifest operations in %.2fs\n"
      "pushed %zu segments, %llu bytes, in %.2fs\n"
      "index holds %u segments, %u vectors\n",
      ops.size(), op_seconds, pushed_segments,
      static_cast<unsigned long long>(pushed_bytes), byte_seconds,
      index->Stats().segments, index->Stats().vectors);
  return 0;
}

int Pull(const Options& o) {
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, keys.current(), e->id(), e->dimension(),
                    ReplicaFor(o), &index);
    if (s != IndexStatus::kOk) {
      std::fprintf(stderr, "cannot open the index: %s\n", IndexStatusName(s));
      return 1;
    }
  }
  RelayHandle h;
  if (!OpenRelay(o, keys, &h)) return 1;

  const auto t0 = std::chrono::steady_clock::now();
  // Every device that has published manifest operations, learned the same way
  // a client learns who else exists.
  std::vector<ReplicaId> devices;
  {
    relay::GetReportsRequest gr;
    gr.vault = h.vault;
    relay::ReportsResponse rr;
    if (h.transport->GetReports(gr, &rr)) {
      for (const relay::SealedReport& s : rr.reports) {
        ReplicaId d;
        d.bytes = s.device.bytes;
        devices.push_back(d);
      }
    }
  }
  // A driver has no device roster, so it also asks the relay who has written
  // manifest operations by trying the ids it knows. Publishing a report makes
  // this device discoverable to the other one.
  (void)h.client->PublishReport(1, {IndexObject()}, h.me);
  if (std::find(devices.begin(), devices.end(), h.me) == devices.end()) {
    devices.push_back(h.me);
  }

  std::size_t applied = 0;
  std::size_t refused = 0;
  for (const ReplicaId& d : devices) {
    if (d == h.me) continue;
    sync::FetchStats st;
    const sync::SyncStatus s = h.client->FetchObjectWith(
        IndexObject(), d,
        [](const OpPayload& p, uint64_t* prev) {
          ManifestOp op;
          if (!DecodeManifestOp(p.bytes, &op)) {
            std::fprintf(
                stderr,
                "  payload of %zu bytes did not decode as a manifest "
                "operation (version byte %u)\n",
                p.bytes.size(),
                p.bytes.empty()
                    ? 0u
                    : static_cast<unsigned>(static_cast<uint8_t>(p.bytes[0])));
            return false;
          }
          *prev = op.prev;
          return true;
        },
        [&index, &applied, &refused](const OpPayload& p) {
          ManifestOp op;
          if (!DecodeManifestOp(p.bytes, &op)) return false;
          const ManifestApply a = index->ApplyManifestOp(op);
          if (a == ManifestApply::kModelMismatch) {
            ++refused;
          } else if (a == ManifestApply::kApplied) {
            ++applied;
          }
          // kMalformed is the only refusal that breaks the fetch: it means the
          // stream is not what it claims to be.
          return a != ManifestApply::kMalformed;
        },
        &st);
    if (s != sync::SyncStatus::kOk) {
      std::printf("  manifest fetch from %s: %s\n", d.Short().c_str(),
                  sync::SyncStatusName(s));
    }
  }
  if (h.log->Sync() != LogStatus::kOk) return 1;
  const double op_seconds = Since(t0);

  const auto b0 = std::chrono::steady_clock::now();
  std::size_t pulled = 0;
  uint64_t pulled_bytes = 0;
  std::size_t failed = 0;
  // REPLACEMENTS FIRST, AND RE-ASKED PER SEGMENT.
  //
  // A segment a retirement is waiting on is genuinely still live -- the safety
  // condition says so, and MissingFrom lists it -- but it stops being wanted
  // the instant its replacement arrives, so fetching in manifest order spends a
  // round trip on each of them for nothing. Invisible on localhost and glaring
  // on a network: a cold pull of a compacted 2000-note index made 2000 doomed
  // fetches, half a second at a sub-millisecond round trip; the 200ms cost is
  // arithmetic rather than measured, because the run was killed.
  //
  // Both halves are on Index (include/umbra/ai/index.h) rather than here. They
  // were here first, and a duplicated line disabled the entire fetch loop with
  // the whole suite still green, because nothing tests this binary.
  for (const SegmentId& id : index->MissingInFetchOrder()) {
    if (!index->Wants(id)) continue;
    std::string sealed;
    if (h.client->PullSegment(id.bytes, &sealed) != sync::SyncStatus::kOk) {
      ++failed;
      continue;
    }
    const IndexStatus s = index->AdoptSegment(sealed);
    if (s == IndexStatus::kOk) {
      ++pulled;
      pulled_bytes += sealed.size();
    } else {
      ++failed;
      std::printf("  segment %s refused: %s\n", id.Short().c_str(),
                  IndexStatusName(s));
    }
  }
  const double byte_seconds = Since(b0);

  const IndexStats st = index->Stats();
  std::printf(
      "applied %zu manifest operations in %.2fs (%zu refused for the model)\n"
      "pulled %zu segments, %llu bytes, in %.2fs (%zu failed)\n"
      "index holds %u segments, %u vectors, %u objects\n"
      "complete: %s",
      applied, op_seconds, refused, pulled,
      static_cast<unsigned long long>(pulled_bytes), byte_seconds, failed,
      st.segments, st.vectors, st.objects, index->Complete() ? "yes" : "no");
  if (!index->Complete()) {
    std::printf(" (%zu segment(s) still missing)", index->Missing().size());
  }
  std::printf("\n");
  const std::vector<SegmentId> waiting = index->AwaitingReplacement();
  if (!waiting.empty()) {
    // The safety condition, visible. A device holding more than the manifest
    // implies should be able to say why.
    std::printf(
        "%zu retired segment(s) are still live because their replacement has "
        "not arrived\n",
        waiting.size());
  }
  return 0;
}

// WHAT IS IN THE VAULT, ANSWERED FROM STRUCTURE.
//
// Not a summary. A summary of a vault has to be a summary of everything in it,
// and the only way retrieval can produce one is to summarize the handful of
// passages it happened to return -- which reads as authoritative and is a
// summary of six chunks. See ADR 0009 for what was measured and rejected.
//
// This counts instead. Every live chunk is grouped by its embedding, which was
// computed when the note was indexed and is sitting there already, and the
// answer is groups with sizes and members. A label is a guess; a membership is
// a fact, and the two are printed differently.
int Topics(const Options& o) {
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, keys.current(), e->id(), e->dimension(),
                    ReplicaFor(o), &index);
    if (s != IndexStatus::kOk) {
      std::fprintf(stderr, "cannot open the index: %s\n", IndexStatusName(s));
      return 1;
    }
  }

  TopicOptions to;
  to.k = o.topic_k;
  TopicMap map;
  const auto t0 = std::chrono::steady_clock::now();
  const TopicStatus st = BuildTopicMap(*index, to, &map);
  const double grouped = Since(t0);
  if (st != TopicStatus::kOk) {
    std::fprintf(stderr, "cannot group this index: %s\n", TopicStatusName(st));
    return 1;
  }

  // Labels, if there is a generator. k calls, one per group, each seeing only
  // that group's nearest members -- so a label is a description of real text
  // rather than of the question that was never asked.
  std::vector<std::string> files;
  ListMarkdown(o.vault, "", &files);
  const DocumentSource source = VaultSource(o.vault, files);
  double labelled = 0;
  if (!o.generator.empty()) {
    std::unique_ptr<Generator> gen =
        NewOllamaGenerator(o.generator, "127.0.0.1", 11434);
    const auto l0 = std::chrono::steady_clock::now();
    for (Topic& t : map.topics) {
      if (t.chunks == 0) continue;
      std::string prompt;
      for (const TopicExample& ex : t.examples) {
        std::string doc;
        if (source && source(ex.object, &doc) && ex.end <= doc.size() &&
            ex.start < ex.end) {
          prompt += doc.substr(ex.start, ex.end - ex.start);
          prompt += "\n---\n";
        }
      }
      if (prompt.empty()) continue;
      std::string reply;
      if (gen->Generate(
              "Name the common subject of these excerpts in two to five words. "
              "Reply with the name alone, no punctuation, no preamble.",
              prompt, &reply)) {
        // One line, trimmed. A model that wrote a paragraph gets its first line.
        const std::size_t nl = reply.find('\n');
        if (nl != std::string::npos) reply = reply.substr(0, nl);
        const std::size_t b = reply.find_first_not_of(" \t\"*#");
        const std::size_t en = reply.find_last_not_of(" \t\"*#.");
        if (b != std::string::npos && en >= b)
          t.label = reply.substr(b, en - b + 1);
      }
    }
    labelled = Since(l0);
  }

  std::printf(
      "%u chunks from %u notes, grouped into %u in %.2fs"
      " (%u iterations, mean cohesion %.3f)\n",
      map.chunks, map.notes, map.k, grouped, map.iterations, map.cohesion);
  if (o.generator.empty()) {
    std::printf("no --generator, so the groups are counted but not named\n");
  } else {
    std::printf("named with %s in %.2fs\n", o.generator.c_str(), labelled);
  }
  std::printf("\n%-34s %7s %6s %9s\n", "group", "chunks", "notes", "cohesion");
  for (const Topic& t : map.topics) {
    if (t.chunks == 0) continue;
    std::printf(
        "%-34s %7u %6u %9.3f%s\n",
        (t.label.empty() ? "(unnamed)" : t.label).substr(0, 34).c_str(),
        t.chunks, t.notes, t.cohesion,
        // A LOOSE GROUP IS SAID TO BE LOOSE. Whatever was left over
        // after the tight groups formed lands in one of these, and a
        // name put on it means less than the name suggests.
        t.cohesion < 0.45f ? "  loose, treat the name with suspicion" : "");
    for (const TopicExample& ex : t.examples) {
      std::printf("    %.3f  %s:%u-%u%s%s\n", ex.similarity,
                  PathOf(o.vault, files, ex.object).c_str(), ex.start, ex.end,
                  ex.heading_path.empty() ? "" : "  ", ex.heading_path.c_str());
    }
  }
  return 0;
}

int Stats(const Options& o) {
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  const IndexStatus s = Index::Open(o.index_dir, &keys, keys.current(), e->id(),
                                    e->dimension(), ReplicaFor(o), &index);
  if (s != IndexStatus::kOk) {
    std::fprintf(stderr, "cannot open the index: %s\n", IndexStatusName(s));
    return 1;
  }
  const IndexStats st = index->Stats();
  std::printf(
      "segments   %u\n"
      "vectors    %u (%u tombstoned)\n"
      "objects    %u\n"
      "sealed     %llu bytes\n"
      "on disk    %llu bytes\n",
      st.segments, st.vectors, st.tombstoned, st.objects,
      static_cast<unsigned long long>(st.segment_bytes),
      static_cast<unsigned long long>(DirectoryBytes(o.index_dir)));
  return 0;
}

int CompactCommand(const Options& o) {
  VaultKeys keys = VaultKeysFor(o);
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, keys.current(), e->id(), e->dimension(),
                    ReplicaFor(o), &index);
    if (s != IndexStatus::kOk) {
      std::fprintf(stderr, "cannot open the index at %s: %s\n",
                   o.index_dir.c_str(), IndexStatusName(s));
      return 1;
    }
  }
  const IndexStats before = index->Stats();
  const auto t0 = std::chrono::steady_clock::now();
  uint32_t merged = 0;
  uint32_t reclaimed = 0;
  if (index->Compact(2, 10, &merged, &reclaimed) != IndexStatus::kOk) {
    std::fprintf(stderr, "compaction failed\n");
    return 1;
  }
  const IndexStats after = index->Stats();
  std::printf(
      "merged %u segments, reclaimed %u vectors in %.2fs\n"
      "segments %u -> %u, vectors %u -> %u, dead %u -> %u\n",
      merged, reclaimed, Since(t0), before.segments, after.segments,
      before.vectors, after.vectors, before.tombstoned, after.tombstoned);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    const char* next = (i + 1 < argc) ? argv[i + 1] : nullptr;
    if (a == "--topics") {
      o.topics = true;
      // An optional count may follow. Only consumed when it is a number, so
      // "--topics --ask ..." is not misread as a count of zero.
      if (next != nullptr && next[0] >= '1' && next[0] <= '9') {
        o.topic_k = static_cast<uint32_t>(std::atoi(next));
        ++i;
      }
    } else if (a == "--state-dir" && next) {
      o.state_dir = next;
      ++i;
    } else if (a == "--pass-file" && next) {
      o.pass_file = next;
      ++i;
    } else if (a == "--vault" && next) {
      o.vault = next;
      ++i;
    } else if (a == "--index" && next) {
      o.index_dir = next;
      ++i;
    } else if (a == "--model" && next) {
      o.model = next;
      ++i;
    } else if (a == "--generator" && next) {
      o.generator = next;
      ++i;
    } else if (a == "--floor" && next) {
      o.floor = static_cast<float>(std::atof(next));
      ++i;
    } else if (a == "--ask" && next) {
      o.question = next;
      ++i;
    } else if (a == "--eval" && next) {
      o.eval_file = next;
      ++i;
    } else if (a == "--build") {
      o.build = true;
    } else if (a == "--stats") {
      o.stats = true;
    } else if (a == "--compact") {
      o.compact = true;
    } else if (a == "--relay" && next) {
      o.relay = next;
      ++i;
    } else if (a == "--push") {
      o.push = true;
    } else if (a == "--pull") {
      o.pull = true;
    } else {
      Usage();
      return 2;
    }
  }
  if (o.index_dir.empty()) {
    Usage();
    return 2;
  }
  // EVERY COMMAND NEEDS A VAULT, because the vault is where both this device's
  // identity and the keys that open the index live. --stats used to be exempt;
  // it is not any more, because reading an index means decrypting it.
  if (o.vault.empty()) {
    std::fprintf(stderr,
                 "--vault is required: the keys that open an index, and the "
                 "device identity that signs its operations, both live beside "
                 "the vault rather than beside the index\n");
    return 2;
  }
  if (o.build) return Build(o);  // --compact modifies it rather than replacing
  if (o.push) return Push(o);
  if (o.pull) return Pull(o);
  if (!o.question.empty()) return Ask(o);
  if (!o.eval_file.empty()) return Eval(o);
  if (o.topics) return Topics(o);
  if (o.stats) return Stats(o);
  if (o.compact) return CompactCommand(o);
  Usage();
  return 2;
}
