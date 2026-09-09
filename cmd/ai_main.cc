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
#include "umbra/crdt/op.h"
#include "umbra/crdt/oplog.h"
#include "umbra/crypto/keys.h"
#include "umbra/sync/client.h"

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

VaultKeys KeysFor(const std::string& passphrase) {
  std::array<uint8_t, kSaltBytes> salt{};
  salt.fill(0x5A);
  Argon2idParams p = Argon2idParams::Default();
  // A DRIVER, NOT A VAULT. These parameters are deliberately weak because this
  // tool measures indexing rather than key derivation, and nine seconds of
  // Argon2id per invocation would drown the numbers it exists to report. A real
  // client uses the defaults.
  p.opslimit = 1;
  p.memlimit = 8u * 1024 * 1024;
  VaultKeys k;
  if (VaultKeys::Create(passphrase, salt, p, &k) != CryptoStatus::kOk) {
    std::fprintf(stderr, "cannot derive keys\n");
    std::exit(1);
  }
  // CREATE DRAWS A RANDOM EPOCH KEY, so a second invocation of this tool would
  // derive the same root and a different content key, and every segment written
  // by the first run would fail to open. That is exactly what happened: the
  // index reported segment-lost on a manifest that was perfectly correct.
  //
  // A real client stores its epoch keys wrapped under the root and recovers
  // them (cmd/sync_main.cc). This driver has no vault to store them in, so it
  // derives one -- which keys.h says NOT to do for a real vault, because a
  // removed device knows the root and could compute it. There is nothing to
  // revoke here; there would be in a client.
  const SecretKey e0 = DeriveSubkey(k.root(), 0, "umbAiDrv");
  k.OverwriteEpochForBootstrap(0, e0);
  return k;
}

// A DRIVER'S IDENTITY, DERIVED FROM ITS INDEX DIRECTORY. A real client uses the
// device id it enrolled with (cmd/sync_main.cc); this tool has no enrolment, so
// it takes a stable id from the path it was pointed at -- stable across runs,
// different between two index directories on one machine, which is what makes
// two --index dirs behave as two devices for testing.
ReplicaId ReplicaForIndex(const std::string& dir) {
  ReplicaId r;
  uint8_t digest[16];
  crypto_generichash(digest, sizeof(digest),
                     reinterpret_cast<const unsigned char*>(dir.data()),
                     dir.size(), nullptr, 0);
  std::memcpy(r.bytes.data(), digest, r.bytes.size());
  return r;
}

std::unique_ptr<Embedder> MakeEmbedder(const std::string& model,
                                       uint32_t hashing_dim) {
  if (model == "hashing") return NewHashingEmbedder(hashing_dim);
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
  std::fprintf(stderr,
               "umbra_ai --vault DIR --index DIR [--model NAME] COMMAND\n"
               "\n"
               "  --build              chunk, embed and index the vault\n"
               "                       add --compact to merge segments after\n"
               "  --ask QUESTION       retrieve and answer\n"
               "  --eval FILE          run a question set and report\n"
               "  --stats              what the index holds\n"
               "  --compact            merge segments and drop tombstones\n"
               "  --push               publish this index to the relay\n"
               "  --pull               fetch the index from the relay\n"
               "\n"
               "  --relay HOST:PORT    where the vault's relay is\n"
               "\n"
               "  --model NAME         all-minilm, nomic-embed-text, or\n"
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
};

int Build(const Options& o) {
  std::vector<std::string> files;
  ListMarkdown(o.vault, "", &files);
  if (files.empty()) {
    std::fprintf(stderr, "no markdown under %s\n", o.vault.c_str());
    return 1;
  }
  VaultKeys keys = KeysFor("umbra ai driver");
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  if (Index::Open(o.index_dir, &keys, 0, e->id(), e->dimension(),
                  ReplicaForIndex(o.index_dir), &index) != IndexStatus::kOk) {
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
  VaultKeys keys = KeysFor("umbra ai driver");
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, 0, e->id(), e->dimension(),
                    ReplicaForIndex(o.index_dir), &index);
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
    std::printf("%s\n\n", r.text.c_str());
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
  VaultKeys keys = KeysFor("umbra ai driver");
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, 0, e->id(), e->dimension(),
                    ReplicaForIndex(o.index_dir), &index);
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
  std::printf("%-4s %-52s %s\n", "rank", "question", "expected");
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
    const auto t0 = std::chrono::steady_clock::now();
    if (Retrieve(*index, e.get(), source, question, opts, &passages, nullptr) !=
        IndexStatus::kOk) {
      continue;
    }
    seconds += Since(t0);
    ++asked;

    if (passages.empty()) {
      ++refusals;
      if (expect_none) ++correct_refusals;
      std::printf("%-4s %-52s %s\n", expect_none ? "ok" : "MISS",
                  question.substr(0, 52).c_str(), want.c_str());
      continue;
    }
    if (expect_none) {
      std::printf("%-4s %-52s %s\n", "BAD", question.substr(0, 52).c_str(),
                  "answered a question the vault cannot answer");
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
    std::printf("%-4s %-52s %s\n",
                rank == 0 ? "MISS" : std::to_string(rank).c_str(),
                question.substr(0, 52).c_str(), want.substr(0, 40).c_str());
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
  h->me = ReplicaForIndex(o.index_dir);

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
  VaultKeys keys = KeysFor("umbra ai driver");
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, 0, e->id(), e->dimension(),
                    ReplicaForIndex(o.index_dir), &index);
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
  VaultKeys keys = KeysFor("umbra ai driver");
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, 0, e->id(), e->dimension(),
                    ReplicaForIndex(o.index_dir), &index);
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
    const sync::SyncStatus s = h.client->FetchObject(
        IndexObject(), d,
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
  for (const SegmentId& id : index->Missing()) {
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

int Stats(const Options& o) {
  VaultKeys keys = KeysFor("umbra ai driver");
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  const IndexStatus s =
      Index::Open(o.index_dir, &keys, 0, e->id(), e->dimension(),
                  ReplicaForIndex(o.index_dir), &index);
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
  VaultKeys keys = KeysFor("umbra ai driver");
  std::unique_ptr<Embedder> e = MakeEmbedder(o.model, 256);
  std::unique_ptr<Index> index;
  {
    const IndexStatus s =
        Index::Open(o.index_dir, &keys, 0, e->id(), e->dimension(),
                    ReplicaForIndex(o.index_dir), &index);
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
    if (a == "--vault" && next) {
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
  if (o.build) return Build(o);  // --compact modifies it rather than replacing
  if (o.push) return Push(o);
  if (o.pull) return Pull(o);
  if (!o.question.empty()) return Ask(o);
  if (!o.eval_file.empty()) return Eval(o);
  if (o.stats) return Stats(o);
  if (o.compact) return CompactCommand(o);
  Usage();
  return 2;
}
