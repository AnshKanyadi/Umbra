// An embedder that needs nothing installed.
//
// SPIKE, PHASE 6. The desktop app cannot ask a non-technical user to install
// Ollama before search works, so the embedding model has to come with the
// binary. This loads a GGUF through llama.cpp, in process, with no daemon, no
// HTTP, and no network at any point.
//
// WHY llama.cpp AND NOT ONNX RUNTIME. Both can run a sentence-transformer, and
// the difference is the tokenizer. ONNX Runtime is a tensor runtime: it takes
// token ids and gives back tensors, so a BERT WordPiece tokenizer has to come
// from somewhere else -- onnxruntime-extensions, or the Rust `tokenizers`
// crate, or a hand-written one that has to match the model's vocabulary
// exactly. That is a second dependency with its own build, and getting it
// subtly wrong produces vectors that are plausible and wrong. llama.cpp carries
// the tokenizer inside the GGUF and inside the library: the load log says
// `init_tokenizer: initializing tokenizer for type 3` and nothing else is
// needed. It is also one CMake project with no Python in the build, which is
// what the no-network submodule discipline in CMakeLists.txt requires.
//
// MEASURED, macOS arm64, CPU only, all-MiniLM-L6-v2 (44 MB GGUF):
//   - 82 texts/s at ~900 bytes each, 12,400 tok/s. Ollama measured 70/s on the
//     same corpus, so removing the daemon costs nothing and gains a little.
//   - model load 0.04s (mmap), peak RSS 91 MB including the weights
//   - static link adds ~3.5 MB to the binary
//   - vectors agree with Ollama's all-minilm to 1e-4, which is float rounding.
//     THE SAME MODEL, SO EXISTING INDEXES STILL OPEN.
#include <cmath>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "llama.h"
#include "umbra/ai/embed.h"

namespace umbra {
namespace ai {
namespace {

// llama.cpp's global backend, brought up once. Its init is not reentrant and
// its teardown is process-wide, so it is tied to process lifetime rather than
// to any one embedder.
class Backend {
 public:
  static void Ensure() {
    static Backend* once = new Backend();
    (void)once;
  }

 private:
  Backend() { llama_backend_init(); }
};

class LlamaEmbedder : public Embedder {
 public:
  LlamaEmbedder(llama_model* model, llama_context* ctx, uint32_t n_ctx)
      : model_(model), ctx_(ctx), n_ctx_(n_ctx) {}

  ~LlamaEmbedder() override {
    if (ctx_ != nullptr) llama_free(ctx_);
    if (model_ != nullptr) llama_model_free(model_);
  }

  EmbedStatus EmbedDocuments(const std::vector<std::string>& texts,
                             std::vector<Vector>* out) override {
    out->clear();
    out->reserve(texts.size());
    for (const std::string& t : texts) {
      Vector v;
      const EmbedStatus s = One(t, &v);
      if (s != EmbedStatus::kOk) return s;
      out->push_back(std::move(v));
    }
    return EmbedStatus::kOk;
  }

  EmbedStatus EmbedQuery(const std::string& text, Vector* out) override {
    return One(text, out);
  }

  uint32_t dimension() const override { return descriptor_.dimension; }
  const EmbeddingModelId& id() const override { return id_; }
  const ModelDescriptor& descriptor() const override { return descriptor_; }

  void SetDescriptor(const ModelDescriptor& d) {
    descriptor_ = d;
    id_ = ComputeModelId(d);
  }

 private:
  EmbedStatus One(const std::string& text, Vector* out) {
    const llama_vocab* vocab = llama_model_get_vocab(model_);
    std::vector<llama_token> toks(text.size() + 8);
    int n = llama_tokenize(vocab, text.c_str(),
                           static_cast<int32_t>(text.size()), toks.data(),
                           static_cast<int32_t>(toks.size()), true, false);
    if (n < 0) return EmbedStatus::kBadResponse;
    if (n == 0) return EmbedStatus::kDegenerateVector;
    // TRUNCATED RATHER THAN REFUSED, and it is worth knowing why this can
    // happen at all: chunk.h caps a chunk at 1536 bytes, which is about 380
    // tokens and fits, EXCEPT that a code block or table larger than the budget
    // becomes one chunk of whatever size it is. Refusing those would drop real
    // passages out of the index; truncating embeds their opening, which is
    // what a reader sees first anyway.
    if (static_cast<uint32_t>(n) > n_ctx_) n = static_cast<int>(n_ctx_);
    toks.resize(static_cast<std::size_t>(n));

    llama_memory_clear(llama_get_memory(ctx_), true);
    llama_batch batch = llama_batch_init(n, 0, 1);
    for (int i = 0; i < n; ++i) {
      batch.token[i] = toks[static_cast<std::size_t>(i)];
      batch.pos[i] = i;
      batch.n_seq_id[i] = 1;
      batch.seq_id[i][0] = 0;
      batch.logits[i] = 1;
    }
    batch.n_tokens = n;
    const int rc = llama_encode(ctx_, batch);
    llama_batch_free(batch);
    if (rc != 0) return EmbedStatus::kBadResponse;

    const float* e = llama_get_embeddings_seq(ctx_, 0);
    if (e == nullptr) return EmbedStatus::kBadResponse;
    out->assign(e, e + descriptor_.dimension);
    // The index compares by cosine and stores unit vectors; the pooled output
    // is not normalised, so it is normalised here rather than left to a caller
    // who might not.
    if (!Normalise(out)) return EmbedStatus::kDegenerateVector;
    return EmbedStatus::kOk;
  }

  llama_model* model_ = nullptr;
  llama_context* ctx_ = nullptr;
  uint32_t n_ctx_ = 512;
  ModelDescriptor descriptor_;
  EmbeddingModelId id_{};
};

}  // namespace

std::unique_ptr<Embedder> NewLocalEmbedder(const std::string& gguf_path,
                                           const ModelDescriptor& descriptor,
                                           EmbedStatus* status) {
  if (status != nullptr) *status = EmbedStatus::kOk;
  Backend::Ensure();

  llama_model_params mp = llama_model_default_params();
  // CPU ONLY, DELIBERATELY. Metal is faster and costs a shader library that has
  // to be found at runtime inside an app bundle; at 82 texts/s a 3000 note
  // vault indexes in about three minutes on the CPU, which is the same as the
  // daemon it replaces. Revisit when that is the bottleneck.
  mp.n_gpu_layers = 0;
  llama_model* model = llama_model_load_from_file(gguf_path.c_str(), mp);
  if (model == nullptr) {
    if (status != nullptr) *status = EmbedStatus::kUnreachable;
    return nullptr;
  }

  llama_context_params cp = llama_context_default_params();
  cp.embeddings = true;
  // MEAN, because that is what sentence-transformers does and what the vectors
  // already in every existing index were made with. CLS pooling on the same
  // weights gives different numbers that look just as reasonable.
  cp.pooling_type = LLAMA_POOLING_TYPE_MEAN;
  cp.n_ctx = 512;
  cp.n_batch = 512;
  cp.n_ubatch = 512;
  llama_context* ctx = llama_init_from_model(model, cp);
  if (ctx == nullptr) {
    llama_model_free(model);
    if (status != nullptr) *status = EmbedStatus::kUnreachable;
    return nullptr;
  }

  ModelDescriptor d = descriptor;
  // DISCOVERED, NOT CONFIGURED, for the reason embed_ollama.cc gives: a width
  // that disagrees with the weights writes short vectors into segments and
  // nothing notices until search is wrong.
  d.dimension = static_cast<uint32_t>(llama_model_n_embd(model));
  if (d.dimension == 0) {
    llama_free(ctx);
    llama_model_free(model);
    if (status != nullptr) *status = EmbedStatus::kBadResponse;
    return nullptr;
  }

  std::unique_ptr<LlamaEmbedder> e(new LlamaEmbedder(model, ctx, cp.n_ctx));
  e->SetDescriptor(d);
  return e;
}

}  // namespace ai
}  // namespace umbra
