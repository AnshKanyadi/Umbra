// Chunking markdown.
//
// The determinism tests are the point of this file. Everything else checks that
// the chunker does something sensible; those check that it does the SAME thing
// on every machine, which is a correctness requirement rather than a quality
// one -- see the note at the top of include/umbra/ai/chunk.h.
#include "umbra/ai/chunk.h"

#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "utf8.h"

namespace umbra {
namespace ai {
namespace {

ObjectId ObjectFromSeed(uint8_t seed) {
  ObjectId id;
  id.bytes.fill(seed);
  return id;
}

std::string FixtureDir() {
  const char* from_env = std::getenv("UMBRA_FIXTURES");
  if (from_env != nullptr && *from_env != '\0') return from_env;
  return UMBRA_FIXTURE_DIR;
}

bool ReadFile(const std::string& path, std::string* out) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) return false;
  char buf[8192];
  std::size_t n = 0;
  out->clear();
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out->append(buf, n);
  std::fclose(f);
  return true;
}

// EVERY FIXTURE AND ITS GOLDEN BOUNDARY DIGEST, IN ONE TABLE.
//
// This used to be two lists -- one of fixtures to exercise, one of expected
// digests -- and a fixture was added to the first and not the second, so the
// file that found a real splitting bug was not itself covered by the
// determinism test. One table cannot drift against itself.
//
// Sorted by name so the corpus does not depend on directory enumeration order,
// which is unspecified and differs between APFS and ext4.
//
// Regenerate with UMBRA_PRINT_DIGESTS=1 after a deliberate change to the
// chunker, and update these in the SAME commit as the change. A mismatch on one
// platform and not another is a portability bug and the fix belongs in the
// chunker, not here.
struct Golden {
  const char* name;
  const char* digest;
};

const Golden kCorpus[] = {
    {"basic.md",
     "f9298e19450b5e533e4d6e23bf1dab17a8702068a41cd477b496fb1bc68725ef"},
    {"code.md",
     "3d42b0420ffec355d7837c9d3cb427bc95f6265c0c9284d4180ad0945b253234"},
    {"crlf.md",
     "34973c45803a340e552330cdd9619fd33a3670d9dc3df43db90052f9a2b6d100"},
    {"frontmatter.md",
     "64a0922a9ff14d9f6992c24037bd3f35b975eeaeb0c9e4fe45456b03d4603071"},
    {"links.md",
     "fadab0e714f3468f4d372c21e31bfa13f6ea521c8364de2b5243890f095d8f44"},
    {"listcode.md",
     "e765288983bd0d8381940d7c6509d7d95d348066280c0f1bd11d70ebfbeedb7b"},
    {"longline.md",
     "109f2b2fa0718730fb306d17b835d61289ed501a01cabf2dcf7e4feffdf418d8"},
    {"mixed.md",
     "7abefdddcc516d01b4b1913f0821d427de3c23c9c8ea1a4903fb50ba1ada0b1e"},
    {"onlytable.md",
     "c61ff7950f830bd8193d87fce603273b5018176e77abb343c543d85d1cf0acc5"},
    {"table.md",
     "6b88c0fad7cc0bba2faf77b119aef62e261500afcbd67205052797185b0c42b6"},
    {"tiny.md",
     "d6a0d6d54dd4e301e0cbaae45ac0dd251f09c45c3036742c44a18a615316c398"},
};

std::string LoadFixture(const std::string& name) {
  std::string body;
  const std::string path = FixtureDir() + "/" + name;
  EXPECT_TRUE(ReadFile(path, &body)) << "cannot read fixture " << path;
  return body;
}

std::vector<Chunk> ChunkFixture(const std::string& name) {
  const std::string body = LoadFixture(name);
  std::vector<Chunk> out;
  EXPECT_EQ(ChunkMarkdown(ObjectFromSeed(1), body, &out), ChunkStatus::kOk)
      << name;
  return out;
}

}  // namespace

// ---------------------------------------------------------------- determinism

// THE TEST THE WHOLE DESIGN HANGS ON. A golden digest over the chunk boundaries
// of every fixture. It runs on macOS/arm64 and on Linux/x86-64 under clang and
// gcc in CI, which is what turns "deterministic" from an intention into a
// measurement: `char` signedness, size_t width, and locale all differ across
// those and any of them would move a boundary.
//
// If this fails after a deliberate change to the chunker, the digest below is
// updated in the same commit. If it fails on ONE platform and not another, the
// chunker has a portability bug and the digest must not be touched.
TEST(Chunking, TheCorpusDigestIsTheSameEverywhere) {
  const bool print = std::getenv("UMBRA_PRINT_DIGESTS") != nullptr;
  for (const Golden& g : kCorpus) {
    const std::vector<Chunk> chunks = ChunkFixture(g.name);
    const std::string got = ChunkingDigest(chunks);
    if (print) {
      std::printf("    {\"%s\",\n     \"%s\"},\n", g.name, got.c_str());
      continue;
    }
    EXPECT_EQ(got, g.digest)
        << g.name << " chunked differently than the golden boundaries. "
        << "If this fails on one platform only, the chunker is not portable.";
  }
}

// Repeated runs in one process, which catches uninitialised memory and
// iteration-order dependence but NOT the cross-platform hazards. It is here
// because it is cheap, not because it is sufficient.
TEST(Chunking, RepeatedRunsAgree) {
  for (const Golden& g : kCorpus) {
    const char* name = g.name;
    const std::string body = LoadFixture(name);
    std::vector<Chunk> first;
    ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(2), body, &first), ChunkStatus::kOk);
    for (int i = 0; i < 8; ++i) {
      std::vector<Chunk> again;
      ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(2), body, &again),
                ChunkStatus::kOk);
      ASSERT_EQ(ChunkingDigest(first), ChunkingDigest(again)) << name;
      ASSERT_EQ(first.size(), again.size()) << name;
      for (std::size_t k = 0; k < first.size(); ++k) {
        EXPECT_EQ(first[k].text, again[k].text) << name << " chunk " << k;
        EXPECT_EQ(first[k].heading_path, again[k].heading_path);
        EXPECT_EQ(first[k].link_ratio, again[k].link_ratio);
      }
    }
  }
}

// THE OBJECT ID MUST NOT REACH THE BOUNDARIES. Two devices chunk the same
// document under the same object id, but a test that passed only because the id
// happened to match would hide a real dependency.
TEST(Chunking, TheObjectIdDoesNotMoveABoundary) {
  for (const Golden& g : kCorpus) {
    const char* name = g.name;
    const std::string body = LoadFixture(name);
    std::vector<Chunk> a;
    std::vector<Chunk> b;
    ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(3), body, &a), ChunkStatus::kOk);
    ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(200), body, &b), ChunkStatus::kOk);
    EXPECT_EQ(ChunkingDigest(a), ChunkingDigest(b)) << name;
  }
}

// A BYTE THAT IS NEGATIVE AS A SIGNED CHAR. If any comparison in the chunker
// used a plain `char`, this document would chunk differently on x86 and ARM.
// The test cannot run on two architectures at once, so it asserts the property
// that makes the difference impossible: high bytes are treated as ordinary
// content, never as structure.
TEST(Chunking, HighBytesAreContentNotStructure) {
  std::string doc = "# H\n\n";
  for (int i = 0x80; i < 0x100; i += 0x10) {
    // Valid UTF-8 two-byte sequences covering the range that differs in sign.
    doc += static_cast<char>(0xC3);
    doc += static_cast<char>(static_cast<unsigned char>(i & 0xBF));
  }
  doc += "\n";
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(4), doc, &out), ChunkStatus::kOk);
  ASSERT_FALSE(out.empty());
  // One heading and one paragraph: the high bytes started nothing.
  EXPECT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].kind, ChunkKind::kProse);
}

// ------------------------------------------------------------------ structure

TEST(Chunking, ByteRangesAreContiguousAndInsideTheDocument) {
  for (const Golden& g : kCorpus) {
    const char* name = g.name;
    const std::string body = LoadFixture(name);
    std::vector<Chunk> out;
    ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(5), body, &out), ChunkStatus::kOk);
    uint32_t previous_end = 0;
    for (std::size_t i = 0; i < out.size(); ++i) {
      const Chunk& c = out[i];
      EXPECT_LT(c.start, c.end) << name << " chunk " << i << " is empty";
      EXPECT_LE(c.end, body.size()) << name << " chunk " << i << " runs past";
      EXPECT_GE(c.start, previous_end)
          << name << " chunk " << i << " overlaps the one before";
      EXPECT_EQ(c.ordinal, i);
      previous_end = c.end;
    }
  }
}

// A CITATION HAS TO QUOTE THE SOURCE. The bytes a chunk names must be the bytes
// in the document, or following a citation lands somewhere else.
TEST(Chunking, TheCitedRangeIsTheSourceText) {
  const std::string body = LoadFixture("basic.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(6), body, &out), ChunkStatus::kOk);
  ASSERT_FALSE(out.empty());
  for (const Chunk& c : out) {
    const std::string cited = body.substr(c.start, c.end - c.start);
    // The embedded text may carry a heading path prefix, so the cited bytes are
    // a suffix of it rather than the whole of it.
    EXPECT_NE(c.text.find(cited), std::string::npos)
        << "chunk " << c.ordinal << " cites bytes it did not embed";
  }
}

// THE RULE THAT MATTERS MOST. A code block cut in half embeds as something that
// looks like code and is not.
TEST(Chunking, ACodeBlockIsNeverSplit) {
  const std::string body = LoadFixture("code.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(7), body, &out), ChunkStatus::kOk);

  // The fixture's first fenced block is far over the ceiling, so it must appear
  // as one oversized chunk rather than several.
  const Chunk* big = nullptr;
  for (const Chunk& c : out) {
    if (c.kind != ChunkKind::kCode) continue;
    if (big == nullptr || c.bytes() > big->bytes()) big = &c;
  }
  ASSERT_NE(big, nullptr) << "no code chunk was produced";
  EXPECT_GT(big->bytes(), kMaxBytes)
      << "the fixture no longer has an oversized block, so this proves nothing";

  // Every fence opener in the document is matched by a closer inside the SAME
  // chunk, or runs to the end of that chunk.
  for (const Chunk& c : out) {
    const std::string cited = body.substr(c.start, c.end - c.start);
    std::size_t fences = 0;
    std::size_t at = 0;
    while ((at = cited.find("```", at)) != std::string::npos) {
      ++fences;
      at += 3;
    }
    if (c.kind == ChunkKind::kCode) {
      EXPECT_TRUE(fences == 0 || fences == 2 || fences == 1)
          << "chunk " << c.ordinal << " holds " << fences << " fences";
    }
  }
}

TEST(Chunking, FrontMatterIsItsOwnChunk) {
  const std::string body = LoadFixture("frontmatter.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(8), body, &out), ChunkStatus::kOk);
  ASSERT_FALSE(out.empty());
  EXPECT_EQ(out[0].kind, ChunkKind::kFrontMatter);
  EXPECT_EQ(out[0].start, 0u);
  const std::string cited = body.substr(out[0].start, out[0].bytes());
  EXPECT_EQ(cited.find("---"), 0u);
  EXPECT_NE(cited.find("aliases"), std::string::npos);
  EXPECT_EQ(cited.find("# The body"), std::string::npos)
      << "front matter swallowed the body";

  // The `---` later in the document is a thematic break and must not have
  // started a second front matter block.
  for (std::size_t i = 1; i < out.size(); ++i) {
    EXPECT_NE(out[i].kind, ChunkKind::kFrontMatter) << "chunk " << i;
  }
}

// A TABLE FRAGMENT WITHOUT ITS HEADER IS A GRID WITH NO COLUMN NAMES. When a
// table is too big to keep whole, every piece carries the header row in the
// text it embeds, and the byte range still points only at that piece's rows.
TEST(Chunking, ASplitTableCarriesItsHeaderIntoEveryPiece) {
  const std::string body = LoadFixture("table.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(9), body, &out), ChunkStatus::kOk);

  std::size_t pieces = 0;
  for (const Chunk& c : out) {
    if (c.kind != ChunkKind::kTable) continue;
    ++pieces;
    EXPECT_NE(c.text.find("| device | epoch | last seen | notes |"),
              std::string::npos)
        << "table piece " << c.ordinal << " has no header row";
    const std::string cited = body.substr(c.start, c.bytes());
    if (pieces > 1) {
      EXPECT_EQ(cited.find("| device | epoch |"), std::string::npos)
          << "the header was counted inside the cited range, so two pieces "
             "cite the same bytes";
    }
  }
  EXPECT_GT(pieces, 1u) << "the fixture table is no longer big enough to split";
}

TEST(Chunking, ATableThatFitsIsNotSplit) {
  const std::string body = LoadFixture("onlytable.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(10), body, &out), ChunkStatus::kOk);
  ASSERT_EQ(out.size(), 1u) << "a note that is one small table is one chunk";
  EXPECT_EQ(out[0].kind, ChunkKind::kTable);
}

// A MAP OF CONTENT IS A REAL NOTE AND IS NOT DROPPED. It is indexed like
// anything else and measured, so the retrieval layer can decide what a vector
// made almost entirely of link syntax is worth.
TEST(Chunking, ALinkHeavyNoteIsMeasuredNotDiscarded) {
  const std::string body = LoadFixture("links.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(11), body, &out), ChunkStatus::kOk);
  ASSERT_FALSE(out.empty());

  bool saw_link_list = false;
  uint32_t highest = 0;
  for (const Chunk& c : out) {
    highest = std::max(highest, c.link_ratio);
    if (c.kind == ChunkKind::kLinkList) saw_link_list = true;
  }
  EXPECT_TRUE(saw_link_list) << "a note of nothing but links was not flagged";
  EXPECT_GT(highest, 6000u) << "link ratio " << highest << " is implausible";

  // Prose stays prose.
  const std::string prose = "# H\n\nOrdinary sentences with no links at all.\n";
  std::vector<Chunk> plain;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(12), prose, &plain), ChunkStatus::kOk);
  ASSERT_FALSE(plain.empty());
  EXPECT_EQ(plain[0].link_ratio, 0u);
}

TEST(Chunking, HeadingsBecomeThePathAndStartChunks) {
  const std::string body = LoadFixture("basic.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(13), body, &out), ChunkStatus::kOk);
  bool saw_nested = false;
  for (const Chunk& c : out) {
    if (c.heading_path.find("Design > Text") != std::string::npos) {
      saw_nested = true;
      EXPECT_NE(c.text.find("Project Umbra > Design > Text"), std::string::npos)
          << "the path was not prefixed onto the embedded text";
    }
  }
  EXPECT_TRUE(saw_nested) << "no chunk carried a nested heading path";
}

TEST(Chunking, CarriageReturnsDoNotChangeTheStructure) {
  const std::string crlf = LoadFixture("crlf.md");
  std::string lf;
  for (std::size_t i = 0; i < crlf.size(); ++i) {
    if (crlf[i] == '\r') continue;
    lf += crlf[i];
  }
  std::vector<Chunk> a;
  std::vector<Chunk> b;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(14), crlf, &a), ChunkStatus::kOk);
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(14), lf, &b), ChunkStatus::kOk);
  // NOT the same digest -- they are different bytes, so the ranges differ and
  // must. The same STRUCTURE: the same number of chunks, of the same kinds.
  ASSERT_EQ(a.size(), b.size())
      << "carriage returns changed how many chunks the document has";
  for (std::size_t i = 0; i < a.size(); ++i) {
    EXPECT_EQ(a[i].kind, b[i].kind) << "chunk " << i;
  }
}

// The last resort path: one run of bytes with no boundary in it. The cut must
// land on a code point boundary or the chunk is not text.
TEST(Chunking, AnUnbreakableRunIsCutOnACodePointBoundary) {
  const std::string body = LoadFixture("longline.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(15), body, &out), ChunkStatus::kOk);
  ASSERT_GT(out.size(), 1u) << "the long line was not split at all";
  for (const Chunk& c : out) {
    const uint8_t first = static_cast<uint8_t>(body[c.start]);
    EXPECT_NE(first & 0xC0u, 0x80u)
        << "chunk " << c.ordinal << " starts inside a code point";
  }
}

TEST(Chunking, CjkTextIsCutOnACodePointBoundary) {
  std::string doc = "# CJK\n\n";
  for (int i = 0; i < 400; ++i) doc += "日本語のテキストです。";
  doc += "\n";
  ChunkOptions small;
  small.target_bytes = 200;
  small.max_bytes = 300;
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(16), doc, small, &out),
            ChunkStatus::kOk);
  ASSERT_GT(out.size(), 1u);
  for (const Chunk& c : out) {
    EXPECT_NE(static_cast<uint8_t>(doc[c.start]) & 0xC0u, 0x80u)
        << "chunk " << c.ordinal << " starts mid code point";
    const std::string cited = doc.substr(c.start, c.bytes());
    // Every chunk must itself be valid UTF-8.
    std::vector<char32_t> decoded;
    EXPECT_TRUE(::umbra::Utf8Decode(cited, &decoded))
        << "chunk " << c.ordinal << " is not valid UTF-8";
  }
}

// ------------------------------------------------------------------- refusals

TEST(Chunking, RefusesTextThatIsNotUtf8) {
  std::string bad = "# H\n\nbody ";
  bad += static_cast<char>(0xFF);
  bad += "\n";
  std::vector<Chunk> out;
  EXPECT_EQ(ChunkMarkdown(ObjectFromSeed(17), bad, &out),
            ChunkStatus::kNotUtf8);
  EXPECT_TRUE(out.empty());
}

TEST(Chunking, AnEmptyDocumentProducesNothing) {
  std::vector<Chunk> out;
  EXPECT_EQ(ChunkMarkdown(ObjectFromSeed(18), "", &out), ChunkStatus::kOk);
  EXPECT_TRUE(out.empty());
}

// A FENCED BLOCK INSIDE A LIST ITEM IS STILL A FENCED BLOCK.
//
// The block scanner treats a run of list items as one block, so a fence inside
// an item never reaches the fence branch. That is fine while the list fits. It
// is NOT fine when the list is over the ceiling and gets split at line
// boundaries, because the cut can land between ``` and ```, which is exactly
// the failure the whole design is meant to prevent -- and it is easy to miss,
// because the code block is not where you would look for it.
TEST(Chunking, AFenceInsideAListIsNotSplit) {
  const std::string body = LoadFixture("listcode.md");
  std::vector<Chunk> out;
  ASSERT_EQ(ChunkMarkdown(ObjectFromSeed(19), body, &out), ChunkStatus::kOk);
  ASSERT_GT(out.size(), 1u)
      << "the fixture no longer exceeds the ceiling, so this proves nothing";
  for (const Chunk& c : out) {
    const std::string cited = body.substr(c.start, c.bytes());
    std::size_t fences = 0;
    std::size_t at = 0;
    while ((at = cited.find("```", at)) != std::string::npos) {
      ++fences;
      at += 3;
    }
    EXPECT_EQ(fences % 2, 0u)
        << "chunk " << c.ordinal << " holds " << fences
        << " fence markers, so a code block was cut in half";
  }
}

}  // namespace ai
}  // namespace umbra
