#include "umbra/ai/chunk.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>

#include "utf8.h"

namespace umbra {
namespace ai {
namespace {

// EVERY BYTE COMES THROUGH HERE. `char` is signed on x86 and unsigned on ARM,
// so comparing a raw char against 0x80 gives opposite answers on the two
// platforms this ships on. That would be a determinism bug that only appears
// on documents containing non-ASCII text, which is to say most real vaults.
uint8_t Byte(const std::string& s, uint32_t i) {
  return static_cast<uint8_t>(s[i]);
}

// Locale-free classifiers. std::isspace depends on the C locale, which a host
// program can change out from under us.
bool IsSpaceByte(uint8_t c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' ||
         c == '\f';
}
bool IsHSpace(uint8_t c) { return c == ' ' || c == '\t'; }
bool IsDigitByte(uint8_t c) { return c >= '0' && c <= '9'; }

struct Line {
  uint32_t start = 0;  // first byte
  uint32_t end = 0;    // one past the last byte, excluding the newline
  uint32_t next = 0;   // first byte of the following line
};

std::vector<Line> SplitLines(const std::string& s) {
  std::vector<Line> lines;
  const uint32_t n = static_cast<uint32_t>(s.size());
  uint32_t i = 0;
  while (i < n) {
    Line l;
    l.start = i;
    uint32_t j = i;
    while (j < n && Byte(s, j) != '\n') ++j;
    l.end = j;
    // A CRLF file and an LF file are different bytes and therefore different
    // documents; the carriage return is excluded from the line's content so
    // that block detection agrees on both, while the byte ranges still point
    // at the real bytes.
    if (l.end > l.start && Byte(s, l.end - 1) == '\r') --l.end;
    l.next = (j < n) ? j + 1 : n;
    lines.push_back(l);
    i = l.next;
  }
  return lines;
}

std::string LineText(const std::string& s, const Line& l) {
  return s.substr(l.start, l.end - l.start);
}

bool LineIsBlank(const std::string& s, const Line& l) {
  for (uint32_t i = l.start; i < l.end; ++i) {
    if (!IsSpaceByte(Byte(s, i))) return false;
  }
  return true;
}

uint32_t Indent(const std::string& s, const Line& l) {
  uint32_t n = 0;
  for (uint32_t i = l.start; i < l.end; ++i) {
    const uint8_t c = Byte(s, i);
    if (c == ' ') {
      ++n;
    } else if (c == '\t') {
      n += 4;
    } else {
      break;
    }
  }
  return n;
}

uint32_t FirstNonSpace(const std::string& s, const Line& l) {
  uint32_t i = l.start;
  while (i < l.end && IsHSpace(Byte(s, i))) ++i;
  return i;
}

// ATX headings only. Setext headings (underlined with = or -) are handled in
// the block scanner because they need the following line.
bool HeadingLevel(const std::string& s, const Line& l, uint32_t* level) {
  uint32_t i = FirstNonSpace(s, l);
  if (Indent(s, l) >= 4) return false;  // that is a code block, not a heading
  uint32_t hashes = 0;
  while (i < l.end && Byte(s, i) == '#') {
    ++hashes;
    ++i;
  }
  if (hashes == 0 || hashes > 6) return false;
  // "#hashtag" is not a heading; a heading needs a space or nothing after.
  if (i < l.end && !IsHSpace(Byte(s, i))) return false;
  *level = hashes;
  return true;
}

std::string HeadingTitle(const std::string& s, const Line& l) {
  uint32_t i = FirstNonSpace(s, l);
  while (i < l.end && Byte(s, i) == '#') ++i;
  while (i < l.end && IsHSpace(Byte(s, i))) ++i;
  uint32_t j = l.end;
  // Trailing hashes are a closing sequence, not part of the title.
  while (j > i && IsHSpace(Byte(s, j - 1))) --j;
  uint32_t k = j;
  while (k > i && Byte(s, k - 1) == '#') --k;
  if (k < j && (k == i || IsHSpace(Byte(s, k - 1)))) {
    j = k;
    while (j > i && IsHSpace(Byte(s, j - 1))) --j;
  }
  return s.substr(i, j - i);
}

// A fence is three or more backticks or tildes at an indent below four.
bool FenceAt(const std::string& s, const Line& l, uint8_t* ch, uint32_t* len) {
  if (Indent(s, l) >= 4) return false;
  const uint32_t i = FirstNonSpace(s, l);
  if (i >= l.end) return false;
  const uint8_t c = Byte(s, i);
  if (c != '`' && c != '~') return false;
  uint32_t n = 0;
  uint32_t j = i;
  while (j < l.end && Byte(s, j) == c) {
    ++n;
    ++j;
  }
  if (n < 3) return false;
  // A backtick info string may not itself contain a backtick.
  if (c == '`') {
    for (uint32_t k = j; k < l.end; ++k) {
      if (Byte(s, k) == '`') return false;
    }
  }
  *ch = c;
  *len = n;
  return true;
}

bool ClosesFence(const std::string& s, const Line& l, uint8_t ch,
                 uint32_t len) {
  if (Indent(s, l) >= 4) return false;
  uint32_t i = FirstNonSpace(s, l);
  uint32_t n = 0;
  while (i < l.end && Byte(s, i) == ch) {
    ++n;
    ++i;
  }
  if (n < len) return false;
  while (i < l.end && IsHSpace(Byte(s, i))) ++i;
  return i == l.end;
}

bool IsTableLine(const std::string& s, const Line& l) {
  const uint32_t i = FirstNonSpace(s, l);
  return i < l.end && Byte(s, i) == '|';
}

// The `|---|:---:|` row that turns two lines into a table.
bool IsTableDelimiter(const std::string& s, const Line& l) {
  if (!IsTableLine(s, l)) return false;
  bool saw_dash = false;
  for (uint32_t i = FirstNonSpace(s, l); i < l.end; ++i) {
    const uint8_t c = Byte(s, i);
    if (c == '-') {
      saw_dash = true;
    } else if (c != '|' && c != ':' && !IsHSpace(c)) {
      return false;
    }
  }
  return saw_dash;
}

bool IsQuoteLine(const std::string& s, const Line& l) {
  if (Indent(s, l) >= 4) return false;
  const uint32_t i = FirstNonSpace(s, l);
  return i < l.end && Byte(s, i) == '>';
}

// `- x`, `* x`, `+ x`, `1. x`, `1) x`, and the task-list forms.
bool IsListItemStart(const std::string& s, const Line& l) {
  if (Indent(s, l) >= 4) return false;
  uint32_t i = FirstNonSpace(s, l);
  if (i >= l.end) return false;
  const uint8_t c = Byte(s, i);
  if (c == '-' || c == '*' || c == '+') {
    // `---` is a thematic break, not a list.
    uint32_t j = i;
    uint32_t same = 0;
    while (j < l.end && (Byte(s, j) == c || IsHSpace(Byte(s, j)))) {
      if (Byte(s, j) == c) ++same;
      ++j;
    }
    if (j == l.end && same >= 3) return false;
    return i + 1 < l.end && IsHSpace(Byte(s, i + 1));
  }
  if (IsDigitByte(c)) {
    uint32_t j = i;
    uint32_t digits = 0;
    while (j < l.end && IsDigitByte(Byte(s, j)) && digits < 9) {
      ++j;
      ++digits;
    }
    if (j < l.end && (Byte(s, j) == '.' || Byte(s, j) == ')')) {
      return j + 1 < l.end && IsHSpace(Byte(s, j + 1));
    }
  }
  return false;
}

bool IsThematicBreak(const std::string& s, const Line& l) {
  if (Indent(s, l) >= 4) return false;
  uint32_t i = FirstNonSpace(s, l);
  if (i >= l.end) return false;
  const uint8_t c = Byte(s, i);
  if (c != '-' && c != '*' && c != '_') return false;
  uint32_t same = 0;
  for (uint32_t j = i; j < l.end; ++j) {
    const uint8_t d = Byte(s, j);
    if (d == c) {
      ++same;
    } else if (!IsHSpace(d)) {
      return false;
    }
  }
  return same >= 3;
}

// A setext underline: === or --- directly under a non-blank line.
uint32_t SetextLevel(const std::string& s, const Line& l) {
  if (Indent(s, l) >= 4) return 0;
  uint32_t i = FirstNonSpace(s, l);
  if (i >= l.end) return 0;
  const uint8_t c = Byte(s, i);
  if (c != '=' && c != '-') return 0;
  for (uint32_t j = i; j < l.end; ++j) {
    const uint8_t d = Byte(s, j);
    if (d != c && !IsHSpace(d)) return 0;
  }
  return c == '=' ? 1u : 2u;
}

// ---------------------------------------------------------------------------
// Blocks

enum class BlockKind : uint8_t {
  kFrontMatter,
  kHeading,
  kCode,
  kTable,
  kList,
  kQuote,
  kParagraph,
  kBreak,
  kBlank,
};

struct Block {
  BlockKind kind = BlockKind::kParagraph;
  uint32_t start = 0;
  uint32_t end = 0;  // exclusive, includes the trailing newline
  uint32_t level = 0;
  std::string title;          // headings only
  uint32_t header_start = 0;  // tables only: the header plus delimiter rows
  uint32_t header_end = 0;
};

// FRONT MATTER IS ONLY FRONT MATTER AT THE TOP. A `---` in the middle of a
// document is a thematic break, and treating it as the start of metadata would
// swallow the rest of the note.
bool ScanFrontMatter(const std::string& s, const std::vector<Line>& lines,
                     uint32_t* consumed, Block* out) {
  if (lines.empty()) return false;
  const std::string first = LineText(s, lines[0]);
  const bool yaml = first == "---";
  const bool toml = first == "+++";
  if (!yaml && !toml) return false;
  const std::string closer = yaml ? "---" : "+++";
  for (uint32_t i = 1; i < static_cast<uint32_t>(lines.size()); ++i) {
    if (LineText(s, lines[i]) == closer) {
      out->kind = BlockKind::kFrontMatter;
      out->start = lines[0].start;
      out->end = lines[i].next;
      *consumed = i + 1;
      return true;
    }
  }
  // An unterminated opener is not front matter; it is a thematic break and a
  // document. Falling through leaves it to the ordinary scanner.
  return false;
}

std::vector<Block> ScanBlocks(const std::string& s) {
  const std::vector<Line> lines = SplitLines(s);
  std::vector<Block> blocks;
  const uint32_t n = static_cast<uint32_t>(lines.size());
  uint32_t i = 0;

  {
    Block fm;
    uint32_t used = 0;
    if (ScanFrontMatter(s, lines, &used, &fm)) {
      blocks.push_back(fm);
      i = used;
    }
  }

  while (i < n) {
    const Line& l = lines[i];

    if (LineIsBlank(s, l)) {
      Block b;
      b.kind = BlockKind::kBlank;
      b.start = l.start;
      b.end = l.next;
      blocks.push_back(b);
      ++i;
      continue;
    }

    uint8_t fence_ch = 0;
    uint32_t fence_len = 0;
    if (FenceAt(s, l, &fence_ch, &fence_len)) {
      Block b;
      b.kind = BlockKind::kCode;
      b.start = l.start;
      uint32_t j = i + 1;
      while (j < n && !ClosesFence(s, lines[j], fence_ch, fence_len)) ++j;
      // AN UNTERMINATED FENCE RUNS TO THE END OF THE DOCUMENT. That is what
      // CommonMark says, and it is also the safe reading: the alternative is to
      // decide the fence was not a fence and split the contents, which is the
      // thing this whole file exists to avoid.
      b.end = (j < n) ? lines[j].next : s.size();
      blocks.push_back(b);
      i = (j < n) ? j + 1 : n;
      continue;
    }

    uint32_t level = 0;
    if (HeadingLevel(s, l, &level)) {
      Block b;
      b.kind = BlockKind::kHeading;
      b.start = l.start;
      b.end = l.next;
      b.level = level;
      b.title = HeadingTitle(s, l);
      blocks.push_back(b);
      ++i;
      continue;
    }

    if (IsThematicBreak(s, l)) {
      Block b;
      b.kind = BlockKind::kBreak;
      b.start = l.start;
      b.end = l.next;
      blocks.push_back(b);
      ++i;
      continue;
    }

    // A table needs a header row and a delimiter row.
    if (IsTableLine(s, l) && i + 1 < n && IsTableDelimiter(s, lines[i + 1])) {
      Block b;
      b.kind = BlockKind::kTable;
      b.start = l.start;
      b.header_start = l.start;
      b.header_end = lines[i + 1].next;
      uint32_t j = i + 2;
      while (j < n && IsTableLine(s, lines[j])) ++j;
      b.end = (j > i) ? lines[j - 1].next : l.next;
      blocks.push_back(b);
      i = j;
      continue;
    }

    if (IsQuoteLine(s, l)) {
      Block b;
      b.kind = BlockKind::kQuote;
      b.start = l.start;
      uint32_t j = i;
      while (j < n && !LineIsBlank(s, lines[j]) &&
             (IsQuoteLine(s, lines[j]) || j == i)) {
        ++j;
      }
      b.end = lines[j - 1].next;
      blocks.push_back(b);
      i = j;
      continue;
    }

    if (IsListItemStart(s, l)) {
      Block b;
      b.kind = BlockKind::kList;
      b.start = l.start;
      uint32_t j = i;
      // A list runs until a blank line followed by something that is not
      // indented and not another item. A single blank line inside a list is
      // ordinary; two end it.
      while (j < n) {
        if (LineIsBlank(s, lines[j])) {
          if (j + 1 >= n) break;
          if (LineIsBlank(s, lines[j + 1])) break;
          if (!IsListItemStart(s, lines[j + 1]) &&
              Indent(s, lines[j + 1]) < 2) {
            break;
          }
          ++j;
          continue;
        }
        if (j > i && !IsListItemStart(s, lines[j]) && Indent(s, lines[j]) < 2 &&
            HeadingLevel(s, lines[j], &level)) {
          break;
        }
        ++j;
      }
      b.end = lines[j - 1].next;
      blocks.push_back(b);
      i = j;
      continue;
    }

    // Otherwise a paragraph, to the next blank line or structural line.
    {
      Block b;
      b.kind = BlockKind::kParagraph;
      b.start = l.start;
      uint32_t j = i + 1;
      while (j < n) {
        if (LineIsBlank(s, lines[j])) break;
        const uint32_t setext = SetextLevel(s, lines[j]);
        if (setext != 0 && j == i + 1) {
          // The paragraph was a setext heading after all.
          Block h;
          h.kind = BlockKind::kHeading;
          h.start = l.start;
          h.end = lines[j].next;
          h.level = setext;
          h.title = LineText(s, l);
          blocks.push_back(h);
          i = j + 1;
          b.start = 0;
          b.end = 0;
          break;
        }
        uint8_t fc = 0;
        uint32_t fl = 0;
        if (HeadingLevel(s, lines[j], &level) ||
            FenceAt(s, lines[j], &fc, &fl) || IsThematicBreak(s, lines[j]) ||
            IsListItemStart(s, lines[j])) {
          break;
        }
        ++j;
      }
      if (b.end == 0 && b.start == 0 && !blocks.empty() &&
          blocks.back().kind == BlockKind::kHeading &&
          blocks.back().start == l.start) {
        continue;  // consumed as a setext heading
      }
      b.end = lines[j - 1].next;
      blocks.push_back(b);
      i = j;
    }
  }
  return blocks;
}

// ---------------------------------------------------------------------------
// Link density
//
// A note that is a list of links is a real and common thing in a vault -- an
// index, a map of content, a daily note that is only references. Embedding it
// produces a vector that sits near every other list of links, because that is
// what the text is: link syntax and titles, with almost no prose to distinguish
// it. It is not junk, and dropping it would lose the one note that names where
// everything else lives.
//
// So it is indexed like anything else and MEASURED, and the ratio travels with
// the chunk so retrieval can decide. Reported per ten thousand to keep it an
// integer -- see the determinism note in the header.
uint32_t LinkRatio(const std::string& body) {
  if (body.empty()) return 0;
  const uint32_t n = static_cast<uint32_t>(body.size());
  uint32_t in_link = 0;
  uint32_t i = 0;
  while (i < n) {
    const uint8_t c = static_cast<uint8_t>(body[i]);
    // [[wikilink]]
    if (c == '[' && i + 1 < n && static_cast<uint8_t>(body[i + 1]) == '[') {
      uint32_t j = i + 2;
      while (j + 1 < n && !(static_cast<uint8_t>(body[j]) == ']' &&
                            static_cast<uint8_t>(body[j + 1]) == ']')) {
        ++j;
      }
      if (j + 1 < n) {
        in_link += (j + 2) - i;
        i = j + 2;
        continue;
      }
    }
    // [text](target)
    if (c == '[') {
      uint32_t j = i + 1;
      while (j < n && static_cast<uint8_t>(body[j]) != ']' &&
             static_cast<uint8_t>(body[j]) != '\n') {
        ++j;
      }
      if (j < n && static_cast<uint8_t>(body[j]) == ']' && j + 1 < n &&
          static_cast<uint8_t>(body[j + 1]) == '(') {
        uint32_t k = j + 2;
        while (k < n && static_cast<uint8_t>(body[k]) != ')' &&
               static_cast<uint8_t>(body[k]) != '\n') {
          ++k;
        }
        if (k < n && static_cast<uint8_t>(body[k]) == ')') {
          in_link += (k + 1) - i;
          i = k + 1;
          continue;
        }
      }
    }
    ++i;
  }
  // Against non-whitespace bytes, so that a list of links separated by newlines
  // is not diluted by its own formatting.
  uint32_t solid = 0;
  for (uint32_t k = 0; k < n; ++k) {
    if (!IsSpaceByte(static_cast<uint8_t>(body[k]))) ++solid;
  }
  if (solid == 0) return 0;
  const uint64_t num = static_cast<uint64_t>(in_link) * 10000u;
  const uint64_t r = num / solid;
  return r > 10000u ? 10000u : static_cast<uint32_t>(r);
}

// ---------------------------------------------------------------------------

struct HeadingStack {
  // level -> title, 1..6. A vector rather than a map so iteration order is the
  // order of the document and nothing else.
  std::vector<std::pair<uint32_t, std::string>> items;

  void Push(uint32_t level, const std::string& title) {
    while (!items.empty() && items.back().first >= level) items.pop_back();
    items.push_back({level, title});
  }
  std::string Path() const {
    std::string out;
    for (std::size_t i = 0; i < items.size(); ++i) {
      if (i != 0) out += " > ";
      out += items[i].second;
    }
    return out;
  }
};

// UTF-8 SAFE HARD SPLIT, the last resort. Only reached by a single run of text
// with no structural boundary in it that is still over the ceiling -- a minified
// blob, a base64 payload pasted into a note, a CJK paragraph with no spaces.
// Splitting inside a code point would produce bytes that are not text, so the
// cut walks back to a boundary.
uint32_t BackToCodePointBoundary(const std::string& s, uint32_t at) {
  uint32_t i = at;
  const uint32_t low = (at > 4) ? at - 4 : 0;
  while (i > low && (static_cast<uint8_t>(s[i]) & 0xC0u) == 0x80u) --i;
  return i;
}

}  // namespace

const char* ChunkKindName(ChunkKind k) {
  switch (k) {
    case ChunkKind::kProse:
      return "prose";
    case ChunkKind::kCode:
      return "code";
    case ChunkKind::kTable:
      return "table";
    case ChunkKind::kFrontMatter:
      return "front-matter";
    case ChunkKind::kLinkList:
      return "link-list";
    case ChunkKind::kList:
      return "list";
    case ChunkKind::kQuote:
      return "quote";
  }
  return "unknown";
}

const char* ChunkStatusName(ChunkStatus s) {
  switch (s) {
    case ChunkStatus::kOk:
      return "ok";
    case ChunkStatus::kTooLarge:
      return "too-large";
    case ChunkStatus::kNotUtf8:
      return "not-utf8";
  }
  return "unknown";
}

ChunkStatus ChunkMarkdown(const ObjectId& object, const std::string& text,
                          const ChunkOptions& options,
                          std::vector<Chunk>* out) {
  out->clear();
  if (text.size() > kMaxDocumentBytes) return ChunkStatus::kTooLarge;
  {
    std::vector<char32_t> unused;
    if (!Utf8Decode(text, &unused)) return ChunkStatus::kNotUtf8;
  }
  if (text.empty()) return ChunkStatus::kOk;

  const std::vector<Block> blocks = ScanBlocks(text);
  HeadingStack headings;

  // The chunk being accumulated.
  uint32_t open_start = 0;
  uint32_t open_end = 0;
  bool open = false;
  ChunkKind open_kind = ChunkKind::kProse;
  std::string open_path;

  const auto emit = [&](uint32_t start, uint32_t end, ChunkKind kind,
                        const std::string& path, const std::string& prefix) {
    if (end <= start) return;
    Chunk c;
    c.object = object;
    c.start = start;
    c.end = end;
    c.kind = kind;
    c.heading_path = path;
    c.ordinal = static_cast<uint32_t>(out->size());
    const std::string body = text.substr(start, end - start);
    c.link_ratio = LinkRatio(body);
    if (kind == ChunkKind::kList && c.link_ratio >= 6000) {
      c.kind = ChunkKind::kLinkList;
    }
    std::string embedded;
    if (options.prefix_heading_path && !path.empty()) {
      embedded += path;
      embedded += "\n\n";
    }
    embedded += prefix;
    embedded += body;
    c.text = embedded;
    out->push_back(c);
  };

  const auto flush = [&]() {
    if (!open) return;
    emit(open_start, open_end, open_kind, open_path, std::string());
    open = false;
  };

  for (std::size_t bi = 0; bi < blocks.size(); ++bi) {
    const Block& b = blocks[bi];
    const uint32_t size = b.end - b.start;

    switch (b.kind) {
      case BlockKind::kBlank:
      case BlockKind::kBreak:
        // Whitespace between blocks belongs to whichever chunk is open, so a
        // range stays contiguous and a citation quotes the source as written.
        if (open) open_end = b.end;
        continue;

      case BlockKind::kFrontMatter:
        flush();
        emit(b.start, b.end, ChunkKind::kFrontMatter, std::string(),
             std::string());
        continue;

      case BlockKind::kHeading:
        // A HEADING ENDS THE PREVIOUS CHUNK. Sections are the boundaries the
        // author already chose, and a retrieval hit that starts at a heading
        // reads like an answer rather than like the middle of one.
        flush();
        headings.Push(b.level, b.title);
        open = true;
        open_start = b.start;
        open_end = b.end;
        open_kind = ChunkKind::kProse;
        open_path = headings.Path();
        continue;

      case BlockKind::kCode: {
        // ATOMIC. Larger than the ceiling means an oversized chunk, not a split
        // one: half a function embeds as something that looks like code and is
        // not, and cites a passage that misleads the reader who follows it.
        if (open && (open_end - open_start) + size <= options.max_bytes) {
          open_end = b.end;
          continue;
        }
        flush();
        emit(b.start, b.end, ChunkKind::kCode, headings.Path(), std::string());
        continue;
      }

      case BlockKind::kTable: {
        if (open && (open_end - open_start) + size <= options.max_bytes) {
          open_end = b.end;
          continue;
        }
        flush();
        if (size <= options.max_bytes) {
          emit(b.start, b.end, ChunkKind::kTable, headings.Path(),
               std::string());
          continue;
        }
        // TOO BIG TO KEEP WHOLE, so it is split at row boundaries and every
        // piece is given the header row. A table fragment without its header is
        // a grid of values with no column names -- it embeds as nothing and it
        // cites as less than nothing. The header goes into the embedded text
        // and NOT into the byte range, so the citation still points only at the
        // rows the piece actually covers.
        const std::string header =
            text.substr(b.header_start, b.header_end - b.header_start);
        const std::vector<Line> rows = SplitLines(text);
        uint32_t piece_start = b.header_end;
        uint32_t cursor = b.header_end;
        for (std::size_t ri = 0; ri < rows.size(); ++ri) {
          const Line& r = rows[ri];
          if (r.start < b.header_end) continue;
          if (r.start >= b.end) break;
          const uint32_t candidate = r.next;
          if (candidate - piece_start > options.max_bytes &&
              cursor > piece_start) {
            emit(piece_start, cursor, ChunkKind::kTable, headings.Path(),
                 header);
            piece_start = cursor;
          }
          cursor = candidate;
        }
        if (cursor > piece_start) {
          emit(piece_start, cursor, ChunkKind::kTable, headings.Path(), header);
        }
        continue;
      }

      case BlockKind::kList:
      case BlockKind::kQuote:
      case BlockKind::kParagraph: {
        const ChunkKind kind = (b.kind == BlockKind::kList) ? ChunkKind::kList
                               : (b.kind == BlockKind::kQuote)
                                   ? ChunkKind::kQuote
                                   : ChunkKind::kProse;
        if (open) {
          const uint32_t would_be = b.end - open_start;
          if (would_be <= options.target_bytes ||
              (would_be <= options.max_bytes &&
               (open_end - open_start) < options.min_bytes)) {
            open_end = b.end;
            if (open_kind == ChunkKind::kProse) open_kind = kind;
            continue;
          }
          flush();
        }
        if (size <= options.max_bytes) {
          open = true;
          open_start = b.start;
          open_end = b.end;
          open_kind = kind;
          open_path = headings.Path();
          continue;
        }
        // One block over the ceiling. Split at line boundaries, and only if a
        // single line is itself over the ceiling, at a code point boundary.
        //
        // A FENCE INSIDE A LIST ITEM IS STILL A FENCE. The block scanner treats
        // a run of list items as one block, so a ```sh inside item three never
        // reached the fence branch above -- which is harmless while the list
        // fits and is the exact failure this design exists to prevent once it
        // does not. Cutting between ``` and ``` produces two chunks that each
        // look like code and neither of which is. So the split tracks fence
        // state and refuses to cut inside one.
        const std::vector<Line> ls = SplitLines(text);
        uint32_t piece_start = b.start;
        uint32_t cursor = b.start;
        bool in_fence = false;
        uint8_t fence_char = 0;
        uint32_t fence_width = 0;
        for (std::size_t li = 0; li < ls.size(); ++li) {
          const Line& r = ls[li];
          if (r.start < b.start) continue;
          if (r.start >= b.end) break;
          // THE BOUNDARY IS JUDGED BEFORE THIS LINE IS CONSUMED. The cut
          // being considered sits between the previous line and this one, so
          // the fence state that matters is the state as of the previous line.
          // Updating first and then deciding let a CLOSING fence clear the
          // flag and permit a cut immediately before itself, which put the
          // closer at the head of the next chunk and left the opener stranded
          // in the one before -- five fence markers in a chunk, which is how
          // the test found it.
          const bool may_cut_here = !in_fence;
          {
            uint8_t fc = 0;
            uint32_t fl = 0;
            // The indent is ignored on purpose: a fence inside a list item is
            // indented by the item's marker, and FenceAt refuses anything at
            // four or more. Inside a list that indent is structure, not code.
            Line probe = r;
            probe.start = FirstNonSpace(text, r);
            if (!in_fence && FenceAt(text, probe, &fc, &fl)) {
              in_fence = true;
              fence_char = fc;
              fence_width = fl;
            } else if (in_fence &&
                       ClosesFence(text, probe, fence_char, fence_width)) {
              in_fence = false;
            }
          }
          uint32_t line_end = r.next;
          while (line_end - piece_start > options.max_bytes &&
                 cursor == piece_start && may_cut_here) {
            // A single line longer than the ceiling.
            const uint32_t cut =
                BackToCodePointBoundary(text, piece_start + options.max_bytes);
            if (cut <= piece_start) break;
            emit(piece_start, cut, kind, headings.Path(), std::string());
            piece_start = cut;
            cursor = cut;
          }
          if (line_end - piece_start > options.max_bytes &&
              cursor > piece_start && may_cut_here) {
            emit(piece_start, cursor, kind, headings.Path(), std::string());
            piece_start = cursor;
          }
          cursor = line_end;
        }
        if (cursor > piece_start) {
          open = true;
          open_start = piece_start;
          open_end = cursor;
          open_kind = kind;
          open_path = headings.Path();
        }
        continue;
      }
    }
  }
  flush();

  // A heading with nothing under it produced a chunk that is only the heading.
  // Merging it forward would move the citation; leaving it costs one small
  // vector and keeps the range honest. It is left.
  for (std::size_t i = 0; i < out->size(); ++i) {
    (*out)[i].ordinal = static_cast<uint32_t>(i);
  }
  return ChunkStatus::kOk;
}

ChunkStatus ChunkMarkdown(const ObjectId& object, const std::string& text,
                          std::vector<Chunk>* out) {
  return ChunkMarkdown(object, text, ChunkOptions(), out);
}

std::string ChunkingDigest(const std::vector<Chunk>& chunks) {
  // BLAKE2b over the boundaries and kinds, in order. Not over the text: two
  // devices already agree on the text, and hashing it would hide a boundary
  // disagreement behind a match on content.
  crypto_generichash_state st;
  crypto_generichash_init(&st, nullptr, 0, 32);
  for (const Chunk& c : chunks) {
    uint8_t rec[13];
    rec[0] = static_cast<uint8_t>(c.kind);
    for (int i = 0; i < 4; ++i) {
      rec[1 + static_cast<std::size_t>(i)] =
          static_cast<uint8_t>((c.start >> (24 - 8 * i)) & 0xFF);
      rec[5 + static_cast<std::size_t>(i)] =
          static_cast<uint8_t>((c.end >> (24 - 8 * i)) & 0xFF);
      rec[9 + static_cast<std::size_t>(i)] =
          static_cast<uint8_t>((c.ordinal >> (24 - 8 * i)) & 0xFF);
    }
    crypto_generichash_update(&st, rec, sizeof(rec));
  }
  uint8_t digest[32];
  crypto_generichash_final(&st, digest, sizeof(digest));
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (std::size_t i = 0; i < sizeof(digest); ++i) {
    out.push_back(kHex[digest[i] >> 4]);
    out.push_back(kHex[digest[i] & 0x0F]);
  }
  return out;
}

}  // namespace ai
}  // namespace umbra
