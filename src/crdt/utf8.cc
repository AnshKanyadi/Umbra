#include "utf8.h"

#include "check.h"

namespace umbra {
namespace {

bool IsContinuation(unsigned char c) { return (c & 0xC0) == 0x80; }

}  // namespace

bool Utf8Decode(const std::string& in, std::vector<char32_t>* out) {
  out->clear();
  out->reserve(in.size());
  std::size_t i = 0;
  while (i < in.size()) {
    const unsigned char b0 = static_cast<unsigned char>(in[i]);
    char32_t cp = 0;
    std::size_t len = 0;
    if (b0 < 0x80) {
      cp = b0;
      len = 1;
    } else if ((b0 & 0xE0) == 0xC0) {
      cp = b0 & 0x1F;
      len = 2;
    } else if ((b0 & 0xF0) == 0xE0) {
      cp = b0 & 0x0F;
      len = 3;
    } else if ((b0 & 0xF8) == 0xF0) {
      cp = b0 & 0x07;
      len = 4;
    } else {
      return false;  // continuation byte in lead position, or 5+ byte form
    }
    if (i + len > in.size()) return false;
    for (std::size_t k = 1; k < len; ++k) {
      const unsigned char bk = static_cast<unsigned char>(in[i + k]);
      if (!IsContinuation(bk)) return false;
      cp = (cp << 6) | (bk & 0x3F);
    }
    // Overlong forms encode a value in more bytes than it needs. They are a
    // second spelling of the same character, and two spellings of one character
    // is exactly what a convergent document cannot have.
    if (len == 2 && cp < 0x80) return false;
    if (len == 3 && cp < 0x800) return false;
    if (len == 4 && cp < 0x10000) return false;
    if (cp > 0x10FFFF) return false;
    if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // surrogate half
    out->push_back(cp);
    i += len;
  }
  return true;
}

void Utf8AppendChar(char32_t c, std::string* out) {
  UMBRA_CHECK(c <= 0x10FFFF && !(c >= 0xD800 && c <= 0xDFFF),
              "document holds a value that is not a Unicode scalar");
  if (c < 0x80) {
    out->push_back(static_cast<char>(c));
  } else if (c < 0x800) {
    out->push_back(static_cast<char>(0xC0 | (c >> 6)));
    out->push_back(static_cast<char>(0x80 | (c & 0x3F)));
  } else if (c < 0x10000) {
    out->push_back(static_cast<char>(0xE0 | (c >> 12)));
    out->push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
    out->push_back(static_cast<char>(0x80 | (c & 0x3F)));
  } else {
    out->push_back(static_cast<char>(0xF0 | (c >> 18)));
    out->push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
    out->push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
    out->push_back(static_cast<char>(0x80 | (c & 0x3F)));
  }
}

std::string Utf8Encode(const std::vector<char32_t>& in) {
  std::string s;
  s.reserve(in.size());
  for (char32_t c : in) Utf8AppendChar(c, &s);
  return s;
}

}  // namespace umbra
