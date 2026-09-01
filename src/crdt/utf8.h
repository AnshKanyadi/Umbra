// UTF-8 at the boundary, Unicode scalars inside.
//
// A NODE HOLDS A WHOLE CHARACTER, and that is a correctness decision rather
// than a convenience. If nodes held bytes, every operation would have to be
// codepoint-aligned by discipline -- every caller, every diff, every delete
// range -- and a single unaligned one would split a character between two
// replicas' idea of the document. Holding scalars makes the invariant
// structural: there is no way to express half a character.
#ifndef UMBRA_CRDT_UTF8_H_
#define UMBRA_CRDT_UTF8_H_

#include <cstdint>
#include <string>
#include <vector>

namespace umbra {

// Decodes to scalars. Returns false, leaving *out unspecified, on anything that
// is not well-formed UTF-8: a truncated sequence, a continuation byte where a
// lead byte belongs, an overlong encoding, a surrogate (U+D800..U+DFFF), or a
// value above U+10FFFF.
//
// OVERLONGS AND SURROGATES ARE REFUSED rather than replaced. A replacement
// character would be a silent edit to the user's file, and the two replicas
// that disagreed about whether to replace would then disagree about the
// document.
bool Utf8Decode(const std::string& in, std::vector<char32_t>* out);

// Encodes scalars back. Values outside the scalar range abort: they cannot come
// from Utf8Decode, so one here means the document holds something that was
// never decoded from valid input.
std::string Utf8Encode(const std::vector<char32_t>& in);
void Utf8AppendChar(char32_t c, std::string* out);

}  // namespace umbra

#endif  // UMBRA_CRDT_UTF8_H_
