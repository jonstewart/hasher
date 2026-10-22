#include "tlsh_digest.h"

#include <cctype>
#include <cstring>

namespace {

constexpr char HEX_UPPER[] = "0123456789ABCDEF";

int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

uint8_t swap_nibbles(uint8_t b) {
  return static_cast<uint8_t>((b << 4) | (b >> 4));
}

} // namespace

TlshDigest make_tlsh_digest(
  uint8_t L,
  uint8_t q1,
  uint8_t q2,
  uint8_t checksum,
  const uint8_t* codes)
{
  TlshDigest d{};
  d.L = L;
  d.Q = static_cast<uint8_t>((q1 << 4) | (q2 & 0x0F));
  d.checksum = checksum;
  for (size_t i = 0; i < 128; ++i) {
    d.hi[i >> 3] |= ((codes[i] >> 1) & 1) << (i & 7);
    d.lo[i >> 3] |= (codes[i] & 1) << (i & 7);
  }
  return d;
}

bool tlsh_from_hex(const char* hex, TlshDigest& out) {
  if (!hex) {
    return false;
  }

  if (!std::strncmp(hex, "TNULL", 5)) {
    if (hex[5] != '\0') {
      return false;
    }
    out = TlshDigest{};
    return true;
  }

  if (hex[0] == 'T' && hex[1] == '1') {
    hex += 2;
  }

  // 70 hex chars, then a non-hex char
  uint8_t raw[35];
  for (size_t i = 0; i < 35; ++i) {
    const int h = nibble(hex[2 * i]);
    if (h < 0) {
      return false;
    }
    const int l = nibble(hex[2 * i + 1]);
    if (l < 0) {
      return false;
    }
    raw[i] = static_cast<uint8_t>((h << 4) | l);
  }
  if (nibble(hex[70]) >= 0) {
    return false;
  }

  // The hex form nibble-swaps the three header bytes and emits the body
  // bytes in reverse order; undo both.
  const uint8_t checksum = swap_nibbles(raw[0]);
  const uint8_t L = swap_nibbles(raw[1]);
  // raw[2] is the reference's Q byte (Q1 low nibble, Q2 high) nibble-swapped,
  // which is exactly our Q layout.
  const uint8_t q1 = raw[2] >> 4;
  const uint8_t q2 = raw[2] & 0x0F;

  uint8_t codes[128];
  for (size_t i = 0; i < 32; ++i) {
    const uint8_t code_byte = raw[3 + 31 - i];
    for (size_t j = 0; j < 4; ++j) {
      codes[4 * i + j] = (code_byte >> (2 * j)) & 3;
    }
  }

  out = make_tlsh_digest(L, q1, q2, checksum, codes);
  return true;
}

std::string tlsh_to_hex(const TlshDigest& d) {
  if (d.is_null()) {
    return "TNULL";
  }

  uint8_t raw[35];
  raw[0] = swap_nibbles(d.checksum);
  raw[1] = swap_nibbles(d.L);
  raw[2] = d.Q;
  for (size_t i = 0; i < 32; ++i) {
    uint8_t code_byte = 0;
    for (size_t j = 0; j < 4; ++j) {
      code_byte |= d.bucket(4 * i + j) << (2 * j);
    }
    raw[3 + 31 - i] = code_byte;
  }

  std::string s(SFHASH_TLSH_HEX_LENGTH, '\0');
  s[0] = 'T';
  s[1] = '1';
  for (size_t i = 0; i < 35; ++i) {
    s[2 + 2 * i] = HEX_UPPER[raw[i] >> 4];
    s[3 + 2 * i] = HEX_UPPER[raw[i] & 0x0F];
  }
  return s;
}

//
// C API
//

bool sfhash_tlsh_from_hex(const char* hex, void* digest) {
  return tlsh_from_hex(hex, *static_cast<TlshDigest*>(digest));
}

void sfhash_tlsh_to_hex(const void* digest, char* hex) {
  const auto s = tlsh_to_hex(*static_cast<const TlshDigest*>(digest));
  std::memcpy(hex, s.c_str(), s.size() + 1);
}

bool sfhash_tlsh_is_null(const void* digest) {
  return static_cast<const TlshDigest*>(digest)->is_null();
}

int sfhash_tlsh_diff(const void* a, const void* b, bool include_length) {
  const auto& da = *static_cast<const TlshDigest*>(a);
  const auto& db = *static_cast<const TlshDigest*>(b);
  if (da.is_null() || db.is_null()) {
    return -1;
  }
  return static_cast<int>(tlsh_diff(da, db, include_length));
}
