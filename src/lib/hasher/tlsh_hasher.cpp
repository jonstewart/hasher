#include "tlsh_hasher.h"

#include <algorithm>
#include <cstring>

#include <tlsh_util.h> // l_capturing from the reference implementation

namespace {

// Pearson's sample random table, as used by TLSH
constexpr uint8_t V_TABLE[256] = {
  1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
  14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
  110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
  25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
  97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
  174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
  132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
  119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
  138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
  170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
  125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
  118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
  27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
  233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
  140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
  51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209
};

// b_mapping(salt, i, j, k) with the first step (V_TABLE[salt]) precomputed
template <uint8_t Salt>
inline uint8_t b_map(uint8_t i, uint8_t j, uint8_t k) {
  uint8_t h = V_TABLE[Salt];
  h = V_TABLE[h ^ i];
  h = V_TABLE[h ^ j];
  h = V_TABLE[h ^ k];
  return h;
}

constexpr uint32_t MIN_DATA_LENGTH = 50;
constexpr size_t EFF_BUCKETS = 128;

} // namespace

TlshHasher::TlshHasher() {
  reset();
}

void TlshHasher::reset() {
  std::memset(Buckets, 0, sizeof(Buckets));
  std::memset(Window, 0, sizeof(Window));
  Checksum = 0;
  Length = 0;
}

TlshHasher* TlshHasher::clone() const {
  return new TlshHasher(*this);
}

void TlshHasher::update(const uint8_t* beg, const uint8_t* end) {
  if (beg == end) {
    return;
  }

  uint32_t len = Length;
  uint8_t checksum = Checksum;

  // the previous four bytes, newest first; Window[i] holds byte i (mod 5)
  uint8_t w1 = Window[(len + 4) % 5];
  uint8_t w2 = Window[(len + 3) % 5];
  uint8_t w3 = Window[(len + 2) % 5];
  uint8_t w4 = Window[(len + 1) % 5];

  const uint8_t* p = beg;

  // warm up until four bytes have been seen
  for (; p != end && len < 4; ++p, ++len) {
    w4 = w3;
    w3 = w2;
    w2 = w1;
    w1 = *p;
  }

  uint32_t* const buckets = Buckets;
  for (; p != end; ++p, ++len) {
    const uint8_t w0 = *p;

    checksum = b_map<0>(w0, w1, checksum);

    ++buckets[b_map<2>(w0, w1, w2)];
    ++buckets[b_map<3>(w0, w1, w3)];
    ++buckets[b_map<5>(w0, w2, w3)];
    ++buckets[b_map<7>(w0, w2, w4)];
    ++buckets[b_map<11>(w0, w1, w4)];
    ++buckets[b_map<13>(w0, w3, w4)];

    w4 = w3;
    w3 = w2;
    w2 = w1;
    w1 = w0;
  }

  // store the last four bytes back where the next call expects them
  Window[(len + 4) % 5] = w1;
  Window[(len + 3) % 5] = w2;
  Window[(len + 2) % 5] = w3;
  Window[(len + 1) % 5] = w4;

  Length = len;
  Checksum = checksum;
}

TlshDigest TlshHasher::digest() const {
  if (Length < MIN_DATA_LENGTH) {
    return TlshDigest{};
  }

  // quartiles over the effective buckets
  uint32_t sorted[EFF_BUCKETS];
  std::copy(Buckets, Buckets + EFF_BUCKETS, sorted);
  std::sort(sorted, sorted + EFF_BUCKETS);
  const uint32_t q1 = sorted[EFF_BUCKETS / 4 - 1];
  const uint32_t q2 = sorted[EFF_BUCKETS / 2 - 1];
  const uint32_t q3 = sorted[EFF_BUCKETS - EFF_BUCKETS / 4 - 1];

  if (q3 == 0) {
    return TlshDigest{};
  }

  // buckets must be more than 50% nonzero
  size_t nonzero = 0;
  for (size_t i = 0; i < EFF_BUCKETS; ++i) {
    nonzero += Buckets[i] > 0;
  }
  if (nonzero <= EFF_BUCKETS / 2) {
    return TlshDigest{};
  }

  uint8_t codes[EFF_BUCKETS];
  for (size_t i = 0; i < EFF_BUCKETS; ++i) {
    const uint32_t k = Buckets[i];
    codes[i] = q3 < k ? 3 : (q2 < k ? 2 : (q1 < k ? 1 : 0));
  }

  const uint8_t L = l_capturing(Length);
  const uint8_t Q1 = static_cast<uint8_t>((static_cast<uint64_t>(q1) * 100 / q3) % 16);
  const uint8_t Q2 = static_cast<uint8_t>((static_cast<uint64_t>(q2) * 100 / q3) % 16);

  return make_tlsh_digest(L, Q1, Q2, Checksum, codes);
}

void TlshHasher::get(void* val) {
  const TlshDigest d = digest();
  std::memcpy(val, &d, sizeof(d));
}

std::unique_ptr<HasherImpl> make_tlsh_hasher() {
  return std::unique_ptr<TlshHasher>(new TlshHasher());
}
