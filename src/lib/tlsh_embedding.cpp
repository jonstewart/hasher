#include "tlsh_embedding.h"

#include <cmath>
#include <numbers>

#include "hasher/tlsh.h"

namespace {

// code -> (x, y)
constexpr float BODY_X[4] = { 1.f, 0.f, 0.f, -1.f };
constexpr float BODY_Y[4] = { 0.f, 0.f, 1.f,  1.f };

constexpr double Q_RADIUS = 2.5629154477415055; // 1 / (2 sin(pi / 16))

struct QTable {
  float x[16];
  float y[16];

  QTable() {
    for (int q = 0; q < 16; ++q) {
      const double a = 2.0 * std::numbers::pi * q / 16.0;
      x[q] = static_cast<float>(Q_RADIUS * std::cos(a));
      y[q] = static_cast<float>(Q_RADIUS * std::sin(a));
    }
  }
};

const QTable QT;

const float CS_SCALE = static_cast<float>(1.0 / std::sqrt(3.0));

inline float sq(float v) { return v * v; }

} // namespace

void tlsh_embed(const TlshDigest& d, float* out) {
  for (size_t i = 0; i < 128; ++i) {
    const uint8_t c = d.bucket(i);
    out[2 * i] = BODY_X[c];
    out[2 * i + 1] = BODY_Y[c];
  }
  out[TLSH_EMBED_L_DIM] = static_cast<float>(d.L);
  out[257] = QT.x[d.q1()];
  out[258] = QT.y[d.q1()];
  out[259] = QT.x[d.q2()];
  out[260] = QT.y[d.q2()];
  out[261] = (d.checksum & 1) ? CS_SCALE : 0.f;
  out[262] = (d.checksum & 2) ? CS_SCALE : 0.f;
  out[263] = (d.checksum & 4) ? CS_SCALE : 0.f;
}

float tlsh_embed_dist2(const float* a, const float* b, bool include_length) {
  float s = 0.f;
  for (size_t i = 0; i < TLSH_EMBED_DIMS; ++i) {
    s += sq(a[i] - b[i]);
  }
  if (!include_length) {
    s -= sq(a[TLSH_EMBED_L_DIM] - b[TLSH_EMBED_L_DIM]);
  }
  return s;
}

float tlsh_embed_dist2(const TlshDigest& a, const TlshDigest& b, bool include_length) {
  float d = static_cast<float>(tlsh_embed_body_dist2(a, b));
  if (include_length) {
    d += sq(static_cast<float>(a.L) - static_cast<float>(b.L));
  }
  d += sq(QT.x[a.q1()] - QT.x[b.q1()]) + sq(QT.y[a.q1()] - QT.y[b.q1()]);
  d += sq(QT.x[a.q2()] - QT.x[b.q2()]) + sq(QT.y[a.q2()] - QT.y[b.q2()]);
  d += static_cast<float>(std::popcount(static_cast<unsigned>((a.checksum ^ b.checksum) & 7))) / 3.f;
  return d;
}

float tlsh_embed_dist2_to_point(const TlshDigest& d, const float* p, bool include_length) {
  float s = 0.f;
  for (size_t i = 0; i < 128; ++i) {
    const uint8_t c = d.bucket(i);
    s += sq(BODY_X[c] - p[2 * i]) + sq(BODY_Y[c] - p[2 * i + 1]);
  }
  if (include_length) {
    s += sq(static_cast<float>(d.L) - p[TLSH_EMBED_L_DIM]);
  }
  s += sq(QT.x[d.q1()] - p[257]) + sq(QT.y[d.q1()] - p[258]);
  s += sq(QT.x[d.q2()] - p[259]) + sq(QT.y[d.q2()] - p[260]);
  s += sq(((d.checksum & 1) ? CS_SCALE : 0.f) - p[261]);
  s += sq(((d.checksum & 2) ? CS_SCALE : 0.f) - p[262]);
  s += sq(((d.checksum & 4) ? CS_SCALE : 0.f) - p[263]);
  return s;
}

void tlsh_embed_body(const TlshDigest& d, float* out) {
  for (size_t i = 0; i < 128; ++i) {
    const uint8_t c = d.bucket(i);
    out[2 * i] = BODY_X[c];
    out[2 * i + 1] = BODY_Y[c];
  }
}

uint32_t tlsh_embed_body_i8(const TlshDigest& d, int8_t* out) {
  // code -> (x, y) as BODY_X, BODY_Y, and x^2 + y^2
  static constexpr int8_t X[4] = { 1, 0, 0, -1 };
  static constexpr int8_t Y[4] = { 0, 0, 1,  1 };
  static constexpr uint32_t NORM2[4] = { 1, 0, 1, 2 };
  uint32_t norm2 = 0;
  for (size_t i = 0; i < 128; ++i) {
    const uint8_t c = d.bucket(i);
    out[2 * i] = X[c];
    out[2 * i + 1] = Y[c];
    norm2 += NORM2[c];
  }
  return norm2;
}

float tlsh_embed_body_dist2_to_point(const TlshDigest& d, const float* p) {
  float s = 0.f;
  for (size_t i = 0; i < 128; ++i) {
    const uint8_t c = d.bucket(i);
    s += sq(BODY_X[c] - p[2 * i]) + sq(BODY_Y[c] - p[2 * i + 1]);
  }
  return s;
}

//
// C API
//

void sfhash_tlsh_embed(const void* digest, float* out) {
  tlsh_embed(*static_cast<const TlshDigest*>(digest), out);
}

void sfhash_tlsh_embed_n(const void* digests, size_t n, float* out) {
  const TlshDigest* d = static_cast<const TlshDigest*>(digests);
  for (size_t r = 0; r < n; ++r) {
    tlsh_embed(d[r], out + r * TLSH_EMBED_DIMS);
  }
}

float sfhash_tlsh_embed_dist2(const float* a, const float* b, bool include_length) {
  return tlsh_embed_dist2(a, b, include_length);
}
