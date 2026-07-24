#pragma once

#include "harness.h"   // HashSet, make_sorted_set, splitmix pattern

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace eval {

// Non-owning view so the 808 MB NSRL mapping is never copied. The oracle and
// timing helpers are templated on "HashSetLike" (hlen/count/at/beg/end), so a
// view works everywhere a HashSet does.
struct HashSetView {
  size_t hlen = 0;
  size_t count = 0;
  const uint8_t* data = nullptr;
  const uint8_t* at(size_t i) const { return data + i * hlen; }
  const uint8_t* beg() const { return data; }
  const uint8_t* end() const { return data + count * hlen; }
};

// Adversarial: leading bytes skewed to a handful of values, with dense runs.
// Correctness must hold here; only speed may degrade.
inline HashSet make_adversarial_set(size_t count, size_t hlen, uint64_t seed) {
  HashSet hs; hs.hlen = hlen; hs.count = count; hs.data.resize(count * hlen);
  uint64_t x = seed ? seed : 0xABC;
  auto next = [&x]() {
    x += 0x9E3779B97F4A7C15ull; uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  };
  static const uint8_t lead[] = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF};
  std::vector<std::vector<uint8_t>> rows(count, std::vector<uint8_t>(hlen));
  for (size_t k = 0; k < count; ++k) {
    rows[k][0] = lead[next() % (sizeof(lead))];        // skewed leading byte
    for (size_t j = 1; j < hlen; ++j) rows[k][j] = static_cast<uint8_t>(next());
  }
  std::sort(rows.begin(), rows.end(), [&](const auto& p, const auto& q) {
    return std::memcmp(p.data(), q.data(), hlen) < 0;
  });
  rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
  hs.count = rows.size();
  hs.data.resize(hs.count * hlen);
  for (size_t k = 0; k < hs.count; ++k) std::memcpy(hs.data.data() + k * hlen, rows[k].data(), hlen);
  return hs;
}

struct Split { HashSet tune; HashSet held_out; };
inline Split split_disjoint(size_t count, size_t hlen, uint64_t tune_seed, uint64_t held_seed) {
  return { make_sorted_set(count, hlen, tune_seed), make_sorted_set(count, hlen, held_seed) };
}

// mmap a raw file of fixed-width sorted digests as a view (zero copy, zero parse).
inline HashSetView mmap_raw(const std::string& path, size_t hlen,
                            std::shared_ptr<boost::interprocess::mapped_region>& keepalive) {
  namespace bip = boost::interprocess;
  bip::file_mapping fm(path.c_str(), bip::read_only);
  keepalive = std::make_shared<bip::mapped_region>(fm, bip::read_only);
  HashSetView v;
  v.hlen = hlen;
  v.data = static_cast<const uint8_t*>(keepalive->get_address());
  v.count = keepalive->get_size() / hlen;
  return v;
}

inline HashSetView mmap_nsrl_sha1(const std::string& path,
                                  std::shared_ptr<boost::interprocess::mapped_region>& keepalive) {
  return mmap_raw(path, 20, keepalive);
}

// Parse MD5 (2nd quoted column) from NSRLFile.txt, write raw 16-byte digests
// sorted+deduped to cache_path. On re-run, if cache exists, skip parsing.
inline void derive_nsrl_md5_cache(const std::string& nsrlfile, const std::string& cache_path) {
  { FILE* c = std::fopen(cache_path.c_str(), "rb"); if (c) { std::fclose(c); return; } }
  FILE* in = std::fopen(nsrlfile.c_str(), "rb");
  if (!in) { std::fprintf(stderr, "cannot open %s\n", nsrlfile.c_str()); std::exit(1); }
  std::vector<std::array<uint8_t,16>> md5s;
  char line[512];
  auto hexval = [](char c)->int { if (c>='0'&&c<='9') return c-'0'; if (c>='A'&&c<='F') return c-'A'+10; if (c>='a'&&c<='f') return c-'a'+10; return -1; };
  std::fgets(line, sizeof line, in); // header row
  while (std::fgets(line, sizeof line, in)) {
    // columns are quoted: "sha1","md5",...  find the 2nd quoted field.
    char* p = std::strchr(line, '"'); if (!p) continue;         // open q1
    p = std::strchr(p+1, '"'); if (!p) continue;                // close q1
    p = std::strchr(p+1, '"'); if (!p) continue;                // open q2
    char* q = std::strchr(p+1, '"'); if (!q) continue;          // close q2
    if (q - (p+1) != 32) continue;
    std::array<uint8_t,16> d; bool ok = true;
    for (int i = 0; i < 16; ++i) { int hi = hexval(p[1+2*i]), lo = hexval(p[2+2*i]); if (hi<0||lo<0){ok=false;break;} d[i]=(uint8_t)((hi<<4)|lo); }
    if (ok) md5s.push_back(d);
  }
  std::fclose(in);
  std::sort(md5s.begin(), md5s.end());
  md5s.erase(std::unique(md5s.begin(), md5s.end()), md5s.end());
  FILE* out = std::fopen(cache_path.c_str(), "wb");
  std::fwrite(md5s.data(), 16, md5s.size(), out);
  std::fclose(out);
}

} // namespace eval
