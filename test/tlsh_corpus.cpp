#include "tlsh_corpus.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "tlsh_hasher.h"

namespace {

// Thin wrapper over mt19937_64 that does its own range reduction, so the
// generated corpora do not depend on the standard library's distributions.
struct Rng {
  std::mt19937_64 engine;

  explicit Rng(uint64_t seed): engine(seed) {}

  uint64_t next() {
    return engine();
  }

  // uniform in [0, n)
  uint64_t below(uint64_t n) {
    return n ? next() % n : 0;
  }

  // uniform in [lo, hi]
  uint64_t between(uint64_t lo, uint64_t hi) {
    return lo + below(hi - lo + 1);
  }

  // uniform in [0, 1)
  double unit() {
    return static_cast<double>(next() >> 11) * 0x1.0p-53;
  }

  bool chance(double p) {
    return unit() < p;
  }

  // log-uniform in [lo, hi], like file sizes
  size_t log_uniform(size_t lo, size_t hi) {
    if (hi <= lo) {
      return lo;
    }
    const double l = std::log(static_cast<double>(lo));
    const double h = std::log(static_cast<double>(hi));
    const auto v = static_cast<size_t>(std::exp(l + unit() * (h - l)));
    return std::clamp(v, lo, hi);
  }
};

enum class Alphabet {
  Full,  // uniform bytes
  Small, // 4-24 distinct byte values
  Text,  // words of skewed lowercase letters, whitespace, punctuation
  Runs   // run-length structured binary
};

struct ContentModel {
  Alphabet kind;
  std::vector<uint8_t> symbols; // Small only
};

// letters weighted roughly by English frequency
const char TEXT_LETTERS[] = "eeeeeeettttttaaaaaaooooooiiiiiinnnnnnsssssshhhhhhrrrrrrdddduuullllccmmwwffggyyppbbvkjxqz";

ContentModel pick_model(Rng& rng) {
  ContentModel m;
  switch (rng.below(4)) {
  case 0:
    m.kind = Alphabet::Full;
    break;
  case 1:
    {
      m.kind = Alphabet::Small;
      const size_t n = rng.between(4, 24);
      while (m.symbols.size() < n) {
        const auto b = static_cast<uint8_t>(rng.below(256));
        if (std::find(m.symbols.begin(), m.symbols.end(), b) == m.symbols.end()) {
          m.symbols.push_back(b);
        }
      }
    }
    break;
  case 2:
    m.kind = Alphabet::Text;
    break;
  default:
    m.kind = Alphabet::Runs;
    break;
  }
  return m;
}

uint8_t random_symbol(Rng& rng, const ContentModel& m) {
  switch (m.kind) {
  case Alphabet::Small:
    return m.symbols[rng.below(m.symbols.size())];
  case Alphabet::Text:
    return static_cast<uint8_t>(TEXT_LETTERS[rng.below(sizeof(TEXT_LETTERS) - 1)]);
  default:
    return static_cast<uint8_t>(rng.below(256));
  }
}

std::vector<uint8_t> make_content(Rng& rng, const ContentModel& m, size_t len) {
  std::vector<uint8_t> v;
  v.reserve(len + 64);

  switch (m.kind) {
  case Alphabet::Full:
    while (v.size() < len) {
      uint64_t x = rng.next();
      for (int i = 0; i < 8; ++i) {
        v.push_back(static_cast<uint8_t>(x));
        x >>= 8;
      }
    }
    break;
  case Alphabet::Small:
    while (v.size() < len) {
      v.push_back(random_symbol(rng, m));
    }
    break;
  case Alphabet::Text:
    while (v.size() < len) {
      const size_t wlen = rng.between(1, 11);
      for (size_t i = 0; i < wlen; ++i) {
        v.push_back(random_symbol(rng, m));
      }
      const uint64_t sep = rng.below(16);
      if (sep == 0) {
        v.push_back('.');
        v.push_back('\n');
      }
      else if (sep == 1) {
        v.push_back(',');
        v.push_back(' ');
      }
      else {
        v.push_back(' ');
      }
    }
    break;
  case Alphabet::Runs:
    while (v.size() < len) {
      const size_t rlen = rng.between(1, 16);
      const auto b = static_cast<uint8_t>(rng.below(256));
      v.insert(v.end(), rlen, b);
    }
    break;
  }

  v.resize(len);
  return v;
}

std::vector<uint8_t> mutate(Rng& rng, const std::vector<uint8_t>& base, const ContentModel& m) {
  std::vector<uint8_t> v(base);

  // byte flips over 0.5-5% of the content
  const double rate = 0.005 + rng.unit() * 0.045;
  const size_t flips = std::max<size_t>(1, static_cast<size_t>(rate * v.size()));
  for (size_t i = 0; i < flips; ++i) {
    v[rng.below(v.size())] = random_symbol(rng, m);
  }

  // a few small insertions and deletions
  const size_t edits = rng.below(5);
  for (size_t i = 0; i < edits; ++i) {
    const size_t pos = rng.below(v.size() + 1);
    const size_t n = rng.between(1, 64);
    if (rng.chance(0.5)) {
      std::vector<uint8_t> ins(n);
      for (auto& b: ins) {
        b = random_symbol(rng, m);
      }
      v.insert(v.begin() + pos, ins.begin(), ins.end());
    }
    else if (pos + n <= v.size() && v.size() - n >= 64) {
      v.erase(v.begin() + pos, v.begin() + pos + n);
    }
  }

  // duplicate or move a block
  if (v.size() >= 16 && rng.chance(0.3)) {
    const size_t n = rng.between(1, std::max<size_t>(1, v.size() / 8));
    const size_t src = rng.below(v.size() - n + 1);
    const std::vector<uint8_t> block(v.begin() + src, v.begin() + src + n);
    if (rng.chance(0.5)) {
      v.erase(v.begin() + src, v.begin() + src + n); // move rather than copy
    }
    const size_t dst = rng.below(v.size() + 1);
    v.insert(v.begin() + dst, block.begin(), block.end());
  }

  return v;
}

TlshDigest hash(const std::vector<uint8_t>& v) {
  TlshHasher h;
  h.update(v.data(), v.data() + v.size());
  return h.digest();
}

TlshDigest perturb(Rng& rng, const TlshDigest& s, double bucket_flip_prob) {
  uint8_t codes[128];
  for (size_t b = 0; b < 128; ++b) {
    int c = s.bucket(b);
    if (rng.chance(bucket_flip_prob)) {
      c += rng.chance(0.5) ? 1 : -1;
      c = std::clamp(c, 0, 3);
    }
    codes[b] = static_cast<uint8_t>(c);
  }

  int L = s.L;
  if (rng.chance(0.1)) {
    L += (rng.chance(0.5) ? 1 : -1) * static_cast<int>(rng.between(1, 2));
    L = std::clamp(L, 0, 255);
  }

  int q1 = s.q1();
  if (rng.chance(0.1)) {
    q1 = (q1 + (rng.chance(0.5) ? 1 : 15)) & 0x0F;
  }

  int q2 = s.q2();
  if (rng.chance(0.1)) {
    q2 = (q2 + (rng.chance(0.5) ? 1 : 15)) & 0x0F;
  }

  const auto checksum = static_cast<uint8_t>(rng.below(256));

  TlshDigest d = make_tlsh_digest(
    static_cast<uint8_t>(L),
    static_cast<uint8_t>(q1),
    static_cast<uint8_t>(q2),
    checksum,
    codes
  );
  if (d.is_null()) {
    d.checksum = 1;
  }
  return d;
}

} // namespace

std::vector<TlshFamily> make_tlsh_families(
  uint64_t seed,
  size_t families,
  size_t variants_per_family,
  size_t min_len,
  size_t max_len)
{
  std::vector<TlshFamily> out;
  out.reserve(families);

  Rng rng(seed);

  for (size_t f = 0; f < families; ++f) {
    const ContentModel m = pick_model(rng);
    const size_t len = rng.log_uniform(min_len, max_len);
    const std::vector<uint8_t> base = make_content(rng, m, len);

    TlshFamily fam{hash(base), {}};
    if (fam.base.is_null()) {
      continue;
    }

    fam.variants.reserve(variants_per_family);
    for (size_t v = 0; v < variants_per_family; ++v) {
      const TlshDigest d = hash(mutate(rng, base, m));
      if (!d.is_null()) {
        fam.variants.push_back(d);
      }
    }

    out.push_back(std::move(fam));
  }

  return out;
}

std::vector<TlshDigest> make_tlsh_family_corpus(
  uint64_t seed,
  size_t families,
  size_t variants_per_family,
  size_t min_len,
  size_t max_len)
{
  std::vector<TlshDigest> out;
  out.reserve(families * (variants_per_family + 1));

  for (const auto& fam: make_tlsh_families(seed, families, variants_per_family, min_len, max_len)) {
    out.push_back(fam.base);
    out.insert(out.end(), fam.variants.begin(), fam.variants.end());
  }

  return out;
}

std::vector<TlshDigest> perturb_tlsh_corpus(
  uint64_t seed,
  const std::vector<TlshDigest>& seeds,
  size_t target_size,
  double bucket_flip_prob)
{
  std::vector<TlshDigest> out;
  if (seeds.empty()) {
    return out;
  }
  out.reserve(target_size);

  Rng rng(seed);
  for (size_t i = 0; i < target_size; ++i) {
    out.push_back(perturb(rng, seeds[rng.below(seeds.size())], bucket_flip_prob));
  }

  return out;
}

std::vector<TlshDigest> make_tlsh_corpus(uint64_t seed, size_t n) {
  constexpr size_t VARIANTS_PER_FAMILY = 9; // families of 10
  constexpr size_t MAX_HASHED = 20000;

  const size_t hashed = std::min(n, MAX_HASHED);
  const size_t families = (hashed + VARIANTS_PER_FAMILY) / (VARIANTS_PER_FAMILY + 1);

  std::vector<TlshDigest> corpus = make_tlsh_family_corpus(seed, families, VARIANTS_PER_FAMILY);

  if (corpus.size() > n) {
    corpus.resize(n);
  }
  else if (corpus.size() < n) {
    const std::vector<TlshDigest> extra = perturb_tlsh_corpus(
      seed ^ 0x9E3779B97F4A7C15ull, corpus, n - corpus.size()
    );
    corpus.insert(corpus.end(), extra.begin(), extra.end());
  }

  return corpus;
}
