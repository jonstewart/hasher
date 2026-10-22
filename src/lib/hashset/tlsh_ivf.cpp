#include "hashset/tlsh_ivf.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <numeric>
#include <queue>
#include <random>

#include "rwutil.h"
#include "throw.h"

namespace {

constexpr size_t D = TLSH_EMBED_DIMS;

// k-means over the embeddings of rows [beg, end) (all sharing one L value),
// appending lists to ivf. Row indexes written to ids are offset by base.
void cluster_group(
  const TlshDigest* beg,
  const TlshDigest* end,
  uint64_t base,
  size_t target_list_size,
  std::mt19937_64& rng,
  TlshIvf& ivf)
{
  const size_t m = end - beg;
  const size_t k = std::max<size_t>(1, (m + target_list_size - 1) / target_list_size);

  // embeddings of (a sample of) the group
  const size_t sample_cap = std::max<size_t>(k * 64, 4096);
  std::vector<uint32_t> sample(m);
  std::iota(sample.begin(), sample.end(), 0u);
  if (m > sample_cap) {
    std::shuffle(sample.begin(), sample.end(), rng);
    sample.resize(sample_cap);
    std::sort(sample.begin(), sample.end());
  }

  std::vector<float> emb(sample.size() * D);
  for (size_t i = 0; i < sample.size(); ++i) {
    tlsh_embed(beg[sample[i]], &emb[i * D]);
  }

  std::vector<float> cent(k * D, 0.f);

  if (k == 1) {
    for (size_t i = 0; i < sample.size(); ++i) {
      for (size_t j = 0; j < D; ++j) {
        cent[j] += emb[i * D + j];
      }
    }
    for (size_t j = 0; j < D; ++j) {
      cent[j] /= sample.size();
    }
  }
  else {
    // k-means++ seeding on the sample
    std::vector<float> best(sample.size(), std::numeric_limits<float>::max());
    std::uniform_int_distribution<size_t> pick(0, sample.size() - 1);
    size_t first = pick(rng);
    std::copy_n(&emb[first * D], D, &cent[0]);

    for (size_t c = 1; c < k; ++c) {
      double total = 0;
      for (size_t i = 0; i < sample.size(); ++i) {
        const float d2 = tlsh_embed_dist2(&emb[i * D], &cent[(c - 1) * D]);
        best[i] = std::min(best[i], d2);
        total += best[i];
      }
      size_t chosen = pick(rng);
      if (total > 0) {
        std::uniform_real_distribution<double> u(0, total);
        double r = u(rng);
        for (size_t i = 0; i < sample.size(); ++i) {
          r -= best[i];
          if (r <= 0) {
            chosen = i;
            break;
          }
        }
      }
      std::copy_n(&emb[chosen * D], D, &cent[c * D]);
    }

    // Lloyd iterations
    std::vector<uint32_t> assign(sample.size(), 0);
    std::vector<float> sum(k * D);
    std::vector<uint32_t> cnt(k);
    for (int iter = 0; iter < 10; ++iter) {
      bool changed = false;
      for (size_t i = 0; i < sample.size(); ++i) {
        float bd = std::numeric_limits<float>::max();
        uint32_t bc = 0;
        for (size_t c = 0; c < k; ++c) {
          const float d2 = tlsh_embed_dist2(&emb[i * D], &cent[c * D]);
          if (d2 < bd) {
            bd = d2;
            bc = c;
          }
        }
        if (assign[i] != bc) {
          assign[i] = bc;
          changed = true;
        }
      }
      if (!changed && iter > 0) {
        break;
      }
      std::fill(sum.begin(), sum.end(), 0.f);
      std::fill(cnt.begin(), cnt.end(), 0u);
      for (size_t i = 0; i < sample.size(); ++i) {
        ++cnt[assign[i]];
        for (size_t j = 0; j < D; ++j) {
          sum[assign[i] * D + j] += emb[i * D + j];
        }
      }
      for (size_t c = 0; c < k; ++c) {
        if (cnt[c]) {
          for (size_t j = 0; j < D; ++j) {
            cent[c * D + j] = sum[c * D + j] / cnt[c];
          }
        }
      }
    }
  }

  // final assignment of every row, radius per list
  std::vector<uint32_t> assign(m);
  std::vector<float> rad(k, 0.f);
  std::vector<uint32_t> cnt(k, 0);
  for (size_t i = 0; i < m; ++i) {
    float bd = std::numeric_limits<float>::max();
    uint32_t bc = 0;
    for (size_t c = 0; c < k; ++c) {
      const float d2 = tlsh_embed_dist2_to_point(beg[i], &cent[c * D]);
      if (d2 < bd) {
        bd = d2;
        bc = c;
      }
    }
    assign[i] = bc;
    ++cnt[bc];
    rad[bc] = std::max(rad[bc], bd);
  }

  // emit nonempty lists; ids ascending within a list
  std::vector<uint64_t> start(k + 1, 0);
  for (size_t c = 0; c < k; ++c) {
    start[c + 1] = start[c] + cnt[c];
  }
  const size_t id_base = ivf.ids.size();
  ivf.ids.resize(id_base + m);
  std::vector<uint64_t> fill(start.begin(), start.end() - 1);
  for (size_t i = 0; i < m; ++i) {
    ivf.ids[id_base + fill[assign[i]]++] = static_cast<uint32_t>(base + i);
  }

  for (size_t c = 0; c < k; ++c) {
    if (!cnt[c]) {
      continue;
    }
    ivf.centroids.insert(ivf.centroids.end(), &cent[c * D], &cent[(c + 1) * D]);
    // store the Euclidean radius, padded slightly for float rounding
    ivf.radius.push_back(std::sqrt(rad[c]) * (1.f + 1e-5f) + 1e-4f);
    ivf.list_start.push_back(id_base + start[c + 1]);
  }
  // compact: lists with cnt == 0 were skipped, but their id range is empty,
  // so list_start remains consistent (the previous list's end equals the
  // skipped list's start).
}

} // namespace

TlshIvf build_tlsh_ivf(
  const TlshDigest* beg,
  const TlshDigest* end,
  size_t target_list_size,
  uint64_t seed)
{
  THROW_IF(target_list_size == 0, "target_list_size must be positive");
  const uint64_t n = end - beg;
  THROW_IF(n > std::numeric_limits<uint32_t>::max(), "too many rows for a TIVF index");

  TlshIvf ivf;
  ivf.n = n;
  ivf.list_start.push_back(0);
  ivf.ids.reserve(n);

  std::mt19937_64 rng(seed);

  const TlshDigest* g = beg;
  while (g != end) {
    const TlshDigest* ge = g;
    while (ge != end && ge->L == g->L) {
      ++ge;
    }
    cluster_group(g, ge, g - beg, target_list_size, rng, ivf);
    g = ge;
  }

  return ivf;
}

TlshIvfView make_tlsh_ivf_view(const TlshIvf& ivf) {
  TlshIvfView v;
  v.dims = ivf.dims;
  v.lists = static_cast<uint32_t>(ivf.lists());
  v.n = ivf.n;
  v.centroids = ivf.centroids.data();
  v.radius = ivf.radius.data();
  v.list_start = ivf.list_start.data();
  v.ids = ivf.ids.data();
  return v;
}

constexpr size_t TIVF_HEADER = 32;

size_t length_tivf_data(uint32_t lists, uint64_t n) {
  return TIVF_HEADER +
         static_cast<size_t>(lists) * D * sizeof(float) +
         static_cast<size_t>(lists) * sizeof(float) +
         (static_cast<size_t>(lists) + 1) * sizeof(uint64_t) +
         n * sizeof(uint32_t);
}

size_t write_tivf_data(const TlshIvf& ivf, char* out) {
  const char* beg = out;
  out += write_le<uint16_t>(1, out);                                  // version
  out += write_le<uint16_t>(0, out);                                  // flags
  out += write_le<uint32_t>(ivf.dims, out);
  out += write_le<uint32_t>(static_cast<uint32_t>(ivf.lists()), out);
  out += write_le<uint32_t>(0, out);                                  // reserved
  out += write_le<uint64_t>(ivf.n, out);
  out += write_le<uint64_t>(0, out);                                  // reserved
  out += write_bytes(ivf.centroids.data(), ivf.centroids.size() * sizeof(float), out);
  out += write_bytes(ivf.radius.data(), ivf.radius.size() * sizeof(float), out);
  out += write_bytes(ivf.list_start.data(), ivf.list_start.size() * sizeof(uint64_t), out);
  out += write_bytes(ivf.ids.data(), ivf.ids.size() * sizeof(uint32_t), out);
  return out - beg;
}

TlshIvfView parse_tivf_data(const uint8_t* beg, const uint8_t* end) {
  const uint8_t* cur = beg;
  const uint16_t version = read_le<uint16_t>(beg, cur, end);
  THROW_IF(version != 1, "unsupported TIVF version " << version);
  read_le<uint16_t>(beg, cur, end); // flags
  TlshIvfView v;
  v.dims = read_le<uint32_t>(beg, cur, end);
  THROW_IF(v.dims != D, "unsupported TIVF dims " << v.dims);
  v.lists = read_le<uint32_t>(beg, cur, end);
  read_le<uint32_t>(beg, cur, end); // reserved
  v.n = read_le<uint64_t>(beg, cur, end);
  read_le<uint64_t>(beg, cur, end); // reserved
  THROW_IF(
    static_cast<size_t>(end - beg) != length_tivf_data(v.lists, v.n),
    "TIVF payload has wrong length"
  );
  v.centroids = reinterpret_cast<const float*>(cur);
  cur += static_cast<size_t>(v.lists) * D * sizeof(float);
  v.radius = reinterpret_cast<const float*>(cur);
  cur += static_cast<size_t>(v.lists) * sizeof(float);
  v.list_start = reinterpret_cast<const uint64_t*>(cur);
  cur += (static_cast<size_t>(v.lists) + 1) * sizeof(uint64_t);
  v.ids = reinterpret_cast<const uint32_t*>(cur);
  return v;
}

namespace {

struct Cand {
  float bound;
  uint32_t list;
  bool operator<(const Cand& o) const { return bound > o.bound; } // min-heap
};

struct Hit {
  uint32_t distance;
  uint64_t index;
  bool operator<(const Hit& o) const {
    return distance != o.distance ? distance < o.distance : index < o.index;
  }
};

} // namespace

std::vector<SFHASH_TlshMatch> tlsh_knn_ivf(
  const TlshIvfView& ivf,
  const TlshDigest* rows,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length)
{
  std::vector<SFHASH_TlshMatch> out;
  if (k == 0 || ivf.empty() || q.is_null()) {
    return out;
  }

  if (include_length) {
    max_distance = std::min(max_distance, TLSH_EMBED_MAX_BOUNDED_DIFF);
  }

  float qv[D];
  tlsh_embed(q, qv);

  // lower bound per list
  std::vector<Cand> cands;
  cands.reserve(ivf.lists);
  const float tau0 = static_cast<float>(max_distance);
  for (uint32_t c = 0; c < ivf.lists; ++c) {
    const float dc = std::sqrt(tlsh_embed_dist2(qv, &ivf.centroids[static_cast<size_t>(c) * D], include_length));
    const float b = std::max(0.f, dc - ivf.radius[c]);
    const float b2 = b * b;
    if (b2 <= tau0) {
      cands.push_back({ b2, c });
    }
  }
  std::make_heap(cands.begin(), cands.end());

  // bounded max-heap of the best (distance, index) hits; tau is the largest
  // distance that can still be useful (inclusive)
  std::priority_queue<Hit> best;
  uint32_t tau = max_distance;

  while (!cands.empty()) {
    std::pop_heap(cands.begin(), cands.end());
    const Cand c = cands.back();
    cands.pop_back();
    if (c.bound > static_cast<float>(tau)) {
      break;
    }
    const uint64_t lb = ivf.list_start[c.list], le = ivf.list_start[c.list + 1];
    for (uint64_t i = lb; i < le; ++i) {
      const uint32_t id = ivf.ids[i];
      const TlshDigest& r = rows[id];
      const uint32_t hd = tlsh_header_diff(q, r, include_length);
      if (hd > tau) {
        continue;
      }
      const uint32_t d = hd + tlsh_body_diff(q, r);
      if (d > tau) {
        continue;
      }
      const Hit h{ d, id };
      if (best.size() < k) {
        best.push(h);
      }
      else if (h < best.top()) {
        best.pop();
        best.push(h);
      }
      else {
        continue;
      }
      if (best.size() == k) {
        tau = best.top().distance;
      }
    }
  }

  out.resize(best.size());
  for (size_t i = out.size(); i-- > 0;) {
    out[i] = { best.top().index, best.top().distance };
    best.pop();
  }
  return out;
}
