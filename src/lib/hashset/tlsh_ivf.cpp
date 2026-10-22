#include "hashset/tlsh_ivf.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <numeric>
#include <queue>
#include <random>
#include <atomic>
#include <thread>

#include "rwutil.h"
#include "throw.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_header_order.h"

namespace {

constexpr size_t BD = TLSH_EMBED_BODY_DIMS;

inline float dist2(const float* a, const float* b) {
  float s = 0.f;
  for (size_t j = 0; j < BD; ++j) {
    const float d = a[j] - b[j];
    s += d * d;
  }
  return s;
}

// the lists of one cell
struct CellLists {
  std::vector<TlshDigest> medoids;
  std::vector<uint32_t> radius2;
  std::vector<uint32_t> sizes;
  std::vector<uint32_t> ids; // concatenated, ascending within a list
};

// k-means over the body embeddings of one cell's rows [beg, end). Row
// indexes written to ids are offset by base.
CellLists cluster_cell(
  const TlshDigest* beg,
  const TlshDigest* end,
  uint64_t base,
  size_t target_list_size,
  std::mt19937_64& rng)
{
  CellLists out;
  const size_t m = end - beg;
  const size_t k = std::max<size_t>(1, (m + target_list_size - 1) / target_list_size);

  // body embeddings of (a sample of) the cell
  const size_t sample_cap = std::max<size_t>(k * 32, 2048);
  std::vector<uint32_t> sample(m);
  std::iota(sample.begin(), sample.end(), 0u);
  if (m > sample_cap) {
    std::shuffle(sample.begin(), sample.end(), rng);
    sample.resize(sample_cap);
  }

  std::vector<float> emb(sample.size() * BD);
  for (size_t i = 0; i < sample.size(); ++i) {
    tlsh_embed_body(beg[sample[i]], &emb[i * BD]);
  }

  std::vector<float> cent(k * BD, 0.f);

  if (k == 1) {
    for (size_t i = 0; i < sample.size(); ++i) {
      for (size_t j = 0; j < BD; ++j) {
        cent[j] += emb[i * BD + j];
      }
    }
    for (size_t j = 0; j < BD; ++j) {
      cent[j] /= sample.size();
    }
  }
  else {
    // k-means++ seeding on the sample
    std::vector<float> best(sample.size(), std::numeric_limits<float>::max());
    std::uniform_int_distribution<size_t> pick(0, sample.size() - 1);
    std::copy_n(&emb[pick(rng) * BD], BD, &cent[0]);

    for (size_t c = 1; c < k; ++c) {
      double total = 0;
      for (size_t i = 0; i < sample.size(); ++i) {
        best[i] = std::min(best[i], dist2(&emb[i * BD], &cent[(c - 1) * BD]));
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
      std::copy_n(&emb[chosen * BD], BD, &cent[c * BD]);
    }

    // Lloyd iterations
    std::vector<uint32_t> assign(sample.size(), 0);
    std::vector<float> sum(k * BD);
    std::vector<uint32_t> cnt(k);
    for (int iter = 0; iter < 10; ++iter) {
      bool changed = false;
      for (size_t i = 0; i < sample.size(); ++i) {
        float bd = std::numeric_limits<float>::max();
        uint32_t bc = 0;
        for (size_t c = 0; c < k; ++c) {
          const float d2 = dist2(&emb[i * BD], &cent[c * BD]);
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
        for (size_t j = 0; j < BD; ++j) {
          sum[assign[i] * BD + j] += emb[i * BD + j];
        }
      }
      for (size_t c = 0; c < k; ++c) {
        if (cnt[c]) {
          for (size_t j = 0; j < BD; ++j) {
            cent[c * BD + j] = sum[c * BD + j] / cnt[c];
          }
        }
      }
    }
  }

  // final assignment of every row; the medoid of a list is its member
  // nearest the centroid
  std::vector<uint32_t> assign(m);
  std::vector<float> med_dist(k, std::numeric_limits<float>::max());
  std::vector<uint32_t> medoid(k, 0);
  std::vector<uint32_t> cnt(k, 0);
  for (size_t i = 0; i < m; ++i) {
    float bd = std::numeric_limits<float>::max();
    uint32_t bc = 0;
    for (size_t c = 0; c < k; ++c) {
      const float d2 = tlsh_embed_body_dist2_to_point(beg[i], &cent[c * BD]);
      if (d2 < bd) {
        bd = d2;
        bc = c;
      }
    }
    assign[i] = bc;
    ++cnt[bc];
    if (bd < med_dist[bc]) {
      med_dist[bc] = bd;
      medoid[bc] = static_cast<uint32_t>(i);
    }
  }

  // exact squared embedding radius about the medoid
  std::vector<uint32_t> rad2(k, 0);
  for (size_t i = 0; i < m; ++i) {
    const uint32_t c = assign[i];
    rad2[c] = std::max(rad2[c], tlsh_embed_body_dist2(beg[medoid[c]], beg[i]));
  }

  // emit nonempty lists; ids ascending within a list
  std::vector<uint64_t> start(k + 1, 0);
  for (size_t c = 0; c < k; ++c) {
    start[c + 1] = start[c] + cnt[c];
  }
  out.ids.resize(m);
  std::vector<uint64_t> fill(start.begin(), start.end() - 1);
  for (size_t i = 0; i < m; ++i) {
    out.ids[fill[assign[i]]++] = static_cast<uint32_t>(base + i);
  }

  for (size_t c = 0; c < k; ++c) {
    if (!cnt[c]) {
      continue;
    }
    out.medoids.push_back(beg[medoid[c]]);
    out.radius2.push_back(rad2[c]);
    out.sizes.push_back(cnt[c]);
  }
  return out;
}

} // namespace

TlshIvf build_tlsh_ivf(
  const TlshDigest* beg,
  const TlshDigest* end,
  size_t target_list_size,
  uint64_t seed,
  unsigned threads)
{
  THROW_IF(target_list_size == 0, "target_list_size must be positive");
  const uint64_t n = end - beg;
  THROW_IF(n > std::numeric_limits<uint32_t>::max(), "too many rows for a TIVF index");

  // cell boundaries
  const std::vector<uint64_t> cells = make_tlsh_cell_index(beg, end);

  // nonempty cells, clustered independently (and in parallel)
  std::vector<uint32_t> nonempty;
  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    if (cells[c] != cells[c + 1]) {
      nonempty.push_back(c);
    }
  }

  std::vector<CellLists> results(nonempty.size());

  auto work = [&](size_t i) {
    const uint32_t c = nonempty[i];
    std::mt19937_64 rng(seed ^ (static_cast<uint64_t>(c) * 0x9E3779B97F4A7C15ull));
    results[i] = cluster_cell(beg + cells[c], beg + cells[c + 1], cells[c], target_list_size, rng);
  };

  if (threads == 0) {
    threads = std::max(1u, std::thread::hardware_concurrency());
  }
  threads = static_cast<unsigned>(std::min<size_t>(threads, std::max<size_t>(1, nonempty.size())));

  if (threads <= 1) {
    for (size_t i = 0; i < nonempty.size(); ++i) {
      work(i);
    }
  }
  else {
    std::atomic<size_t> next{0};
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; ++t) {
      pool.emplace_back([&]() {
        for (size_t i = next++; i < nonempty.size(); i = next++) {
          work(i);
        }
      });
    }
    for (auto& t: pool) {
      t.join();
    }
  }

  // concatenate in cell order
  TlshIvf ivf;
  ivf.n = n;
  ivf.cell_lists.assign(TLSH_CELL_COUNT + 1, 0);
  ivf.list_start.push_back(0);
  ivf.ids.reserve(n);

  size_t ri = 0;
  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    ivf.cell_lists[c] = static_cast<uint32_t>(ivf.lists());
    if (ri < nonempty.size() && nonempty[ri] == c) {
      const CellLists& r = results[ri++];
      ivf.medoids.insert(ivf.medoids.end(), r.medoids.begin(), r.medoids.end());
      ivf.radius2.insert(ivf.radius2.end(), r.radius2.begin(), r.radius2.end());
      for (const uint32_t sz: r.sizes) {
        ivf.list_start.push_back(ivf.list_start.back() + sz);
      }
      ivf.ids.insert(ivf.ids.end(), r.ids.begin(), r.ids.end());
    }
  }
  ivf.cell_lists[TLSH_CELL_COUNT] = static_cast<uint32_t>(ivf.lists());

  return ivf;
}

TlshIvfView make_tlsh_ivf_view(const TlshIvf& ivf) {
  TlshIvfView v;
  v.lists = static_cast<uint32_t>(ivf.lists());
  v.n = ivf.n;
  v.cell_lists = ivf.cell_lists.data();
  v.medoids = ivf.medoids.data();
  v.radius2 = ivf.radius2.data();
  v.list_start = ivf.list_start.data();
  v.ids = ivf.ids.data();
  return v;
}

namespace {

constexpr size_t TIVF_HEADER = 32;
constexpr uint16_t TIVF_VERSION = 3;

} // namespace

TlshIvf merge_tlsh_ivf(
  const TlshIvfView& a,
  const uint32_t* a_map,
  const TlshIvfView& b,
  const uint32_t* b_map,
  uint64_t n_out)
{
  THROW_IF(n_out > std::numeric_limits<uint32_t>::max(), "too many rows for a TIVF index");
  THROW_IF(!a.empty() && !a_map, "missing row map for the left index");
  THROW_IF(!b.empty() && !b_map, "missing row map for the right index");

  TlshIvf out;
  out.n = n_out;
  out.cell_lists.assign(TLSH_CELL_COUNT + 1, 0);
  out.list_start.push_back(0);
  out.ids.reserve(n_out);

  // appends the lists of cell c of one input, remapped
  const auto append_cell = [&out](const TlshIvfView& v, const uint32_t* map, uint32_t c) {
    if (v.empty()) {
      return;
    }
    for (uint32_t l = v.cell_lists[c]; l < v.cell_lists[c + 1]; ++l) {
      const size_t before = out.ids.size();
      uint32_t prev = 0;
      for (uint64_t i = v.list_start[l]; i < v.list_start[l + 1]; ++i) {
        const uint32_t id = map[v.ids[i]];
        if (id == TLSH_IVF_DROPPED) {
          continue;
        }
        THROW_IF(
          out.ids.size() > before && id <= prev,
          "row map is not increasing within a TIVF list"
        );
        out.ids.push_back(id);
        prev = id;
      }
      if (out.ids.size() == before) {
        continue; // every member was dropped
      }
      out.medoids.push_back(v.medoids[l]);
      out.radius2.push_back(v.radius2[l]);
      out.list_start.push_back(out.ids.size());
    }
  };

  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    out.cell_lists[c] = static_cast<uint32_t>(out.lists());
    append_cell(a, a_map, c);
    append_cell(b, b_map, c);
  }
  out.cell_lists[TLSH_CELL_COUNT] = static_cast<uint32_t>(out.lists());

  THROW_IF(
    out.ids.size() != n_out,
    "merged TIVF index has " << out.ids.size() << " ids, expected " << n_out
  );

  return out;
}

size_t length_tivf_data(uint32_t lists, uint64_t n) {
  return TIVF_HEADER +
         (TLSH_CELL_COUNT + 1) * sizeof(uint32_t) +
         static_cast<size_t>(lists) * sizeof(TlshDigest) +
         static_cast<size_t>(lists) * sizeof(uint32_t) +
         (static_cast<size_t>(lists) + 1) * sizeof(uint64_t) +
         n * sizeof(uint32_t);
}

size_t write_tivf_data(const TlshIvf& ivf, char* out) {
  const char* beg = out;
  out += write_le<uint16_t>(TIVF_VERSION, out);
  out += write_le<uint16_t>(0, out);                                  // flags
  out += write_le<uint32_t>(BD, out);                                 // dims
  out += write_le<uint32_t>(static_cast<uint32_t>(ivf.lists()), out);
  out += write_le<uint32_t>(0, out);                                  // reserved
  out += write_le<uint64_t>(ivf.n, out);
  out += write_le<uint64_t>(0, out);                                  // reserved
  out += write_bytes(ivf.cell_lists.data(), ivf.cell_lists.size() * sizeof(uint32_t), out);
  out += write_bytes(ivf.medoids.data(), ivf.medoids.size() * sizeof(TlshDigest), out);
  out += write_bytes(ivf.radius2.data(), ivf.radius2.size() * sizeof(uint32_t), out);
  out += write_bytes(ivf.list_start.data(), ivf.list_start.size() * sizeof(uint64_t), out);
  out += write_bytes(ivf.ids.data(), ivf.ids.size() * sizeof(uint32_t), out);
  return out - beg;
}

TlshIvfView parse_tivf_data(const uint8_t* beg, const uint8_t* end) {
  const uint8_t* cur = beg;
  const uint16_t version = read_le<uint16_t>(beg, cur, end);
  THROW_IF(version != TIVF_VERSION, "unsupported TIVF version " << version);
  read_le<uint16_t>(beg, cur, end); // flags
  const uint32_t dims = read_le<uint32_t>(beg, cur, end);
  THROW_IF(dims != BD, "unsupported TIVF dims " << dims);
  TlshIvfView v;
  v.lists = read_le<uint32_t>(beg, cur, end);
  read_le<uint32_t>(beg, cur, end); // reserved
  v.n = read_le<uint64_t>(beg, cur, end);
  read_le<uint64_t>(beg, cur, end); // reserved
  THROW_IF(
    static_cast<size_t>(end - beg) != length_tivf_data(v.lists, v.n),
    "TIVF payload has wrong length"
  );
  v.cell_lists = reinterpret_cast<const uint32_t*>(cur);
  cur += (TLSH_CELL_COUNT + 1) * sizeof(uint32_t);
  v.medoids = reinterpret_cast<const TlshDigest*>(cur);
  cur += static_cast<size_t>(v.lists) * sizeof(TlshDigest);
  v.radius2 = reinterpret_cast<const uint32_t*>(cur);
  cur += static_cast<size_t>(v.lists) * sizeof(uint32_t);
  v.list_start = reinterpret_cast<const uint64_t*>(cur);
  cur += (static_cast<size_t>(v.lists) + 1) * sizeof(uint64_t);
  v.ids = reinterpret_cast<const uint32_t*>(cur);
  THROW_IF(v.cell_lists[0] != 0 || v.cell_lists[TLSH_CELL_COUNT] != v.lists, "bad TIVF cell_lists");
  THROW_IF(v.list_start[0] != 0 || v.list_start[v.lists] != v.n, "bad TIVF list_start");
  return v;
}

namespace {

struct Hit {
  uint32_t distance;
  uint64_t index;
  bool operator<(const Hit& o) const {
    return distance != o.distance ? distance < o.distance : index < o.index;
  }
};

// lists shorter than this are scanned without evaluating their bound
constexpr uint64_t MIN_BOUNDED_LIST = 4;

// Lower bound on the squared body-embedding distance from q to any member of
// a list, given the squared distance d2 to the medoid and the list's squared
// radius r2 (triangle inequality in embedding space). Slightly relaxed so
// float rounding can never prune a valid row.
inline float list_bound(uint32_t d2, uint32_t r2) {
  const float b = std::sqrt(static_cast<float>(d2)) - std::sqrt(static_cast<float>(r2));
  return b > 0.f ? std::max(0.f, b * b - 1e-2f) : 0.f;
}

} // namespace

std::vector<SFHASH_TlshMatch> tlsh_knn_ivf(
  const TlshIvfView& ivf,
  const TlshDigest* rows,
  const TlshDigest& q,
  size_t k,
  uint32_t max_distance,
  bool include_length,
  TlshKnnStats* stats)
{
  std::vector<SFHASH_TlshMatch> out;
  if (k == 0 || ivf.empty() || !rows || q.is_null()) {
    return out;
  }

  const TlshHeaderOrder order(q, include_length);
  const TlshBodyQuery qb(q);

  std::priority_queue<Hit> best;
  uint32_t tau = max_distance; // inclusive bound on useful distances

  std::vector<std::pair<float, uint32_t>> lists; // (body bound, list)

  auto consider = [&](uint32_t d, uint32_t id) {
    const Hit h{ d, id };
    if (best.size() < k) {
      best.push(h);
    }
    else if (h < best.top()) {
      best.pop();
      best.push(h);
    }
    else {
      return;
    }
    if (best.size() == k) {
      tau = best.top().distance;
    }
  };

  // rows [first, first + count) of the hash set, contiguous
  auto scan_rows = [&](uint32_t first, uint64_t count, uint32_t ch) {
    if (stats) {
      stats->rows += count;
    }
    const TlshDigest* r = rows + first;
    const TlshDigest* re = r + count;
    for (; r != re; ++r) {
      const uint32_t d = ch + (r->checksum != q.checksum) + qb.body(*r);
      if (d <= tau) {
        consider(d, static_cast<uint32_t>(r - rows));
      }
    }
  };

  // the rows of list entries [lb, le)
  auto scan_list = [&](uint64_t lb, uint64_t le, uint32_t ch) {
    if (stats) {
      stats->rows += le - lb;
    }
    constexpr uint64_t PF = 8; // rows ahead to prefetch
    for (uint64_t i = lb; i < le; ++i) {
      if (i + PF < le) {
        __builtin_prefetch(rows + ivf.ids[i + PF]);
      }
      const uint32_t id = ivf.ids[i];
      const TlshDigest& r = rows[id];
      const uint32_t d = ch + (r.checksum != q.checksum) + qb.body(r);
      if (d <= tau) {
        consider(d, id);
      }
    }
  };

  for (size_t li = 0; li < 256; ++li) {
    const uint32_t cl = order.l_cost[li];
    if (cl > tau) {
      break;
    }
    for (size_t qi = 0; qi < 256; ++qi) {
      const uint32_t ch = cl + order.q_cost[qi];
      if (ch > tau) {
        break;
      }
      const uint32_t c = (static_cast<uint32_t>(order.l[li]) << 8) | order.q[qi];
      const uint32_t fl = ivf.cell_lists[c], el = ivf.cell_lists[c + 1];
      if (fl == el) {
        continue;
      }
      if (stats) {
        ++stats->cells;
      }

      if (el - fl == 1) {
        // a single list holds the whole cell: its ids are the cell's
        // contiguous row range in ascending order
        const uint64_t lb = ivf.list_start[fl], le = ivf.list_start[el];
        const uint64_t count = le - lb;
        if (count < MIN_BOUNDED_LIST ||
            ch + list_bound(qb.emb_body(ivf.medoids[fl]), ivf.radius2[fl]) <= static_cast<float>(tau)) {
          if (stats && count >= MIN_BOUNDED_LIST) {
            ++stats->lists;
          }
          scan_rows(ivf.ids[lb], count, ch);
        }
        else if (stats) {
          ++stats->lists;
        }
        continue;
      }

      // body lower bound per list, through centroid and radius
      lists.clear();
      if (stats) {
        stats->lists += el - fl;
      }
      for (uint32_t l = fl; l < el; ++l) {
        const float b2 = list_bound(qb.emb_body(ivf.medoids[l]), ivf.radius2[l]);
        if (ch + b2 <= static_cast<float>(tau)) {
          lists.emplace_back(b2, l);
        }
      }
      if (lists.size() > 1) {
        std::sort(lists.begin(), lists.end());
      }
      for (const auto& [b2, l]: lists) {
        if (ch + b2 > static_cast<float>(tau)) {
          break;
        }
        scan_list(ivf.list_start[l], ivf.list_start[l + 1], ch);
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
