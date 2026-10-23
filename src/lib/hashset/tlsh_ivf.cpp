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
#include <functional>
#include <iterator>
#include <thread>
#include <tuple>

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

// a list of one cell while it is merged
struct MergeList {
  TlshDigest medoid;
  uint32_t radius2;
  std::vector<uint32_t> ids; // output rows, ascending
};

/*
 * Coalesces the lists of one cell in place (see merge_tlsh_ivf): while two
 * lists have fewer than half members each, the pair whose union has the
 * smallest exact radius about one of the two medoids becomes one list.
 * Pairs are ranked through a heap with lazy invalidation, so a cell with s
 * small lists costs O(s^2 log s) plus s * (rows in small lists) kernel
 * evaluations. Emptied lists are removed; the order of the rest is kept.
 */
void coalesce_cell(std::vector<MergeList>& lists, const TlshDigest* rows, uint32_t half) {
  std::vector<size_t> small; // indexes into lists
  for (size_t i = 0; i < lists.size(); ++i) {
    if (lists[i].ids.size() < half) {
      small.push_back(i);
    }
  }
  const size_t s = small.size();
  if (s < 2) {
    return;
  }

  // dist[i * s + j]: max squared distance from the medoid of small list i
  // over the members of small list j; exact, including the diagonal
  std::vector<uint32_t> dist(s * s);
  for (size_t i = 0; i < s; ++i) {
    const TlshBodyQuery q(lists[small[i]].medoid);
    for (size_t j = 0; j < s; ++j) {
      uint32_t r = 0;
      for (const uint32_t id: lists[small[j]].ids) {
        r = std::max(r, q.emb_body(rows[id]));
      }
      dist[i * s + j] = r;
    }
  }

  // candidate pair: (radius of the union, i, j, versions of i and j when
  // pushed); the smallest radius first, ties by (i, j)
  struct Cand {
    uint32_t radius2;
    uint32_t i, j;
    uint32_t vi, vj;
    bool operator>(const Cand& o) const {
      return std::tie(radius2, i, j) > std::tie(o.radius2, o.i, o.j);
    }
  };
  std::priority_queue<Cand, std::vector<Cand>, std::greater<Cand>> heap;

  std::vector<uint32_t> version(s, 0);
  std::vector<bool> alive(s, true); // still a small list
  size_t alive_count = s;

  // radius of the union of i and j about the medoid of i
  const auto about = [&](size_t i, size_t j) {
    return std::max(dist[i * s + i], dist[i * s + j]);
  };
  const auto push = [&](size_t i, size_t j) {
    heap.push({
      std::min(about(i, j), about(j, i)),
      static_cast<uint32_t>(i), static_cast<uint32_t>(j),
      version[i], version[j]
    });
  };

  for (size_t i = 0; i < s; ++i) {
    for (size_t j = i + 1; j < s; ++j) {
      push(i, j);
    }
  }

  while (alive_count >= 2 && !heap.empty()) {
    const Cand c = heap.top();
    heap.pop();
    if (!alive[c.i] || !alive[c.j] || version[c.i] != c.vi || version[c.j] != c.vj) {
      continue; // stale
    }
    const size_t i = c.i, j = c.j;
    MergeList& a = lists[small[i]];
    MergeList& b = lists[small[j]];

    // the medoid giving the smaller radius; a's on ties
    const bool keep_a = about(i, j) <= about(j, i);

    std::vector<uint32_t> u;
    u.reserve(a.ids.size() + b.ids.size());
    std::merge(a.ids.begin(), a.ids.end(), b.ids.begin(), b.ids.end(), std::back_inserter(u));
    a.ids = std::move(u);
    if (!keep_a) {
      a.medoid = b.medoid;
    }
    a.radius2 = c.radius2;
    b.ids.clear();
    b.ids.shrink_to_fit();

    // distances from the merged list's medoid, and to its members
    for (size_t k = 0; k < s; ++k) {
      if (!keep_a) {
        dist[i * s + k] = dist[j * s + k];
      }
      dist[k * s + i] = std::max(dist[k * s + i], dist[k * s + j]);
    }
    dist[i * s + i] = c.radius2;

    alive[j] = false;
    --alive_count;
    ++version[i];
    if (a.ids.size() >= half) {
      alive[i] = false;
      --alive_count;
    }
    else {
      for (size_t k = 0; k < s; ++k) {
        if (k != i && alive[k]) {
          push(std::min(i, k), std::max(i, k));
        }
      }
    }
  }

  lists.erase(
    std::remove_if(lists.begin(), lists.end(), [](const MergeList& l) { return l.ids.empty(); }),
    lists.end()
  );
}

// a pivot split leaving fewer than 1 / BISECT_MIN_SIDE_DIVISOR of a node's
// rows on one side is replaced by a median split; this bounds the depth by
// log_{8/7} m and guarantees termination. A quality knob only.
constexpr size_t BISECT_MIN_SIDE_DIVISOR = 8;

/*
 * The partition of one cell's rows for bisect_cell: recursive two-way
 * splits while a node has more than flat_max rows, then a flat clustering
 * of each node into ceil(s / T) lists. perm holds the cell's local row
 * indexes; a node is a range [lo, hi) of perm, rearranged in place, so the
 * lists are contiguous ranges of perm in depth-first order, the lists of
 * one flat node together. Integer kernel only.
 */
class CellBisector {
public:
  CellBisector(const TlshDigest* rows, size_t m, size_t target_list_size, size_t flat_max, std::mt19937_64& rng):
    rows_(rows), perm_(m), target_(target_list_size), flat_max_(flat_max), rng_(rng)
  {
    std::iota(perm_.begin(), perm_.end(), 0u);
  }

  // [lo, hi) ranges of perm, in depth-first order
  std::vector<std::pair<size_t, size_t>> leaves() {
    std::vector<std::pair<size_t, size_t>> out;
    split(0, perm_.size(), out);
    return out;
  }

  const std::vector<uint32_t>& perm() const { return perm_; }

private:
  void split(size_t lo, size_t hi, std::vector<std::pair<size_t, size_t>>& out) {
    if (hi - lo <= flat_max_) {
      cluster(lo, hi, out);
      return;
    }
    const size_t mid = partition(lo, hi);
    split(lo, mid, out);
    split(mid, hi, out);
  }

  /*
   * The flat clustering of node [lo, hi) into at most k = ceil(s / T)
   * lists by integer k-medoids: k-medoids++ seeding, then every member is
   * assigned to its nearest medoid (ties to the smaller medoid index). The
   * node's range of perm is rearranged so each nonempty list is a
   * contiguous range, in medoid order; empty lists are dropped.
   */
  void cluster(size_t lo, size_t hi, std::vector<std::pair<size_t, size_t>>& out) {
    const size_t s = hi - lo;
    const size_t k = (s + target_ - 1) / target_;
    if (k <= 1) {
      out.emplace_back(lo, hi);
      return;
    }
    node_.assign(perm_.begin() + lo, perm_.begin() + hi);
    seed_medoids(k);
    assign_nearest();

    // stable counting sort of the node by list
    std::vector<size_t> start(med_.size() + 1, 0);
    for (const uint32_t l: of_) {
      ++start[l + 1];
    }
    std::partial_sum(start.begin(), start.end(), start.begin());
    for (size_t l = 0; l < med_.size(); ++l) {
      if (start[l] != start[l + 1]) {
        out.emplace_back(lo + start[l], lo + start[l + 1]);
      }
    }
    for (size_t i = 0; i < s; ++i) {
      perm_[lo + start[of_[i]]++] = node_[i];
    }
  }

  /*
   * k-medoids++ over node_: the first medoid is a random member, each next
   * one a member drawn with probability proportional to its squared
   * distance to the nearest medoid so far (best_). When every member
   * coincides with a medoid's body there are fewer than k distinct bodies
   * and seeding stops early. med_ holds positions in node_; O(s k) kernel
   * calls.
   */
  void seed_medoids(size_t k) {
    const size_t s = node_.size();
    med_.assign(1, static_cast<uint32_t>(draw(s)));
    best_.resize(s);
    {
      const TlshBodyQuery q(rows_[node_[med_[0]]]);
      for (size_t i = 0; i < s; ++i) {
        best_[i] = q.emb_body(rows_[node_[i]]);
      }
    }
    while (med_.size() < k) {
      uint64_t sum = 0;
      for (const uint32_t b: best_) {
        sum += b;
      }
      if (sum == 0) {
        break;
      }
      // the first member at which the prefix sum of best_ exceeds r; a
      // member with best_ 0 (a medoid, among others) is never chosen
      uint64_t r = rng_() % sum;
      size_t next = 0;
      for (; r >= best_[next]; ++next) {
        r -= best_[next];
      }
      med_.push_back(static_cast<uint32_t>(next));
      const TlshBodyQuery q(rows_[node_[next]]);
      for (size_t i = 0; i < s; ++i) {
        best_[i] = std::min(best_[i], q.emb_body(rows_[node_[i]]));
      }
    }
  }

  // of_[i] = the index of the medoid nearest node_[i], ties to the smaller
  // index; returns whether any assignment changed
  bool assign_nearest() {
    std::vector<TlshBodyQuery> qs;
    qs.reserve(med_.size());
    for (const uint32_t m: med_) {
      qs.emplace_back(rows_[node_[m]]);
    }
    of_.resize(node_.size(), UINT32_MAX);
    bool changed = false;
    for (size_t i = 0; i < node_.size(); ++i) {
      const TlshDigest& r = rows_[node_[i]];
      uint32_t best = 0, best_d = qs[0].emb_body(r);
      for (uint32_t j = 1; j < qs.size(); ++j) {
        const uint32_t d = qs[j].emb_body(r);
        if (d < best_d) {
          best = j;
          best_d = d;
        }
      }
      changed |= of_[i] != best;
      of_[i] = best;
    }
    return changed;
  }

  // a uniform-ish draw in [0, n) straight from the engine: the standard
  // distributions are implementation-defined, mt19937_64 is not
  size_t draw(size_t n) { return rng_() % n; }

  // the member of [lo, hi) farthest from p, ties by the smaller local index
  uint32_t farthest(size_t lo, size_t hi, uint32_t p) const {
    const TlshBodyQuery q(rows_[p]);
    uint32_t best = p, best_d = 0;
    for (size_t i = lo; i < hi; ++i) {
      const uint32_t id = perm_[i];
      const uint32_t d = q.emb_body(rows_[id]);
      if (d > best_d || (d == best_d && id < best)) {
        best = id;
        best_d = d;
      }
    }
    return best;
  }

  // moves the members of [lo, hi) nearer a than b (ties to a) to the front,
  // stably; returns the end of a's side
  size_t assign(size_t lo, size_t hi, uint32_t a, uint32_t b) {
    const TlshBodyQuery qa(rows_[a]), qb(rows_[b]);
    const auto mid = std::stable_partition(
      perm_.begin() + lo, perm_.begin() + hi,
      [&](uint32_t id) { return qa.emb_body(rows_[id]) <= qb.emb_body(rows_[id]); }
    );
    return mid - perm_.begin();
  }

  // splits node [lo, hi) in two in place; returns the boundary
  size_t partition(size_t lo, size_t hi) {
    const uint32_t p0 = perm_[lo + draw(hi - lo)];
    const uint32_t a = farthest(lo, hi, p0);
    const uint32_t b = farthest(lo, hi, a);
    const size_t mid = assign(lo, hi, a, b);
    if (std::min(mid - lo, hi - mid) * BISECT_MIN_SIDE_DIVISOR < hi - lo) {
      return median_split(lo, hi, a);
    }
    return mid;
  }

  // sorts [lo, hi) by (distance to a, local index) and cuts it in half: the
  // fallback when the pivots split off too few rows (or none, when every
  // body in the node is the same), so every split makes progress
  size_t median_split(size_t lo, size_t hi, uint32_t a) {
    const TlshBodyQuery q(rows_[a]);
    std::vector<std::pair<uint32_t, uint32_t>> keyed;
    keyed.reserve(hi - lo);
    for (size_t i = lo; i < hi; ++i) {
      keyed.emplace_back(q.emb_body(rows_[perm_[i]]), perm_[i]);
    }
    std::sort(keyed.begin(), keyed.end());
    for (size_t i = lo; i < hi; ++i) {
      perm_[i] = keyed[i - lo].second;
    }
    return lo + (hi - lo) / 2;
  }

  const TlshDigest* rows_;
  std::vector<uint32_t> perm_;
  size_t target_, flat_max_;
  std::mt19937_64& rng_;
  // scratch for cluster(): the node's members, the medoids (positions in
  // node_), each member's squared distance to the nearest seed so far, and
  // each member's list
  std::vector<uint32_t> node_, med_, best_, of_;
};

/*
 * The exact 1-center of rows ids (local indexes into rows): the member
 * whose max squared distance to the others is smallest, ties by the smaller
 * index. Returns (medoid, radius2).
 */
std::pair<uint32_t, uint32_t> one_center(const TlshDigest* rows, const uint32_t* ids, size_t n) {
  uint32_t best = ids[0], best_r = UINT32_MAX;
  for (size_t i = 0; i < n; ++i) {
    const TlshBodyQuery q(rows[ids[i]]);
    uint32_t r = 0;
    for (size_t j = 0; j < n && r <= best_r; ++j) {
      r = std::max(r, q.emb_body(rows[ids[j]]));
    }
    if (r < best_r || (r == best_r && ids[i] < best)) {
      best = ids[i];
      best_r = r;
    }
  }
  return { best, best_r };
}

// gives list l (local ids into rows) its exact 1-center and radius
void center_list(MergeList& l, const TlshDigest* rows) {
  const auto [med, r2] = one_center(rows, l.ids.data(), l.ids.size());
  l.medoid = rows[med];
  l.radius2 = r2;
}

// Recursive bisection of one cell's rows [beg, end) (TlshIvfBuild::BISECT).
// Row indexes written to ids are offset by base.
CellLists bisect_cell(
  const TlshDigest* beg,
  const TlshDigest* end,
  uint64_t base,
  size_t target_list_size,
  std::mt19937_64& rng)
{
  const size_t m = end - beg;
  CellBisector bis(beg, m, target_list_size, TLSH_IVF_BISECT_FLAT_MAX, rng);
  const auto leaves = bis.leaves();

  // the leaves, with local ids
  std::vector<MergeList> lists;
  lists.reserve(leaves.size());
  for (const auto& [lo, hi]: leaves) {
    MergeList l;
    l.ids.assign(bis.perm().begin() + lo, bis.perm().begin() + hi);
    std::sort(l.ids.begin(), l.ids.end());
    center_list(l, beg);
    lists.push_back(std::move(l));
  }

  const uint32_t half = static_cast<uint32_t>(TLSH_IVF_BISECT_COALESCE_FACTOR * target_list_size / 2);
  if (half > 0 && lists.size() > 1) {
    // a coalesced list keeps the better of its two medoids; give it its
    // exact 1-center instead. A list is a coalesced one iff it is larger
    // than the leaf its first id came from.
    std::vector<uint32_t> leaf_of(m), leaf_size(lists.size());
    for (size_t i = 0; i < lists.size(); ++i) {
      leaf_size[i] = static_cast<uint32_t>(lists[i].ids.size());
      for (const uint32_t id: lists[i].ids) {
        leaf_of[id] = static_cast<uint32_t>(i);
      }
    }
    coalesce_cell(lists, beg, half);
    for (MergeList& l: lists) {
      if (l.ids.size() != leaf_size[leaf_of[l.ids.front()]]) {
        center_list(l, beg);
      }
    }
  }

  CellLists out;
  out.ids.reserve(m);
  for (const MergeList& l: lists) {
    out.medoids.push_back(l.medoid);
    out.radius2.push_back(l.radius2);
    out.sizes.push_back(static_cast<uint32_t>(l.ids.size()));
    for (const uint32_t id: l.ids) {
      out.ids.push_back(static_cast<uint32_t>(base + id));
    }
  }
  return out;
}

} // namespace

TlshIvf build_tlsh_ivf(
  const TlshDigest* beg,
  const TlshDigest* end,
  size_t target_list_size,
  uint64_t seed,
  unsigned threads,
  TlshIvfBuild method)
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
    results[i] = method == TlshIvfBuild::BISECT ?
      bisect_cell(beg + cells[c], beg + cells[c + 1], cells[c], target_list_size, rng) :
      cluster_cell(beg + cells[c], beg + cells[c + 1], cells[c], target_list_size, rng);
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

namespace {

// exact squared body-embedding radius about m over the rows ids
uint32_t radius_about(const TlshDigest& m, const std::vector<uint32_t>& ids, const TlshDigest* rows) {
  const TlshBodyQuery q(m);
  uint32_t r = 0;
  for (const uint32_t id: ids) {
    r = std::max(r, q.emb_body(rows[id]));
  }
  return r;
}

} // namespace

TlshIvf merge_tlsh_ivf(
  const TlshIvfView& a,
  const uint32_t* a_map,
  const TlshIvfView& b,
  const uint32_t* b_map,
  const TlshDigest* rows,
  uint64_t n_out,
  uint32_t coalesce_threshold)
{
  THROW_IF(n_out > std::numeric_limits<uint32_t>::max(), "too many rows for a TIVF index");
  THROW_IF(!a.empty() && !a_map, "missing row map for the left index");
  THROW_IF(!b.empty() && !b_map, "missing row map for the right index");
  THROW_IF(n_out && !rows, "missing rows for the merged index");

  TlshIvf out;
  out.n = n_out;
  out.cell_lists.assign(TLSH_CELL_COUNT + 1, 0);
  out.list_start.push_back(0);
  out.ids.reserve(n_out);

  const uint32_t half = coalesce_threshold / 2;

  std::vector<MergeList> cell;

  // appends the lists of cell c of one input to cell, remapped; a list that
  // lost members gets its radius recomputed
  const auto gather = [&](const TlshIvfView& v, const uint32_t* map, uint32_t c) {
    if (v.empty()) {
      return;
    }
    for (uint32_t l = v.cell_lists[c]; l < v.cell_lists[c + 1]; ++l) {
      MergeList m{ v.medoids[l], v.radius2[l], {} };
      bool shrunk = false;
      for (uint64_t i = v.list_start[l]; i < v.list_start[l + 1]; ++i) {
        const uint32_t id = map[v.ids[i]];
        if (id == TLSH_IVF_DROPPED) {
          shrunk = true;
          continue;
        }
        THROW_IF(
          !m.ids.empty() && id <= m.ids.back(),
          "row map is not increasing within a TIVF list"
        );
        m.ids.push_back(id);
      }
      if (m.ids.empty()) {
        continue; // every member was dropped
      }
      if (shrunk) {
        m.radius2 = radius_about(m.medoid, m.ids, rows);
      }
      cell.push_back(std::move(m));
    }
  };

  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    out.cell_lists[c] = static_cast<uint32_t>(out.lists());
    cell.clear();
    gather(a, a_map, c);
    gather(b, b_map, c);
    if (half > 0 && cell.size() > 1) {
      coalesce_cell(cell, rows, half);
    }
    for (const MergeList& m: cell) {
      out.medoids.push_back(m.medoid);
      out.radius2.push_back(m.radius2);
      out.ids.insert(out.ids.end(), m.ids.begin(), m.ids.end());
      out.list_start.push_back(out.ids.size());
    }
  }
  out.cell_lists[TLSH_CELL_COUNT] = static_cast<uint32_t>(out.lists());

  THROW_IF(
    out.ids.size() != n_out,
    "merged TIVF index has " << out.ids.size() << " ids, expected " << n_out
  );

  return out;
}

bool tlsh_ivf_check_invariant(const TlshIvfView& v, uint32_t coalesce_threshold) {
  const uint64_t half = coalesce_threshold / 2;
  if (v.empty() || half == 0) {
    return true;
  }
  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    size_t small = 0;
    for (uint32_t l = v.cell_lists[c]; l < v.cell_lists[c + 1]; ++l) {
      if (v.list_start[l + 1] - v.list_start[l] < half && ++small > 1) {
        return false;
      }
    }
  }
  return true;
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
