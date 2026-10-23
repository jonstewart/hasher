/*
 * TLSH kNN and hashing benchmarks.
 *
 *   TLSH_BENCH_N=10000,100000 ./test/bench_tlsh
 *
 * TLSH_BENCH_LIST sets the IVF target list size (default 32) and
 * TLSH_BENCH_BUILD=bisect|kmeans the IVF build method (default bisect, the
 * library's default; kmeans is the float alternative).
 *
 * Compares k-nearest-neighbour search strategies over a sorted corpus (as an
 * hset stores it): brute force with the reference implementation
 * (Tlsh::totalDiff), brute force with libhasher's popcount kernel, the cell
 * index (header-cost pruning), and the IVF index over the lower-bound
 * embedding; plus TlshHasher against the reference hasher. Catch2 prints the
 * per-benchmark statistics; a summary table in ns/query follows.
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <queue>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <tlsh.h> // reference implementation

#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "tlsh_hasher.h"
#include "hashset/tlsh_cell_search.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_search.h"

namespace {

constexpr size_t K = 10;
constexpr uint32_t MAX_DISTANCE = 144;
const size_t IVF_LIST_SIZE = std::getenv("TLSH_BENCH_LIST") ? std::stoull(std::getenv("TLSH_BENCH_LIST")) : 32;
const TlshIvfBuild IVF_BUILD = [] {
  const char* env = std::getenv("TLSH_BENCH_BUILD");
  const std::string s = env && *env ? env : "bisect";
  if (s == "kmeans") {
    return TlshIvfBuild::KMEANS;
  }
  if (s == "bisect") {
    return TlshIvfBuild::BISECT;
  }
  throw std::invalid_argument("TLSH_BENCH_BUILD must be kmeans or bisect, not " + s);
}();
constexpr size_t NUM_QUERIES = 20;
constexpr uint64_t CORPUS_SEED = 0x7a5b;
constexpr uint64_t QUERY_SEED = 0x51e;

std::vector<size_t> bench_sizes() {
  const char* env = std::getenv("TLSH_BENCH_N");
  const std::string s = env && *env ? env : "10000,100000";

  std::vector<size_t> v;
  size_t pos = 0;
  while (pos <= s.size()) {
    size_t comma = s.find(',', pos);
    if (comma == std::string::npos) {
      comma = s.size();
    }
    const std::string tok = s.substr(pos, comma - pos);
    if (!tok.empty()) {
      v.push_back(std::stoull(tok));
    }
    pos = comma + 1;
  }
  return v;
}

using Hit = std::pair<uint32_t, uint32_t>; // (distance, index)

/*
 * Brute-force top-k with a bounded max-heap. Ties at the boundary keep the
 * earlier index, so any two exact distance functions produce identical
 * results.
 */
template <class Dist>
std::vector<Hit> knn(size_t n, size_t k, Dist dist) {
  std::priority_queue<Hit> heap;
  for (uint32_t i = 0; i < n; ++i) {
    const uint32_t d = dist(i);
    if (heap.size() < k) {
      heap.emplace(d, i);
    }
    else if (d < heap.top().first) {
      heap.pop();
      heap.emplace(d, i);
    }
  }

  std::vector<Hit> out;
  out.reserve(heap.size());
  while (!heap.empty()) {
    out.push_back(heap.top());
    heap.pop();
  }
  std::reverse(out.begin(), out.end());
  return out;
}

// Tlsh's copy constructor is shallow; never copy one.
std::unique_ptr<Tlsh> to_reference(const TlshDigest& d) {
  auto t = std::make_unique<Tlsh>();
  const std::string hex = tlsh_to_hex(d);
  if (t->fromTlshStr(hex.c_str()) != 0) {
    throw std::runtime_error("reference rejected " + hex);
  }
  return t;
}

std::vector<std::unique_ptr<Tlsh>> to_reference(const std::vector<TlshDigest>& ds) {
  std::vector<std::unique_ptr<Tlsh>> out;
  out.reserve(ds.size());
  for (const auto& d: ds) {
    out.push_back(to_reference(d));
  }
  return out;
}

// NUM_QUERIES digests drawn from the corpus, each perturbed once
std::vector<TlshDigest> make_queries(const std::vector<TlshDigest>& corpus) {
  std::mt19937_64 rng(QUERY_SEED);
  std::vector<TlshDigest> q;
  for (size_t i = 0; i < NUM_QUERIES; ++i) {
    const std::vector<TlshDigest> pick{corpus[rng() % corpus.size()]};
    q.push_back(perturb_tlsh_corpus(QUERY_SEED + i, pick, 1).front());
  }
  return q;
}

template <class F>
std::vector<std::vector<Hit>> run_all(F f, size_t n) {
  std::vector<std::vector<Hit>> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    out.push_back(f(i));
  }
  return out;
}

// min over reps of the wall time for one pass over all queries, in ns
template <class F>
double min_ns(F f, size_t reps) {
  double best = std::numeric_limits<double>::infinity();
  for (size_t r = 0; r < reps; ++r) {
    const auto t0 = std::chrono::steady_clock::now();
    volatile size_t sink = f();
    (void)sink;
    const auto t1 = std::chrono::steady_clock::now();
    best = std::min(best, std::chrono::duration<double, std::nano>(t1 - t0).count());
  }
  return best;
}

struct Row {
  size_t n;
  double ref_ns;
  double brute_ns;
  double cells_ns;
  double ivf_ns;
  double ivf_build_ms;
  size_t ivf_lists;
};

void print_summary(const std::vector<Row>& rows) {
  std::cout << "\nkNN summary (k=" << K << ", max_distance=" << MAX_DISTANCE
            << ", " << NUM_QUERIES << " queries, min of repeated passes; ns/query)\n"
            << std::setw(10) << "N"
            << std::setw(16) << "reference"
            << std::setw(16) << "brute kernel"
            << std::setw(16) << "cell index"
            << std::setw(16) << "ivf embed"
            << std::setw(12) << "brute/ivf"
            << std::setw(12) << "ref/ivf"
            << std::setw(14) << "ivf build ms"
            << std::setw(10) << "lists" << '\n';
  for (const auto& r: rows) {
    std::cout << std::fixed << std::setprecision(0)
              << std::setw(10) << r.n
              << std::setw(16) << r.ref_ns
              << std::setw(16) << r.brute_ns
              << std::setw(16) << r.cells_ns
              << std::setw(16) << r.ivf_ns
              << std::setw(11) << std::setprecision(1) << r.brute_ns / r.ivf_ns << 'x'
              << std::setw(11) << r.ref_ns / r.ivf_ns << 'x'
              << std::setw(14) << r.ivf_build_ms
              << std::setw(10) << r.ivf_lists << '\n';
  }
  std::cout << std::endl;
}

std::vector<Hit> to_hits(const std::vector<SFHASH_TlshMatch>& m) {
  std::vector<Hit> h;
  h.reserve(m.size());
  for (const auto& x: m) {
    h.emplace_back(x.distance, static_cast<uint32_t>(x.index));
  }
  return h;
}

} // namespace

TEST_CASE("tlsh_knn") {
  std::vector<Row> rows;

  for (const size_t n: bench_sizes()) {
    const std::string tag = " N=" + std::to_string(n);

    std::vector<TlshDigest> corpus = make_tlsh_corpus(CORPUS_SEED, n);
    REQUIRE(corpus.size() == n);
    std::sort(corpus.begin(), corpus.end()); // hset row order
    const std::vector<TlshDigest> queries = make_queries(corpus);

    const std::vector<std::unique_ptr<Tlsh>> ref_corpus = to_reference(corpus);
    const std::vector<std::unique_ptr<Tlsh>> ref_queries = to_reference(queries);

    const auto cells = make_tlsh_cell_index(corpus.data(), corpus.data() + corpus.size());

    const auto t0 = std::chrono::steady_clock::now();
    const TlshIvf ivf = build_tlsh_ivf(
      corpus.data(), corpus.data() + corpus.size(), IVF_LIST_SIZE, TLSH_IVF_DEFAULT_SEED, 0, IVF_BUILD
    );
    const auto t1 = std::chrono::steady_clock::now();
    const double ivf_build_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    const TlshIvfView view = make_tlsh_ivf_view(ivf);

    const TlshDigest* beg = corpus.data();
    const TlshDigest* end = beg + corpus.size();

    auto run_ref = [&](size_t qi) {
      return knn(corpus.size(), K, [&](uint32_t i) {
        return static_cast<uint32_t>(ref_queries[qi]->totalDiff(ref_corpus[i].get(), true));
      });
    };
    auto run_brute = [&](size_t qi) {
      return to_hits(tlsh_knn_brute(beg, end, queries[qi], K, MAX_DISTANCE, true));
    };
    auto run_cells = [&](size_t qi) {
      return to_hits(tlsh_knn_cells(beg, cells.data(), queries[qi], K, MAX_DISTANCE, true));
    };
    auto run_ivf = [&](size_t qi) {
      return to_hits(tlsh_knn_ivf(view, beg, queries[qi], K, MAX_DISTANCE, true));
    };

    // every strategy must agree with the reference exactly, for every query
    const auto expected = run_all(run_ref, NUM_QUERIES);
    const auto brute = run_all(run_brute, NUM_QUERIES);
    const auto cell = run_all(run_cells, NUM_QUERIES);
    const auto fast = run_all(run_ivf, NUM_QUERIES);
    for (size_t qi = 0; qi < NUM_QUERIES; ++qi) {
      // the reference baseline has no max_distance; trim it the same way
      std::vector<Hit> exp;
      for (const auto& h: expected[qi]) {
        if (h.first <= MAX_DISTANCE) {
          exp.push_back(h);
        }
      }
      CHECK(exp == brute[qi]);
      CHECK(exp == cell[qi]);
      CHECK(exp == fast[qi]);
    }

    BENCHMARK("knn_reference_totalDiff" + tag) {
      return run_all(run_ref, NUM_QUERIES);
    };

    BENCHMARK("knn_brute_tlsh_diff" + tag) {
      return run_all(run_brute, NUM_QUERIES);
    };

    BENCHMARK("knn_cell_index" + tag) {
      return run_all(run_cells, NUM_QUERIES);
    };

    BENCHMARK("knn_ivf_embedding" + tag) {
      return run_all(run_ivf, NUM_QUERIES);
    };

    // per-query fixed cost: a radius-0 search visits one cell
    BENCHMARK("knn_ivf_fixed_overhead" + tag) {
      size_t s = 0;
      for (size_t qi = 0; qi < NUM_QUERIES; ++qi) {
        s += tlsh_knn_ivf(view, beg, queries[qi], K, 0, true).size();
      }
      return s;
    };

    {
      TlshKnnStats cs, is;
      for (size_t qi = 0; qi < NUM_QUERIES; ++qi) {
        tlsh_knn_cells(beg, cells.data(), queries[qi], K, MAX_DISTANCE, true, &cs);
        tlsh_knn_ivf(view, beg, queries[qi], K, MAX_DISTANCE, true, &is);
      }
      std::cout << "N=" << n << " per query: cell index visits " << cs.cells / NUM_QUERIES
                << " cells, " << cs.rows / NUM_QUERIES << " rows; ivf visits "
                << is.cells / NUM_QUERIES << " cells, bounds " << is.lists / NUM_QUERIES
                << " lists, scans " << is.rows / NUM_QUERIES << " rows\n";
    }

    const size_t reps = n >= 1000000 ? 2 : 5;
    rows.push_back({
      n,
      min_ns([&]() { return run_all(run_ref, NUM_QUERIES).size(); }, reps) / NUM_QUERIES,
      min_ns([&]() { return run_all(run_brute, NUM_QUERIES).size(); }, reps) / NUM_QUERIES,
      min_ns([&]() { return run_all(run_cells, NUM_QUERIES).size(); }, reps) / NUM_QUERIES,
      min_ns([&]() { return run_all(run_ivf, NUM_QUERIES).size(); }, reps * 4) / NUM_QUERIES,
      ivf_build_ms,
      ivf.lists()
    });
  }

  print_summary(rows);
}

TEST_CASE("tlsh_hash_throughput") {
  constexpr size_t SIZE = size_t(4) << 20;

  std::vector<uint8_t> buf(SIZE);
  std::mt19937_64 rng(CORPUS_SEED);
  for (size_t i = 0; i < SIZE; i += 8) {
    const uint64_t x = rng();
    std::copy_n(reinterpret_cast<const uint8_t*>(&x), 8, buf.begin() + i);
  }

  auto hash_ours = [&]() {
    TlshHasher h;
    h.update(buf.data(), buf.data() + SIZE);
    return h.digest();
  };

  auto hash_ref = [&]() {
    Tlsh t;
    t.update(buf.data(), static_cast<unsigned int>(SIZE));
    t.final();
    return std::string(t.getHash(1));
  };

  CHECK(tlsh_to_hex(hash_ours()) == hash_ref());

  BENCHMARK("TlshHasher 4 MiB") {
    return hash_ours();
  };

  BENCHMARK("reference Tlsh 4 MiB") {
    return hash_ref();
  };

  const double ours_ns = min_ns([&]() { return size_t(hash_ours().L); }, 5);
  const double ref_ns = min_ns([&]() { return hash_ref().size(); }, 5);
  const double mib = static_cast<double>(SIZE) / (1 << 20);

  std::cout << "\nhashing summary (4 MiB random buffer, min of 5)\n"
            << std::fixed << std::setprecision(1)
            << std::setw(22) << "TlshHasher" << std::setw(12) << ours_ns / 1e6 << " ms"
            << std::setw(12) << mib / (ours_ns / 1e9) << " MiB/s\n"
            << std::setw(22) << "reference Tlsh" << std::setw(12) << ref_ns / 1e6 << " ms"
            << std::setw(12) << mib / (ref_ns / 1e9) << " MiB/s\n"
            << std::endl;
}
