/*
 * Incremental merge benchmark: a master TLSH hash set absorbs a stream of
 * batches by successive unions (sfhash_hashset_merge, the TIVF index carried
 * through and coalesced), against one from-scratch build of the final set.
 *
 *   MERGE_BENCH_N=1000000 ./test/bench_hset_merge
 *   MERGE_BENCH_N=100000,1000000 MERGE_BENCH_T=32 MERGE_BENCH_C=0,2 ./test/bench_hset_merge
 *   MERGE_BENCH_BUILD=kmeans MERGE_BENCH_N=100000 ./test/bench_hset_merge
 *
 * MERGE_BENCH_BUILD (bisect, the default, or kmeans) selects the TIVF
 * build method of every from-scratch build, through the builder's
 * SFHASH_HSET_TLSH_INDEX_KMEANS option bit.
 *
 * For each master size N (MERGE_BENCH_N, default 1000000), each clustering
 * target list size T (MERGE_BENCH_T, default 16,32,64; the master and the
 * batches are built with it), each coalescing threshold C as a multiple of
 * T (MERGE_BENCH_C, default 0,1,2,4 for C in {0, T, 2T, 4T}) and two batch
 * scenarios -- hourly: 24 unions of 18,000 rows; daily: 7 unions of 432,000
 * rows (VirusShare's ~5 samples/s) -- it reports the cumulative merge time,
 * the time of one from-scratch build of the final set (sort, dedup,
 * build_tlsh_ivf and the file write through the builder), the TIVF size and
 * list count of the merged and the rebuilt index, the nonempty cells, and
 * the kNN query time (k = 10, max_distance = 144, 50 fixed queries) with the
 * rows scanned per query on both indexes.
 *
 * Files are hashsets-only with the index. Batches are near-duplicates of master rows (digest-space
 * perturbation of the master corpus) plus new families from the corpus
 * generator with a fresh seed. The from-scratch build clusters cells in
 * parallel; the merge is single-threaded.
 */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "helper.h"
#include "util.h"
#include "tlsh_corpus.h"
#include "tlsh_digest.h"
#include "hasher/hashset.h"
#include "hashset/hset.h"
#include "hashset/hset_decoder.h"
#include "hashset/hset_encoder.h"
#include "hashset/tlsh_cells.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_search.h"

namespace {

using clock_type = std::chrono::steady_clock;

double ms(clock_type::duration d) {
  return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(d).count();
}

std::vector<size_t> env_list(const char* name, const std::string& dflt) {
  const char* env = std::getenv(name);
  const std::string s = env && *env ? env : dflt;
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

constexpr size_t K = 10;
constexpr uint32_t MAX_DISTANCE = 144;
constexpr size_t NUM_QUERIES = 50;

// MERGE_BENCH_BUILD: the TIVF build method of every from-scratch build
// (master, batches, rebuild), through the builder's tlsh_options
const char* const BUILD_NAME = [] {
  const char* env = std::getenv("MERGE_BENCH_BUILD");
  const std::string s = env && *env ? env : "bisect";
  if (s == "bisect") {
    return "bisect";
  }
  if (s == "kmeans") {
    return "kmeans";
  }
  throw std::invalid_argument("MERGE_BENCH_BUILD must be kmeans or bisect, not " + s);
}();
const uint32_t BUILD_OPTIONS = SFHASH_HSET_TLSH_INDEX |
  (std::string(BUILD_NAME) == "kmeans" ? uint32_t(SFHASH_HSET_TLSH_INDEX_KMEANS) : 0u);
constexpr uint64_t CORPUS_SEED = 0x6d61737465;
constexpr uint64_t QUERY_SEED = 0x71;

struct Scenario {
  const char* name;
  size_t batch;
  size_t merges;
};

const Scenario SCENARIOS[] = {
  { "hourly", 18000, 24 },
  { "daily", 432000, 7 }
};

using HsetPtr = std::unique_ptr<SFHASH_Hashset, void(*)(SFHASH_Hashset*)>;

struct Loaded {
  std::vector<char> buf;
  HsetPtr hset{ nullptr, sfhash_destroy_hashset };

  const SFHASH_Hashset* get() const { return hset.get(); }
  const TlshDigest* rows() const { return static_cast<const TlshDigest*>(std::get<ConstHashsetData>(hset->holder.hsets[0]).beg); }
  uint64_t n() const { return std::get<HashsetHeader>(hset->holder.hsets[0]).hash_count; }
  const TlshIvfView& ivf() const { return std::get<TlshIvfView>(hset->holder.hsets[0]); }
};

Loaded load_file(const std::string& path) {
  Loaded l;
  l.buf = read_file(path);
  SFHASH_Error* err = nullptr;
  l.hset.reset(sfhash_load_hashset(l.buf.data(), l.buf.data() + l.buf.size(), &err));
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(l.hset);
  return l;
}

// a TLSH-only, hashsets-only file with the index (target list size T) and
// no vectors; returns the build time
clock_type::duration build_file(const std::string& path, const TlshDigest* beg, const TlshDigest* end, size_t T) {
  const auto t0 = clock_type::now();
  const SFHASH_HashAlgorithm htype = SFHASH_TLSH;
  SFHASH_Error* err = nullptr;
  auto bctx = make_unique_del(
    sfhash_hashset_builder_open("bench", "incremental merge benchmark", &htype, 1, false, true, path.c_str(), "test", &err),
    sfhash_hashset_builder_destroy
  );
  REQUIRE(!err);
  sfhash_hashset_builder_set_tlsh_options(bctx.get(), BUILD_OPTIONS);
  bctx->tlsh_ivf_target_list_size = T;
  for (const TlshDigest* d = beg; d != end; ++d) {
    sfhash_hashset_builder_add_hash(bctx.get(), d, sizeof(*d));
  }
  REQUIRE(sfhash_hashset_builder_write(bctx.get(), &err) > 0);
  REQUIRE(!err);
  return clock_type::now() - t0;
}

clock_type::duration merge_union(const Loaded& l, const Loaded& r, const std::string& path, uint32_t C) {
  const auto t0 = clock_type::now();
  SFHASH_Error* err = nullptr;
  const uint64_t size = sfhash_hashset_merge(
    l.get(), r.get(), SFHASH_HSET_OP_UNION, "bench", "incremental merge benchmark", path.c_str(),
    SFHASH_HSET_TLSH_INDEX, C, &err
  );
  if (err) {
    FAIL(err->message);
  }
  REQUIRE(size > 0);
  return clock_type::now() - t0;
}

size_t nonempty_cells(const Loaded& o) {
  const auto cells = make_tlsh_cell_index(o.rows(), o.rows() + o.n());
  size_t n = 0;
  for (uint32_t c = 0; c < TLSH_CELL_COUNT; ++c) {
    n += cells[c] != cells[c + 1];
  }
  return n;
}

struct QueryResult {
  double us_per_query;
  double rows_per_query;
  std::vector<std::vector<SFHASH_TlshMatch>> matches;
};

// the queries against the index, repeated until ~0.3 s has elapsed
QueryResult run_queries(const Loaded& o, const std::vector<TlshDigest>& queries) {
  QueryResult r;
  TlshKnnStats stats;
  for (const auto& q: queries) {
    r.matches.push_back(tlsh_knn_ivf(o.ivf(), o.rows(), q, K, MAX_DISTANCE, true, &stats));
  }
  r.rows_per_query = static_cast<double>(stats.rows) / queries.size();

  size_t reps = 0;
  clock_type::duration total{ 0 };
  while (ms(total) < 300.0 || reps < 3) {
    const auto t0 = clock_type::now();
    size_t found = 0;
    for (const auto& q: queries) {
      found += tlsh_knn_ivf(o.ivf(), o.rows(), q, K, MAX_DISTANCE, true).size();
    }
    total += clock_type::now() - t0;
    ++reps;
    REQUIRE(found <= K * queries.size());
  }
  r.us_per_query = ms(total) * 1000.0 / (reps * queries.size());
  return r;
}

bool same_matches(const std::vector<SFHASH_TlshMatch>& a, const std::vector<SFHASH_TlshMatch>& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (size_t i = 0; i < a.size(); ++i) {
    if (a[i].index != b[i].index || a[i].distance != b[i].distance) {
      return false;
    }
  }
  return true;
}

struct Row {
  size_t n;
  std::string scenario;
  size_t T;
  uint32_t C;
  size_t merges;
  double merge_ms;
  double rebuild_ms;
  uint64_t final_rows;
  size_t tivf_merged, tivf_rebuilt;
  uint32_t lists_merged, lists_rebuilt;
  size_t cells;
  bool bound_ok;
  double knn_merged_us, knn_rebuilt_us;
  double rows_merged, rows_rebuilt;
};

std::vector<TlshDigest> make_batch(uint64_t seed, const std::vector<TlshDigest>& master, size_t size) {
  std::vector<TlshDigest> b = make_tlsh_corpus(seed, size / 2);
  const auto near = perturb_tlsh_corpus(seed ^ 0x5a5a, master, size - b.size(), 0.03);
  b.insert(b.end(), near.begin(), near.end());
  return b;
}

} // namespace

TEST_CASE("bench_hset_merge_incremental") {
  const auto sizes = env_list("MERGE_BENCH_N", "1000000");
  const auto Ts = env_list("MERGE_BENCH_T", "16,32,64");
  const auto Cmults = env_list("MERGE_BENCH_C", "0,1,2,4");

  std::vector<Row> table;

  for (const size_t N: sizes) {
    auto t0 = clock_type::now();
    const std::vector<TlshDigest> master = make_tlsh_corpus(CORPUS_SEED, N);
    const std::vector<TlshDigest> queries = perturb_tlsh_corpus(QUERY_SEED, master, NUM_QUERIES, 0.05);
    std::cout << "N = " << N << ": master corpus " << std::fixed << std::setprecision(0) << ms(clock_type::now() - t0) << " ms" << std::endl;

    for (const Scenario& sc: SCENARIOS) {
      t0 = clock_type::now();
      std::vector<std::vector<TlshDigest>> batches;
      for (size_t i = 0; i < sc.merges; ++i) {
        batches.push_back(make_batch(CORPUS_SEED + 1000 * (i + 1) + sc.batch, master, sc.batch));
      }
      std::cout << "  " << sc.name << ": " << sc.merges << " batches of " << sc.batch << " rows, " << ms(clock_type::now() - t0) << " ms" << std::endl;

      for (const size_t T: Ts) {
        // master and batch files built with this T
        const std::string master_path = "test/bench_merge_master.hset";
        auto build_t = build_file(master_path, master.data(), master.data() + master.size(), T);
        std::cout << "    T = " << T << ": master built in " << ms(build_t) << " ms" << std::endl;

        std::vector<std::string> batch_paths;
        for (size_t i = 0; i < sc.merges; ++i) {
          batch_paths.push_back("test/bench_merge_batch_" + std::to_string(i) + ".hset");
          build_file(batch_paths.back(), batches[i].data(), batches[i].data() + batches[i].size(), T);
        }

        for (const size_t cm: Cmults) {
          const uint32_t C = static_cast<uint32_t>(cm * T);
          Row row{};
          row.n = N;
          row.scenario = sc.name;
          row.T = T;
          row.C = C;
          row.merges = sc.merges;

          // successive unions
          Loaded cur = load_file(master_path);
          clock_type::duration merge_total{ 0 };
          for (size_t i = 0; i < sc.merges; ++i) {
            const Loaded batch = load_file(batch_paths[i]);
            const std::string out = i % 2 ? "test/bench_merge_out_a.hset" : "test/bench_merge_out_b.hset";
            merge_total += merge_union(cur, batch, out, C);
            cur = load_file(out);
          }
          row.merge_ms = ms(merge_total);
          row.final_rows = cur.n();
          row.lists_merged = cur.ivf().lists;
          row.tivf_merged = length_tivf_data(cur.ivf().lists, cur.n());
          row.cells = nonempty_cells(cur);
          REQUIRE(tlsh_ivf_check_invariant(cur.ivf(), C));

          // one from-scratch build of the same rows
          const std::string rebuilt_path = "test/bench_merge_rebuilt.hset";
          row.rebuild_ms = ms(build_file(rebuilt_path, cur.rows(), cur.rows() + cur.n(), T));
          const Loaded rebuilt = load_file(rebuilt_path);
          REQUIRE(rebuilt.n() == cur.n());
          REQUIRE(std::memcmp(rebuilt.rows(), cur.rows(), cur.n() * sizeof(TlshDigest)) == 0);
          row.lists_rebuilt = rebuilt.ivf().lists;
          row.tivf_rebuilt = length_tivf_data(rebuilt.ivf().lists, rebuilt.n());
          row.bound_ok = row.lists_merged <= row.lists_rebuilt + row.cells;

          // queries
          const QueryResult qm = run_queries(cur, queries);
          const QueryResult qr = run_queries(rebuilt, queries);
          for (size_t i = 0; i < queries.size(); ++i) {
            REQUIRE(same_matches(qm.matches[i], qr.matches[i]));
          }
          row.knn_merged_us = qm.us_per_query;
          row.knn_rebuilt_us = qr.us_per_query;
          row.rows_merged = qm.rows_per_query;
          row.rows_rebuilt = qr.rows_per_query;

          std::cout << "      C = " << std::setw(3) << C
                    << ": merges " << std::setprecision(0) << row.merge_ms << " ms, rebuild " << row.rebuild_ms
                    << " ms, lists " << row.lists_merged << " vs " << row.lists_rebuilt
                    << ", kNN " << std::setprecision(1) << row.knn_merged_us << " vs " << row.knn_rebuilt_us
                    << " us, rows/query " << std::setprecision(0) << row.rows_merged << " vs " << row.rows_rebuilt
                    << std::endl;
          table.push_back(row);

          std::filesystem::remove(rebuilt_path);
        }

        for (const auto& p: batch_paths) {
          std::filesystem::remove(p);
        }
        std::filesystem::remove(master_path);
      }
    }
    std::filesystem::remove("test/bench_merge_out_a.hset");
    std::filesystem::remove("test/bench_merge_out_b.hset");
  }

  // summary
  std::cout << "\nIncremental merge vs from-scratch rebuild (TIVF; build " << BUILD_NAME << "; k = " << K
            << ", max_distance = " << MAX_DISTANCE << ", " << NUM_QUERIES << " queries)\n\n"
            << "| N | batches | T | C | merge total ms | rebuild ms | rows | TIVF merged KiB | TIVF rebuilt KiB | lists merged | lists rebuilt | cells | bound | kNN merged us | kNN rebuilt us | rows/q merged | rows/q rebuilt |\n"
            << "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n";
  for (const Row& r: table) {
    std::cout << "| " << r.n
              << " | " << r.merges << " x " << (r.scenario == "hourly" ? 18000 : 432000)
              << " | " << r.T
              << " | " << r.C
              << " | " << std::fixed << std::setprecision(0) << r.merge_ms
              << " | " << r.rebuild_ms
              << " | " << r.final_rows
              << " | " << r.tivf_merged / 1024
              << " | " << r.tivf_rebuilt / 1024
              << " | " << r.lists_merged
              << " | " << r.lists_rebuilt
              << " | " << r.cells
              << " | " << (r.bound_ok ? "ok" : "-")
              << " | " << std::setprecision(1) << r.knn_merged_us
              << " | " << r.knn_rebuilt_us
              << " | " << std::setprecision(0) << r.rows_merged
              << " | " << r.rows_rebuilt
              << " |\n";
  }
  std::cout << std::endl;
}
