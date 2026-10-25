/*
 * vs_knn_eval: TLSH kNN evaluation over a real (or synthetic) hset.
 *
 * Times three kNN methods per query, single-threaded, over two query sets,
 * and writes per-query timings, ordered results and the tie/depth data an
 * information-retrieval analysis needs as CSV files (DuckDB-loadable).
 *
 * Methods
 *   brute  sfhash_hashset_tlsh_knn_with(..., SFHASH_TLSH_KNN_BRUTE): exact,
 *          every row; the TLSH ground truth.
 *   index  sfhash_hashset_tlsh_knn_with(..., SFHASH_TLSH_KNN_INDEX): exact,
 *          TIVF lists pruned with the embedding via the triangle inequality.
 *   embed  approximate, CrowdStrike style: phi(query) by sfhash_tlsh_embed,
 *          squared Euclidean distance to every row's embedding, top k in a
 *          bounded max-heap on (dist2, row), so ties go to the lower row.
 *          The rows' embeddings are computed in memory with
 *          sfhash_tlsh_embed, untimed and on --threads threads, before the
 *          timed passes (hset files do not store them).
 *
 * Query sets
 *   member  rows sampled uniformly without replacement from the TLSH hash
 *           set (non-null rows); the query is the row's digest.
 *   random  uniformly random valid digests (uniform L, Q, 128 2-bit codes
 *           and checksum; reserved byte 0; never the null digest).
 *
 * After the timed passes, an untimed multi-threaded analysis pass scans
 * every row for every query: the full TLSH distance histogram (for d_k,
 * count_lt, count_le), and the embedding top --deep-k (over the same
 * in-memory embeddings).
 *
 * See bench/README.md ("TLSH kNN eval") for usage and the output schema.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hasher/hashset.h"
#include "hasher/tlsh.h"
#include "hashset/hset.h"
#include "hashset/tlsh_ivf.h"
#include "hashset/tlsh_search.h"
#include "tlsh_digest.h"

namespace {

using Clock = std::chrono::steady_clock;

constexpr size_t DIMS = SFHASH_TLSH_EMBEDDING_DIMS;
static_assert(DIMS % 8 == 0);
constexpr uint32_t MAX_TLSH_DIST = 4096; // true maximum is 2473

//
// options
//

struct Options {
  std::string hset;
  std::string out;
  size_t k = 100;
  uint32_t max_distance = UINT32_MAX;
  bool include_length = true;
  size_t queries = 1000;
  size_t warm_reads = 3;
  size_t warmup = 50;
  size_t deep_k = 1000;
  uint64_t member_seed = 0x76736b6e6e6d656dull; // "vsknnmem"
  uint64_t random_seed = 0x76736b6e6e72616eull; // "vsknnran"
  uint64_t warmup_seed = 0x76736b6e6e77726dull; // "vsknnwrm"
  std::vector<std::string> sets{"member", "random"};
  std::vector<std::string> methods{"brute", "index", "embed"};
  std::string embed_kernel = "vec";
  unsigned threads = std::max(1u, std::thread::hardware_concurrency());
  int pin_cpu = -1;
  bool populate = true;
  bool analysis = true;
  bool hist = true;
};

[[noreturn]] void usage(const std::string& msg = "") {
  if (!msg.empty()) {
    std::cerr << "error: " << msg << "\n\n";
  }
  std::cerr <<
R"(usage: vs_knn_eval --hset FILE --out DIR [options]

  --k N                 neighbours per query (100)
  --max-distance N      TLSH distance cap, or "unbounded" (unbounded = 4294967295)
  --include-length B    true|false (true)
  --queries N           queries per set (1000)
  --sets LIST           member,random
  --methods LIST        brute,index,embed
  --member-seed S       mt19937_64 seed of the member sample
  --random-seed S       mt19937_64 seed of the random digests
  --warmup-seed S       mt19937_64 seed of the warm-up queries
  --warm-reads N        sequential reads of the hset file before timing (3)
  --warmup N            untimed warm-up queries per set x method (50)
  --deep-k N            depth of the untimed embedding ranking (1000; 0 = off)
  --embed-kernel K      vec (plain loop, compiler-vectorized) or
                        lib (sfhash_tlsh_embed_dist2, scalar) (vec)
  --threads N           threads of the untimed row embedding and analysis
                        pass (all CPUs)
  --pin-cpu C           pin the timing thread to CPU C (analysis threads are not pinned)
  --no-populate         mmap without MAP_POPULATE
  --no-analysis         skip the untimed analysis pass (no deep/hist, no d_k)
  --no-hist             do not write hist.csv
)";
  std::exit(2);
}

bool parse_bool(const std::string& s) {
  if (s == "true" || s == "1" || s == "yes") {
    return true;
  }
  if (s == "false" || s == "0" || s == "no") {
    return false;
  }
  usage("bad boolean '" + s + "'");
}

std::vector<std::string> split_list(const std::string& s) {
  std::vector<std::string> v;
  std::stringstream ss(s);
  std::string tok;
  while (std::getline(ss, tok, ',')) {
    if (!tok.empty()) {
      v.push_back(tok);
    }
  }
  return v;
}

Options parse_args(int argc, char** argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    std::string v;
    const auto eq = a.find('=');
    const bool has_eq = a.rfind("--", 0) == 0 && eq != std::string::npos;
    if (has_eq) {
      v = a.substr(eq + 1);
      a = a.substr(0, eq);
    }
    auto val = [&]() -> std::string {
      if (has_eq) {
        return v;
      }
      if (i + 1 >= argc) {
        usage("missing value for " + a);
      }
      return argv[++i];
    };
    auto num = [&]() { return std::stoull(val(), nullptr, 0); };

    if (a == "--hset") o.hset = val();
    else if (a == "--out") o.out = val();
    else if (a == "--k") o.k = num();
    else if (a == "--max-distance") {
      const std::string s = val();
      const uint64_t m = s == "unbounded" ? UINT32_MAX : std::stoull(s, nullptr, 0);
      if (m > UINT32_MAX) usage("max-distance too large");
      o.max_distance = static_cast<uint32_t>(m);
    }
    else if (a == "--include-length") o.include_length = parse_bool(val());
    else if (a == "--queries") o.queries = num();
    else if (a == "--sets") o.sets = split_list(val());
    else if (a == "--methods") o.methods = split_list(val());
    else if (a == "--member-seed") o.member_seed = num();
    else if (a == "--random-seed") o.random_seed = num();
    else if (a == "--warmup-seed") o.warmup_seed = num();
    else if (a == "--warm-reads") o.warm_reads = num();
    else if (a == "--warmup") o.warmup = num();
    else if (a == "--deep-k") o.deep_k = num();
    else if (a == "--embed-kernel") o.embed_kernel = val();
    else if (a == "--threads") o.threads = std::max<unsigned>(1, num());
    else if (a == "--pin-cpu") o.pin_cpu = static_cast<int>(num());
    else if (a == "--no-populate") o.populate = false;
    else if (a == "--no-analysis") o.analysis = false;
    else if (a == "--no-hist") o.hist = false;
    else if (a == "--help" || a == "-h") usage();
    else usage("unknown option " + a);
  }
  if (o.hset.empty() || o.out.empty()) usage("--hset and --out are required");
  if (o.k == 0) usage("--k must be positive");
  for (const auto& s: o.sets) {
    if (s != "member" && s != "random") usage("unknown set " + s);
  }
  for (const auto& m: o.methods) {
    if (m != "brute" && m != "index" && m != "embed") usage("unknown method " + m);
  }
  if (o.embed_kernel != "vec" && o.embed_kernel != "lib") usage("--embed-kernel is vec or lib");
  return o;
}

//
// system info
//

uint64_t meminfo_kb(const char* key) {
  std::ifstream f("/proc/meminfo");
  std::string k;
  uint64_t v;
  std::string unit;
  while (f >> k >> v) {
    std::getline(f, unit);
    if (k == std::string(key) + ":") {
      return v;
    }
  }
  return 0;
}

std::string cpu_model() {
  std::ifstream f("/proc/cpuinfo");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("model name", 0) == 0) {
      const auto c = line.find(':');
      return c == std::string::npos ? line : line.substr(c + 2);
    }
  }
  return "unknown";
}

std::string run_cmd(const std::string& cmd) {
  std::string out;
  if (FILE* p = popen(cmd.c_str(), "r")) {
    char buf[256];
    while (fgets(buf, sizeof buf, p)) {
      out += buf;
    }
    pclose(p);
  }
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
    out.pop_back();
  }
  return out;
}

// commit of the source tree the binary was built in (walks up from the exe)
std::string git_commit() {
  std::error_code ec;
  std::filesystem::path p = std::filesystem::canonical("/proc/self/exe", ec);
  if (ec) {
    return "";
  }
  for (p = p.parent_path(); !p.empty() && p != p.root_path(); p = p.parent_path()) {
    if (std::filesystem::exists(p / ".git")) {
      const std::string dir = "'" + p.string() + "'";
      std::string c = run_cmd("git -C " + dir + " rev-parse HEAD 2>/dev/null");
      if (!run_cmd("git -C " + dir + " status --porcelain --untracked-files=no 2>/dev/null").empty()) {
        c += "-dirty";
      }
      return c;
    }
  }
  return "";
}

std::string iso_now() {
  const std::time_t t = std::time(nullptr);
  char buf[64];
  std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S%z", std::localtime(&t));
  return buf;
}

double secs_since(Clock::time_point t0) {
  return std::chrono::duration<double>(Clock::now() - t0).count();
}

//
// file: warm reads, mapping, residency
//

struct WarmRead {
  double seconds;
  double mib_per_s;
};

std::vector<WarmRead> warm_reads(const std::string& path, size_t passes, uint64_t size) {
  std::vector<WarmRead> out;
  std::vector<char> buf(size_t(16) << 20);
  for (size_t i = 0; i < passes; ++i) {
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
      throw std::runtime_error("cannot open " + path);
    }
    ::posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    const auto t0 = Clock::now();
    uint64_t total = 0;
    ssize_t r;
    while ((r = ::read(fd, buf.data(), buf.size())) > 0) {
      total += static_cast<uint64_t>(r);
    }
    ::close(fd);
    const double s = secs_since(t0);
    out.push_back({s, total / 1048576.0 / s});
    std::cerr << "warm read " << (i + 1) << "/" << passes << ": " << total << " bytes in "
              << s << " s (" << out.back().mib_per_s << " MiB/s)\n";
    if (total != size) {
      throw std::runtime_error("short read of " + path);
    }
  }
  return out;
}

struct Mapping {
  void* base = MAP_FAILED;
  size_t size = 0;

  Mapping(const std::string& path, size_t sz, bool populate): size(sz) {
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
      throw std::runtime_error("cannot open " + path);
    }
    base = ::mmap(nullptr, size, PROT_READ, MAP_SHARED | (populate ? MAP_POPULATE : 0), fd, 0);
    ::close(fd);
    if (base == MAP_FAILED) {
      throw std::runtime_error("cannot mmap " + path);
    }
  }

  ~Mapping() {
    if (base != MAP_FAILED) {
      ::munmap(base, size);
    }
  }

  // fraction of pages resident in memory (mincore)
  double resident() const {
    const size_t page = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    std::vector<unsigned char> v((size + page - 1) / page);
    if (::mincore(base, size, v.data()) != 0) {
      return -1;
    }
    size_t r = 0;
    for (unsigned char c: v) {
      r += c & 1;
    }
    return v.empty() ? 1.0 : static_cast<double>(r) / v.size();
  }
};

//
// embedding distance kernels; noinline so that the timed and untimed passes
// compute bit-identical values (ties in embedding space are common)
//

// The plain single-accumulator loop, with reassociation allowed for this
// function only so that the compiler vectorizes the reduction (without it a
// float sum stays scalar and strictly ordered, as in sfhash_tlsh_embed_dist2).
// On this Westmere, at -O2 and -O3 alike, it runs at ~145 ns/row in cache
// against ~370 ns/row for the strictly ordered loop. (A hand-split 8-lane
// accumulator array was as fast at -O2 but 3x slower at -O3, where GCC 15
// vectorizes it across the outer loop with shuffles.)
#if defined(__clang__)
__attribute__((noinline)) float emb_dist2_vec(const float* a, const float* b, bool include_length) {
#pragma clang fp reassociate(on)
#else
__attribute__((noinline, optimize("-fassociative-math", "-fno-signed-zeros", "-fno-trapping-math")))
float emb_dist2_vec(const float* a, const float* b, bool include_length) {
#endif
  float s = 0.f;
  for (size_t i = 0; i < DIMS; ++i) {
    const float d = a[i] - b[i];
    s += d * d;
  }
  if (!include_length) {
    const float d = a[SFHASH_TLSH_EMBEDDING_L_DIM] - b[SFHASH_TLSH_EMBEDDING_L_DIM];
    s -= d * d;
  }
  return s;
}

__attribute__((noinline)) float emb_dist2_lib(const float* a, const float* b, bool include_length) {
  return sfhash_tlsh_embed_dist2(a, b, include_length);
}

using Kernel = float (*)(const float*, const float*, bool);

struct EmbHit {
  float d;
  uint64_t row;
};

inline bool emb_nearer(const EmbHit& a, const EmbHit& b) {
  return a.d < b.d || (a.d == b.d && a.row < b.row);
}

// bounded max-heap of the k nearest (d, row); rows arrive in ascending order
struct EmbTopK {
  size_t k;
  std::vector<EmbHit> heap;

  explicit EmbTopK(size_t kk): k(kk) {
    heap.reserve(k + 1);
  }

  void push(float d, uint64_t row) {
    if (heap.size() < k) {
      heap.push_back({d, row});
      std::push_heap(heap.begin(), heap.end(), emb_nearer);
    }
    else if (d < heap.front().d) {
      // ascending rows: an equal distance never displaces the top
      std::pop_heap(heap.begin(), heap.end(), emb_nearer);
      heap.back() = {d, row};
      std::push_heap(heap.begin(), heap.end(), emb_nearer);
    }
  }

  std::vector<EmbHit> sorted() {
    std::sort_heap(heap.begin(), heap.end(), emb_nearer);
    return std::move(heap);
  }
};

// the timed embedding kNN: phi(q), a scan of every row's embedding, a
// bounded heap
template <Kernel K>
std::vector<EmbHit> embed_knn(const float* vecs, uint64_t n, const void* digest, size_t k, bool include_length) {
  alignas(16) float q[DIMS];
  sfhash_tlsh_embed(digest, q);
  EmbTopK top(k);
  const float* v = vecs;
  for (uint64_t r = 0; r < n; ++r, v += DIMS) {
    top.push(K(q, v, include_length), r);
  }
  return top.sorted();
}

// the n x DIMS embedding matrix of rows, computed on threads threads; the
// memory is 4096-byte aligned, as the TVEC data of older hset files was
struct EmbeddingMatrix {
  float* data = nullptr;

  EmbeddingMatrix() = default;
  EmbeddingMatrix(const EmbeddingMatrix&) = delete;
  EmbeddingMatrix& operator=(const EmbeddingMatrix&) = delete;
  ~EmbeddingMatrix() { std::free(data); }

  void compute(const TlshDigest* rows, uint64_t n, unsigned threads) {
    const size_t bytes = ((n * DIMS * sizeof(float) + 4095) / 4096) * 4096;
    data = static_cast<float*>(std::aligned_alloc(4096, bytes ? bytes : 4096));
    if (!data) {
      throw std::runtime_error("cannot allocate " + std::to_string(bytes) + " bytes for the row embeddings");
    }
    std::vector<std::thread> pool;
    const uint64_t per = (n + threads - 1) / threads;
    for (unsigned t = 0; t < threads; ++t) {
      const uint64_t lo = std::min(n, t * per), hi = std::min(n, lo + per);
      pool.emplace_back([this, rows, lo, hi]() {
        for (uint64_t r = lo; r < hi; ++r) {
          sfhash_tlsh_embed(rows + r, data + r * DIMS);
        }
      });
    }
    for (auto& th: pool) {
      th.join();
    }
  }
};

//
// queries
//

struct Query {
  std::string set;
  size_t qid;
  TlshDigest d;
  int64_t source_row; // -1 for random
};

std::string hex(const TlshDigest& d) {
  char buf[SFHASH_TLSH_HEX_LENGTH + 1];
  sfhash_tlsh_to_hex(&d, buf);
  return buf;
}

// uniformly random valid digest: uniform L, Q (= Q1, Q2 nibbles), checksum
// and 128 2-bit codes (= uniform hi/lo plane bits), reserved 0, not null,
// and round-trips through the library's hex codec
TlshDigest random_digest(std::mt19937_64& rng) {
  for (;;) {
    TlshDigest d{};
    const uint64_t h = rng();
    d.L = static_cast<uint8_t>(h);
    d.Q = static_cast<uint8_t>(h >> 8);
    d.checksum = static_cast<uint8_t>(h >> 16);
    d.reserved = 0;
    for (size_t i = 0; i < 2; ++i) {
      const uint64_t a = rng();
      const uint64_t b = rng();
      std::memcpy(d.hi + 8 * i, &a, 8);
      std::memcpy(d.lo + 8 * i, &b, 8);
    }
    if (sfhash_tlsh_is_null(&d)) {
      continue;
    }
    TlshDigest back{};
    const std::string s = hex(d);
    if (!sfhash_tlsh_from_hex(s.c_str(), &back) || !(back == d)) {
      continue;
    }
    return d;
  }
}

// count distinct indexes uniformly from [lo, hi) in draw order, skipping excluded
std::vector<uint64_t> sample_rows(
  std::mt19937_64& rng, uint64_t lo, uint64_t hi, size_t count,
  const std::unordered_set<uint64_t>& exclude)
{
  const uint64_t m = hi - lo;
  if (count + exclude.size() > m) {
    throw std::runtime_error("not enough rows to sample " + std::to_string(count) + " queries");
  }
  std::unordered_set<uint64_t> seen;
  std::vector<uint64_t> out;
  while (out.size() < count) {
    const uint64_t r = lo + rng() % m;
    if (!exclude.count(r) && seen.insert(r).second) {
      out.push_back(r);
    }
  }
  return out;
}

//
// stats
//

struct Stats {
  size_t n = 0;
  double mean = 0, median = 0, stddev = 0, p99 = 0, min = 0, max = 0; // us
};

Stats stats_us(std::vector<double> ns) {
  Stats s;
  s.n = ns.size();
  if (ns.empty()) {
    return s;
  }
  std::sort(ns.begin(), ns.end());
  double sum = 0;
  for (double x: ns) sum += x;
  s.mean = sum / ns.size();
  double ss = 0;
  for (double x: ns) ss += (x - s.mean) * (x - s.mean);
  s.stddev = ns.size() > 1 ? std::sqrt(ss / (ns.size() - 1)) : 0;
  s.median = ns.size() % 2 ? ns[ns.size() / 2] : 0.5 * (ns[ns.size() / 2 - 1] + ns[ns.size() / 2]);
  // nearest rank
  const size_t r99 = static_cast<size_t>(std::ceil(0.99 * ns.size()));
  s.p99 = ns[std::max<size_t>(r99, 1) - 1];
  s.min = ns.front();
  s.max = ns.back();
  for (double* p: {&s.mean, &s.median, &s.stddev, &s.p99, &s.min, &s.max}) {
    *p /= 1000.0;
  }
  return s;
}

struct TimerOverhead {
  double min_ns, median_ns, mean_ns;
};

TimerOverhead timer_overhead() {
  constexpr size_t N = 1000000;
  std::vector<double> v(N);
  for (size_t i = 0; i < N; ++i) {
    const auto t0 = Clock::now();
    const auto t1 = Clock::now();
    v[i] = std::chrono::duration<double, std::nano>(t1 - t0).count();
  }
  double sum = 0;
  for (double x: v) sum += x;
  std::sort(v.begin(), v.end());
  return {v.front(), v[N / 2], sum / N};
}

//
// output helpers
//

struct Csv {
  FILE* f;
  std::vector<char> buf;

  Csv(const std::filesystem::path& p, const char* header): buf(size_t(4) << 20) {
    f = std::fopen(p.c_str(), "w");
    if (!f) {
      throw std::runtime_error("cannot write " + p.string());
    }
    std::setvbuf(f, buf.data(), _IOFBF, buf.size());
    std::fputs(header, f);
    std::fputc('\n', f);
  }

  ~Csv() {
    std::fclose(f);
  }
};

std::string json_str(const std::string& s) {
  std::string o = "\"";
  for (char c: s) {
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if (static_cast<unsigned char>(c) < 0x20) {
      char b[8];
      std::snprintf(b, sizeof b, "\\u%04x", c);
      o += b;
    }
    else o += c;
  }
  return o + "\"";
}

std::string hex_u64(uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "0x%016llx", static_cast<unsigned long long>(v));
  return b;
}

// per (set, method) timed outcome
struct Pass {
  std::string set;
  std::string method;
  std::vector<double> ns;                  // per qid
  std::vector<std::vector<uint64_t>> rows; // per qid, ordered results
  std::vector<std::vector<uint32_t>> tdist; // library distance (brute/index)
  std::vector<std::vector<float>> edist;   // embedding distance (embed)
  std::vector<TlshKnnStats> ivf;           // index only
  double warmup_s = 0;
  double timed_s = 0;
};

void pin_thread(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (pthread_setaffinity_np(pthread_self(), sizeof set, &set) != 0) {
    throw std::runtime_error("cannot pin to CPU " + std::to_string(cpu));
  }
}

} // namespace

int main(int argc, char** argv) {
  const Options opt = parse_args(argc, argv);
  const auto run_t0 = Clock::now();

  try {
    std::filesystem::create_directories(opt.out);
    const std::filesystem::path out(opt.out);

    // original affinity, restored in analysis threads when --pin-cpu is used
    cpu_set_t orig_mask;
    CPU_ZERO(&orig_mask);
    sched_getaffinity(0, sizeof orig_mask, &orig_mask);
    const int affinity_cpus = CPU_COUNT(&orig_mask);

    struct stat st;
    if (::stat(opt.hset.c_str(), &st) != 0) {
      throw std::runtime_error("cannot stat " + opt.hset);
    }
    const uint64_t file_size = static_cast<uint64_t>(st.st_size);
    const uint64_t mem_total_kb = meminfo_kb("MemTotal");
    const uint64_t mem_avail0_kb = meminfo_kb("MemAvailable");
    std::cerr << "hset " << opt.hset << ": " << file_size / 1048576.0 << " MiB; MemAvailable "
              << mem_avail0_kb / 1024.0 << " MiB of " << mem_total_kb / 1024.0 << " MiB ("
              << 100.0 * file_size / (mem_avail0_kb * 1024.0) << "% of available)\n";
    if (file_size > mem_avail0_kb * 1024) {
      std::cerr << "WARNING: hset is larger than MemAvailable; timings will include I/O\n";
    }
    if (affinity_cpus == 1 && opt.threads > 1) {
      std::cerr << "note: process is pinned to one CPU; the analysis pass's " << opt.threads
                << " threads will share it (prefer --pin-cpu)\n";
    }

    // 1. warm the page cache
    const auto wr = warm_reads(opt.hset, opt.warm_reads, file_size);

    // 2. map and load
    auto t0 = Clock::now();
    Mapping map(opt.hset, file_size, opt.populate);
    SFHASH_Error* err = nullptr;
    std::unique_ptr<SFHASH_Hashset, decltype(&sfhash_destroy_hashset)> hset(
      sfhash_load_hashset(map.base, static_cast<const char*>(map.base) + file_size, &err),
      sfhash_destroy_hashset
    );
    if (!hset) {
      throw std::runtime_error(std::string("cannot load hset: ") + (err ? err->message : "?"));
    }
    const double load_s = secs_since(t0);

    const int tidx_i = sfhash_hashset_index_for_type(hset.get(), SFHASH_TLSH);
    if (tidx_i < 0) {
      throw std::runtime_error("hset has no TLSH hash set");
    }
    const size_t tidx = static_cast<size_t>(tidx_i);
    const uint64_t n = sfhash_hashset_count(hset.get(), tidx);
    if (n == 0) {
      throw std::runtime_error("TLSH hash set is empty");
    }
    const TlshDigest* rows = static_cast<const TlshDigest*>(sfhash_hashset_hash(hset.get(), tidx, 0));
    const uint32_t strategies = sfhash_hashset_tlsh_knn_strategies(hset.get(), tidx);
    const auto& hs_tuple = hset->holder.hsets[tidx];
    const TlshIvfView& ivf_view = std::get<TlshIvfView>(hs_tuple);

    std::vector<std::string> methods;
    for (const auto& m: opt.methods) {
      if (m == "index" && !(strategies & SFHASH_TLSH_KNN_INDEX)) {
        std::cerr << "WARNING: hset has no TIVF index; skipping method index\n";
        continue;
      }
      methods.push_back(m);
    }

    // null rows sort first (all-zero bytes)
    uint64_t null_rows = 0;
    while (null_rows < n && rows[null_rows].is_null()) {
      ++null_rows;
    }

    std::cerr << "TLSH rows " << n << " (" << null_rows << " null), index "
              << ((strategies & SFHASH_TLSH_KNN_INDEX) ? "yes" : "no") << " (" << ivf_view.lists
              << " lists), load " << load_s << " s\n";

    // the rows' embeddings, for the embed method and the deep ranking:
    // untimed, before the timed passes
    EmbeddingMatrix emb;
    double embed_s = 0;
    if (std::find(methods.begin(), methods.end(), "embed") != methods.end() || (opt.analysis && opt.deep_k)) {
      const auto et0 = Clock::now();
      emb.compute(rows, n, opt.threads);
      embed_s = secs_since(et0);
      std::cerr << "row embeddings: " << n * DIMS * sizeof(float) / 1048576.0 << " MiB in " << embed_s
                << " s on " << opt.threads << " threads\n";
    }
    const float* vecs = emb.data;

    // 3. queries
    std::unordered_set<uint64_t> none;
    std::vector<Query> queries;
    std::vector<uint64_t> member_rows;
    {
      std::mt19937_64 mrng(opt.member_seed);
      member_rows = sample_rows(mrng, null_rows, n, opt.queries, none);
      std::mt19937_64 rrng(opt.random_seed);
      for (const auto& s: opt.sets) {
        for (size_t i = 0; i < opt.queries; ++i) {
          if (s == "member") {
            queries.push_back({s, i, rows[member_rows[i]], static_cast<int64_t>(member_rows[i])});
          }
          else {
            queries.push_back({s, i, random_digest(rrng), -1});
          }
        }
      }
    }
    // warm-up queries, drawn apart from the measured ones
    std::vector<TlshDigest> warm_member, warm_random;
    {
      std::mt19937_64 wrng(opt.warmup_seed);
      std::unordered_set<uint64_t> measured(member_rows.begin(), member_rows.end());
      const size_t avail = (n - null_rows) - measured.size();
      for (uint64_t r: sample_rows(wrng, null_rows, n, std::min(opt.warmup, avail), measured)) {
        warm_member.push_back(rows[r]);
      }
      for (size_t i = 0; i < opt.warmup; ++i) {
        warm_random.push_back(random_digest(wrng));
      }
    }
    auto set_queries = [&](const std::string& s) {
      std::vector<const Query*> v;
      for (const auto& q: queries) {
        if (q.set == s) v.push_back(&q);
      }
      return v;
    };

    // 4. timer overhead
    const TimerOverhead tov = timer_overhead();
    std::cerr << "steady_clock overhead: min " << tov.min_ns << " ns, median " << tov.median_ns
              << " ns, mean " << tov.mean_ns << " ns\n";

    if (opt.pin_cpu >= 0) {
      pin_thread(opt.pin_cpu);
    }

    const double resident_before = map.resident();
    const uint64_t mem_avail1_kb = meminfo_kb("MemAvailable");
    std::cerr << "hset resident before timing: " << 100 * resident_before << "%\n";

    // 5. timed passes: for each set, for each method, warm up then time
    const Kernel kernel = opt.embed_kernel == "lib" ? emb_dist2_lib : emb_dist2_vec;
    auto run_embed = [&](const void* d, size_t k) {
      return opt.embed_kernel == "lib"
        ? embed_knn<emb_dist2_lib>(vecs, n, d, k, opt.include_length)
        : embed_knn<emb_dist2_vec>(vecs, n, d, k, opt.include_length);
    };
    std::vector<SFHASH_TlshMatch> mbuf(opt.k);
    auto run_lib = [&](const void* d, uint32_t strategy) {
      return sfhash_hashset_tlsh_knn_with(
        hset.get(), tidx, d, opt.k, opt.max_distance, opt.include_length, strategy, mbuf.data()
      );
    };

    std::vector<Pass> passes;
    for (const auto& s: opt.sets) {
      const auto qs = set_queries(s);
      const auto& warm = s == "member" ? warm_member : warm_random;
      for (const auto& m: methods) {
        Pass p;
        p.set = s;
        p.method = m;
        const uint32_t strategy = m == "brute" ? SFHASH_TLSH_KNN_BRUTE : SFHASH_TLSH_KNN_INDEX;

        auto wt0 = Clock::now();
        volatile size_t sink = 0;
        for (const auto& d: warm) {
          sink = sink + (m == "embed" ? run_embed(&d, opt.k).size() : run_lib(&d, strategy));
        }
        p.warmup_s = secs_since(wt0);

        p.ns.resize(qs.size());
        p.rows.resize(qs.size());
        p.tdist.resize(qs.size());
        p.edist.resize(qs.size());
        if (m == "index") p.ivf.resize(qs.size());

        const auto pt0 = Clock::now();
        const size_t report_every = std::max<size_t>(1, qs.size() / 10);
        for (size_t i = 0; i < qs.size(); ++i) {
          const TlshDigest* d = &qs[i]->d;
          if (m == "embed") {
            const auto a = Clock::now();
            std::vector<EmbHit> hits = run_embed(d, opt.k);
            const auto b = Clock::now();
            p.ns[i] = std::chrono::duration<double, std::nano>(b - a).count();
            for (const auto& h: hits) {
              p.rows[i].push_back(h.row);
              p.edist[i].push_back(h.d);
            }
          }
          else {
            const auto a = Clock::now();
            const size_t cnt = run_lib(d, strategy);
            const auto b = Clock::now();
            p.ns[i] = std::chrono::duration<double, std::nano>(b - a).count();
            for (size_t j = 0; j < cnt; ++j) {
              p.rows[i].push_back(mbuf[j].index);
              p.tdist[i].push_back(mbuf[j].distance);
            }
            if (m == "index") {
              // untimed: the same search again, with work counters
              tlsh_knn_ivf(ivf_view, rows, *d, opt.k, opt.max_distance, opt.include_length, &p.ivf[i]);
            }
          }
          if ((i + 1) % report_every == 0) {
            const double el = secs_since(pt0);
            std::cerr << "  " << s << "/" << m << ": " << (i + 1) << "/" << qs.size() << " ("
                      << el << " s, eta " << el / (i + 1) * (qs.size() - i - 1) << " s)\n";
          }
        }
        p.timed_s = secs_since(pt0);
        std::cerr << s << "/" << m << ": warm-up " << warm.size() << " queries " << p.warmup_s
                  << " s, timed " << qs.size() << " queries " << p.timed_s << " s\n";
        passes.push_back(std::move(p));
      }
    }
    const double resident_after = map.resident();

    // 6. untimed analysis: full TLSH distance histogram and deep embedding
    // ranking per query, several queries per scan, across threads
    struct Depth {
      std::vector<uint64_t> hist;   // TLSH distance -> rows
      std::vector<EmbHit> deep;
      uint64_t identical = 0;
    };
    std::vector<Depth> depth(queries.size());
    double analysis_s = 0;
    for (size_t i = 0; i < queries.size(); ++i) {
      const auto range = std::equal_range(rows, rows + n, queries[i].d);
      depth[i].identical = static_cast<uint64_t>(range.second - range.first);
    }
    if (opt.analysis) {
      const auto at0 = Clock::now();
      constexpr size_t BATCH = 8;
      std::atomic<size_t> next{0};
      std::atomic<size_t> done{0};
      const size_t nbatches = (queries.size() + BATCH - 1) / BATCH;
      auto worker = [&]() {
        if (opt.pin_cpu >= 0) {
          pthread_setaffinity_np(pthread_self(), sizeof orig_mask, &orig_mask);
        }
        for (size_t b; (b = next.fetch_add(1)) < nbatches;) {
          const size_t lo = b * BATCH;
          const size_t hi = std::min(queries.size(), lo + BATCH);
          const size_t m = hi - lo;
          std::vector<std::vector<uint64_t>> hist(m, std::vector<uint64_t>(MAX_TLSH_DIST, 0));
          for (uint64_t r = 0; r < n; ++r) {
            for (size_t j = 0; j < m; ++j) {
              ++hist[j][tlsh_diff(queries[lo + j].d, rows[r], opt.include_length)];
            }
          }
          if (opt.deep_k) {
            std::vector<std::array<float, DIMS>> qv(m);
            std::vector<EmbTopK> tops;
            for (size_t j = 0; j < m; ++j) {
              sfhash_tlsh_embed(&queries[lo + j].d, qv[j].data());
              tops.emplace_back(opt.deep_k);
            }
            const float* v = vecs;
            for (uint64_t r = 0; r < n; ++r, v += DIMS) {
              for (size_t j = 0; j < m; ++j) {
                tops[j].push(kernel(qv[j].data(), v, opt.include_length), r);
              }
            }
            for (size_t j = 0; j < m; ++j) {
              depth[lo + j].deep = tops[j].sorted();
            }
          }
          for (size_t j = 0; j < m; ++j) {
            depth[lo + j].hist = std::move(hist[j]);
          }
          const size_t dn = done.fetch_add(1) + 1;
          if (dn % std::max<size_t>(1, nbatches / 10) == 0) {
            std::cerr << "  analysis: " << dn << "/" << nbatches << " batches (" << secs_since(at0) << " s)\n";
          }
        }
      };
      std::vector<std::thread> pool;
      for (unsigned t = 0; t < opt.threads; ++t) {
        pool.emplace_back(worker);
      }
      for (auto& t: pool) {
        t.join();
      }
      analysis_s = secs_since(at0);
      std::cerr << "analysis pass: " << analysis_s << " s on " << opt.threads << " threads\n";
    }

    // 7. checks and per-query derived values
    auto find_pass = [&](const std::string& s, const std::string& m) -> Pass* {
      for (auto& p: passes) {
        if (p.set == s && p.method == m) return &p;
      }
      return nullptr;
    };

    struct QDerived {
      bool have_dk = false;
      uint32_t d_k = 0;
      uint64_t count_lt = 0, count_le = 0;
      int index_exact = -1; // -1 n/a
    };
    std::vector<QDerived> qd(queries.size());
    struct SetChecks {
      size_t index_mismatch = 0;
      size_t index_count_mismatch = 0;
      size_t brute_dk_mismatch = 0;  // brute's k-th distance vs histogram
      size_t lib_dist_mismatch = 0;  // library distance vs sfhash_tlsh_diff
      size_t deep_prefix_mismatch = 0; // embed top-k vs deep top-k prefix
      double recall_naive = 0, recall_tie = 0;
      size_t recall_n = 0;
    };
    std::vector<SetChecks> checks(opt.sets.size());

    // global query index of (set, qid)
    std::vector<size_t> set_base(opt.sets.size());
    for (size_t si = 0, base = 0; si < opt.sets.size(); ++si, base += opt.queries) {
      set_base[si] = base;
    }

    for (size_t si = 0; si < opt.sets.size(); ++si) {
      const std::string& s = opt.sets[si];
      Pass* brute = find_pass(s, "brute");
      Pass* index = find_pass(s, "index");
      Pass* embed = find_pass(s, "embed");
      auto& c = checks[si];
      for (size_t i = 0; i < opt.queries; ++i) {
        const size_t gi = set_base[si] + i;
        const Query& q = queries[gi];
        QDerived& x = qd[gi];

        if (opt.analysis) {
          // d_k: the k-th smallest distance <= max_distance, from the histogram
          uint64_t cum = 0;
          uint32_t last = 0;
          bool any = false;
          for (uint32_t d = 0; d < MAX_TLSH_DIST && d <= opt.max_distance; ++d) {
            if (!depth[gi].hist[d]) continue;
            any = true;
            last = d;
            if (cum + depth[gi].hist[d] >= opt.k) {
              cum += depth[gi].hist[d];
              break;
            }
            cum += depth[gi].hist[d];
          }
          if (any && !q.d.is_null()) {
            x.have_dk = true;
            x.d_k = last;
            for (uint32_t d = 0; d <= x.d_k; ++d) {
              (d < x.d_k ? x.count_lt : x.count_le) += depth[gi].hist[d];
            }
            x.count_le += x.count_lt;
          }
          if (brute) {
            const auto& bd = brute->tdist[i];
            if (x.have_dk != !bd.empty() || (!bd.empty() && bd.back() != x.d_k)) {
              ++c.brute_dk_mismatch;
            }
          }
        }

        for (Pass* p: {brute, index}) {
          if (!p) continue;
          for (size_t j = 0; j < p->rows[i].size(); ++j) {
            const int d = sfhash_tlsh_diff(&q.d, &rows[p->rows[i][j]], opt.include_length);
            if (d < 0 || static_cast<uint32_t>(d) != p->tdist[i][j]) ++c.lib_dist_mismatch;
          }
        }

        if (brute && index) {
          const bool same = brute->rows[i] == index->rows[i] && brute->tdist[i] == index->tdist[i];
          x.index_exact = same ? 1 : 0;
          if (!same) ++c.index_mismatch;
          if (brute->rows[i].size() != index->rows[i].size()) ++c.index_count_mismatch;
        }

        if (embed && opt.analysis && opt.deep_k) {
          const auto& deep = depth[gi].deep;
          const auto& er = embed->rows[i];
          bool same = true;
          for (size_t j = 0; j < er.size(); ++j) {
            if (j >= deep.size() || deep[j].row != er[j] || deep[j].d != embed->edist[i][j]) {
              same = false;
              break;
            }
          }
          if (!same) ++c.deep_prefix_mismatch;
        }

        if (embed && brute && !brute->rows[i].empty()) {
          std::unordered_set<uint64_t> b(brute->rows[i].begin(), brute->rows[i].end());
          size_t inter = 0, tie = 0;
          const uint32_t dk = brute->tdist[i].back();
          for (uint64_t r: embed->rows[i]) {
            inter += b.count(r);
            const int d = sfhash_tlsh_diff(&q.d, &rows[r], opt.include_length);
            tie += d >= 0 && static_cast<uint32_t>(d) <= dk;
          }
          c.recall_naive += static_cast<double>(inter) / b.size();
          c.recall_tie += std::min(1.0, static_cast<double>(tie) / b.size());
          ++c.recall_n;
        }
      }
      if (c.recall_n) {
        c.recall_naive /= c.recall_n;
        c.recall_tie /= c.recall_n;
      }
    }

    // 8. outputs
    {
      Csv f(out / "queries.csv",
            "qset,qid,digest,lval,source_row,n_identical,d_k,count_lt,count_le,index_exact");
      for (size_t gi = 0; gi < queries.size(); ++gi) {
        const Query& q = queries[gi];
        const QDerived& x = qd[gi];
        std::fprintf(f.f, "%s,%zu,%s,%u,", q.set.c_str(), q.qid, hex(q.d).c_str(), unsigned(q.d.L));
        if (q.source_row >= 0) std::fprintf(f.f, "%lld", static_cast<long long>(q.source_row));
        std::fprintf(f.f, ",%llu,", static_cast<unsigned long long>(depth[gi].identical));
        if (x.have_dk) {
          std::fprintf(f.f, "%u,%llu,%llu", x.d_k, static_cast<unsigned long long>(x.count_lt),
                       static_cast<unsigned long long>(x.count_le));
        }
        else {
          std::fputs(",,", f.f);
        }
        std::fputc(',', f.f);
        if (x.index_exact >= 0) std::fputs(x.index_exact ? "true" : "false", f.f);
        std::fputc('\n', f.f);
      }
    }
    {
      Csv f(out / "timings.csv", "qset,qid,method,ns,n_results,ivf_cells,ivf_lists,ivf_rows");
      for (const auto& p: passes) {
        for (size_t i = 0; i < p.ns.size(); ++i) {
          std::fprintf(f.f, "%s,%zu,%s,%.0f,%zu,", p.set.c_str(), i, p.method.c_str(), p.ns[i],
                       p.rows[i].size());
          if (!p.ivf.empty()) {
            std::fprintf(f.f, "%llu,%llu,%llu\n",
                         static_cast<unsigned long long>(p.ivf[i].cells),
                         static_cast<unsigned long long>(p.ivf[i].lists),
                         static_cast<unsigned long long>(p.ivf[i].rows));
          }
          else {
            std::fputs(",,\n", f.f);
          }
        }
      }
    }
    {
      Csv f(out / "results.csv", "qset,qid,method,rank,row_idx,tlsh_dist,emb_dist2");
      for (const auto& p: passes) {
        const size_t si = std::find(opt.sets.begin(), opt.sets.end(), p.set) - opt.sets.begin();
        for (size_t i = 0; i < p.rows.size(); ++i) {
          const Query& q = queries[set_base[si] + i];
          alignas(16) float qv[DIMS];
          sfhash_tlsh_embed(&q.d, qv);
          for (size_t j = 0; j < p.rows[i].size(); ++j) {
            const uint64_t r = p.rows[i][j];
            const int td = sfhash_tlsh_diff(&q.d, &rows[r], opt.include_length);
            // the row's embedding: from the matrix when it was computed,
            // else computed here (the same values)
            alignas(16) float rv[DIMS];
            const float* v = vecs ? vecs + r * DIMS : rv;
            if (!vecs) {
              sfhash_tlsh_embed(&rows[r], rv);
            }
            const float ed = p.method == "embed" ? p.edist[i][j] : kernel(qv, v, opt.include_length);
            std::fprintf(f.f, "%s,%zu,%s,%zu,%llu,%d,%.9g\n", p.set.c_str(), i, p.method.c_str(), j + 1,
                         static_cast<unsigned long long>(r), td, ed);
          }
        }
      }
    }
    if (opt.analysis && opt.deep_k) {
      Csv f(out / "deep.csv", "qset,qid,rank,row_idx,emb_dist2,tlsh_dist");
      for (size_t gi = 0; gi < queries.size(); ++gi) {
        const Query& q = queries[gi];
        const auto& deep = depth[gi].deep;
        for (size_t j = 0; j < deep.size(); ++j) {
          std::fprintf(f.f, "%s,%zu,%zu,%llu,%.9g,%d\n", q.set.c_str(), q.qid, j + 1,
                       static_cast<unsigned long long>(deep[j].row), deep[j].d,
                       sfhash_tlsh_diff(&q.d, &rows[deep[j].row], opt.include_length));
        }
      }
    }
    if (opt.analysis && opt.hist) {
      Csv f(out / "hist.csv", "qset,qid,tlsh_dist,n_rows");
      for (size_t gi = 0; gi < queries.size(); ++gi) {
        const Query& q = queries[gi];
        for (uint32_t d = 0; d < MAX_TLSH_DIST; ++d) {
          if (depth[gi].hist[d]) {
            std::fprintf(f.f, "%s,%zu,%u,%llu\n", q.set.c_str(), q.qid, d,
                         static_cast<unsigned long long>(depth[gi].hist[d]));
          }
        }
      }
    }

    // 9. summary
    std::ostringstream sum;
    sum << "\nvs_knn_eval summary: " << opt.hset << "\n"
        << "rows " << n << ", k " << opt.k << ", max_distance " << opt.max_distance
        << ", include_length " << (opt.include_length ? "true" : "false")
        << ", embed kernel " << opt.embed_kernel << ", timer overhead " << tov.median_ns
        << " ns (median, not subtracted)\n\n";
    char line[256];
    std::snprintf(line, sizeof line, "%-7s %-6s %6s %11s %11s %11s %11s %11s %11s %9s\n",
                  "set", "method", "n", "mean_us", "median_us", "stddev_us", "p99_us", "max_us",
                  "min_us", "ns/row");
    sum << line;
    std::vector<std::pair<const Pass*, Stats>> pstats;
    for (const auto& p: passes) {
      const Stats st = stats_us(p.ns);
      pstats.emplace_back(&p, st);
      std::snprintf(line, sizeof line, "%-7s %-6s %6zu %11.1f %11.1f %11.1f %11.1f %11.1f %11.1f %9.3f\n",
                    p.set.c_str(), p.method.c_str(), st.n, st.mean, st.median, st.stddev, st.p99,
                    st.max, st.min, st.mean * 1000.0 / n);
      sum << line;
    }
    sum << "\n";
    for (size_t si = 0; si < opt.sets.size(); ++si) {
      const auto& c = checks[si];
      const bool have_bi = find_pass(opt.sets[si], "brute") && find_pass(opt.sets[si], "index");
      sum << opt.sets[si] << ": ";
      if (have_bi) {
        sum << "brute/index mismatches " << c.index_mismatch << " of " << opt.queries;
        if (c.index_mismatch) sum << "  <<<<<<<<<< INDEX IS NOT EXACT >>>>>>>>>>";
      }
      if (c.recall_n) {
        std::snprintf(line, sizeof line, "; embed recall@%zu naive %.4f, tie-aware %.4f", opt.k,
                      c.recall_naive, c.recall_tie);
        sum << line;
      }
      sum << "\n";
      if (c.lib_dist_mismatch || c.brute_dk_mismatch || c.deep_prefix_mismatch || c.index_count_mismatch) {
        sum << "  WARNING: lib-vs-sfhash_tlsh_diff distance mismatches " << c.lib_dist_mismatch
            << ", brute d_k vs full scan " << c.brute_dk_mismatch
            << ", embed top-k vs deep prefix " << c.deep_prefix_mismatch
            << ", brute/index result counts " << c.index_count_mismatch << "\n";
      }
    }
    std::snprintf(line, sizeof line,
                  "\nhset %.1f MiB, MemAvailable %.1f MiB at start / %.1f MiB before timing; "
                  "resident %.1f%% before / %.1f%% after timing\n",
                  file_size / 1048576.0, mem_avail0_kb / 1024.0, mem_avail1_kb / 1024.0,
                  100 * resident_before, 100 * resident_after);
    sum << line;
    sum << "analysis pass " << analysis_s << " s; total " << secs_since(run_t0) << " s\n";
    std::cout << sum.str() << std::flush;
    {
      std::ofstream f(out / "summary.txt");
      f << sum.str();
    }

    // 10. run metadata
    {
      std::ofstream j(out / "run.json");
      j.precision(10);
      j << "{\n";
      j << "  \"program\": \"vs_knn_eval\",\n";
      j << "  \"date\": " << json_str(iso_now()) << ",\n";
      j << "  \"git_commit\": " << json_str(git_commit()) << ",\n";
      j << "  \"binary_built\": " << json_str(std::string(__DATE__) + " " + __TIME__) << ",\n";
      j << "  \"argv\": [";
      for (int i = 0; i < argc; ++i) j << (i ? ", " : "") << json_str(argv[i]);
      j << "],\n";
      j << "  \"hset\": {\"path\": " << json_str(opt.hset) << ", \"size_bytes\": " << file_size
        << ", \"name\": " << json_str(sfhash_hashset_name(hset.get()))
        << ", \"timestamp\": " << json_str(sfhash_hashset_timestamp(hset.get()))
        << ", \"tlsh_rows\": " << n << ", \"null_rows\": " << null_rows
        << ", \"has_index\": " << ((strategies & SFHASH_TLSH_KNN_INDEX) ? "true" : "false")
        << ", \"ivf_lists\": " << ivf_view.lists
        << ", \"embed_seconds\": " << embed_s
        << ", \"load_seconds\": " << load_s << "},\n";
      j << "  \"params\": {\"k\": " << opt.k << ", \"max_distance\": " << opt.max_distance
        << ", \"include_length\": " << (opt.include_length ? "true" : "false")
        << ", \"queries_per_set\": " << opt.queries << ", \"deep_k\": " << opt.deep_k
        << ", \"embed_kernel\": " << json_str(opt.embed_kernel)
        << ", \"sets\": [";
      for (size_t i = 0; i < opt.sets.size(); ++i) j << (i ? ", " : "") << json_str(opt.sets[i]);
      j << "], \"methods\": [";
      for (size_t i = 0; i < methods.size(); ++i) j << (i ? ", " : "") << json_str(methods[i]);
      j << "]},\n";
      // hex strings: u64 seeds do not survive JSON readers that use doubles
      j << "  \"seeds\": {\"member\": " << json_str(hex_u64(opt.member_seed))
        << ", \"random\": " << json_str(hex_u64(opt.random_seed))
        << ", \"warmup\": " << json_str(hex_u64(opt.warmup_seed))
        << ", \"rng\": \"std::mt19937_64, rng() % m\"},\n";
      j << "  \"warmup\": {\"file_reads\": [";
      for (size_t i = 0; i < wr.size(); ++i) {
        j << (i ? ", " : "") << "{\"seconds\": " << wr[i].seconds << ", \"mib_per_s\": " << wr[i].mib_per_s << "}";
      }
      j << "], \"queries_per_set_method\": " << opt.warmup << ", \"mmap_populate\": "
        << (opt.populate ? "true" : "false") << "},\n";
      j << "  \"timer_overhead_ns\": {\"min\": " << tov.min_ns << ", \"median\": " << tov.median_ns
        << ", \"mean\": " << tov.mean_ns << ", \"subtracted\": false},\n";
      j << "  \"machine\": {\"cpu\": " << json_str(cpu_model()) << ", \"online_cpus\": "
        << std::thread::hardware_concurrency() << ", \"affinity_cpus\": " << affinity_cpus
        << ", \"pin_cpu\": " << opt.pin_cpu << ", \"analysis_threads\": " << opt.threads
        << ", \"mem_total_kb\": " << mem_total_kb << ", \"mem_available_kb_start\": " << mem_avail0_kb
        << ", \"mem_available_kb_before_timing\": " << mem_avail1_kb
        << ", \"hset_resident_before_timing\": " << resident_before
        << ", \"hset_resident_after_timing\": " << resident_after
        << ", \"kernel\": " << json_str(run_cmd("uname -sr")) << "},\n";
      j << "  \"passes\": [\n";
      for (size_t i = 0; i < pstats.size(); ++i) {
        const Pass& p = *pstats[i].first;
        const Stats& st = pstats[i].second;
        j << "    {\"set\": " << json_str(p.set) << ", \"method\": " << json_str(p.method)
          << ", \"n\": " << st.n << ", \"mean_us\": " << st.mean << ", \"median_us\": " << st.median
          << ", \"stddev_us\": " << st.stddev << ", \"p99_us\": " << st.p99 << ", \"max_us\": " << st.max
          << ", \"min_us\": " << st.min << ", \"warmup_seconds\": " << p.warmup_s
          << ", \"timed_seconds\": " << p.timed_s << "}" << (i + 1 < pstats.size() ? "," : "") << "\n";
      }
      j << "  ],\n";
      j << "  \"checks\": [\n";
      for (size_t si = 0; si < opt.sets.size(); ++si) {
        const auto& c = checks[si];
        j << "    {\"set\": " << json_str(opt.sets[si]) << ", \"brute_index_mismatches\": " << c.index_mismatch
          << ", \"brute_index_count_mismatches\": " << c.index_count_mismatch
          << ", \"lib_distance_mismatches\": " << c.lib_dist_mismatch
          << ", \"brute_dk_mismatches\": " << c.brute_dk_mismatch
          << ", \"embed_deep_prefix_mismatches\": " << c.deep_prefix_mismatch
          << ", \"embed_recall_naive\": " << c.recall_naive << ", \"embed_recall_tie_aware\": " << c.recall_tie
          << "}" << (si + 1 < opt.sets.size() ? "," : "") << "\n";
      }
      j << "  ],\n";
      j << "  \"analysis_seconds\": " << analysis_s << ",\n";
      j << "  \"total_seconds\": " << secs_since(run_t0) << "\n";
      j << "}\n";
    }

    // every output is written; a non-exact index is still a failed run
    size_t bad = 0;
    for (const auto& c: checks) bad += c.index_mismatch;
    return bad ? 3 : 0;
  }
  catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << std::endl;
    return 2;
  }
}
