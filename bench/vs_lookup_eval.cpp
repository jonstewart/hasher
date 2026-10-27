// bench/vs_lookup_eval.cpp
//
// Hash set lookup eval driver: times individual SHA-256 lookups through the
// public client API (sfhash_hashset_lookup, include/hasher/hashset.h) against
// an hset, e.g. the VirusShare hset with records. Single-threaded:
//
//   bench/vs_lookup_eval export   HSET --out sha256.txt [--seed S]
//   bench/vs_lookup_eval found    HSET --list sha256.txt --csv found.csv
//   bench/vs_lookup_eval notfound HSET --list sha256.txt --csv notfound.csv
//
// export    writes every SHA-256 of the hset's sha256 hash set as lowercase
//           hex, one per line, shuffled with mt19937_64(seed) (std::shuffle,
//           libstdc++), and compares the count with the record count.
// found     looks up every hash of the list, each timed on its own; the first
//           miss prints the hash and its position and exits 2.
// notfound  looks up --count (10,000) uniformly random SHA-256 values, the
//           32 bytes drawn from mt19937_64(seed) (seed from std::random_device
//           unless --seed is given), each timed on its own. A hit that is in
//           the exported list is a genuine collision (recorded); a hit that is
//           not, or a random value that is in the list but was not found, is a
//           lookup bug and exits 2.
//
// Before a timed pass (found, notfound): the hset file is streamed N times
// with large read()s (--warm-reads, default 3), every page of the mapping the
// library uses is touched once, the file size is compared against
// MemAvailable, and --warmup-queries lookups run untimed (default 100000;
// "all" for the whole list). After the per-query pass, an aggregate pass times
// the whole query set as one region (no per-query timer cost) as a cross-check
// of the mean; --catch-bench K adds a Catch2 BENCHMARK over K sampled queries.
//
// Outputs: the per-query CSV (i,sha256,found,ns; ns is the raw timed interval
// including the timer's own overhead, which is reported separately) and a
// JSON run-metadata file (--meta, default <csv>.meta.json or <out>.meta.json).
//
// Exit codes: 0 ok, 1 usage/IO error, 2 lookup assertion failed.

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "hasher/common.h"
#include "hasher/hashset.h"
#include "hasher/hex.h"

// Internal header, only for the record count, which the public API does not
// expose.
#include "hashset/hset.h"

namespace bip = boost::interprocess;

namespace {

using Hash = std::array<uint8_t, 32>;
using clk = std::chrono::steady_clock;

[[noreturn]] void die(const std::string& msg, int code = 1) {
  std::fflush(stdout);
  std::fprintf(stderr, "vs_lookup_eval: %s\n", msg.c_str());
  std::exit(code);
}

std::string hex(const Hash& h) {
  char buf[65];
  sfhash_hex(buf, h.data(), h.size());
  buf[64] = '\0';
  return buf;
}

double secs_since(clk::time_point t0) {
  return std::chrono::duration<double>(clk::now() - t0).count();
}

// --------------------------------------------------------------------------
// Options
// --------------------------------------------------------------------------

struct Options {
  std::string cmd;
  std::string hset;
  std::string list;      // export: --out; found/notfound: --list
  std::string csv;
  std::string meta;
  bool seed_given = false;
  uint64_t seed = 0x5653'4C4B'5550'0001ull;  // export default ("VSLKUP" 1)
  uint64_t count = 10000;                    // notfound
  uint64_t limit = 0;                        // found: 0 = whole list
  unsigned warm_reads = 3;
  uint64_t warmup_queries = 100000;
  bool warmup_all = false;
  bool aggregate = true;
  uint64_t catch_bench = 0;
  double noise_secs = 2.0;
  bool unique = false;        // export
  uint64_t inject_hits = 0;   // notfound self-test
};

void usage() {
  std::fprintf(stderr,
    "usage:\n"
    "  vs_lookup_eval export   HSET --out LIST [--seed S] [--unique] [--meta FILE]\n"
    "  vs_lookup_eval found    HSET --list LIST --csv CSV [common]\n"
    "                          [--limit K]\n"
    "  vs_lookup_eval notfound HSET [--list LIST] --csv CSV [common]\n"
    "                          [--count N (10000)] [--seed S (random_device)]\n"
    "                          [--inject-hits K (self-test: replace K queries\n"
    "                           with hashes taken from the hset)]\n"
    "common: [--warm-reads N (3)] [--warmup-queries M|all (100000)]\n"
    "        [--no-aggregate] [--catch-bench K] [--noise-secs S (2)]\n"
    "        [--meta FILE (CSV.meta.json)]\n");
}

uint64_t parse_u64(const std::string& s, const char* what) {
  try {
    size_t pos = 0;
    const uint64_t v = std::stoull(s, &pos, 0);
    if (pos != s.size()) throw std::invalid_argument(s);
    return v;
  }
  catch (const std::exception&) {
    die(std::string("bad value for ") + what + ": '" + s + "'");
  }
}

Options parse_args(int argc, char** argv) {
  if (argc < 3) { usage(); std::exit(1); }
  Options o;
  o.cmd = argv[1];
  o.hset = argv[2];
  if (o.cmd != "export" && o.cmd != "found" && o.cmd != "notfound") {
    usage(); std::exit(1);
  }
  for (int i = 3; i < argc; ++i) {
    const std::string a = argv[i];
    auto val = [&]() -> std::string {
      if (i + 1 >= argc) die("missing value for " + a);
      return argv[++i];
    };
    if (a == "--out" || a == "--list") o.list = val();
    else if (a == "--csv") o.csv = val();
    else if (a == "--meta") o.meta = val();
    else if (a == "--seed") { o.seed = parse_u64(val(), "--seed"); o.seed_given = true; }
    else if (a == "--count") o.count = parse_u64(val(), "--count");
    else if (a == "--limit") o.limit = parse_u64(val(), "--limit");
    else if (a == "--warm-reads") o.warm_reads = static_cast<unsigned>(parse_u64(val(), "--warm-reads"));
    else if (a == "--warmup-queries") {
      const std::string v = val();
      if (v == "all") o.warmup_all = true;
      else o.warmup_queries = parse_u64(v, "--warmup-queries");
    }
    else if (a == "--no-aggregate") o.aggregate = false;
    else if (a == "--catch-bench") o.catch_bench = parse_u64(val(), "--catch-bench");
    else if (a == "--unique") o.unique = true;
    else if (a == "--noise-secs") o.noise_secs = std::stod(val());
    else if (a == "--inject-hits") o.inject_hits = parse_u64(val(), "--inject-hits");
    else if (a == "-h" || a == "--help") { usage(); std::exit(0); }
    else { usage(); die("unknown argument '" + a + "'"); }
  }
  if (o.cmd == "export" && o.list.empty()) die("export needs --out LIST");
  if (o.cmd == "found" && o.list.empty()) die("found needs --list LIST");
  if (o.cmd != "export" && o.csv.empty()) die(o.cmd + " needs --csv CSV");
  if (o.meta.empty()) o.meta = (o.cmd == "export" ? o.list : o.csv) + ".meta.json";
  return o;
}

// --------------------------------------------------------------------------
// Environment
// --------------------------------------------------------------------------

std::string cpu_model() {
  std::ifstream in("/proc/cpuinfo");
  std::string line;
  while (std::getline(in, line)) {
    if (line.rfind("model name", 0) == 0) {
      const auto p = line.find(':');
      if (p != std::string::npos) {
        auto s = line.substr(p + 1);
        s.erase(0, s.find_first_not_of(" \t"));
        // collapse runs of spaces
        std::string out;
        for (char c: s) if (!(c == ' ' && !out.empty() && out.back() == ' ')) out += c;
        return out;
      }
    }
  }
  return "unknown";
}

uint64_t meminfo_kb(const char* key) {
  std::ifstream in("/proc/meminfo");
  std::string k;
  uint64_t v;
  std::string unit;
  while (in >> k >> v) {
    std::getline(in, unit);
    if (k == std::string(key) + ":") return v;
  }
  return 0;
}

std::string clocksource() {
  std::ifstream in("/sys/devices/system/clocksource/clocksource0/current_clocksource");
  std::string s;
  in >> s;
  return s.empty() ? "unknown" : s;
}

std::string loadavg() {
  std::ifstream in("/proc/loadavg");
  std::string a, b, c;
  in >> a >> b >> c;
  return a + " " + b + " " + c;
}

std::string iso_now() {
  const std::time_t t = std::time(nullptr);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

std::string hostname() {
  char buf[256] = {0};
  gethostname(buf, sizeof(buf) - 1);
  return buf;
}

// --------------------------------------------------------------------------
// JSON metadata (flat writer; values are numbers, strings or raw JSON)
// --------------------------------------------------------------------------

std::string jstr(const std::string& s) {
  std::string o = "\"";
  for (char c: s) {
    switch (c) {
    case '"': o += "\\\""; break;
    case '\\': o += "\\\\"; break;
    case '\n': o += "\\n"; break;
    case '\t': o += "\\t"; break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        char b[8];
        std::snprintf(b, sizeof(b), "\\u%04x", c);
        o += b;
      }
      else o += c;
    }
  }
  return o + "\"";
}

std::string jnum(double v) {
  if (!std::isfinite(v)) return "null";
  char b[64];
  if (v == std::floor(v) && std::fabs(v) < 1e15) {
    std::snprintf(b, sizeof(b), "%.0f", v);
  }
  else {
    std::snprintf(b, sizeof(b), "%.10g", v);
  }
  return b;
}

struct Json {
  std::vector<std::pair<std::string, std::string>> kv;
  void str(const std::string& k, const std::string& v) { kv.emplace_back(k, jstr(v)); }
  void num(const std::string& k, double v) { kv.emplace_back(k, jnum(v)); }
  void u64(const std::string& k, uint64_t v) { kv.emplace_back(k, std::to_string(v)); }
  void boolean(const std::string& k, bool v) { kv.emplace_back(k, v ? "true" : "false"); }
  void raw(const std::string& k, const std::string& v) { kv.emplace_back(k, v); }
  std::string dump(int indent = 2) const {
    std::string pad(indent, ' ');
    std::string o = "{\n";
    for (size_t i = 0; i < kv.size(); ++i) {
      o += pad + jstr(kv[i].first) + ": " + kv[i].second;
      o += (i + 1 < kv.size()) ? ",\n" : "\n";
    }
    return o + std::string(indent - 2, ' ') + "}";
  }
  void write(const std::string& path) const {
    std::ofstream out(path);
    if (!out) die("cannot write " + path);
    out << dump() << "\n";
    if (!out) die("error writing " + path);
  }
};

// This process's faults and context switches, sampled around a timed pass:
// interference (preemption, page faults) shows up here.
struct Interference {
  long minflt = 0, majflt = 0, nvcsw = 0, nivcsw = 0;

  static Interference sample() {
    Interference x;
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    x.minflt = ru.ru_minflt;
    x.majflt = ru.ru_majflt;
    x.nvcsw = ru.ru_nvcsw;
    x.nivcsw = ru.ru_nivcsw;
    return x;
  }

  // b minus a, as JSON, and printed
  static std::string delta(const Interference& a, const Interference& b) {
    Json j;
    j.raw("minor_faults", std::to_string(b.minflt - a.minflt));
    j.raw("major_faults", std::to_string(b.majflt - a.majflt));
    j.raw("voluntary_ctxsw", std::to_string(b.nvcsw - a.nvcsw));
    j.raw("involuntary_ctxsw", std::to_string(b.nivcsw - a.nivcsw));
    std::printf("interference: faults minor %ld major %ld; ctxsw vol %ld invol %ld\n",
                b.minflt - a.minflt, b.majflt - a.majflt, b.nvcsw - a.nvcsw,
                b.nivcsw - a.nivcsw);
    return j.dump(4);
  }
};

// --------------------------------------------------------------------------
// The hset: mapped read-only as the clients (hsetop) map it
// --------------------------------------------------------------------------

struct Hset {
  std::string path;
  bip::file_mapping fm;
  bip::mapped_region mr;
  std::unique_ptr<SFHASH_Hashset, void(*)(SFHASH_Hashset*)> h{nullptr, sfhash_destroy_hashset};
  int tidx = -1;
  uint64_t count = 0;

  explicit Hset(const std::string& p): path(p) {
    try {
      fm = bip::file_mapping(p.c_str(), bip::read_only);
      mr = bip::mapped_region(fm, bip::read_only);
    }
    catch (const bip::interprocess_exception& e) {
      die(p + ": " + e.what());
    }
    SFHASH_Error* err = nullptr;
    h.reset(sfhash_load_hashset(beg(), end(), &err));
    if (err) {
      const std::string msg = err->message;
      sfhash_free_error(err);
      die(p + ": " + msg);
    }
    tidx = sfhash_hashset_index_for_type(h.get(), SFHASH_SHA_2_256);
    if (tidx < 0) {
      die(p + ": no sha256 hash set (a records-only hset cannot be "
          "queried with sfhash_hashset_lookup)");
    }
    count = sfhash_hashset_count(h.get(), tidx);
  }

  const uint8_t* beg() const { return static_cast<const uint8_t*>(mr.get_address()); }
  const uint8_t* end() const { return beg() + mr.get_size(); }
  uint64_t size() const { return mr.get_size(); }
  uint64_t record_count() const { return h->holder.rhdr.record_count; }

  bool lookup(const Hash& x) const {
    return sfhash_hashset_lookup(h.get(), static_cast<size_t>(tidx), x.data());
  }
};

// --------------------------------------------------------------------------
// Hash lists
// --------------------------------------------------------------------------

void write_list(const std::string& path, const std::vector<Hash>& v) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) die("cannot write " + path);
  std::vector<char> buf(1 << 20);
  std::setvbuf(f, buf.data(), _IOFBF, buf.size());
  char line[65];
  line[64] = '\n';
  for (const auto& h: v) {
    sfhash_hex(line, h.data(), h.size());
    if (std::fwrite(line, 1, 65, f) != 65) die("error writing " + path);
  }
  if (std::fclose(f) != 0) die("error writing " + path);
}

std::vector<Hash> read_list(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) die("cannot read " + path);
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  std::vector<Hash> v;
  v.reserve(s.size() / 65 + 1);
  size_t pos = 0, lineno = 0;
  while (pos < s.size()) {
    size_t e = s.find('\n', pos);
    if (e == std::string::npos) e = s.size();
    ++lineno;
    size_t len = e - pos;
    if (len && s[pos + len - 1] == '\r') --len;
    if (len) {
      Hash h;
      if (len != 64 || !sfhash_unhex(h.data(), s.data() + pos, 64)) {
        die(path + ":" + std::to_string(lineno) + ": not a SHA-256 hex digest");
      }
      v.push_back(h);
    }
    pos = e + 1;
  }
  return v;
}

// --------------------------------------------------------------------------
// Page cache control
// --------------------------------------------------------------------------

struct WarmInfo {
  std::vector<double> read_secs;
  double touch_secs = 0;
  uint64_t mem_available_kb = 0;
  uint64_t mem_total_kb = 0;
  bool fits = true;
  double warmup_secs = 0;
  uint64_t warmup_n = 0;
};

void warm_file(const Hset& hs, unsigned passes, WarmInfo& wi) {
  wi.mem_available_kb = meminfo_kb("MemAvailable");
  wi.mem_total_kb = meminfo_kb("MemTotal");
  const double size_gib = hs.size() / double(1ull << 30);
  const double avail_gib = wi.mem_available_kb / double(1ull << 20);
  std::printf("hset file: %.3f GiB; MemAvailable %.2f GiB, MemTotal %.2f GiB\n",
              size_gib, avail_gib, wi.mem_total_kb / double(1ull << 20));
  // leave headroom for the query list, the timing arrays and the rest
  wi.fits = hs.size() < 0.8 * wi.mem_available_kb * 1024.0;
  if (!wi.fits) {
    std::printf("WARNING: the hset is larger than 80%% of MemAvailable; it will "
                "not stay in the page cache and lookups will include I/O\n");
  }

  const int fd = ::open(hs.path.c_str(), O_RDONLY);
  if (fd < 0) die("cannot open " + hs.path);
  std::vector<char> buf(16u << 20);
  for (unsigned p = 0; p < passes; ++p) {
    const auto t0 = clk::now();
    uint64_t total = 0;
    ssize_t r;
    while ((r = ::pread(fd, buf.data(), buf.size(), total)) > 0) total += r;
    if (r < 0) die("error reading " + hs.path);
    const double s = secs_since(t0);
    wi.read_secs.push_back(s);
    std::printf("warm read %u/%u: %.2f s, %.1f MiB/s\n", p + 1, passes, s,
                total / double(1u << 20) / s);
    std::fflush(stdout);
  }
  ::close(fd);

  // fault in every page of the mapping the library reads, so that the timed
  // lookups take no page faults (minor or major)
  const auto t0 = clk::now();
  const long page = sysconf(_SC_PAGESIZE);
  volatile uint8_t sink = 0;
  uint8_t acc = 0;
  for (const uint8_t* p = hs.beg(); p < hs.end(); p += page) acc ^= *p;
  sink = acc;
  (void)sink;
  wi.touch_secs = secs_since(t0);
  std::printf("touched every page of the mapping: %.2f s\n", wi.touch_secs);
}

// --------------------------------------------------------------------------
// Timers
// --------------------------------------------------------------------------

struct Timer {
  // Time fn() once with steady_clock; returns the interval in ns.
  template <class Fn>
  inline uint64_t time(Fn&& fn) const {
    const auto t0 = clk::now();
    fn();
    const auto t1 = clk::now();
    return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
  }
};

// --------------------------------------------------------------------------
// Statistics
// --------------------------------------------------------------------------

struct Stats {
  uint64_t n = 0;
  double mean = 0, median = 0, stddev = 0, p90 = 0, p99 = 0, p999 = 0,
         min = 0, max = 0;
};

// Percentiles are nearest-rank on the sorted sample, element floor(q (n - 1)),
// which is DuckDB's quantile_disc.
Stats stats_of(std::vector<double> v) {
  Stats s;
  s.n = v.size();
  if (v.empty()) return s;
  std::sort(v.begin(), v.end());
  double sum = 0;
  for (double x: v) sum += x;
  s.mean = sum / v.size();
  double ss = 0;
  for (double x: v) ss += (x - s.mean) * (x - s.mean);
  s.stddev = v.size() > 1 ? std::sqrt(ss / (v.size() - 1)) : 0.0;  // sample
  auto q = [&](double p) { return v[static_cast<size_t>(std::floor(p * (v.size() - 1)))]; };
  s.median = q(0.5);
  s.p90 = q(0.9);
  s.p99 = q(0.99);
  s.p999 = q(0.999);
  s.min = v.front();
  s.max = v.back();
  return s;
}

void print_stats(const char* title, const Stats& s, double wall_s) {
  std::printf("%s: n=%" PRIu64 " mean=%.1f median=%.1f stddev=%.1f p90=%.1f "
              "p99=%.1f p99.9=%.1f min=%.1f max=%.1f ns; wall %.3f s\n",
              title, s.n, s.mean, s.median, s.stddev, s.p90, s.p99, s.p999,
              s.min, s.max, wall_s);
}

std::string stats_json(const Stats& s) {
  Json j;
  j.u64("n", s.n);
  j.num("mean", s.mean);
  j.num("median", s.median);
  j.num("stddev", s.stddev);
  j.num("p90", s.p90);
  j.num("p99", s.p99);
  j.num("p99_9", s.p999);
  j.num("min", s.min);
  j.num("max", s.max);
  return j.dump(4);
}

// Platform noise floor: read the clock back to back for S seconds and count
// the gaps, i.e. the times the CPU was taken away (timer ticks, other
// interrupts, VM exits, preemption). A query that straddles one carries it.
struct Noise {
  double secs = 0;
  uint64_t over_2us = 0, over_5us = 0, over_10us = 0, over_100us = 0;
  double median_gap_over_5us_ns = 0, max_gap_ns = 0;
};

Noise measure_noise(double secs) {
  Noise nz;
  nz.secs = secs;
  if (secs <= 0) return nz;
  std::vector<double> gaps;
  const auto start = clk::now();
  const auto stop = start + std::chrono::duration_cast<clk::duration>(
    std::chrono::duration<double>(secs));
  auto prev = start;
  for (;;) {
    const auto t = clk::now();
    const double d = std::chrono::duration<double, std::nano>(t - prev).count();
    prev = t;
    if (d > 2000) {
      ++nz.over_2us;
      if (d > 5000) { ++nz.over_5us; gaps.push_back(d); }
      if (d > 10000) ++nz.over_10us;
      if (d > 100000) ++nz.over_100us;
    }
    if (t >= stop) break;
  }
  if (!gaps.empty()) {
    std::sort(gaps.begin(), gaps.end());
    nz.median_gap_over_5us_ns = gaps[gaps.size() / 2];
    nz.max_gap_ns = gaps.back();
  }
  std::printf("noise floor (%.1f s of back-to-back clock reads): gaps over 5 us "
              "%.0f/s (median %.1f us), over 10 us %.0f/s, over 100 us %" PRIu64
              ", max %.1f us\n", secs, nz.over_5us / secs,
              nz.median_gap_over_5us_ns / 1e3, nz.over_10us / secs,
              nz.over_100us, nz.max_gap_ns / 1e3);
  return nz;
}

std::string noise_json(const Noise& nz) {
  Json j;
  j.num("secs", nz.secs);
  j.u64("gaps_over_2us", nz.over_2us);
  j.u64("gaps_over_5us", nz.over_5us);
  j.u64("gaps_over_10us", nz.over_10us);
  j.u64("gaps_over_100us", nz.over_100us);
  j.num("median_gap_over_5us_ns", nz.median_gap_over_5us_ns);
  j.num("max_gap_ns", nz.max_gap_ns);
  return j.dump(4);
}

// timer overhead: an empty timed region, many times
Stats timer_overhead(const Timer& t) {
  constexpr size_t N = 1000000;
  std::vector<double> v(N);
  for (size_t i = 0; i < N; ++i) {
    v[i] = double(t.time([] { asm volatile("" ::: "memory"); }));
  }
  return stats_of(std::move(v));
}

// --------------------------------------------------------------------------
// Catch2 BENCHMARK cross-check (optional)
// --------------------------------------------------------------------------

const Hset* g_hset = nullptr;
std::vector<Hash> g_bench_sample;
size_t g_bench_pos = 0;

TEST_CASE("vs_lookup_eval cross-check", "[vs_lookup_eval]") {
  REQUIRE(g_hset);
  REQUIRE(!g_bench_sample.empty());
  const auto& hs = *g_hset;
  const auto& sample = g_bench_sample;
  BENCHMARK_ADVANCED("sfhash_hashset_lookup (one per run, walking the sample)")(
    Catch::Benchmark::Chronometer meter)
  {
    // a running position, so successive runs and samples walk the whole
    // sample instead of repeating its first meter.runs() entries
    meter.measure([&] {
      const bool r = hs.lookup(sample[g_bench_pos]);
      if (++g_bench_pos == sample.size()) g_bench_pos = 0;
      return r;
    });
  };
}

void run_catch(const Hset& hs, const std::vector<Hash>& sample) {
  g_hset = &hs;
  g_bench_sample = sample;
  std::printf("\nCatch2 BENCHMARK cross-check over %zu sampled queries:\n", sample.size());
  std::fflush(stdout);
  Catch::Session session;
  const char* args[] = {"vs_lookup_eval", "--benchmark-samples", "100",
                        "--benchmark-warmup-time", "500", "[vs_lookup_eval]"};
  session.applyCommandLine(6, args);
  session.run();
  g_bench_sample.clear();
}

// --------------------------------------------------------------------------
// The timed pass
// --------------------------------------------------------------------------

void write_csv(const std::string& path, const std::vector<Hash>& q,
               const std::vector<uint8_t>& found, const std::vector<double>& ns) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) die("cannot write " + path);
  std::vector<char> buf(4 << 20);
  std::setvbuf(f, buf.data(), _IOFBF, buf.size());
  std::fputs("i,sha256,found,ns\n", f);
  char hx[65];
  hx[64] = '\0';
  for (size_t i = 0; i < ns.size(); ++i) {
    sfhash_hex(hx, q[i].data(), 32);
    std::fprintf(f, "%zu,%s,%u,%.0f\n", i, hx, unsigned(found[i]), ns[i]);
  }
  if (std::fclose(f) != 0) die("error writing " + path);
}

struct TimedPass {
  std::vector<uint8_t> found;
  std::vector<double> ns;
  double wall_s = 0;
  Stats st;
  uint64_t over_10us = 0, over_100us = 0;
  std::string interference;
  // aggregate pass (whole query set as one timed region)
  double agg_mean_ns = 0;
  double agg_wall_s = 0;
};

// Per-query timed pass. If stop_on_miss, the first miss ends the program.
TimedPass timed_pass(const Hset& hs, const Timer& t, const std::vector<Hash>& q,
                     bool stop_on_miss) {
  TimedPass tp;
  std::vector<uint64_t> ticks(q.size());
  tp.found.resize(q.size());
  const Interference i0 = Interference::sample();
  const auto w0 = clk::now();
  for (size_t i = 0; i < q.size(); ++i) {
    bool r = false;
    ticks[i] = t.time([&] { r = hs.lookup(q[i]); });
    tp.found[i] = r;
    if (stop_on_miss && !r) {
      die("MISS: " + hex(q[i]) + " at position " + std::to_string(i) +
          " (0-based line of the list) was not found", 2);
    }
  }
  tp.wall_s = secs_since(w0);
  tp.interference = Interference::delta(i0, Interference::sample());
  tp.ns.resize(q.size());
  for (size_t i = 0; i < q.size(); ++i) {
    tp.ns[i] = double(ticks[i]);
    tp.over_10us += tp.ns[i] > 1e4;
    tp.over_100us += tp.ns[i] > 1e5;
  }
  tp.st = stats_of(tp.ns);
  return tp;
}

void print_pass(const char* title, const TimedPass& tp) {
  print_stats(title, tp.st, tp.wall_s);
  std::printf("queries over 10 us: %" PRIu64 ", over 100 us: %" PRIu64 "\n",
              tp.over_10us, tp.over_100us);
}

void pass_json(Json& j, const TimedPass& tp) {
  j.raw("stats_ns", stats_json(tp.st));
  j.u64("queries_over_10us", tp.over_10us);
  j.u64("queries_over_100us", tp.over_100us);
  j.raw("interference", tp.interference);
  j.num("timed_pass_wall_secs", tp.wall_s);
  if (tp.agg_wall_s > 0) {
    j.num("aggregate_mean_ns", tp.agg_mean_ns);
    j.num("aggregate_wall_secs", tp.agg_wall_s);
  }
}

void aggregate_pass(const Hset& hs, const std::vector<Hash>& q, TimedPass& tp) {
  uint64_t hits = 0;
  const auto t0 = clk::now();
  for (const auto& h: q) hits += hs.lookup(h);
  tp.agg_wall_s = secs_since(t0);
  tp.agg_mean_ns = tp.agg_wall_s * 1e9 / q.size();
  std::printf("aggregate pass (one timed region, no per-query timers): n=%zu "
              "hits=%" PRIu64 " mean %.1f ns/lookup; wall %.3f s\n",
              q.size(), hits, tp.agg_mean_ns, tp.agg_wall_s);
}

// metadata common to found and notfound
Json common_meta(const Options& o, const Hset& hs, const WarmInfo& wi,
                 const Stats& ovh) {
  Json j;
  j.str("tool", "vs_lookup_eval");
  j.str("subcommand", o.cmd);
  j.str("date", iso_now());
  j.str("host", hostname());
  j.str("cpu_model", cpu_model());
  j.str("clocksource", clocksource());
  j.str("loadavg_at_end", loadavg());
  j.str("lookup_api", "sfhash_hashset_lookup");
  j.str("hset_path", std::filesystem::absolute(hs.path).string());
  j.u64("hset_size", hs.size());
  j.str("hset_name", sfhash_hashset_name(hs.h.get()));
  j.u64("sha256_count", hs.count);
  j.u64("record_count", hs.record_count());
  j.u64("mem_available_kb", wi.mem_available_kb);
  j.u64("mem_total_kb", wi.mem_total_kb);
  j.boolean("fits_in_cache", wi.fits);
  j.u64("warm_reads", wi.read_secs.size());
  {
    std::string a = "[";
    for (size_t i = 0; i < wi.read_secs.size(); ++i) {
      a += (i ? ", " : "") + jnum(wi.read_secs[i]);
    }
    j.raw("warm_read_secs", a + "]");
  }
  j.num("page_touch_secs", wi.touch_secs);
  j.u64("warmup_queries", wi.warmup_n);
  j.num("warmup_secs", wi.warmup_secs);
  j.str("timer", "steady_clock");
  j.num("timer_overhead_median_ns", ovh.median);
  j.num("timer_overhead_mean_ns", ovh.mean);
  j.raw("timer_overhead_ns", stats_json(ovh));
  j.str("ns_note", "ns is the raw timed interval and includes the timer overhead");
  j.str("csv", o.csv);
  return j;
}

void setup_timer(const Options& o, const Timer& t, Stats& ovh, Noise& nz) {
  std::printf("timer: std::chrono::steady_clock (clocksource %s)\n", clocksource().c_str());
  ovh = timer_overhead(t);
  std::printf("timer overhead (empty timed region, 1M reps): median %.1f ns, "
              "mean %.1f ns, p99 %.1f ns, p99.9 %.1f ns, max %.1f ns\n",
              ovh.median, ovh.mean, ovh.p99, ovh.p999, ovh.max);
  nz = measure_noise(o.noise_secs);
}

void print_env(const Options& o) {
  std::printf("vs_lookup_eval %s  %s\n", o.cmd.c_str(), iso_now().c_str());
  std::printf("cpu: %s; loadavg %s\n", cpu_model().c_str(), loadavg().c_str());
}

void print_hset(const Hset& hs) {
  std::printf("hset: %s (\"%s\"), %" PRIu64 " sha256 hashes, %" PRIu64 " records\n",
              hs.path.c_str(), sfhash_hashset_name(hs.h.get()), hs.count,
              hs.record_count());
}

// --------------------------------------------------------------------------
// Subcommands
// --------------------------------------------------------------------------

int cmd_export(const Options& o) {
  print_env(o);
  const auto t0 = clk::now();
  Hset hs(o.hset);
  print_hset(hs);

  std::vector<Hash> v(hs.count);
  uint64_t dups = 0;
  for (uint64_t i = 0; i < hs.count; ++i) {
    std::memcpy(v[i].data(), sfhash_hashset_hash(hs.h.get(), hs.tidx, i), 32);
    if (i && v[i] == v[i - 1]) ++dups;
  }
  std::printf("exported %" PRIu64 " sha256 hashes (%" PRIu64 " distinct, %" PRIu64
              " adjacent duplicates)\n", hs.count, hs.count - dups, dups);
  const uint64_t rc = hs.record_count();
  if (rc == 0) {
    std::printf("hset has no records (hashsets-only); nothing to compare\n");
  }
  else if (rc != hs.count) {
    std::printf("NOTE: record count %" PRIu64 " differs from sha256 count %" PRIu64
                " by %" PRId64 " (duplicate samples or records without a sha256)\n",
                rc, hs.count, int64_t(rc) - int64_t(hs.count));
  }
  else {
    std::printf("record count %" PRIu64 " equals the sha256 count%s\n", rc,
                dups ? " (the duplicate rows belong to records differing in other fields)" : "");
  }

  if (o.unique && dups) {
    v.erase(std::unique(v.begin(), v.end()), v.end());
    std::printf("--unique: kept %zu distinct hashes\n", v.size());
  }

  std::printf("shuffling with mt19937_64 seed %" PRIu64 " (0x%016" PRIx64 ")\n", o.seed, o.seed);
  std::mt19937_64 rng(o.seed);
  std::shuffle(v.begin(), v.end(), rng);
  write_list(o.list, v);
  const double wall = secs_since(t0);
  std::printf("wrote %s; %.2f s\n", o.list.c_str(), wall);

  Json j;
  j.str("tool", "vs_lookup_eval");
  j.str("subcommand", "export");
  j.str("date", iso_now());
  j.str("host", hostname());
  j.str("cpu_model", cpu_model());
  j.str("hset_path", std::filesystem::absolute(hs.path).string());
  j.u64("hset_size", hs.size());
  j.str("hset_name", sfhash_hashset_name(hs.h.get()));
  j.u64("sha256_count", hs.count);
  j.u64("sha256_distinct", hs.count - dups);
  j.u64("record_count", rc);
  j.raw("record_minus_sha256", std::to_string(int64_t(rc) - int64_t(hs.count)));
  j.str("list", o.list);
  j.u64("list_count", v.size());
  j.boolean("unique", o.unique);
  j.u64("seed", o.seed);
  j.str("shuffle", "std::shuffle with std::mt19937_64(seed), libstdc++");
  j.num("wall_secs", wall);
  j.write(o.meta);
  std::printf("metadata: %s\n", o.meta.c_str());
  return 0;
}

int cmd_found(const Options& o) {
  print_env(o);
  Hset hs(o.hset);
  print_hset(hs);

  auto t0 = clk::now();
  std::vector<Hash> q = read_list(o.list);
  std::printf("read %zu hashes from %s in %.2f s\n", q.size(), o.list.c_str(), secs_since(t0));
  if (q.empty()) die("empty list " + o.list);
  if (o.limit && o.limit < q.size()) {
    q.resize(o.limit);
    std::printf("limited to the first %zu hashes\n", q.size());
  }

  WarmInfo wi;
  warm_file(hs, o.warm_reads, wi);

  Timer t;
  Stats ovh;
  Noise nz;
  setup_timer(o, t, ovh, nz);

  // untimed warm-up: a sample of the list (a different seeded draw), or all
  {
    std::vector<size_t> idx;
    if (o.warmup_all || o.warmup_queries >= q.size()) {
      idx.resize(q.size());
      for (size_t i = 0; i < q.size(); ++i) idx[i] = i;
    }
    else {
      std::mt19937_64 rng(0x5741524Dull);  // "WARM"
      std::uniform_int_distribution<size_t> pick(0, q.size() - 1);
      idx.resize(o.warmup_queries);
      for (auto& i: idx) i = pick(rng);
    }
    uint64_t hits = 0;
    const auto w0 = clk::now();
    for (size_t i: idx) hits += hs.lookup(q[i]);
    wi.warmup_secs = secs_since(w0);
    wi.warmup_n = idx.size();
    std::printf("warm-up: %zu untimed lookups, %" PRIu64 " found, %.2f s\n",
                idx.size(), hits, wi.warmup_secs);
    if (hits != idx.size()) {
      std::printf("warm-up saw a miss; the timed pass will identify it\n");
    }
  }

  std::fflush(stdout);
  TimedPass tp = timed_pass(hs, t, q, true);
  std::printf("all %zu hashes found\n", q.size());
  print_pass("found (per query, raw)", tp);
  if (o.aggregate) aggregate_pass(hs, q, tp);

  t0 = clk::now();
  write_csv(o.csv, q, tp.found, tp.ns);
  std::printf("wrote %s in %.2f s\n", o.csv.c_str(), secs_since(t0));

  if (o.catch_bench) {
    std::vector<Hash> sample;
    std::mt19937_64 rng(0x43415443ull);  // "CATC"
    std::sample(q.begin(), q.end(), std::back_inserter(sample),
                std::min<uint64_t>(o.catch_bench, q.size()), rng);
    run_catch(hs, sample);
  }

  Json j = common_meta(o, hs, wi, ovh);
  j.raw("noise_floor", noise_json(nz));
  j.str("list", o.list);
  j.u64("list_count", q.size());
  j.u64("limit", o.limit);
  j.u64("queries", q.size());
  j.u64("found", q.size());
  pass_json(j, tp);
  j.u64("catch_bench_sample", o.catch_bench);
  j.write(o.meta);
  std::printf("metadata: %s\n", o.meta.c_str());
  return 0;
}

int cmd_notfound(const Options& o) {
  print_env(o);
  Hset hs(o.hset);
  print_hset(hs);

  uint64_t seed = o.seed;
  if (!o.seed_given) {
    std::random_device rd;
    seed = (uint64_t(rd()) << 32) ^ rd();
  }
  std::printf("random SHA-256 queries: %" PRIu64 " from mt19937_64 seed %" PRIu64
              " (0x%016" PRIx64 ")%s\n", o.count, seed, seed,
              o.seed_given ? "" : " [from std::random_device]");
  auto gen = [](uint64_t n, uint64_t s) {
    std::mt19937_64 rng(s);
    std::vector<Hash> v(n);
    for (auto& h: v) {
      for (size_t k = 0; k < 32; k += 8) {
        const uint64_t x = rng();
        std::memcpy(h.data() + k, &x, 8);
      }
    }
    return v;
  };
  std::vector<Hash> q = gen(o.count, seed);
  if (o.inject_hits) {
    // self-test of the hit handling: overwrite K evenly spaced queries with
    // stored hashes
    const uint64_t k = std::min<uint64_t>(o.inject_hits, q.size());
    for (uint64_t j = 0; j < k; ++j) {
      const uint64_t row = (j * 2654435761ull) % hs.count;
      std::memcpy(q[j * q.size() / k].data(),
                  sfhash_hashset_hash(hs.h.get(), hs.tidx, row), 32);
    }
    std::printf("SELF-TEST: injected %" PRIu64 " stored hashes into the queries\n", k);
  }

  WarmInfo wi;
  warm_file(hs, o.warm_reads, wi);

  Timer t;
  Stats ovh;
  Noise nz;
  setup_timer(o, t, ovh, nz);

  // untimed warm-up with other random values (misses, like the timed pass)
  {
    const uint64_t n = o.warmup_all ? std::max<uint64_t>(o.count, hs.count) : o.warmup_queries;
    const std::vector<Hash> w = gen(n, seed ^ 0x5741524D5741524Dull);
    uint64_t hits = 0;
    const auto w0 = clk::now();
    for (const auto& h: w) hits += hs.lookup(h);
    wi.warmup_secs = secs_since(w0);
    wi.warmup_n = n;
    std::printf("warm-up: %" PRIu64 " untimed random lookups, %" PRIu64
                " found, %.2f s\n", n, hits, wi.warmup_secs);
  }

  std::fflush(stdout);
  TimedPass tp = timed_pass(hs, t, q, false);
  print_pass("notfound (per query, raw)", tp);
  if (o.aggregate) aggregate_pass(hs, q, tp);

  // Check the result against the exported list: a hit must be in the list
  // (a genuine collision), and a value in the list must have been a hit.
  std::vector<size_t> hits;
  for (size_t i = 0; i < q.size(); ++i) if (tp.found[i]) hits.push_back(i);
  std::vector<std::string> collisions;
  bool bug = false;
  bool checked = false;
  if (!o.list.empty()) {
    auto t0 = clk::now();
    std::vector<Hash> all = read_list(o.list);
    std::sort(all.begin(), all.end());
    checked = true;
    for (size_t i = 0; i < q.size(); ++i) {
      const bool in_list = std::binary_search(all.begin(), all.end(), q[i]);
      if (tp.found[i] && in_list) {
        std::printf("COLLISION: random value %s (query %zu) is in the exported "
                    "list: a genuine SHA-256 collision with a sample\n",
                    hex(q[i]).c_str(), i);
        collisions.push_back(hex(q[i]));
      }
      else if (tp.found[i]) {
        std::fprintf(stderr, "LOOKUP BUG: %s (query %zu) was found but is not in "
                     "the exported list\n", hex(q[i]).c_str(), i);
        bug = true;
      }
      else if (in_list) {
        std::fprintf(stderr, "LOOKUP BUG: %s (query %zu) is in the exported list "
                     "but was not found\n", hex(q[i]).c_str(), i);
        bug = true;
      }
    }
    std::printf("checked all %zu queries against the %zu exported hashes in %.2f s\n",
                q.size(), all.size(), secs_since(t0));
  }
  else if (!hits.empty()) {
    std::fprintf(stderr, "%zu random values were found and there is no --list to "
                 "tell a collision from a lookup bug\n", hits.size());
    for (size_t i: hits) std::fprintf(stderr, "  %s (query %zu)\n", hex(q[i]).c_str(), i);
    bug = true;
  }
  std::printf("%zu of %zu random values found (%zu collisions)\n",
              hits.size(), q.size(), collisions.size());

  write_csv(o.csv, q, tp.found, tp.ns);
  std::printf("wrote %s\n", o.csv.c_str());

  if (o.catch_bench) {
    std::vector<Hash> sample(q.begin(), q.begin() + std::min<uint64_t>(o.catch_bench, q.size()));
    run_catch(hs, sample);
  }

  Json j = common_meta(o, hs, wi, ovh);
  j.raw("noise_floor", noise_json(nz));
  j.str("list", o.list);
  j.u64("seed", seed);
  j.boolean("seed_from_random_device", !o.seed_given);
  j.u64("inject_hits", o.inject_hits);
  j.u64("queries", q.size());
  j.u64("found", hits.size());
  j.boolean("checked_against_list", checked);
  {
    std::string a = "[";
    for (size_t i = 0; i < collisions.size(); ++i) a += (i ? ", " : "") + jstr(collisions[i]);
    j.raw("collisions", a + "]");
  }
  j.boolean("lookup_bug", bug);
  pass_json(j, tp);
  j.u64("catch_bench_sample", o.catch_bench);
  j.write(o.meta);
  std::printf("metadata: %s\n", o.meta.c_str());
  if (bug) die("lookup assertion failed", 2);
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
  const Options o = parse_args(argc, argv);
  if (o.cmd == "export") return cmd_export(o);
  if (o.cmd == "found") return cmd_found(o);
  return cmd_notfound(o);
}
