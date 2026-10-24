/*
vsscan: hash every sample in password-protected zips (VirusShare) and build
an hset from the results. See utils/VIRUSSHARE_HOWTO.

  vsscan scan [OPTIONS] -o OUTDIR ZIP...
  vsscan build [OPTIONS] OUT.hset INPUT...
  vsscan hash FILE...

Samples are hashed in memory; nothing from an archive is written to disk
except the hashes.
*/

#include "vsscan.h"
#include "vsscan_record.h"

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "hasher/hasher.h"

namespace {

const char* USAGE =
R"(Usage:
  vsscan scan [OPTIONS] -o OUTDIR ZIP...
      Hash every member of each zip (MD5, SHA-1, SHA-256, TLSH, ssdeep,
      entropy, size) into OUTDIR/<zip stem>.tsv, with per-entry errors in
      <stem>.errors.tsv and a one-row <stem>.summary.tsv written when the
      zip is finished. Zips whose summary says "complete" are skipped.

      -o, --out DIR          output directory (required)
      -j, --jobs N           zips read concurrently (default 1: on a RAID
                             that streams one file well, two concurrent
                             zips read slower than one)
      -r, --readers N        reader threads per zip, each with its own
                             libarchive handle taking every N-th entry
                             (default 8; decryption and inflation run on
                             the readers)
      -t, --threads N        hashing threads (default: number of CPUs)
      -p, --passphrase S     zip passphrase (default "infected")
      -m, --max-buffer MiB   sample bytes buffered for hashing (default 2048)
      -n, --limit N          stop each zip after N entries (status "partial")
      -T, --time-limit SECS  stop reading after SECS seconds (status "partial")
      -P, --progress SECS    progress interval, 0 for none (default 10)
      -b, --block-size KiB   libarchive read block size (default 1024)
      -A, --prefetch MiB     read each zip sequentially this far ahead of
                             its readers into the page cache, 0 for off
                             (default 512)
      --streaming            use the streaming zip reader (no central
                             directory; for truncated zips)
      --force                rescan zips that have complete outputs

  vsscan build [OPTIONS] OUT.hset INPUT...
      Build one hset with records (md5, sha1, sha2_256, tlsh, sizes) from
      vsscan TSVs; an INPUT directory means its data TSVs.

      --name S               hset name (default "VirusShare")
      --desc S               hset description
      --tlsh-options N       SFHASH_HSET_TLSH_* bits (default 3: TVEC and
                             TIVF); HSET_TLSH_OPTIONS also sets it
      --temp DIR             builder temp directory (default ".")

  vsscan hash FILE...
      Print the TSV row (zip column "-") of each local file, for testing.
)";

[[noreturn]] void usage_error(const std::string& msg) {
  std::cerr << "vsscan: " << msg << "\n\n" << USAGE;
  std::exit(2);
}

// matches "--long" / "-s" with the value in the next argument, or
// "--long=value"
bool take_opt(
  int argc, char** argv, int& i,
  const char* shrt, const char* lng, std::string& val)
{
  const std::string a = argv[i];
  const std::string l = lng;
  if (a.rfind(l + "=", 0) == 0) {
    val = a.substr(l.size() + 1);
    return true;
  }
  if (a == l || (shrt && a == shrt)) {
    if (i + 1 >= argc) {
      usage_error("missing value for " + a);
    }
    val = argv[++i];
    return true;
  }
  return false;
}

uint64_t to_u64(const std::string& s, const char* what) {
  try {
    size_t pos;
    const unsigned long long v = std::stoull(s, &pos);
    if (pos != s.size() || s[0] == '-') {
      throw std::invalid_argument(s);
    }
    return v;
  }
  catch (const std::exception&) {
    usage_error(std::string("bad value for ") + what + ": " + s);
  }
}

double to_double(const std::string& s, const char* what) {
  try {
    size_t pos;
    const double v = std::stod(s, &pos);
    if (pos != s.size() || v < 0) {
      throw std::invalid_argument(s);
    }
    return v;
  }
  catch (const std::exception&) {
    usage_error(std::string("bad value for ") + what + ": " + s);
  }
}

int cmd_scan(int argc, char** argv) {
  ScanOptions o;
  std::string v;
  for (int i = 0; i < argc; ++i) {
    const std::string a = argv[i];
    if (take_opt(argc, argv, i, "-o", "--out", v)) o.out_dir = v;
    else if (take_opt(argc, argv, i, "-j", "--jobs", v)) o.jobs = to_u64(v, "--jobs");
    else if (take_opt(argc, argv, i, "-r", "--readers", v)) o.readers_per_zip = to_u64(v, "--readers");
    else if (take_opt(argc, argv, i, "-t", "--threads", v)) o.threads = to_u64(v, "--threads");
    else if (take_opt(argc, argv, i, "-p", "--passphrase", v)) o.passphrase = v;
    else if (take_opt(argc, argv, i, "-m", "--max-buffer", v)) o.max_buffer = to_u64(v, "--max-buffer") << 20;
    else if (take_opt(argc, argv, i, "-n", "--limit", v)) o.limit = to_u64(v, "--limit");
    else if (take_opt(argc, argv, i, "-T", "--time-limit", v)) o.time_limit = to_double(v, "--time-limit");
    else if (take_opt(argc, argv, i, "-P", "--progress", v)) o.progress_interval = to_double(v, "--progress");
    else if (take_opt(argc, argv, i, "-b", "--block-size", v)) o.block_size = to_u64(v, "--block-size") << 10;
    else if (take_opt(argc, argv, i, "-A", "--prefetch", v)) o.prefetch_ahead = to_u64(v, "--prefetch") << 20;
    else if (a == "--streaming") o.streaming = true;
    else if (a == "--force") o.force = true;
    else if (a.size() > 1 && a[0] == '-') usage_error("unknown option " + a);
    else o.zips.emplace_back(a);
  }

  if (o.out_dir.empty()) usage_error("scan needs --out");
  if (o.zips.empty()) usage_error("scan needs at least one zip");
  if (o.jobs == 0) usage_error("--jobs must be positive");
  if (o.readers_per_zip == 0) usage_error("--readers must be positive");
  if (o.max_buffer == 0) usage_error("--max-buffer must be positive");
  if (o.block_size == 0) usage_error("--block-size must be positive");

  const auto results = run_scan(o);
  int rc = 0;
  for (const auto& r: results) {
    if (r.status == "failed") {
      rc = 1;
    }
  }
  return rc;
}

int cmd_build(int argc, char** argv) {
  BuildOptions o;
  if (const char* env = std::getenv("HSET_TLSH_OPTIONS")) {
    o.tlsh_options = to_u64(env, "HSET_TLSH_OPTIONS");
  }

  std::vector<std::string> pos;
  std::string v;
  for (int i = 0; i < argc; ++i) {
    const std::string a = argv[i];
    if (take_opt(argc, argv, i, nullptr, "--name", v)) o.name = v;
    else if (take_opt(argc, argv, i, nullptr, "--desc", v)) o.desc = v;
    else if (take_opt(argc, argv, i, nullptr, "--tlsh-options", v)) o.tlsh_options = to_u64(v, "--tlsh-options");
    else if (take_opt(argc, argv, i, nullptr, "--temp", v)) o.temp_dir = v;
    else if (a.size() > 1 && a[0] == '-') usage_error("unknown option " + a);
    else pos.push_back(a);
  }

  if (pos.size() < 2) usage_error("build needs OUT.hset and at least one INPUT");
  o.output = pos[0];
  o.inputs.assign(pos.begin() + 1, pos.end());

  run_build(o);
  return 0;
}

int cmd_hash(int argc, char** argv) {
  if (argc == 0) usage_error("hash needs at least one file");

  std::unique_ptr<SFHASH_Hasher, void (*)(SFHASH_Hasher*)> h(
    sfhash_create_hasher(vsscan_hash_algs()), sfhash_destroy_hasher
  );

  std::cout << tsv_header() << '\n';
  for (int i = 0; i < argc; ++i) {
    std::ifstream in(argv[i], std::ios::binary);
    if (!in) {
      std::cerr << "vsscan: cannot open " << argv[i] << '\n';
      return 1;
    }
    const std::vector<uint8_t> buf(
      (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()
    );
    SampleRecord rec;
    rec.zip = "-";
    rec.index = i;
    rec.member = argv[i];
    hash_sample(h.get(), buf.data(), buf.data() + buf.size(), rec);
    std::cout << format_tsv_row(rec);
  }
  return 0;
}

}

int main(int argc, char** argv) {
  std::ios_base::sync_with_stdio(false);

  // libarchive converts every zip entry's DOS timestamp with mktime, which
  // reruns tzset under glibc's global lock; with TZ unset and no
  // /etc/localtime (as in this VM) each call also tries to open
  // /etc/localtime. That serialized the reader threads, at 131,072 failed
  // opens per VirusShare zip and handle. Timestamps are not recorded, so
  // any fixed zone will do.
  if (!std::getenv("TZ")) {
    setenv("TZ", "UTC", 1);
  }
  tzset();

  if (argc < 2) {
    std::cerr << USAGE;
    return 2;
  }

  const std::string cmd = argv[1];
  try {
    if (cmd == "scan") return cmd_scan(argc - 2, argv + 2);
    if (cmd == "build") return cmd_build(argc - 2, argv + 2);
    if (cmd == "hash") return cmd_hash(argc - 2, argv + 2);
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
      std::cout << USAGE;
      return 0;
    }
    usage_error("unknown command " + cmd);
  }
  catch (const std::exception& e) {
    std::cerr << "vsscan: error: " << e.what() << '\n';
    return 1;
  }
}
