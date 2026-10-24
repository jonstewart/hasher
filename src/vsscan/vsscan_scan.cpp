// vsscan scan: stream password-protected zips through libarchive, hashing
// every member in memory on a shared Boost.Asio thread pool.
//
// Sample contents are never written to disk: each member is read into a
// heap buffer by its zip's reader thread, hashed by a pool worker, and the
// buffer is freed.

#include "vsscan.h"
#include "vsscan_record.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include "hasher/hex.h"

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {

/*
 * Bounds the bytes of sample data buffered between the readers and the
 * hashing pool. Requests are served in FIFO order so that a large sample
 * cannot be starved by a stream of small ones; a request larger than the
 * whole budget is clamped to it (that sample then waits for the pool to
 * drain and is held alone).
 */
class ByteBudget {
public:
  explicit ByteBudget(uint64_t cap): cap_(std::max<uint64_t>(cap, 1)) {}

  uint64_t acquire(uint64_t n) {
    n = std::min(n, cap_);
    std::unique_lock<std::mutex> l(m_);
    const uint64_t ticket = next_ticket_++;
    cv_.wait(l, [&]{ return serving_ == ticket && used_ + n <= cap_; });
    used_ += n;
    ++serving_;
    cv_.notify_all();
    return n;
  }

  void release(uint64_t n) {
    std::lock_guard<std::mutex> l(m_);
    used_ -= n;
    cv_.notify_all();
  }

  uint64_t in_use() {
    std::lock_guard<std::mutex> l(m_);
    return used_;
  }

private:
  const uint64_t cap_;
  std::mutex m_;
  std::condition_variable cv_;
  uint64_t used_ = 0;
  uint64_t next_ticket_ = 0;
  uint64_t serving_ = 0;
};

struct Stats {
  std::atomic<uint64_t> entries{0};
  std::atomic<uint64_t> rows{0};
  std::atomic<uint64_t> errors{0};
  std::atomic<uint64_t> bytes{0};
  std::atomic<uint64_t> zip_bytes{0}; // progress through the zip files
  std::atomic<uint64_t> zips_done{0};
  std::atomic<uint64_t> zips_active{0};
  uint64_t zips_total = 0;
};

struct HasherDeleter {
  void operator()(SFHASH_Hasher* h) const { sfhash_destroy_hasher(h); }
};

SFHASH_Hasher* thread_hasher() {
  // named for top -H / pidstat -t
  thread_local const bool named = (pthread_setname_np(pthread_self(), "vsscan-hash"), true);
  (void) named;
  thread_local std::unique_ptr<SFHASH_Hasher, HasherDeleter> h(
    sfhash_create_hasher(vsscan_hash_algs())
  );
  return h.get();
}

struct FileCloser {
  void operator()(std::FILE* f) const { if (f) std::fclose(f); }
};

using FilePtr = std::unique_ptr<std::FILE, FileCloser>;

FilePtr open_out(const fs::path& p) {
  FilePtr f(std::fopen(p.c_str(), "wb"));
  if (!f) {
    throw std::runtime_error("cannot open " + p.string() + ": " + std::strerror(errno));
  }
  std::setvbuf(f.get(), nullptr, _IOFBF, 1 << 20);
  return f;
}

void close_out(FilePtr& f, const fs::path& p) {
  std::FILE* raw = f.release();
  if (std::fclose(raw) != 0) {
    throw std::runtime_error("error writing " + p.string() + ": " + std::strerror(errno));
  }
}

std::string utc_now() {
  const std::time_t t = std::time(nullptr);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

std::string one_line(std::string s) {
  for (char& c: s) {
    if (c == '\t' || c == '\n' || c == '\r') {
      c = ' ';
    }
  }
  return s;
}

struct ZipJob {
  fs::path zip;
  std::string name;

  FilePtr rows_f;
  FilePtr err_f;
  std::mutex rows_m;
  std::mutex err_m;

  std::atomic<uint64_t> rows{0};
  std::atomic<uint64_t> errors{0};
  std::atomic<uint64_t> mismatches{0};
  std::atomic<uint64_t> bytes{0};

  // furthest position reached in the zip file by reader 0
  std::atomic<uint64_t> max_pos{0};

  std::mutex done_m;
  std::condition_variable done_cv;
  uint64_t pending = 0;

  Stats* stats = nullptr;

  void write_row(const std::string& row) {
    std::lock_guard<std::mutex> l(rows_m);
    std::fwrite(row.data(), 1, row.size(), rows_f.get());
  }

  // a line in the errors file; counted as an error unless it is a warning
  void log(int64_t index, std::string_view member, std::string_view stage, std::string_view msg, bool is_error = true) {
    std::ostringstream o;
    o << tsv_escape(name) << '\t' << index << '\t' << tsv_escape(member) << '\t'
      << stage << '\t' << one_line(std::string(msg)) << '\n';
    const std::string line = o.str();
    {
      std::lock_guard<std::mutex> l(err_m);
      std::fwrite(line.data(), 1, line.size(), err_f.get());
    }
    if (is_error) {
      ++errors;
      ++stats->errors;
    }
  }

  void task_started() {
    std::lock_guard<std::mutex> l(done_m);
    ++pending;
  }

  void task_done() {
    std::lock_guard<std::mutex> l(done_m);
    if (--pending == 0) {
      done_cv.notify_all();
    }
  }

  void wait_tasks() {
    std::unique_lock<std::mutex> l(done_m);
    done_cv.wait(l, [&]{ return pending == 0; });
  }
};

struct ArchiveDeleter {
  void operator()(archive* a) const { archive_read_free(a); }
};

using ArchivePtr = std::unique_ptr<archive, ArchiveDeleter>;

std::string archive_err(archive* a) {
  const char* s = archive_error_string(a);
  return s ? s : "unknown libarchive error";
}

ArchivePtr open_archive(const fs::path& zip, const ScanOptions& opts, std::string& err) {
  ArchivePtr a(archive_read_new());
  if (opts.streaming) {
    archive_read_support_format_zip_streamable(a.get());
  }
  else {
    archive_read_support_format_zip_seekable(a.get());
  }
  archive_read_add_passphrase(a.get(), opts.passphrase.c_str());

  if (archive_read_open_filename(a.get(), zip.c_str(), opts.block_size) != ARCHIVE_OK) {
    err = archive_err(a.get());
    return nullptr;
  }
  return a;
}

const char* entry_name(archive_entry* e) {
  if (const char* p = archive_entry_pathname(e)) {
    return p;
  }
  if (const char* p = archive_entry_pathname_utf8(e)) {
    return p;
  }
  return "";
}

void hash_task(
  ZipJob* job,
  uint64_t index,
  const std::string& member,
  std::vector<uint8_t>& buf)
{
  SampleRecord rec;
  rec.zip = job->name;
  rec.index = index;
  rec.member = member;

  hash_sample(thread_hasher(), buf.data(), buf.data() + buf.size(), rec);
  job->write_row(format_tsv_row(rec));

  ++job->rows;
  job->bytes += rec.size;
  ++job->stats->rows;
  job->stats->bytes += rec.size;

  std::string name_md5;
  if (virusshare_name_md5(member, name_md5)) {
    char hex[33];
    sfhash_hex(hex, rec.md5, sizeof(rec.md5));
    hex[32] = '\0';
    if (name_md5 != hex) {
      ++job->mismatches;
      job->log(index, member, "name-md5-mismatch", std::string("md5 is ") + hex, false);
    }
  }
}

void write_summary(const fs::path& out_dir, const ZipResult& r) {
  const fs::path p = summary_path(out_dir, r.zip);
  const fs::path tmp = p.string() + ".partial";
  {
    std::ofstream o(tmp);
    o << "zip\tstatus\tentries\trows\terrors\tname_md5_mismatches\tbytes\tzip_bytes\tseconds\tfinished\n"
      << r.zip << '\t' << r.status << '\t' << r.entries << '\t' << r.rows << '\t'
      << r.errors << '\t' << r.name_md5_mismatches << '\t' << r.bytes << '\t'
      << r.zip_bytes << '\t' << r.seconds << '\t' << utc_now() << '\n';
    o.close();
    if (!o) {
      throw std::runtime_error("error writing " + tmp.string());
    }
  }
  fs::rename(tmp, p);
}

struct StrideResult {
  uint64_t entries = 0;
  bool failed = false;
  bool stopped = false;
};

/*
 * One reader of a zip: its own libarchive handle, reading the data of the
 * entries whose index is congruent to r modulo k and skipping the others
 * (in seekable mode a skipped entry's data is seeked over, not decrypted).
 * The k readers of a zip move through the file together, so the disk still
 * sees one roughly sequential stream while decryption and inflation, which
 * libarchive does on the reading thread, run on k cores.
 */
StrideResult read_stride(
  ZipJob& job,
  const ScanOptions& opts,
  unsigned r,
  unsigned k,
  boost::asio::thread_pool& pool,
  ByteBudget& budget,
  Stats& stats,
  Clock::time_point deadline,
  bool has_deadline)
{
  StrideResult res;
  uint64_t index = 0; // index of the next entry to read
  unsigned recoveries = 0;
  bool done = false;

  auto mine = [&](uint64_t i) { return i % k == r; };

  while (!done && !res.failed && !res.stopped) {
    std::string err;
    ArchivePtr a = open_archive(job.zip, opts, err);
    if (!a) {
      if (r == 0 || index > 0) {
        job.log(-1, "", "open", err);
      }
      res.failed = true;
      break;
    }

    archive_entry* e = nullptr;

    // after a recovery, skip the entries already handled (in seekable mode
    // this reads only their local headers)
    for (uint64_t i = 0; i < index; ++i) {
      const int hr = archive_read_next_header(a.get(), &e);
      if (hr == ARCHIVE_EOF || hr == ARCHIVE_FATAL) {
        job.log(i, "", "recover", "cannot skip back to entry " + std::to_string(index) + ": " + archive_err(a.get()));
        res.failed = true;
        break;
      }
    }

    while (!res.failed) {
      if (opts.limit && index >= opts.limit) {
        res.stopped = true;
        break;
      }
      if (has_deadline && Clock::now() >= deadline) {
        res.stopped = true;
        break;
      }

      const int hr = archive_read_next_header(a.get(), &e);
      if (hr == ARCHIVE_EOF) {
        done = true;
        break;
      }
      if (hr == ARCHIVE_FATAL) {
        // the next entry cannot be located; reopening would fail here
        // again. Every reader sees this; the entry's owner reports it.
        if (mine(index)) {
          job.log(index, "", "header", archive_err(a.get()));
        }
        res.failed = true;
        break;
      }

      if (r == 0) {
        // the readers move together; reader 0 reports their progress
        const int64_t pos = archive_filter_bytes(a.get(), -1);
        const uint64_t prev = job.max_pos;
        if (pos > 0 && static_cast<uint64_t>(pos) > prev) {
          stats.zip_bytes += pos - prev;
          job.max_pos = pos;
        }
      }

      const uint64_t idx = index++;
      if (!mine(idx)) {
        continue;
      }

      ++res.entries;
      ++stats.entries;

      const std::string member = entry_name(e);

      if (hr == ARCHIVE_FAILED || hr == ARCHIVE_RETRY) {
        job.log(idx, member, "header", archive_err(a.get()));
        continue;
      }
      if (hr == ARCHIVE_WARN) {
        job.log(idx, member, "header-warning", archive_err(a.get()), false);
      }

      if (archive_entry_filetype(e) != AE_IFREG) {
        if (archive_entry_filetype(e) != AE_IFDIR) {
          job.log(idx, member, "not-regular", "skipped entry of type " + std::to_string(archive_entry_filetype(e)), false);
        }
        continue;
      }

      const bool size_known = archive_entry_size_is_set(e);
      const uint64_t size = size_known ? static_cast<uint64_t>(archive_entry_size(e)) : 0;

      uint64_t held = size_known ? budget.acquire(size) : 0;

      std::vector<uint8_t> buf;
      int data_rc = ARCHIVE_OK;
      try {
        buf.resize(size);
        size_t off = 0;
        uint8_t probe[64 * 1024];
        while (true) {
          la_ssize_t n;
          if (off < buf.size()) {
            n = archive_read_data(a.get(), buf.data() + off, buf.size() - off);
            if (n > 0) {
              off += n;
            }
          }
          else {
            // the expected size is reached: confirm the end of the entry
            n = archive_read_data(a.get(), probe, sizeof(probe));
            if (n > 0) {
              buf.insert(buf.end(), probe, probe + n);
              off += n;
            }
          }
          if (n == 0) {
            break;
          }
          if (n < 0) {
            data_rc = static_cast<int>(n);
            break;
          }
        }
        buf.resize(off);
      }
      catch (const std::bad_alloc&) {
        budget.release(held);
        job.log(idx, member, "data", "out of memory reading " + std::to_string(size) + " bytes");
        continue;
      }

      if (data_rc != ARCHIVE_OK) {
        budget.release(held);
        buf.clear();
        buf.shrink_to_fit();

        if (data_rc == ARCHIVE_FATAL) {
          job.log(idx, member, "data-fatal", archive_err(a.get()));
          if (opts.streaming || ++recoveries > opts.max_recoveries) {
            if (!opts.streaming) {
              job.log(idx, member, "recover", "too many recoveries, giving up");
            }
            res.failed = true;
          }
          // reopen the archive and resume at the next entry
          break;
        }

        // ARCHIVE_WARN or ARCHIVE_FAILED (e.g. bad CRC, incorrect
        // passphrase, unsupported compression or encryption): this entry
        // only
        job.log(idx, member, data_rc == ARCHIVE_WARN ? "data-warning" : "data", archive_err(a.get()));
        continue;
      }

      if (!size_known) {
        held = budget.acquire(buf.size());
      }

      job.task_started();
      auto data = std::make_shared<std::vector<uint8_t>>(std::move(buf));
      boost::asio::post(pool, [&job, &budget, idx, member, data, held]() {
        try {
          hash_task(&job, idx, member, *data);
        }
        catch (const std::exception& ex) {
          job.log(idx, member, "hash", ex.what());
        }
        data->clear();
        data->shrink_to_fit();
        budget.release(held);
        job.task_done();
      });
    }

    // a FATAL data error leaves the loop with no flag set: reopen
  }

  return res;
}

/*
 * Reads the zip sequentially ahead of the readers with large reads, so that
 * the disk sees one deep sequential stream and the readers' own small reads
 * (and the k - 1 readers trailing the first) are served from the page
 * cache. The data is discarded. Stops when stop is set.
 */
void prefetch_zip(
  const fs::path& zip,
  const std::atomic<uint64_t>& reader_pos,
  const std::atomic<bool>& stop,
  uint64_t ahead,
  size_t chunk)
{
  const int fd = ::open(zip.c_str(), O_RDONLY);
  if (fd < 0) {
    return;
  }
  posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
  std::vector<uint8_t> buf(chunk);
  uint64_t pos = 0;
  while (!stop) {
    if (pos < reader_pos + ahead) {
      const ssize_t n = ::pread(fd, buf.data(), buf.size(), pos);
      if (n <= 0) {
        break; // end of file or error; the readers will report errors
      }
      pos += n;
    }
    else {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  ::close(fd);
}

ZipResult scan_zip(
  const fs::path& zip,
  const ScanOptions& opts,
  boost::asio::thread_pool& pool,
  ByteBudget& budget,
  Stats& stats,
  Clock::time_point deadline,
  bool has_deadline)
{
  const auto t0 = Clock::now();

  ZipJob job;
  job.zip = zip;
  job.name = zip.filename().string();
  job.stats = &stats;

  ZipResult res;
  res.zip = job.name;
  std::error_code ec;
  res.zip_bytes = fs::file_size(zip, ec);

  const fs::path rows_final = rows_path(opts.out_dir, zip);
  const fs::path errs_final = errors_path(opts.out_dir, zip);
  const fs::path rows_tmp = rows_final.string() + ".partial";
  const fs::path errs_tmp = errs_final.string() + ".partial";

  job.rows_f = open_out(rows_tmp);
  job.err_f = open_out(errs_tmp);
  std::fprintf(job.rows_f.get(), "%s\n", tsv_header());
  std::fprintf(job.err_f.get(), "zip\tindex\tmember\tstage\tmessage\n");

  // the streaming reader cannot skip entries without decoding them
  const unsigned k = opts.streaming ? 1 : std::max(1u, opts.readers_per_zip);

  std::vector<StrideResult> strides(k);
  {
    std::atomic<bool> stop_prefetch{false};
    std::thread prefetcher;
    if (opts.prefetch_ahead > 0) {
      prefetcher = std::thread([&]{
        pthread_setname_np(pthread_self(), "vsscan-pref");
        prefetch_zip(zip, job.max_pos, stop_prefetch, opts.prefetch_ahead, 8 << 20);
      });
    }

    std::vector<std::thread> readers;
    for (unsigned r = 0; r < k; ++r) {
      readers.emplace_back([&, r]{
        pthread_setname_np(pthread_self(), "vsscan-read");
        try {
          strides[r] = read_stride(job, opts, r, k, pool, budget, stats, deadline, has_deadline);
        }
        catch (const std::exception& ex) {
          job.log(-1, "", "reader", ex.what());
          strides[r].failed = true;
        }
      });
    }
    for (auto& t: readers) {
      t.join();
    }

    stop_prefetch = true;
    if (prefetcher.joinable()) {
      prefetcher.join();
    }
  }

  job.wait_tasks();

  close_out(job.rows_f, rows_tmp);
  close_out(job.err_f, errs_tmp);
  fs::rename(rows_tmp, rows_final);
  fs::rename(errs_tmp, errs_final);

  bool failed = false, stopped = false;
  for (const auto& sr: strides) {
    failed |= sr.failed;
    stopped |= sr.stopped;
    res.entries += sr.entries;
  }

  res.status = failed ? "failed" : (stopped ? "partial" : "complete");
  res.rows = job.rows;
  res.errors = job.errors;
  res.name_md5_mismatches = job.mismatches;
  res.bytes = job.bytes;
  res.seconds = std::chrono::duration<double>(Clock::now() - t0).count();

  write_summary(opts.out_dir, res);
  return res;
}

struct ProcSample {
  uint64_t rchar = 0;
  double cpu_seconds = 0;
};

ProcSample proc_sample() {
  ProcSample s;
  {
    std::ifstream io("/proc/self/io");
    std::string k;
    uint64_t v;
    while (io >> k >> v) {
      if (k == "rchar:") {
        s.rchar = v;
      }
    }
  }
  {
    std::ifstream st("/proc/self/stat");
    std::string line;
    std::getline(st, line);
    // fields after the parenthesized comm; utime and stime are 14 and 15
    const auto rp = line.rfind(')');
    if (rp != std::string::npos) {
      std::istringstream in(line.substr(rp + 2));
      std::string f;
      uint64_t ut = 0, stime = 0;
      for (int i = 3; i <= 15 && in >> f; ++i) {
        if (i == 14) ut = std::stoull(f);
        if (i == 15) stime = std::stoull(f);
      }
      s.cpu_seconds = double(ut + stime) / sysconf(_SC_CLK_TCK);
    }
  }
  return s;
}

}

fs::path rows_path(const fs::path& out_dir, const fs::path& zip) {
  return out_dir / (zip.stem().string() + ".tsv");
}

fs::path errors_path(const fs::path& out_dir, const fs::path& zip) {
  return out_dir / (zip.stem().string() + ".errors.tsv");
}

fs::path summary_path(const fs::path& out_dir, const fs::path& zip) {
  return out_dir / (zip.stem().string() + ".summary.tsv");
}

bool zip_is_complete(const fs::path& out_dir, const fs::path& zip) {
  std::ifstream in(summary_path(out_dir, zip));
  std::string header, row;
  if (!std::getline(in, header) || !std::getline(in, row)) {
    return false;
  }
  const auto t1 = row.find('\t');
  if (t1 == std::string::npos) {
    return false;
  }
  const auto t2 = row.find('\t', t1 + 1);
  return row.substr(t1 + 1, t2 - t1 - 1) == "complete" && fs::exists(rows_path(out_dir, zip));
}

std::vector<ZipResult> run_scan(const ScanOptions& opts) {
  fs::create_directories(opts.out_dir);

  const unsigned threads = opts.threads ? opts.threads : std::max(1u, std::thread::hardware_concurrency());

  std::vector<ZipResult> results(opts.zips.size());
  std::vector<size_t> todo;
  for (size_t i = 0; i < opts.zips.size(); ++i) {
    if (!opts.force && zip_is_complete(opts.out_dir, opts.zips[i])) {
      results[i].zip = opts.zips[i].filename().string();
      results[i].status = "skipped";
      std::cerr << "vsscan: skipping " << results[i].zip << " (complete output exists)\n";
    }
    else {
      todo.push_back(i);
    }
  }

  Stats stats;
  stats.zips_total = todo.size();

  std::cerr << "vsscan: " << todo.size() << " zips to scan, " << opts.jobs
            << " at a time, " << (opts.streaming ? 1 : opts.readers_per_zip)
            << " readers per zip, " << threads << " hashing threads, buffer "
            << (opts.max_buffer >> 20) << " MiB\n";

  boost::asio::thread_pool pool(threads);
  ByteBudget budget(opts.max_buffer);

  const auto t0 = Clock::now();
  const ProcSample ps0 = proc_sample();
  const bool has_deadline = opts.time_limit > 0;
  const auto deadline = t0 + std::chrono::duration_cast<Clock::duration>(
    std::chrono::duration<double>(opts.time_limit)
  );

  // progress reporter
  std::mutex prog_m;
  std::condition_variable prog_cv;
  bool prog_stop = false;
  std::thread progress;
  if (opts.progress_interval > 0) {
    progress = std::thread([&]{
      ProcSample last = proc_sample();
      uint64_t last_entries = 0, last_bytes = 0, last_zb = 0;
      auto last_t = Clock::now();
      std::unique_lock<std::mutex> l(prog_m);
      while (!prog_cv.wait_for(
        l, std::chrono::duration<double>(opts.progress_interval),
        [&]{ return prog_stop; }))
      {
        const auto now = Clock::now();
        const double dt = std::chrono::duration<double>(now - last_t).count();
        const double el = std::chrono::duration<double>(now - t0).count();
        const ProcSample ps = proc_sample();
        const uint64_t ent = stats.entries, by = stats.bytes, zb = stats.zip_bytes;
        char line[512];
        std::snprintf(
          line, sizeof(line),
          "[%7.0fs] zips %llu/%llu done, %llu active | entries %llu (%.1f/s) | "
          "zip %.0f MB (%.1f MB/s) | hashed %.0f MB (%.1f MB/s) | io %.1f MB/s | "
          "cpu %.0f%% | buffered %.0f MB | errors %llu\n",
          el,
          (unsigned long long) stats.zips_done.load(),
          (unsigned long long) stats.zips_total,
          (unsigned long long) stats.zips_active.load(),
          (unsigned long long) ent, (ent - last_entries) / dt,
          zb / 1e6, (zb - last_zb) / 1e6 / dt,
          by / 1e6, (by - last_bytes) / 1e6 / dt,
          (ps.rchar - last.rchar) / 1e6 / dt,
          100.0 * (ps.cpu_seconds - last.cpu_seconds) / dt,
          budget.in_use() / 1e6,
          (unsigned long long) stats.errors.load()
        );
        std::cerr << line << std::flush;
        last = ps;
        last_entries = ent;
        last_bytes = by;
        last_zb = zb;
        last_t = now;
      }
    });
  }

  std::atomic<size_t> next{0};
  std::vector<std::thread> readers;
  const unsigned nreaders = std::min<size_t>(std::max(1u, opts.jobs), todo.size());
  for (unsigned r = 0; r < nreaders; ++r) {
    readers.emplace_back([&]{
      size_t k;
      while ((k = next++) < todo.size()) {
        const size_t i = todo[k];
        if (has_deadline && Clock::now() >= deadline) {
          results[i].zip = opts.zips[i].filename().string();
          results[i].status = "not-started";
          continue;
        }
        ++stats.zips_active;
        try {
          results[i] = scan_zip(opts.zips[i], opts, pool, budget, stats, deadline, has_deadline);
        }
        catch (const std::exception& e) {
          results[i].zip = opts.zips[i].filename().string();
          results[i].status = "failed";
          std::cerr << "vsscan: " << results[i].zip << ": " << e.what() << '\n';
        }
        --stats.zips_active;
        ++stats.zips_done;
        const auto& r = results[i];
        std::cerr << "vsscan: " << r.zip << ": " << r.status << ", " << r.entries
                  << " entries, " << r.rows << " rows, " << r.errors << " errors, "
                  << r.bytes / 1e6 << " MB in " << r.seconds << " s\n";
      }
    });
  }

  for (auto& t: readers) {
    t.join();
  }
  pool.join();

  if (progress.joinable()) {
    {
      std::lock_guard<std::mutex> l(prog_m);
      prog_stop = true;
    }
    prog_cv.notify_all();
    progress.join();
  }

  const double el = std::chrono::duration<double>(Clock::now() - t0).count();
  const ProcSample ps = proc_sample();
  char line[512];
  std::snprintf(
    line, sizeof(line),
    "vsscan: done in %.1f s: %llu entries (%.1f/s), %llu rows, %llu errors, "
    "zip %.0f MB (%.1f MB/s), hashed %.0f MB (%.1f MB/s), io %.0f MB, cpu %.0f%%\n",
    el,
    (unsigned long long) stats.entries.load(), stats.entries / el,
    (unsigned long long) stats.rows.load(),
    (unsigned long long) stats.errors.load(),
    stats.zip_bytes / 1e6, stats.zip_bytes / 1e6 / el,
    stats.bytes / 1e6, stats.bytes / 1e6 / el,
    (ps.rchar - ps0.rchar) / 1e6,
    100.0 * (ps.cpu_seconds - ps0.cpu_seconds) / el
  );
  std::cerr << line;

  return results;
}
