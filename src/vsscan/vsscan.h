#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

struct ScanOptions {
  std::filesystem::path out_dir;
  std::vector<std::filesystem::path> zips;
  std::string passphrase = "infected";
  unsigned jobs = 1;                     // zips read concurrently
  unsigned readers_per_zip = 8;          // libarchive handles (threads) per zip
  unsigned threads = 0;                  // hashing workers; 0 = nproc
  uint64_t max_buffer = 2ull << 30;      // bytes of sample data in flight
  uint64_t limit = 0;                    // entries per zip; 0 = all
  double time_limit = 0;                 // seconds; 0 = none
  double progress_interval = 10;         // seconds; 0 = quiet
  size_t block_size = 1 << 20;           // libarchive read block size
  uint64_t prefetch_ahead = 512ull << 20; // read the zip this far ahead of the readers; 0 = off
  bool streaming = false;                // streaming zip reader (no central directory)
  bool force = false;                    // rescan zips with complete outputs
  unsigned max_recoveries = 100;         // reopen-and-skip attempts per zip
};

struct ZipResult {
  std::string zip;
  std::string status; // complete, partial, failed, skipped
  uint64_t entries = 0;   // entries seen (headers read)
  uint64_t rows = 0;      // samples hashed and written
  uint64_t errors = 0;    // per-entry errors
  uint64_t name_md5_mismatches = 0;
  uint64_t bytes = 0;     // uncompressed bytes hashed
  uint64_t zip_bytes = 0; // size of the zip file
  double seconds = 0;
};

// Scans the zips; returns the per-zip results in input order. Throws only
// for setup errors (output directory, bad options).
std::vector<ZipResult> run_scan(const ScanOptions& opts);

// Output paths for a zip.
std::filesystem::path rows_path(const std::filesystem::path& out_dir, const std::filesystem::path& zip);
std::filesystem::path errors_path(const std::filesystem::path& out_dir, const std::filesystem::path& zip);
std::filesystem::path summary_path(const std::filesystem::path& out_dir, const std::filesystem::path& zip);

// True if summary_path exists and records status "complete".
bool zip_is_complete(const std::filesystem::path& out_dir, const std::filesystem::path& zip);

struct BuildOptions {
  std::filesystem::path output;
  std::vector<std::filesystem::path> inputs; // TSV files or scan output directories
  std::string name = "VirusShare";
  std::string desc = "VirusShare samples scanned by vsscan";
  uint32_t tlsh_options = 2;                 // SFHASH_HSET_TLSH_INDEX
  std::filesystem::path temp_dir = ".";
};

// Builds one hset with records from the TSVs. Returns the file size.
uint64_t run_build(const BuildOptions& opts);
