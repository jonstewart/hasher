// vsscan build: turn vsscan's per-zip TSVs into one hset with records.
//
// The record of a sample holds md5, sha1, sha256, tlsh and size (the order
// mkhashset needs: it reads a size column to the end of the line), the fields
// the hset record format can store (fixed-length hash types); the hset gets
// a hash section for each, and the TLSH section its TVEC vectors and TIVF
// index (by default). ssdeep, entropy, zip and member name stay in the TSVs.

#include "vsscan.h"
#include "vsscan_record.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "hasher/common.h"
#include "hasher/hashset.h"
#include "hasher/tlsh.h"

namespace fs = std::filesystem;

namespace {

bool ends_with(const std::string& s, const std::string& suf) {
  return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

// the data TSVs of the inputs: files as given, directories expanded to
// their *.tsv files other than *.errors.tsv and *.summary.tsv, sorted
std::vector<fs::path> collect_tsvs(const std::vector<fs::path>& inputs) {
  std::vector<fs::path> out;
  for (const auto& in: inputs) {
    if (fs::is_directory(in)) {
      std::vector<fs::path> dir;
      for (const auto& de: fs::directory_iterator(in)) {
        const std::string n = de.path().filename().string();
        if (de.is_regular_file() && ends_with(n, ".tsv") &&
            !ends_with(n, ".errors.tsv") && !ends_with(n, ".summary.tsv")) {
          dir.push_back(de.path());
        }
      }
      std::sort(dir.begin(), dir.end());
      out.insert(out.end(), dir.begin(), dir.end());
    }
    else {
      out.push_back(in);
    }
  }
  return out;
}

struct BuilderDeleter {
  void operator()(SFHASH_HashsetBuildCtx* b) const { sfhash_hashset_builder_destroy(b); }
};

void throw_if_err(SFHASH_Error* err) {
  if (err) {
    const std::string msg = err->message;
    sfhash_free_error(err);
    throw std::runtime_error(msg);
  }
}

}

uint64_t run_build(const BuildOptions& opts) {
  using Clock = std::chrono::steady_clock;
  const auto t0 = Clock::now();

  const auto tsvs = collect_tsvs(opts.inputs);
  if (tsvs.empty()) {
    throw std::runtime_error("no input TSVs");
  }

  // warn about scan outputs that are not complete
  for (const auto& t: tsvs) {
    const fs::path dir = t.parent_path();
    const fs::path zip = t.stem().string() + ".zip";
    if (fs::exists(summary_path(dir, zip)) && !zip_is_complete(dir, zip)) {
      std::cerr << "vsscan build: warning: " << t << " is from an incomplete scan\n";
    }
  }

  const SFHASH_HashAlgorithm fields[] = {
    SFHASH_MD5, SFHASH_SHA_1, SFHASH_SHA_2_256, SFHASH_TLSH, SFHASH_SIZE
  };

  SFHASH_Error* err = nullptr;
  std::unique_ptr<SFHASH_HashsetBuildCtx, BuilderDeleter> bctx(
    sfhash_hashset_builder_open(
      opts.name.c_str(), opts.desc.c_str(),
      fields, std::size(fields),
      true, true,
      opts.output.c_str(), opts.temp_dir.c_str(), &err
    )
  );
  throw_if_err(err);

  sfhash_hashset_builder_set_tlsh_options(bctx.get(), opts.tlsh_options);

  uint64_t rows = 0, bad = 0, tnull = 0;
  SampleRecord rec;
  std::string line;

  for (const auto& t: tsvs) {
    std::ifstream in(t);
    if (!in) {
      throw std::runtime_error("cannot open " + t.string());
    }
    uint64_t lineno = 0;
    while (std::getline(in, line)) {
      ++lineno;
      if (!parse_tsv_row(line, rec)) {
        if (lineno > 1 && !line.empty()) {
          if (++bad <= 10) {
            std::cerr << "vsscan build: " << t << ':' << lineno << ": malformed row skipped\n";
          }
        }
        continue;
      }

      sfhash_hashset_builder_add_hash(bctx.get(), rec.md5, sizeof(rec.md5));
      sfhash_hashset_builder_add_hash(bctx.get(), rec.sha1, sizeof(rec.sha1));
      sfhash_hashset_builder_add_hash(bctx.get(), rec.sha256, sizeof(rec.sha256));
      if (sfhash_tlsh_is_null(rec.tlsh)) {
        // TNULL: the field is absent and contributes no TLSH row
        sfhash_hashset_builder_add_hash(bctx.get(), nullptr, 0);
        ++tnull;
      }
      else {
        sfhash_hashset_builder_add_hash(bctx.get(), rec.tlsh, sizeof(rec.tlsh));
      }
      sfhash_hashset_builder_add_hash(bctx.get(), &rec.size, sizeof(rec.size));

      if (++rows % 1000000 == 0) {
        std::cerr << "vsscan build: read " << rows << " rows ("
                  << std::chrono::duration<double>(Clock::now() - t0).count() << " s)\n";
      }
    }
  }

  const double t_read = std::chrono::duration<double>(Clock::now() - t0).count();
  std::cerr << "vsscan build: read " << rows << " rows from " << tsvs.size()
            << " TSVs (" << tnull << " TNULL, " << bad << " malformed) in "
            << t_read << " s; writing " << opts.output << '\n';

  const uint64_t size = sfhash_hashset_builder_write(bctx.get(), &err);
  throw_if_err(err);

  const double t_all = std::chrono::duration<double>(Clock::now() - t0).count();
  std::cerr << "vsscan build: wrote " << size << " bytes in " << (t_all - t_read)
            << " s (total " << t_all << " s)\n";
  return size;
}
