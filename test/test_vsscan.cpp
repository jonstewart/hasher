#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include "hasher/hasher.h"
#include "hasher/hashset.h"
#include "hasher/hex.h"
#include "hasher/tlsh.h"

#include "vsscan.h"
#include "vsscan_record.h"

namespace fs = std::filesystem;

namespace {

std::string hex(const uint8_t* b, size_t n) {
  std::string s(2 * n, '\0');
  sfhash_hex(s.data(), b, n);
  return s;
}

std::string tlsh_hex(const uint8_t* d) {
  char h[SFHASH_TLSH_HEX_LENGTH + 1];
  sfhash_tlsh_to_hex(d, h);
  return h;
}

SampleRecord hash_of(const std::string& data) {
  std::unique_ptr<SFHASH_Hasher, void (*)(SFHASH_Hasher*)> h(
    sfhash_create_hasher(vsscan_hash_algs()), sfhash_destroy_hasher
  );
  SampleRecord rec;
  const auto* b = reinterpret_cast<const uint8_t*>(data.data());
  hash_sample(h.get(), b, b + data.size(), rec);
  return rec;
}

std::string seq(int a, int b) {
  std::string s;
  for (int i = a; i <= b; ++i) {
    s += std::to_string(i) + '\n';
  }
  return s;
}

std::vector<std::vector<std::string>> read_tsv(const fs::path& p) {
  std::ifstream in(p);
  std::vector<std::vector<std::string>> rows;
  std::string line;
  std::getline(in, line); // header
  while (std::getline(in, line)) {
    std::vector<std::string> cols;
    std::stringstream ss(line);
    std::string c;
    while (std::getline(ss, c, '\t')) {
      cols.push_back(c);
    }
    rows.push_back(cols);
  }
  return rows;
}

}

TEST_CASE("vsscan_hash_sample_empty") {
  const SampleRecord r = hash_of("");
  CHECK(r.size == 0);
  CHECK(hex(r.md5, 16) == "d41d8cd98f00b204e9800998ecf8427e");
  CHECK(hex(r.sha1, 20) == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  CHECK(hex(r.sha256, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CHECK(sfhash_tlsh_is_null(r.tlsh));
  CHECK(r.ssdeep == "3::");
  CHECK(r.entropy == 0.0);
}

TEST_CASE("vsscan_hash_sample_small_is_tnull") {
  const SampleRecord r = hash_of("hello, world\n");
  CHECK(r.size == 13);
  CHECK(hex(r.md5, 16) == "22c3683b094136c3398391ae71b20f04");
  CHECK(tlsh_hex(r.tlsh) == "TNULL");
  CHECK(r.ssdeep == "3:iKJF5/v:nFhv");
}

TEST_CASE("vsscan_hash_sample_matches_reference_tools") {
  // expected values from coreutils, the reference TLSH and ssdeep
  const SampleRecord r = hash_of(seq(1, 10000));
  CHECK(r.size == 48894);
  CHECK(hex(r.md5, 16) == "72d4ff27a28afbc066d5804999d5a504");
  CHECK(hex(r.sha1, 20) == "f70b7b8768a1183d6d1cd79d3b076d9eb5156350");
  CHECK(hex(r.sha256, 32) == "8060aa0ac20a3e5db2b67325c98a0122f2d09a612574458225dcb9a086f87cc3");
  CHECK(tlsh_hex(r.tlsh) == "T1DB238748A9C959F09B40DD5FA21DA7B6932B0966F9D730122B2A36064FB303B5F6CDC1");
  CHECK(r.ssdeep == "768:FhmbZzmt6ptaG7bVzN72sCuYJu8qyizGaBXQOmKrGDPifmunXBluGmxdrbxUzn:sP/xHKD8XOx6");
  CHECK(std::fabs(r.entropy - 3.3688473999916599) < 1e-12);
}

TEST_CASE("vsscan_hash_sample_resets_between_samples") {
  std::unique_ptr<SFHASH_Hasher, void (*)(SFHASH_Hasher*)> h(
    sfhash_create_hasher(vsscan_hash_algs()), sfhash_destroy_hasher
  );
  const std::string a = seq(1, 10000);
  SampleRecord r1, r2;
  hash_sample(h.get(), reinterpret_cast<const uint8_t*>(a.data()), reinterpret_cast<const uint8_t*>(a.data()) + a.size(), r1);
  hash_sample(h.get(), nullptr, nullptr, r2);
  CHECK(hex(r2.md5, 16) == "d41d8cd98f00b204e9800998ecf8427e");
  CHECK(sfhash_tlsh_is_null(r2.tlsh));
  hash_sample(h.get(), reinterpret_cast<const uint8_t*>(a.data()), reinterpret_cast<const uint8_t*>(a.data()) + a.size(), r2);
  CHECK(format_tsv_row(r1) == format_tsv_row(r2));
}

TEST_CASE("vsscan_tsv_escape_round_trip") {
  const std::string s = "a\tb\nc\\d\re";
  CHECK(tsv_escape(s) == "a\\tb\\nc\\\\d\\re");
  CHECK(tsv_unescape(tsv_escape(s)) == s);
  CHECK(tsv_escape("plain/path.exe") == "plain/path.exe");
}

TEST_CASE("vsscan_tsv_row_round_trip") {
  SampleRecord r = hash_of(seq(1, 10000));
  r.zip = "VirusShare_00000.zip";
  r.index = 42;
  r.member = "odd\tname\nwith\\escapes";

  const std::string row = format_tsv_row(r);
  CHECK(row.back() == '\n');
  CHECK(std::count(row.begin(), row.end(), '\t') == 9);

  SampleRecord p;
  REQUIRE(parse_tsv_row(row, p));
  CHECK(p.zip == r.zip);
  CHECK(p.index == 42);
  CHECK(p.member == r.member);
  CHECK(p.size == r.size);
  CHECK(!std::memcmp(p.md5, r.md5, 16));
  CHECK(!std::memcmp(p.sha1, r.sha1, 20));
  CHECK(!std::memcmp(p.sha256, r.sha256, 32));
  CHECK(!std::memcmp(p.tlsh, r.tlsh, 36));
  CHECK(p.ssdeep == r.ssdeep);
  CHECK(std::fabs(p.entropy - r.entropy) < 1e-9);

  SampleRecord n = hash_of("");
  n.zip = "z";
  n.member = "empty";
  REQUIRE(parse_tsv_row(format_tsv_row(n), p));
  CHECK(sfhash_tlsh_is_null(p.tlsh));

  CHECK(!parse_tsv_row(tsv_header(), p));
  CHECK(!parse_tsv_row("", p));
  CHECK(!parse_tsv_row("too\tfew\tcolumns", p));
}

TEST_CASE("vsscan_virusshare_name_md5") {
  std::string m;
  CHECK(virusshare_name_md5("VirusShare_2D75cc1bf8e57872781f9cd04a529256", m));
  CHECK(m == "2d75cc1bf8e57872781f9cd04a529256");
  CHECK(virusshare_name_md5("dir/VirusShare_2d75cc1bf8e57872781f9cd04a529256", m));
  CHECK(!virusshare_name_md5("VirusShare_2d75cc1bf8e57872781f9cd04a52925", m));
  CHECK(!virusshare_name_md5("VirusShare_2d75cc1bf8e57872781f9cd04a52925g", m));
  CHECK(!virusshare_name_md5("calc.exe", m));
}

/*
 * test/vsscan_fixture.zip holds benign generated files: ZipCrypto entries
 * (deflated and stored, an empty file, a 13-byte file, a directory and a
 * file in it, a file named VirusShare_<zeros> whose md5 differs), one
 * AES-256 entry, and wrongpw.txt encrypted with another password.
 */
TEST_CASE("vsscan_scan_and_build_fixture") {
  const fs::path out = "test/vsscan_out";
  fs::remove_all(out);

  for (unsigned readers: {1u, 3u}) {
    ScanOptions o;
    o.out_dir = out;
    o.zips = { "test/vsscan_fixture.zip" };
    o.readers_per_zip = readers;
    o.threads = 2;
    o.progress_interval = 0;
    o.force = true;

    const auto res = run_scan(o);
    REQUIRE(res.size() == 1);
    CHECK(res[0].status == "complete");
    CHECK(res[0].entries == 8);
    CHECK(res[0].rows == 6);
    CHECK(res[0].errors == 1);
    CHECK(res[0].name_md5_mismatches == 1);
    CHECK(zip_is_complete(out, "test/vsscan_fixture.zip"));

    std::map<std::string, std::vector<std::string>> by_member;
    for (const auto& r: read_tsv(out / "vsscan_fixture.tsv")) {
      REQUIRE(r.size() == 10);
      CHECK(r[0] == "vsscan_fixture.zip");
      by_member[r[2]] = r;
    }
    REQUIRE(by_member.size() == 6);
    CHECK(by_member.count("wrongpw.txt") == 0);
    CHECK(by_member["empty.bin"][3] == "0");
    CHECK(by_member["empty.bin"][7] == "TNULL");
    CHECK(by_member["tiny.txt"][4] == "22c3683b094136c3398391ae71b20f04");
    CHECK(by_member["tiny.txt"][7] == "TNULL");
    CHECK(by_member["seq.txt"][6] == "8060aa0ac20a3e5db2b67325c98a0122f2d09a612574458225dcb9a086f87cc3");
    CHECK(by_member["seq.txt"][7] == "T1DB238748A9C959F09B40DD5FA21DA7B6932B0966F9D730122B2A36064FB303B5F6CDC1");
    CHECK(by_member["dir/inner.txt"][6] == "1255c3948d0740be6ee391abe73520b6528d3bedbe1a045f0ccbded5beb8835a");
    CHECK(by_member["aes.txt"][4] == "faa7fab690f783c941e5b60bb9b91ec9");
    CHECK(by_member["aes.txt"][7] == "T156025E0BF59D66D28F43F836F05B617F42262E6BDBE76061176D3280092B84E5EBCC46");
    CHECK(by_member["VirusShare_00000000000000000000000000000000"][4] == "aed563ecafb4bcc5654c597a421547b2");

    const auto errs = read_tsv(out / "vsscan_fixture.errors.tsv");
    std::map<std::string, std::string> stage_of;
    for (const auto& e: errs) {
      REQUIRE(e.size() == 5);
      stage_of[e[2]] = e[3];
    }
    CHECK(stage_of["wrongpw.txt"] == "data");
    CHECK(stage_of["VirusShare_00000000000000000000000000000000"] == "name-md5-mismatch");
  }

  SECTION("a complete zip is skipped") {
    ScanOptions o;
    o.out_dir = out;
    o.zips = { "test/vsscan_fixture.zip" };
    o.progress_interval = 0;
    const auto res = run_scan(o);
    CHECK(res[0].status == "skipped");
  }

  SECTION("a limited scan is partial and is not skipped") {
    ScanOptions o;
    o.out_dir = out;
    o.zips = { "test/vsscan_fixture.zip" };
    o.progress_interval = 0;
    o.limit = 3;
    o.force = true;
    const auto res = run_scan(o);
    CHECK(res[0].status == "partial");
    CHECK(res[0].entries == 3);
    CHECK(!zip_is_complete(out, "test/vsscan_fixture.zip"));
  }

  SECTION("a missing zip fails") {
    ScanOptions o;
    o.out_dir = out;
    o.zips = { "test/no_such.zip" };
    o.progress_interval = 0;
    const auto res = run_scan(o);
    CHECK(res[0].status == "failed");
    CHECK(res[0].errors == 1);
  }

  SECTION("build makes an hset with records") {
    BuildOptions b;
    b.output = out / "fixture.hset";
    b.inputs = { out };
    REQUIRE(run_build(b) > 0);

    boost::interprocess::file_mapping fm(b.output.c_str(), boost::interprocess::read_only);
    boost::interprocess::mapped_region mr(fm, boost::interprocess::read_only);
    const char* beg = static_cast<const char*>(mr.get_address());
    SFHASH_Error* err = nullptr;
    std::unique_ptr<SFHASH_Hashset, void (*)(SFHASH_Hashset*)> h(
      sfhash_load_hashset(beg, beg + mr.get_size(), &err), sfhash_destroy_hashset
    );
    REQUIRE(h);

    const int md5 = sfhash_hashset_index_for_type(h.get(), SFHASH_MD5);
    const int sha1 = sfhash_hashset_index_for_type(h.get(), SFHASH_SHA_1);
    const int sha256 = sfhash_hashset_index_for_type(h.get(), SFHASH_SHA_2_256);
    const int size = sfhash_hashset_index_for_type(h.get(), SFHASH_SIZE);
    const int tlsh = sfhash_hashset_index_for_type(h.get(), SFHASH_TLSH);
    REQUIRE(md5 >= 0);
    REQUIRE(sha1 >= 0);
    REQUIRE(sha256 >= 0);
    REQUIRE(size >= 0);
    REQUIRE(tlsh >= 0);

    CHECK(sfhash_hashset_count(h.get(), md5) == 6);
    CHECK(sfhash_hashset_count(h.get(), sha256) == 6);
    // empty.bin, tiny.txt and the 100 x's have no TLSH
    CHECK(sfhash_hashset_count(h.get(), tlsh) == 3);
    CHECK(sfhash_hashset_tlsh_knn_strategies(h.get(), tlsh) == (SFHASH_TLSH_KNN_BRUTE | SFHASH_TLSH_KNN_INDEX));
    size_t dims = 0;
    CHECK(sfhash_hashset_tlsh_vectors(h.get(), tlsh, &dims) != nullptr);
    CHECK(dims == SFHASH_TLSH_EMBEDDING_DIMS);

    uint8_t d[32];
    REQUIRE(sfhash_unhex(d, "8060aa0ac20a3e5db2b67325c98a0122f2d09a612574458225dcb9a086f87cc3", 64));
    CHECK(sfhash_hashset_lookup(h.get(), sha256, d));
    REQUIRE(sfhash_unhex(d, "faa7fab690f783c941e5b60bb9b91ec9", 32));
    CHECK(sfhash_hashset_lookup(h.get(), md5, d));
    REQUIRE(sfhash_unhex(d, "aaa7fab690f783c941e5b60bb9b91ec9", 32));
    CHECK(!sfhash_hashset_lookup(h.get(), md5, d));

    uint8_t t[36];
    REQUIRE(sfhash_tlsh_from_hex("T1DB238748A9C959F09B40DD5FA21DA7B6932B0966F9D730122B2A36064FB303B5F6CDC1", t));
    SFHASH_TlshMatch m[3];
    REQUIRE(sfhash_hashset_tlsh_knn(h.get(), tlsh, t, 3, UINT32_MAX, true, m) == 3);
    CHECK(m[0].distance == 0);

    // the record of the sha256 row holds the size
    const size_t rows = sfhash_hashset_count(h.get(), sha256);
    REQUIRE(sfhash_unhex(d, "8060aa0ac20a3e5db2b67325c98a0122f2d09a612574458225dcb9a086f87cc3", 64));
    size_t row = rows;
    for (size_t i = 0; i < rows; ++i) {
      if (!std::memcmp(sfhash_hashset_hash(h.get(), sha256, i), d, 32)) {
        row = i;
      }
    }
    REQUIRE(row < rows);
    const auto* rec = sfhash_hashset_record_for_hash(h.get(), sha256, row);
    const int fsize = sfhash_hashset_record_field_index_for_type(h.get(), SFHASH_SIZE);
    REQUIRE(fsize >= 0);
    const auto* f = static_cast<const uint8_t*>(sfhash_hashset_record_field(rec, fsize));
    uint64_t sz = 0;
    CHECK(f[0] == 1); // presence byte
    std::memcpy(&sz, f + 1, sizeof(sz));
    CHECK(sz == 48894);
  }
}
