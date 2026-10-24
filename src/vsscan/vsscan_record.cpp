#include "vsscan_record.h"

#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <vector>

#include "hasher/common.h"
#include "hasher/hex.h"
#include "hasher/tlsh.h"

uint32_t vsscan_hash_algs() {
  return SFHASH_MD5 | SFHASH_SHA_1 | SFHASH_SHA_2_256 | SFHASH_TLSH |
         SFHASH_FUZZY | SFHASH_ENTROPY | SFHASH_SIZE;
}

void hash_sample(
  SFHASH_Hasher* hasher,
  const uint8_t* beg,
  const uint8_t* end,
  SampleRecord& rec)
{
  sfhash_reset_hasher(hasher);
  // ssdeep wants the length before any input
  sfhash_hasher_set_total_input_length(hasher, end - beg);
  sfhash_update_hasher(hasher, beg, end);

  SFHASH_HashValues hv;
  sfhash_get_hashes(hasher, &hv);

  rec.size = end - beg;
  std::memcpy(rec.md5, hv.Md5, sizeof(rec.md5));
  std::memcpy(rec.sha1, hv.Sha1, sizeof(rec.sha1));
  std::memcpy(rec.sha256, hv.Sha2_256, sizeof(rec.sha256));
  std::memcpy(rec.tlsh, hv.Tlsh, sizeof(rec.tlsh));
  rec.ssdeep.assign(
    reinterpret_cast<const char*>(hv.Fuzzy),
    strnlen(reinterpret_cast<const char*>(hv.Fuzzy), sizeof(hv.Fuzzy))
  );
  rec.entropy = hv.Entropy;
}

const char* tsv_header() {
  return "zip\tindex\tmember\tsize\tmd5\tsha1\tsha256\ttlsh\tssdeep\tentropy";
}

std::string tsv_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char c: s) {
    switch (c) {
    case '\\': out += "\\\\"; break;
    case '\t': out += "\\t"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    default:   out += c;
    }
  }
  return out;
}

std::string tsv_unescape(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\\' && i + 1 < s.size()) {
      switch (s[++i]) {
      case 't': out += '\t'; break;
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      default:  out += s[i]; break; // "\\" and anything unexpected
      }
    }
    else {
      out += s[i];
    }
  }
  return out;
}

namespace {

void append_hex(std::string& out, const uint8_t* b, size_t n) {
  const size_t off = out.size();
  out.resize(off + 2 * n);
  sfhash_hex(&out[off], b, n);
}

std::vector<std::string_view> split_tabs(std::string_view s) {
  std::vector<std::string_view> cols;
  size_t i = 0;
  while (true) {
    const size_t j = s.find('\t', i);
    if (j == std::string_view::npos) {
      cols.push_back(s.substr(i));
      break;
    }
    cols.push_back(s.substr(i, j - i));
    i = j + 1;
  }
  return cols;
}

template <class T>
bool parse_num(std::string_view s, T& v) {
  const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
  return r.ec == std::errc() && r.ptr == s.data() + s.size();
}

bool parse_hex(std::string_view s, uint8_t* dst, size_t n) {
  return s.size() == 2 * n && sfhash_unhex(dst, s.data(), s.size());
}

}

std::string format_tsv_row(const SampleRecord& rec) {
  std::string row;
  row.reserve(512 + rec.member.size());

  row += tsv_escape(rec.zip);
  row += '\t';
  row += std::to_string(rec.index);
  row += '\t';
  row += tsv_escape(rec.member);
  row += '\t';
  row += std::to_string(rec.size);
  row += '\t';
  append_hex(row, rec.md5, sizeof(rec.md5));
  row += '\t';
  append_hex(row, rec.sha1, sizeof(rec.sha1));
  row += '\t';
  append_hex(row, rec.sha256, sizeof(rec.sha256));
  row += '\t';

  char tlsh_hex[SFHASH_TLSH_HEX_LENGTH + 1];
  sfhash_tlsh_to_hex(rec.tlsh, tlsh_hex);
  row += tlsh_hex;
  row += '\t';

  row += tsv_escape(rec.ssdeep); // ssdeep has no tabs, but be safe
  row += '\t';

  char ent[64];
  std::snprintf(ent, sizeof(ent), "%.9f", rec.entropy);
  row += ent;
  row += '\n';
  return row;
}

bool parse_tsv_row(std::string_view line, SampleRecord& rec) {
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
    line.remove_suffix(1);
  }

  if (line.empty() || line == tsv_header()) {
    return false;
  }

  const auto cols = split_tabs(line);
  if (cols.size() != 10) {
    return false;
  }

  rec.zip = tsv_unescape(cols[0]);
  if (!parse_num(cols[1], rec.index)) {
    return false;
  }
  rec.member = tsv_unescape(cols[2]);
  if (!parse_num(cols[3], rec.size)) {
    return false;
  }
  if (!parse_hex(cols[4], rec.md5, sizeof(rec.md5)) ||
      !parse_hex(cols[5], rec.sha1, sizeof(rec.sha1)) ||
      !parse_hex(cols[6], rec.sha256, sizeof(rec.sha256))) {
    return false;
  }

  // sfhash_tlsh_from_hex wants a NUL or non-hex terminator
  const std::string tlsh(cols[7]);
  if (!sfhash_tlsh_from_hex(tlsh.c_str(), rec.tlsh)) {
    return false;
  }

  rec.ssdeep = tsv_unescape(cols[8]);

  // from_chars for double is fine in libstdc++ >= 11
  if (!parse_num(cols[9], rec.entropy)) {
    return false;
  }

  return true;
}

bool virusshare_name_md5(std::string_view member, std::string& md5_hex) {
  const size_t slash = member.find_last_of('/');
  const std::string_view base =
    slash == std::string_view::npos ? member : member.substr(slash + 1);

  constexpr std::string_view prefix = "VirusShare_";
  if (base.size() != prefix.size() + 32 || base.substr(0, prefix.size()) != prefix) {
    return false;
  }

  md5_hex.clear();
  for (const char c: base.substr(prefix.size())) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
    md5_hex += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return true;
}
