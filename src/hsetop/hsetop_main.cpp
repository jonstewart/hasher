/*

Whole-set operations on hset files by merging (no rebuild):

hsetop union      NAME DESC LEFT.hset RIGHT.hset OUT.hset
hsetop intersect  NAME DESC LEFT.hset RIGHT.hset OUT.hset
hsetop difference NAME DESC LEFT.hset RIGHT.hset OUT.hset   (LEFT minus RIGHT)

NAME and DESC become the output's name and description. The inputs are
memory-mapped read-only. Every hash section of the output is the merge of
the inputs' sorted sections; a TLSH section's cell index and kNN index
(TIVF) are carried through the merge rather than rebuilt. The
output has a record table only when both inputs do; otherwise it is a
hashsets-only file. See HASHSET_FORMAT, "Set operations".

By default the TLSH index is written iff both inputs have it. Set
HSET_TLSH_OPTIONS to a bitwise OR of SFHASH_HSET_TLSH_* bits to choose
explicitly: SFHASH_HSET_TLSH_INDEX (2) writes the index, computing it for
the output when an input lacks one, and 0 writes none (bit 1 is reserved
and ignored). An index computed that way is built by integer clustering,
whose bytes are the same on every platform, unless
SFHASH_HSET_TLSH_INDEX_KMEANS (8) is added to select the float k-means
(equally exact, quadratic in the largest header cell, bytes dependent on
compiler and platform). By default, and whenever both inputs have an
index, the index is merged and the bit has no effect.

A merged TIVF index coalesces small lists per header cell so that repeated
incremental merges stay within one list per cell of a from-scratch build
(docs/TLSH_EMBEDDING.md, "Incremental merge"). HSET_COALESCE sets the
threshold C (lists of fewer than C / 2 rows are coalesced); 0 disables
coalescing and the default is 64.

The same operations are available through the library's
sfhash_hashset_builder_union_open / _intersect_open / _subtract_open, which
build the same merged file through the builder's open / write / destroy
sequence.

Examples:

hsetop union 'NSRL + malware' 'everything we know' nsrl.hset malware.hset all.hset
hsetop difference 'unknown' 'local files not in the NSRL' local.hset nsrl.hset unknown.hset

*/

#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <string>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/lexical_cast.hpp>

#include "throw.h"
#include "hasher/common.h"
#include "hasher/hashset.h"

namespace bip = boost::interprocess;

namespace {

struct Mapped {
  bip::file_mapping fm;
  bip::mapped_region mr;

  Mapped(const char* path):
    fm(open_mapping(path)), mr(fm, bip::read_only) {}

  const void* beg() const { return mr.get_address(); }
  const void* end() const { return static_cast<const char*>(mr.get_address()) + mr.get_size(); }

private:
  static bip::file_mapping open_mapping(const char* path) {
    try {
      return bip::file_mapping(path, bip::read_only);
    }
    catch (const bip::interprocess_exception& e) {
      THROW(path << ": " << e.what());
    }
  }
};

using HsetPtr = std::unique_ptr<SFHASH_Hashset, void(*)(SFHASH_Hashset*)>;

HsetPtr load(const Mapped& m, const char* path) {
  SFHASH_Error* err = nullptr;
  HsetPtr hset(sfhash_load_hashset(m.beg(), m.end(), &err), sfhash_destroy_hashset);
  if (err) {
    const std::string msg = err->message;
    sfhash_free_error(err);
    THROW(path << ": " << msg);
  }
  return hset;
}

uint32_t parse_op(const char* s) {
  if (!std::strcmp(s, "union")) {
    return SFHASH_HSET_OP_UNION;
  }
  if (!std::strcmp(s, "intersect")) {
    return SFHASH_HSET_OP_INTERSECT;
  }
  if (!std::strcmp(s, "difference")) {
    return SFHASH_HSET_OP_DIFFERENCE;
  }
  THROW("unknown operation '" << s << "', expected union, intersect or difference");
}

} // namespace

int main(int argc, char** argv) {
  if (argc != 7) {
    std::cerr << "Usage: hsetop union|intersect|difference NAME DESC LEFT.hset RIGHT.hset OUT.hset" << std::endl;
    return -1;
  }

  try {
    const uint32_t op = parse_op(argv[1]);

    uint32_t tlsh_options = SFHASH_HSET_TLSH_INHERIT;
    if (const char* opts = std::getenv("HSET_TLSH_OPTIONS")) {
      try {
        tlsh_options = boost::lexical_cast<uint32_t>(opts);
      }
      catch (const boost::bad_lexical_cast&) {
        THROW("HSET_TLSH_OPTIONS is not a nonnegative integer: '" << opts << "'");
      }
    }

    uint32_t coalesce = SFHASH_HSET_COALESCE_DEFAULT;
    if (const char* c = std::getenv("HSET_COALESCE")) {
      try {
        coalesce = boost::lexical_cast<uint32_t>(c);
      }
      catch (const boost::bad_lexical_cast&) {
        THROW("HSET_COALESCE is not a nonnegative integer: '" << c << "'");
      }
    }

    const Mapped lm(argv[4]);
    const Mapped rm(argv[5]);
    const HsetPtr l = load(lm, argv[4]);
    const HsetPtr r = load(rm, argv[5]);

    SFHASH_Error* err = nullptr;
    const uint64_t size = sfhash_hashset_merge(
      l.get(), r.get(), op, argv[2], argv[3], argv[6], tlsh_options, coalesce, &err
    );
    if (err) {
      const std::string msg = err->message;
      sfhash_free_error(err);
      THROW(msg);
    }

    std::cerr << "wrote " << argv[6] << " (" << size << " bytes)\n";
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
