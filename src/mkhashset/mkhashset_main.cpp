/*

TODO: Update examples
TODO: Determine whether we can still use stdin

Make a hashset from a list of filenames:

find -type f | xargs sha1sum | cut -f1 -d' ' | mkhashset 'Some test hashes' 'These are test hashes.' sha1 >sha1.hset

Make a hashset and sizeset from a list of filenames:

for i in $(find -type f) ; do echo $(stat --printf=%s $i) $(md5sum $i | cut -f1 -d' ') $(sha1sum $i | cut -f1 -d' ') ; done | mkhashset 'Some test hashes' 'These are test hashes.' sizes md5 sha1 >test.hset

Make a hashset and sizeset from the NSRL:

for i in NSRLFile.*.txt.gz ; do zcat $i | ./nsrldump.py ; done | mkhashset 'NSRL' 'The NSRL!' sha1 >nsrl.hset

Make a hashset with md5 and TLSH columns. TLSH digests are the usual
70-character hex strings, with or without the "T1" prefix; "TNULL" (or an
empty column) marks a file with no TLSH digest:

for i in $(find -type f) ; do echo $(md5sum $i | cut -f1 -d' ') $(tlsh -f $i | cut -f1) ; done >md5_tlsh.txt
mkhashset 'Some test hashes' 'md5 and tlsh' md5 tlsh true true md5_tlsh.txt md5_tlsh.hset

TLSH hashsets get the embedding vectors (TVEC) and the kNN index (TIVF) by
default. Set HSET_TLSH_OPTIONS to a bitwise OR of SFHASH_HSET_TLSH_VECTORS (1)
and SFHASH_HSET_TLSH_INDEX (2) to choose; 0 writes neither:

HSET_TLSH_OPTIONS=0 mkhashset 'Some test hashes' 'md5 and tlsh' md5 tlsh true true md5_tlsh.txt md5_tlsh.hset

The TIVF index is built by integer clustering by default, whose bytes are the
same on every platform. Add SFHASH_HSET_TLSH_INDEX_KMEANS (8) to build it with
the float k-means instead: equally exact, but quadratic in the largest header
cell, and its bytes depend on compiler and platform. Both sections, k-means
index:

HSET_TLSH_OPTIONS=11 mkhashset 'Some test hashes' 'md5 and tlsh' md5 tlsh true true md5_tlsh.txt md5_tlsh.hset

*/

#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "util.h"
#include "hasher/hashset.h"
#include "hashset/hset_encoder.h"

int main(int argc, char** argv) {
  if (argc < 7) {
    std::cerr << "Usage: mkhashset NAME DESC TYPE... RECORDS HASHSETS INFILE OUTIFLE" << std::endl;
    return -1;
  }

  try {
    // turn off synchronization of C++ streams with C streams
    std::ios_base::sync_with_stdio(false);

    std::vector<SFHASH_HashAlgorithm> htypes;
    for (int i = 3; i < argc - 4; ++i) {
      const SFHASH_HashAlgorithm t = sfhash_hash_type(argv[i]);
      THROW_IF(
        t == SFHASH_INVALID,
        "unrecognized hash type '" << argv[i] << "'"
      );

      htypes.push_back(t);
    }

    const auto& conv = make_text_converters(htypes);

    std::cerr << "creating hset file\n";

    bool with_records = !std::strcmp(argv[argc-4], "true");
    bool with_hashsets = !std::strcmp(argv[argc-3], "true");

    const std::filesystem::path outfile = argv[argc-1];
    const std::filesystem::path infile = argv[argc-2];
    const std::filesystem::path tmpdir = ".";
    std::ifstream in(infile);

    // optional TLSH sections, both by default
    uint32_t tlsh_options = SFHASH_HSET_TLSH_VECTORS | SFHASH_HSET_TLSH_INDEX;
    if (const char* opts = std::getenv("HSET_TLSH_OPTIONS")) {
      try {
        tlsh_options = boost::lexical_cast<uint32_t>(opts);
      }
      catch (const boost::bad_lexical_cast&) {
        THROW("HSET_TLSH_OPTIONS is not a nonnegative integer: '" << opts << "'");
      }
    }

    write_hset(in, htypes, conv, argv[1], argv[2], outfile, tmpdir, with_records, with_hashsets, tlsh_options);
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
