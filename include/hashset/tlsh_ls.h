#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "throw.h"
#include "tlsh_digest.h"
#include "hashset/lookupstrategy.h"
#include "hashset/tlsh_cells.h"

/*
 * Lookup strategy for TLSH hashsets using the cell index HINT (type 0x7400).
 * A lookup is a binary search within the row range of the digest's cell.
 */
class TlshLookupStrategy: public LookupStrategy {
public:
  // cells points at TLSH_CELL_COUNT + 1 little-endian uint64_t offsets, or
  // is null for a plain binary search over all rows. It need not be aligned.
  TlshLookupStrategy(const void* beg, const void* end, const void* cells):
    Beg(static_cast<const TlshDigest*>(beg)),
    End(static_cast<const TlshDigest*>(end)),
    Cells(nullptr)
  {
    if (cells) {
      if (reinterpret_cast<uintptr_t>(cells) % alignof(uint64_t) == 0) {
        Cells = static_cast<const uint64_t*>(cells);
      }
      else {
        // the mapped payload is unaligned; keep an aligned copy
        OwnedCells.resize(TLSH_CELL_COUNT + 1);
        std::memcpy(OwnedCells.data(), cells, OwnedCells.size() * sizeof(uint64_t));
        Cells = OwnedCells.data();
      }

      const uint64_t n = End - Beg;
      THROW_IF(Cells[0] != 0, "bad TLSH cell index: first offset is " << Cells[0]);
      THROW_IF(
        Cells[TLSH_CELL_COUNT] != n,
        "bad TLSH cell index: last offset is " << Cells[TLSH_CELL_COUNT] << ", expected " << n
      );
      for (size_t c = 0; c < TLSH_CELL_COUNT; ++c) {
        THROW_IF(Cells[c] > Cells[c + 1], "bad TLSH cell index: offsets decrease at cell " << c);
      }
    }
  }

  virtual ~TlshLookupStrategy() {}

  virtual bool contains(const uint8_t* hash) const override {
    const TlshDigest& d = *reinterpret_cast<const TlshDigest*>(hash);
    const auto [lo, hi] = cell_range(d);
    return std::binary_search(lo, hi, d);
  }

  // the rows holding digests in the same cell as d
  std::pair<const TlshDigest*, const TlshDigest*> cell_range(const TlshDigest& d) const {
    if (!Cells) {
      return { Beg, End };
    }
    const uint32_t c = tlsh_cell_id(d);
    return { Beg + Cells[c], Beg + Cells[c + 1] };
  }

  const TlshDigest* begin() const { return Beg; }

  const TlshDigest* end() const { return End; }

  // TLSH_CELL_COUNT + 1 offsets, or null
  const uint64_t* cells() const { return Cells; }

private:
  const TlshDigest* Beg;
  const TlshDigest* End;
  const uint64_t* Cells;
  std::vector<uint64_t> OwnedCells;
};
