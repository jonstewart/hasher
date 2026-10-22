#include "hashset/tlsh_cells.h"

#include "throw.h"

std::vector<uint64_t> make_tlsh_cell_index(const TlshDigest* beg, const TlshDigest* end) {
  std::vector<uint64_t> cells(TLSH_CELL_COUNT + 1, 0);

  const uint64_t n = end - beg;

  // count the rows in each cell
  for (const TlshDigest* d = beg; d != end; ++d) {
    THROW_IF(d != beg && *d < *(d - 1), "TLSH rows are not sorted");
    ++cells[tlsh_cell_id(*d) + 1];
  }

  // prefix sum turns counts into start offsets
  for (size_t c = 1; c <= TLSH_CELL_COUNT; ++c) {
    cells[c] += cells[c - 1];
  }

  THROW_IF(cells[TLSH_CELL_COUNT] != n, "TLSH cell index does not cover all rows");

  return cells;
}
