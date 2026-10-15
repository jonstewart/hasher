#include "hashset/record_iterator.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <numeric>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("RecordProxy_swap") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x22, 0x22,
    0x11, 0x11
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  std::swap(a, b);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));
}

TEST_CASE("RecordProxy_copy_assignment") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x22, 0x22,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  a = b;

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp, rlen));
}

TEST_CASE("RecordProxy_copy_ctor") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy b{{dat + rlen, rlen}};
  RecordProxy a(b);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp + rlen, rlen));
}

TEST_CASE("RecordProxy_move_assignment") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x22, 0x22,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  a = std::move(b);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp, rlen));
}

TEST_CASE("RecordProxy_move_ctor") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy b{{dat + rlen, rlen}};
  RecordProxy a(std::move(b));

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));

  CHECK(!std::memcmp(a.rec.data(), exp + rlen, rlen));
  CHECK(a.rec.data() != exp);
}

TEST_CASE("RecordProxy_cmp") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const size_t rlen = 2;

  RecordProxy a{{dat, rlen}};
  RecordProxy b{{dat + rlen, rlen}};

  CHECK(a < b);
  CHECK(a <= b);
  CHECK(!(a == b));
  CHECK(a != b);
  CHECK(b >= a);
  CHECK(b > a);

  CHECK(!(a < a));
  CHECK(a <= a);
  CHECK(a == a);
  CHECK(!(a != a));
  CHECK(a >= a);
  CHECK(!(a > a));
}

template <class Itr>
void check_weakly_incrementable(Itr a) {
  CHECK(std::addressof(++a) == std::addressof(a));
}

template <class Itr>
void check_forward_iterator_1(Itr a, Itr b) {
// only if a, b are dereferenceable
  CHECKED_IF(a == b) {
    CHECK(++a == ++b);
  }
}

template <class Itr>
void check_forward_iterator_2(Itr a) {
// only if a is dereferenceable
  CHECK(((void)[](auto x){ ++x; }(a), *a) == *a);
}

template <class Itr>
void check_bidirectional_iterator_1(Itr a) {
// a is incrementable
  CHECK(std::addressof(--a) == std::addressof(a));
}

template <class Itr>
void check_bidirectional_iterator_2(Itr a) {
// a is decrementable
  Itr b = a;
  CHECK(a-- == b);
}

template <class Itr>
void check_bidirectional_iterator_3(Itr a) {
  Itr b = a;
  CHECK(a-- == b--);
}

template <class Itr>
void check_bidirectional_iterator_4(Itr a) {
  Itr b = a;
  CHECK(--(++a) == b);
}

template <class Itr>
void check_bidirectional_iterator_5(Itr a) {
  Itr b = a;
  CHECK(++(--a) == b);
}

template <class Itr>
void check_random_access_iterator_1(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK((a += n) == b);
}

template <class Itr>
void check_random_access_iterator_2(Itr a, typename Itr::difference_type n) {
  CHECK(std::addressof(a += n) == std::addressof(a));
}

template <class Itr>
void check_random_access_iterator_3(Itr a, typename Itr::difference_type n) {
  Itr b = a + n;
  CHECK(b == (a += n));
}

template <class Itr>
void check_random_access_iterator_4(Itr a, typename Itr::difference_type n) {
  CHECK(a + n == n + a);
}

template <class Itr>
void check_random_access_iterator_5(Itr a, typename Itr::difference_type x, typename Itr::difference_type y) {
  CHECK(a + (x + y) == (a + x) + y);
}

template <class Itr>
void check_random_access_iterator_6(Itr a) {
  CHECK(a + 0 == a);
}

template <class Itr>
void check_random_access_iterator_7(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK(a + (n - 1) == --b);
}

template <class Itr>
void check_random_access_iterator_8(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK((b += -n) == a);
}

template <class Itr>
void check_random_access_iterator_9(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK((b -= n) == a);
}

template <class Itr>
void check_random_access_iterator_10(Itr b, typename Itr::difference_type n) {
  CHECK(std::addressof(b -= n) == std::addressof(b));
}

template <class Itr>
void check_random_access_iterator_11(Itr b, typename Itr::difference_type n) {
  Itr a = b - n;
  CHECK(a == (b -= n));
}

template <class Itr>
void check_random_access_iterator_12(Itr a, Itr b, typename Itr::difference_type n) {
  CHECK(a[n] == *b);
}

template <class Itr>
void check_random_access_iterator_13(Itr a, Itr b) {
  CHECK(a <= b);
}

TEST_CASE("RecordIterator_random_access_iterator") {

  uint8_t data[] = {
    0x10, 0x01,
    0x20, 0x02,
    0x30, 0x03,
    0x40, 0x04,
    0x50, 0x05
  };

  const size_t rlen = 2;
  const ssize_t rcount = std::size(data) / rlen;

  const RecordIterator beg(std::begin(data), rlen);
  const RecordIterator end(std::end(data), rlen);

  for (size_t ai = 0; ai < rcount; ai += rlen) {
    RecordIterator a(data + ai, rlen);

    check_weakly_incrementable(a);

    check_forward_iterator_2(a);

    check_bidirectional_iterator_1(a);
    check_bidirectional_iterator_2(a);
    check_bidirectional_iterator_3(a);
    check_bidirectional_iterator_4(a);
    check_bidirectional_iterator_5(a);

    check_random_access_iterator_6(a);

    for (size_t bi = 0; bi < rcount; bi += rlen) {
      RecordIterator b(data + bi, rlen);
      check_forward_iterator_1(a, b);
    }

    for (RecordIterator::difference_type x = -rcount; x < rcount; ++x) {
      for (RecordIterator::difference_type y = -rcount; y < rcount; ++y) {
        check_random_access_iterator_5(a, x, y);
      }
    }

    for (RecordIterator::difference_type n = -rcount; n < rcount; ++n) {
      RecordIterator b = a + n;

      check_random_access_iterator_1(a, b, n);
      check_random_access_iterator_2(a, n);
      check_random_access_iterator_3(a, n);
      check_random_access_iterator_4(a, n);

      check_random_access_iterator_7(a, b, n);
      check_random_access_iterator_8(a, b, n);
      check_random_access_iterator_9(a, b, n);
      check_random_access_iterator_10(b, n);

      check_random_access_iterator_11(b, n);

      if ((a + n) - beg >= 0 && ((a + n) - beg) < end - beg) {
        check_random_access_iterator_12(a, b, n);
      }

      if (n >= 0) {
        check_random_access_iterator_13(a, b);
      }
    }
  }
}

TEST_CASE("RecordIterator_sort_small") {
  uint8_t dat[] = {
    0x33, 0x33,
    0x22, 0x22,
    0x11, 0x11
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22,
    0x33, 0x33
  };

  const size_t rlen = 2;
  const size_t rcount = std::size(dat) / rlen;

  RecordIterator beg(std::begin(dat), rlen);
  RecordIterator end(std::end(dat), rlen);

  std::sort(beg, end);

  for (size_t i = 0; i < rcount; ++i) {
    CHECK(!std::memcmp(dat + i*rlen, exp + i*rlen, rlen));
  }
}

TEST_CASE("RecordIterator_sort_large") {
  // large enough that std::sort partitions rather than insertion sorting
  const size_t rlen = 3;
  const size_t rcount = 1000;

  std::mt19937 rng(42);
  std::uniform_int_distribution<int> byte(0, 255);

  std::vector<std::array<uint8_t, rlen>> recs(rcount);
  for (auto& r: recs) {
    for (auto& b: r) {
      b = byte(rng);
    }
  }

  std::vector<uint8_t> dat;
  for (const auto& r: recs) {
    dat.insert(dat.end(), r.begin(), r.end());
  }

  std::sort(recs.begin(), recs.end());

  RecordIterator beg(dat.data(), rlen);
  RecordIterator end(dat.data() + dat.size(), rlen);

  std::sort(beg, end);

  for (size_t i = 0; i < rcount; ++i) {
    CHECK(!std::memcmp(dat.data() + i*rlen, recs[i].data(), rlen));
  }
}

TEST_CASE("HashRecordIterator_sort_large") {
  // large enough that std::sort partitions rather than insertion sorting
  const size_t hlen = 3;
  const size_t hcount = 1000;

  std::mt19937 rng(42);
  std::uniform_int_distribution<int> byte(0, 255);

  std::vector<uint8_t> hashes(hcount * hlen);
  for (auto& b: hashes) {
    b = byte(rng);
  }

  // record the original position of each hash
  std::vector<uint64_t> idx(hcount);
  std::iota(idx.begin(), idx.end(), 0);

  const std::vector<uint8_t> orig(hashes);

  HashRecordIterator beg(0, hashes.data(), hlen, idx.data());
  HashRecordIterator end(hcount, hashes.data(), hlen, idx.data());

  std::sort(beg, end);

  for (size_t i = 0; i < hcount; ++i) {
    // the hashes are sorted
    if (i > 0) {
      CHECK(std::memcmp(hashes.data() + (i-1)*hlen, hashes.data() + i*hlen, hlen) <= 0);
    }

    // each index still points to its hash
    REQUIRE(idx[i] < hcount);
    CHECK(!std::memcmp(hashes.data() + i*hlen, orig.data() + idx[i]*hlen, hlen));
  }
}

TEST_CASE("RecordIterator_value_type_is_a_copy") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  const uint8_t exp[] = { 0x11, 0x11 };

  const size_t rlen = 2;

  RecordIterator beg(std::begin(dat), rlen);

  // std::sort initializes its pivot this way, from the prvalue proxy; the
  // value must not alias the record it came from
  RecordIterator::value_type v = *beg;

  *beg = *(beg + 1);

  CHECK(!std::memcmp(v.rec.data(), exp, rlen));
}

TEST_CASE("HashRecordProxy_swap") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22
  };

  uint64_t idx[] = { 1, 2 };

  const uint8_t exp[] = {
    0x22, 0x22,
    0x11, 0x11
  };

  const uint64_t exp_idx[] = { 2, 1 };

  const size_t hlen = 2;

  HashRecordProxy a{{dat, hlen}, idx};
  HashRecordProxy b{{dat + hlen, hlen}, idx + 1};

  std::swap(a, b);

  CHECK(!std::memcmp(dat, exp, std::size(dat)));
  CHECK(idx[0] == exp_idx[0]);
  CHECK(idx[1] == exp_idx[1]);
}

TEST_CASE("HashRecordIterator_value_type_is_a_copy") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x22, 0x22,
    0x33, 0x33
  };

  uint64_t idx[] = { 1, 2, 3 };

  const size_t hlen = 2;

  HashRecordIterator beg(0, dat, hlen, idx);

  // std::sort initializes its pivot this way, from the prvalue proxy; the
  // value must not alias the hash and index it came from
  HashRecordIterator::value_type v = *beg;

  *beg = *(beg + 1);

  // store the value elsewhere to check both its hash and its index
  *(beg + 2) = v;

  const uint8_t exp[] = {
    0x22, 0x22,
    0x22, 0x22,
    0x11, 0x11
  };

  const uint64_t exp_idx[] = { 2, 2, 1 };

  CHECK(!std::memcmp(dat, exp, std::size(dat)));
  CHECK(idx[0] == exp_idx[0]);
  CHECK(idx[1] == exp_idx[1]);
  CHECK(idx[2] == exp_idx[2]);
}

TEST_CASE("RecordIterator_unique") {
  uint8_t dat[] = {
    0x11, 0x11,
    0x11, 0x11,
    0x11, 0x11,
    0x11, 0x11,
    0x11, 0x11,
    0x22, 0x22,
    0x33, 0x33,
    0x33, 0x33
  };

  const uint8_t exp[] = {
    0x11, 0x11,
    0x22, 0x22,
    0x33, 0x33
  };

  const size_t rlen = 2;

  RecordIterator beg(std::begin(dat), rlen);
  RecordIterator end(std::end(dat), rlen);

  RecordIterator nend = std::unique(beg, end);

  CHECK(nend - beg == std::size(exp) / rlen);

  CHECK(!std::memcmp(dat, exp, rlen));
  CHECK(!std::memcmp(dat + rlen, exp + rlen, rlen));
  CHECK(!std::memcmp(dat + 2*rlen, exp + 2*rlen, rlen));
}
