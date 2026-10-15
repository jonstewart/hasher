#pragma once

// C++20: #include <concepts>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <ostream>
#include <span>

#include <iostream>

#include "hex.h"
#include "hashset/arrow_proxy.h"

/*
 * The iterators below dereference to proxies which alias records in a
 * buffer. Each iterator's value_type is a distinct owning type, so that
 * when an algorithm holds a value (e.g., std::sort's pivot, initialized
 * from the prvalue returned by iter_move) it gets a copy of the record
 * rather than (via guaranteed copy elision) an alias into the buffer.
 */

struct Record;

struct RecordProxy {
  std::span<uint8_t> rec;
  std::unique_ptr<uint8_t[]> tmp;

  RecordProxy(std::span<uint8_t> rec): rec(rec) {
  }

  RecordProxy(const RecordProxy& o): rec(o.rec) {
  }

  RecordProxy& operator=(const RecordProxy& o) noexcept {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    return *this;
  }

  RecordProxy(RecordProxy&& o) noexcept {
    tmp.reset(new uint8_t[o.rec.size()]);
    std::memcpy(tmp.get(), o.rec.data(), o.rec.size());
    rec = { tmp.get(), o.rec.size() };
  }

  RecordProxy& operator=(RecordProxy&& o) noexcept {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    return *this;
  }

  RecordProxy& operator=(const Record& o) noexcept;

  int cmp(const RecordProxy& o) const noexcept {
    return std::memcmp(rec.data(), o.rec.data(), rec.size());
  }

  bool operator==(const RecordProxy& o) const noexcept {
    return cmp(o) == 0;
  }

  bool operator!=(const RecordProxy& o) const noexcept {
    return !(*this == o);
  }

  bool operator<(const RecordProxy& o) const noexcept {
    return cmp(o) < 0;
  }

  bool operator<=(const RecordProxy& o) const noexcept {
    return cmp(o) <= 0;
  }

  bool operator>(const RecordProxy& o) const noexcept {
    return cmp(o) > 0;
  }

  bool operator>=(const RecordProxy& o) const noexcept {
    return cmp(o) >= 0;
  }

// C++20:
/*
  auto operator<=>(const RecordProxy& o) const noexcept {
    return std::memcmp(rec.data(), o.rec.data(), rec.size());
  }

  bool operator==(const RecordProxy& o) const noexcept {
    return (*this <=> o) == 0;
  }
*/
};

struct Record {
  std::unique_ptr<uint8_t[]> buf;
  std::span<uint8_t> rec;

  Record(const RecordProxy& o):
    buf(new uint8_t[o.rec.size()]), rec(buf.get(), o.rec.size())
  {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
  }

  Record(Record&&) noexcept = default;

  Record& operator=(Record&&) noexcept = default;

  Record& operator=(const RecordProxy& o) noexcept {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    return *this;
  }

  // rewritten candidates supply the reversed RecordProxy-Record comparisons
  int operator<=>(const RecordProxy& o) const noexcept {
    return std::memcmp(rec.data(), o.rec.data(), rec.size());
  }

  bool operator==(const RecordProxy& o) const noexcept {
    return (*this <=> o) == 0;
  }
};

inline RecordProxy& RecordProxy::operator=(const Record& o) noexcept {
  std::memcpy(rec.data(), o.rec.data(), rec.size());
  return *this;
}

std::ostream& operator<<(std::ostream& out, const RecordProxy& r);

void swap(RecordProxy a, RecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);

namespace std {
void swap(RecordProxy a, RecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);
}

//C++20: static_assert(std::swappable<RecordProxy>);

class RecordIterator {
public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = Record;
  using reference = RecordProxy;
  using pointer = ArrowProxy<reference>;
  using difference_type = std::ptrdiff_t;

  RecordIterator(
    uint8_t* cur,
    uint64_t record_length
  ):
    cur(cur), record_length(record_length)
  {}

  RecordIterator():
    cur(nullptr), record_length(0)
  {}

  reference operator*() const noexcept {
    return reference{{cur, record_length}};
  }

  pointer operator->() const noexcept {
    return pointer{{{cur, record_length}}};
  }

  RecordIterator& operator++() noexcept {
    cur += record_length;
    return *this;
  }

  RecordIterator operator++(int) noexcept {
    RecordIterator itr{*this};
    ++(*this);
    return itr;
  }

  RecordIterator& operator--() noexcept {
    cur -= record_length;
    return *this;
  }

  RecordIterator operator--(int) noexcept {
    RecordIterator itr{*this};
    --(*this);
    return itr;
  }

  RecordIterator operator+(difference_type n) const noexcept {
    RecordIterator itr{*this};
    return itr += n;
  }

  friend RecordIterator operator+(difference_type n, const RecordIterator& i) noexcept {
    return i + n;
  }

  RecordIterator operator-(difference_type n) const noexcept {
    RecordIterator itr{*this};
    return itr -= n;
  }

  difference_type operator-(const RecordIterator& o) const noexcept {
    return (cur - o.cur) / record_length;
  }

  RecordIterator& operator+=(difference_type n) noexcept {
    cur += n * record_length;
    return *this;
  }

  RecordIterator& operator-=(difference_type n) noexcept {
    cur -= n * record_length;
    return *this;
  }

  reference operator[](difference_type n) const noexcept {
    return *(*this + n);
  }

  bool operator<(const RecordIterator& o) const noexcept {
    return cur < o.cur;
  }

  bool operator<=(const RecordIterator& o) const noexcept {
    return cur <= o.cur;
  }

  bool operator>(const RecordIterator& o) const noexcept {
    return cur > o.cur;
  }

  bool operator>=(const RecordIterator& o) const noexcept {
    return cur >= o.cur;
  }

// C++20:
/*
  auto operator<=>(const RecordIterator& o) const noexcept {
    return cur - o.cur;
  }
*/

  bool operator==(const RecordIterator& o) const noexcept {
    return cur == o.cur;
  }

  bool operator!=(const RecordIterator& o) const noexcept {
    return cur != o.cur;
  }

  friend std::ostream& operator<<(std::ostream& out, const RecordIterator& i);

private:
  uint8_t* cur;
  uint64_t record_length;
};

// C++20: static_assert(std::random_access_iterator<RecordIterator>);

struct HashRecord;

struct HashRecordProxy {
  std::span<uint8_t> rec;
  uint64_t* idx;

  std::unique_ptr<uint8_t[]> tmp;
  uint64_t tmp_idx;

  HashRecordProxy(std::span<uint8_t> rec, uint64_t* idx): rec(rec), idx(idx) {
  }

  HashRecordProxy(const HashRecordProxy& o): rec(o.rec), idx(o.idx) {
  }

  HashRecordProxy& operator=(const HashRecordProxy& o) noexcept {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    *idx = *(o.idx);
    return *this;
  }

  HashRecordProxy(HashRecordProxy&& o) noexcept {
    tmp.reset(new uint8_t[o.rec.size()]);
    std::memcpy(tmp.get(), o.rec.data(), o.rec.size());
    rec = { tmp.get(), o.rec.size() };

    tmp_idx = *(o.idx);
    idx = &tmp_idx;
  }

  HashRecordProxy& operator=(HashRecordProxy&& o) noexcept {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    *idx = *(o.idx);
    return *this;
  }

  HashRecordProxy& operator=(const HashRecord& o) noexcept;

// C++20:
/*
  auto operator<=>(const HashRecordProxy& o) const noexcept {
    const auto r = std::memcmp(rec.data(), o.rec.data(), rec.size());
    return r == 0 ? static_cast<int64_t>(*(o.idx)) - static_cast<int64_t>(*idx) : r;
  }

  bool operator==(const HashRecordProxy& o) const noexcept {
    return (*this <=> o) == 0;
  }
*/

  int cmp(const HashRecordProxy& o) const noexcept {
    const auto r = std::memcmp(rec.data(), o.rec.data(), rec.size());
    return r == 0 ? static_cast<int64_t>(*(o.idx)) - static_cast<int64_t>(*idx) : r;
  }

  bool operator<(const HashRecordProxy& o) const noexcept {
    return cmp(o) < 0;
  }

  bool operator==(const HashRecordProxy& o) const noexcept {
    return cmp(o) == 0;
  }
};

struct HashRecord {
  std::unique_ptr<uint8_t[]> buf;
  std::span<uint8_t> rec;
  uint64_t idx;

  HashRecord(const HashRecordProxy& o):
    buf(new uint8_t[o.rec.size()]), rec(buf.get(), o.rec.size()), idx(*o.idx)
  {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
  }

  HashRecord(HashRecord&&) noexcept = default;

  HashRecord& operator=(HashRecord&&) noexcept = default;

  HashRecord& operator=(const HashRecordProxy& o) noexcept {
    std::memcpy(rec.data(), o.rec.data(), rec.size());
    idx = *(o.idx);
    return *this;
  }

  // rewritten candidates supply the reversed HashRecordProxy-HashRecord
  // comparisons
  int64_t operator<=>(const HashRecordProxy& o) const noexcept {
    const auto r = std::memcmp(rec.data(), o.rec.data(), rec.size());
    return r == 0 ? static_cast<int64_t>(*(o.idx)) - static_cast<int64_t>(idx) : r;
  }

  bool operator==(const HashRecordProxy& o) const noexcept {
    return (*this <=> o) == 0;
  }
};

inline HashRecordProxy& HashRecordProxy::operator=(const HashRecord& o) noexcept {
  std::memcpy(rec.data(), o.rec.data(), rec.size());
  *idx = o.idx;
  return *this;
}

std::ostream& operator<<(std::ostream& out, const HashRecordProxy& r);

void swap(HashRecordProxy a, HashRecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);

namespace std {
void swap(HashRecordProxy a, HashRecordProxy b);

//void swap(RecordProxy& a, RecordProxy& b);
}

class HashRecordIterator {
public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = HashRecord;
  using reference = HashRecordProxy;
  using pointer = ArrowProxy<reference>;
  using difference_type = std::ptrdiff_t;

  HashRecordIterator(
    size_t pos,
    uint8_t* hashes,
    uint64_t record_length,
    uint64_t* indices
  ):
    pos(pos), hashes(hashes), record_length(record_length), indices(indices)
  {}

  HashRecordIterator():
    pos(0), hashes(nullptr), record_length(0), indices(nullptr)
  {}

  reference operator*() const noexcept {
    return reference{{hashes + pos * record_length, record_length}, indices + pos};
  }

  pointer operator->() const noexcept {
    return pointer{{{hashes + pos * record_length, record_length}, indices + pos}};
  }

  HashRecordIterator& operator++() noexcept {
    ++pos;
    return *this;
  }

  HashRecordIterator operator++(int) noexcept {
    HashRecordIterator itr{*this};
    ++(*this);
    return itr;
  }

  HashRecordIterator& operator--() noexcept {
    --pos;
    return *this;
  }

  HashRecordIterator operator--(int) noexcept {
    HashRecordIterator itr{*this};
    --(*this);
    return itr;
  }

  HashRecordIterator operator+(difference_type n) const noexcept {
    HashRecordIterator itr{*this};
    return itr += n;
  }

  friend HashRecordIterator operator+(difference_type n, const HashRecordIterator& i) noexcept {
    return i + n;
  }

  HashRecordIterator operator-(difference_type n) const noexcept {
    HashRecordIterator itr{*this};
    return itr -= n;
  }

  difference_type operator-(const HashRecordIterator& o) const noexcept {
    return difference_type(pos) - difference_type(o.pos);
  }

  HashRecordIterator& operator+=(difference_type n) noexcept {
    pos += n;
    return *this;
  }

  HashRecordIterator& operator-=(difference_type n) noexcept {
    pos -= n;
    return *this;
  }

  reference operator[](difference_type n) const noexcept {
    return *(*this + n);
  }

  bool operator<(const HashRecordIterator& o) const noexcept {
    return pos < o.pos;
  }

  bool operator<=(const HashRecordIterator& o) const noexcept {
    return pos <= o.pos;
  }

  bool operator>(const HashRecordIterator& o) const noexcept {
    return pos > o.pos;
  }

  bool operator>=(const HashRecordIterator& o) const noexcept {
    return pos >= o.pos;
  }

// C++20:
/*
  auto operator<=>(const HashRecordIterator& o) const noexcept {
    return pos - o.pos;
  }
*/

  bool operator==(const HashRecordIterator& o) const noexcept {
    return pos == o.pos;
  }

  bool operator!=(const HashRecordIterator& o) const noexcept {
    return pos != o.pos;
  }

private:
  size_t pos;
  uint8_t* hashes;
  uint64_t record_length;
  uint64_t* indices;
};

// C++20: static_assert(std::random_access_iterator<HashRecordIterator>);
