#pragma once

#include "hasher_impl.h"
#include "tlsh_digest.h"

#include <cstdint>
#include <memory>

/*
 * Streaming TLSH (128 buckets, 1-byte checksum), bit-identical to the
 * reference implementation but with a trivially copyable state so that
 * clone() is cheap and safe.
 */
class TlshHasher: public HasherImpl {
public:
  TlshHasher();

  virtual ~TlshHasher() {}

  virtual void update(const uint8_t* beg, const uint8_t* end) override;

  virtual void set_total_input_length(uint64_t) override {}

  // writes a TlshDigest (36 bytes); null digest if the input cannot be hashed
  virtual void get(void* val) override;

  virtual void reset() override;

  virtual TlshHasher* clone() const override;

  TlshDigest digest() const;

private:
  uint32_t Buckets[256];
  uint8_t Window[5];
  uint8_t Checksum;
  // the reference implementation tracks the length as an unsigned int
  uint32_t Length;
};

std::unique_ptr<HasherImpl> make_tlsh_hasher();
