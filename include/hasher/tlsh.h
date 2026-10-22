#ifndef HASHER_TLSH_H_
#define HASHER_TLSH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 TLSH digests

 libhasher stores a TLSH digest (128 buckets, 1-byte checksum) in a fixed
 36-byte canonical form rather than the 70-character hex transport encoding.
 The layout is chosen so that bytewise lexicographic order is the canonical
 sort order (L, Q1, Q2, body, checksum) used by hash sets:

   offset  0: L          log-scaled input length
   offset  1: Q          (Q1 << 4) | Q2
   offset  2: plane_hi   16 bytes; bit i = bit 1 of bucket code i
   offset 18: plane_lo   16 bytes; bit i = bit 0 of bucket code i
   offset 34: checksum
   offset 35: reserved   always 0

 Bit i of a plane lives in byte i / 8 at bit position i % 8.

 An all-zero digest is the null digest ("TNULL"), produced for inputs the
 algorithm cannot hash (fewer than 50 bytes, or too little variety).
******************************************************************************/

#define SFHASH_TLSH_DIGEST_LENGTH 36

/* "T1" prefix + 70 hex characters */
#define SFHASH_TLSH_HEX_LENGTH 72

/*
 * Decode a hex TLSH string into the 36-byte canonical form.
 *
 * Accepts 70 hex characters with or without the "T1" prefix, in either
 * case, and the literal "TNULL" (which yields the null digest). hex must be
 * NUL-terminated or followed by a non-hex character.
 *
 * Returns true on success, false if the input is not a TLSH string.
 */
bool sfhash_tlsh_from_hex(const char* hex, void* digest);

/*
 * Encode a 36-byte canonical digest as "T1" + 70 uppercase hex characters,
 * NUL-terminated (73 bytes written). The null digest encodes as "TNULL".
 */
void sfhash_tlsh_to_hex(const void* digest, char* hex);

/* True if digest is the null digest. */
bool sfhash_tlsh_is_null(const void* digest);

/*
 * TLSH distance between two canonical digests, identical to the reference
 * implementation's Tlsh::totalDiff(other, include_length).
 *
 * Returns -1 if either digest is null.
 */
int sfhash_tlsh_diff(const void* a, const void* b, bool include_length);

/******************************************************************************
 Lower-bound Euclidean embedding

 sfhash_tlsh_embed maps a digest to SFHASH_TLSH_EMBEDDING_DIMS float32
 coordinates such that for any two digests a, b with sfhash_tlsh_diff(a, b,
 true) <= 144, the squared Euclidean distance between their embeddings is at
 most that TLSH distance. See docs/TLSH_EMBEDDING.md.
******************************************************************************/

#define SFHASH_TLSH_EMBEDDING_DIMS 264

/* Index of the length (L) coordinate; omit it for include_length = false. */
#define SFHASH_TLSH_EMBEDDING_L_DIM 256

void sfhash_tlsh_embed(const void* digest, float* out);

/* Squared Euclidean distance between two embeddings. */
float sfhash_tlsh_embed_dist2(const float* a, const float* b, bool include_length);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_TLSH_H_ */
