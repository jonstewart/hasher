#!/usr/bin/python3

"""
Make a hashset from a list of filenames:

find -type f | xargs sha1sum | cut -f1 -d' ' | sort -u | ./mkhashset.py sha1 'Some test hashes' 'These are test hashes.' >sha1.hset


Make a hashset and sizeset from a list of filenames:

for i in  $(find -type f); do echo $(sha1sum $i) $(stat --printf=%s $i) ; done | cut -f1,3 -d' ' | sort -u | ./mkhashset.py sha1 'Some test hashes' 'These are test hashes.' >sha1.hset


Make a hashset and sizeset from the NSRL:

for i in NSRLFile.*.txt.gz ; do zcat $i | ./nsrldump.py ; done | ./mkhashset.py sha1 'NSRL' 'The NSRL!' >nsrl.hset
"""
import argparse
import datetime
import hashlib
import sys


HASH_TYPE = {
    'md5':       1 <<  0,
    'sha1':      1 <<  1,
    'sha2_224':  1 <<  2,
    'sha2_256':  1 <<  3,
    'sha2_384':  1 <<  4,
    'sha2_512':  1 <<  5,
    'sha3_224':  1 <<  6,
    'sha3_256':  1 <<  7,
    'sha3_384':  1 <<  8,
    'sha3_512':  1 <<  9,
    'blake3':    1 << 10,
    'quick_md5': 1 << 14,
    'tlsh':      1 << 15,
    'other':     1 << 31
}

# hash lengths in bytes, where the hex input doesn't tell us directly
HASH_LENGTH = {
    'tlsh': 36
}


def tlsh_from_hex(s):
    """Decode a TLSH string ("T1" + 70 hex, bare 70 hex, or "TNULL") into
    libhasher's 36-byte canonical form (see include/hasher/tlsh.h):

      L, Q, plane_hi[16], plane_lo[16], checksum, 0

    where bit i of plane_hi/plane_lo is bit 1/bit 0 of bucket code i.
    """
    if s.upper() == 'TNULL':
        return bytes(HASH_LENGTH['tlsh'])
    if s[:2].upper() == 'T1':
        s = s[2:]
    if len(s) != 70:
        raise ValueError(f'bad TLSH string: {s!r}')
    raw = bytes.fromhex(s)

    def swap_nibbles(b):
        return ((b & 0x0F) << 4) | (b >> 4)

    checksum = swap_nibbles(raw[0])
    length = swap_nibbles(raw[1])
    q = raw[2]
    # body bytes are stored reversed in the hex form; body[i] packs bucket
    # codes 4i..4i+3 at bit positions 2j
    body = raw[3:35][::-1]
    plane_hi = bytearray(16)
    plane_lo = bytearray(16)
    for i in range(128):
        code = (body[i // 4] >> (2 * (i % 4))) & 3
        plane_hi[i // 8] |= (code >> 1) << (i % 8)
        plane_lo[i // 8] |= (code & 1) << (i % 8)

    return bytes([length, q]) + bytes(plane_hi) + bytes(plane_lo) + bytes([checksum, 0])


def nonempty_lines(src):
    for line in src:
        line = line.strip()
        if line:
            yield line


def expected_index(h, set_size):
    high32 = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]
    return (high32 * set_size) >> 32


def write_cstring(b, field_width, buf):
    wlen = buf.write(b)
    wlen += buf.write(b'\0' * (field_width - len(b)))
    return wlen


def run(hash_type, hashset_name, hashset_desc, inlines, outbuf):
    parse_hash = tlsh_from_hex if hash_type == 'tlsh' else bytes.fromhex
    hash_type = HASH_TYPE[hash_type]

    hashset_name = hashset_name.encode('UTF-8')
    hashset_desc = hashset_desc.encode('UTF-8')

    hashset_name_field_len = 96
    hashset_desc_field_len = 512

    # reject overlong strings before we do any work
    if len(hashset_name) + 1 > hashset_name_field_len:
        raise RuntimeError('hashset name too long')

    if len(hashset_desc) + 1 > hashset_desc_field_len:
        raise RuntimeError('hashset description too long')

    version = 1
    flags = 0

    hashes = []
    sizes = []

    for line in nonempty_lines(inlines):
        cols = line.split(' ')
        hashes.append(parse_hash(cols[0]))
        if len(cols) == 2:
            sizes.append(int(cols[1]))

    if len(hashes) != len(sizes) and sizes:
        raise RuntimeError('some sizes missing')

    hash_length = len(hashes[0])

    max_delta = 0
    for i, h in enumerate(hashes):
        ei = expected_index(h, len(hashes))
        max_delta = max(max_delta, abs(i - ei))

    hashset = b''.join(hashes)
    hasher = hashlib.sha256()
    hasher.update(hashset)

    hashes_off = 4096
    sizes_off = hashes_off + len(hashes)*hash_length if sizes else 0

    timestamp = datetime.datetime.now().isoformat(timespec='microseconds').encode('UTF-8')
    timestamp_field_len = 40

    pos = 0
    pos += outbuf.write(b'SetOHash')
    pos += outbuf.write(version.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(flags.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hash_type.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hash_length.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(len(hashes).to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hashes_off.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(sizes_off.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(max_delta.to_bytes(8, 'little', signed=False))
    pos += outbuf.write(hasher.digest())
    pos += write_cstring(hashset_name, hashset_name_field_len, outbuf)
    pos += write_cstring(timestamp, timestamp_field_len, outbuf)
    pos += write_cstring(hashset_desc, hashset_desc_field_len, outbuf)
    pos += outbuf.write(b'\0' * (hashes_off-pos))
    pos += outbuf.write(hashset)

    if sizes:
        pos += outbuf.write(b'\0' * (sizes_off-pos))
        for s in sizes:
            pos += outbuf.write(s.to_bytes(8, 'little', signed=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("hash_type", help="Hash type")
    parser.add_argument("hashset_name", help="Name of hash set")
    parser.add_argument("hashset_desc", help="Hash set description")
    args = parser.parse_args()
    run(args.hash_type, args.hashset_name, args.hashset_desc, sys.stdin,
        sys.stdout.buffer)  # pylint: disable=no-value-for-parameter
