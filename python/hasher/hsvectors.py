"""
hsvectors: read the chunks and TLSH rows of an hset file without libhasher

An hset file is "SetOHash", a 32-byte SHA-256, then chunks. Each chunk is a
4-byte type, a little-endian u64 payload length and the payload; the first
chunk, FTOC, lists (offset, type) of every chunk in the file. A TLSH hash set
is the chunk run

    HHnn HINT HDAT [RIDX] [TIVF]

where HDAT holds n sorted 36-byte canonical digests, RIDX n little-endian
u64 record indexes and TIVF the kNN index. The file does not store the
rows' embeddings (the TVEC chunk that did was removed from the format and is
rejected); compute them with libhasher, hasher.tlsh_embed() per digest or
HSet.tlsh_embeddings() for a whole hash set. See HASHSET_FORMAT and
docs/TLSH_EMBEDDING.md.

This module is pure Python with no dependency on the C library. numpy is a
soft dependency: the load_tlsh_* functions need it and raise ImportError
without it; read_toc, tlsh_sections, the *_rows functions and the hex codec
work everywhere.

    from hasher import hsvectors
    D = hsvectors.load_tlsh_digests('corpus.hset')   # (n, 36) uint8 memmap
    print(hsvectors.tlsh_hex(bytes(D[0])))
"""

from collections import namedtuple
import hashlib
import os
import struct

__all__ = [
    'MAGIC', 'TLSH_DIGEST_LENGTH', 'TLSH_EMBEDDING_DIMS',
    'ChunkEntry', 'TlshSection', 'TivfHeader',
    'read_toc', 'chunk_name', 'hhdr_hash_type', 'chunk_sha256',
    'tlsh_sections', 'tivf_header',
    'load_tlsh_digests', 'load_tlsh_record_index',
    'tlsh_digest_rows', 'tlsh_record_index_rows',
    'tlsh_hex', 'tlsh_from_hex',
]

MAGIC = b'SetOHash'
HSET_HASH_LENGTH = 32
CHUNK_HEADER_LENGTH = 12  # 4-byte type + u64 length

TLSH_DIGEST_LENGTH = 36
TLSH_EMBEDDING_DIMS = 264
TLSH_HASH_BIT = 15        # SFHASH_TLSH == 1 << 15

TIVF_HEADER_LENGTH = 32

# hash type bit -> field name, as in hasher.ALL_HASHES
HASH_NAMES = [
    'md5', 'sha1', 'sha2_224', 'sha2_256', 'sha2_384', 'sha2_512',
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'blake3', 'fuzzy',
    'entropy', 'size', 'quick_md5', 'tlsh',
]

# (offset, type, length): type is the 4-byte chunk type decoded as latin-1,
# e.g. 'FTOC', 'TIVF'; a hash set header is 'HH' + the hash type bit as a
# big-endian u16, see chunk_name()/hhdr_hash_type()
ChunkEntry = namedtuple('ChunkEntry', 'offset type length')

# the chunks of one TLSH hash set; each is a ChunkEntry or None
TlshSection = namedtuple('TlshSection', 'hhdr hint hdat ridx tivf')

TivfHeader = namedtuple('TivfHeader', 'version flags dims lists n')


class _Reader(object):
    """Random access reads from a path or a bytes-like object."""

    def __init__(self, src):
        self.path = None
        self.buf = None
        if isinstance(src, (str, os.PathLike)):
            self.path = os.fspath(src)
            self.size = os.path.getsize(self.path)
        else:
            try:
                self.buf = memoryview(src)
            except TypeError:
                raise TypeError(
                    f'expected a path or a bytes-like object, got {type(src).__name__}'
                ) from None
            self.size = self.buf.nbytes

    def read(self, offset, length):
        if offset < 0 or offset + length > self.size:
            raise ValueError(
                f'{length} bytes at offset {offset} run past the end of the hset ({self.size} bytes)'
            )
        if self.buf is not None:
            return bytes(self.buf[offset:offset + length])
        with open(self.path, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
        if len(data) != length:
            raise ValueError(f'short read at offset {offset}')
        return data


def _chunk_header(rd, offset):
    hdr = rd.read(offset, CHUNK_HEADER_LENGTH)
    ctype = hdr[:4].decode('latin-1')
    (length,) = struct.unpack_from('<Q', hdr, 4)
    return ctype, length


def read_toc(src):
    """The chunks of an hset file, as [ChunkEntry(offset, type, length)], in
    FTOC order (FTOC itself first). src is a path or a bytes-like object
    (bytes, mmap, ...). Raises ValueError if the file is not an hset or the
    FTOC disagrees with the chunk headers."""
    rd = _Reader(src)

    if rd.size < len(MAGIC) + HSET_HASH_LENGTH + CHUNK_HEADER_LENGTH:
        raise ValueError('file too short to be an hset')
    if rd.read(0, len(MAGIC)) != MAGIC:
        raise ValueError('bad magic: not an hset file')

    ftoc_off = len(MAGIC) + HSET_HASH_LENGTH
    ftype, flen = _chunk_header(rd, ftoc_off)
    if ftype != 'FTOC':
        raise ValueError(f'expected FTOC chunk at offset {ftoc_off}, found {ftype!r}')
    if flen % 12 != 0:
        raise ValueError(f'FTOC length {flen} is not a multiple of 12')

    payload = rd.read(ftoc_off + CHUNK_HEADER_LENGTH, flen)
    toc = []
    for i in range(0, flen, 12):
        (offset,) = struct.unpack_from('<Q', payload, i)
        etype = payload[i + 8:i + 12].decode('latin-1')
        ctype, length = _chunk_header(rd, offset)
        if ctype != etype:
            raise ValueError(
                f'FTOC lists {chunk_name(etype)} at offset {offset}, found {chunk_name(ctype)}'
            )
        if offset + CHUNK_HEADER_LENGTH + length > rd.size:
            raise ValueError(f'{chunk_name(ctype)} chunk at offset {offset} runs past the end of the hset')
        toc.append(ChunkEntry(offset, ctype, length))

    if not toc or toc[0] != ChunkEntry(ftoc_off, 'FTOC', flen):
        raise ValueError('FTOC does not list itself first')
    return toc


def chunk_sha256(src, entry, block_size=1 << 20):
    """The SHA-256 hex digest of the payload of a chunk (entry is a
    ChunkEntry from read_toc). A file is read in blocks of block_size bytes,
    so a chunk of any size is hashed without holding it in memory."""
    rd = _Reader(src)
    h = hashlib.sha256()
    begin = entry.offset + CHUNK_HEADER_LENGTH
    end = begin + entry.length
    if end > rd.size:
        raise ValueError(
            f'{entry.length} bytes at offset {begin} run past the end of the hset ({rd.size} bytes)'
        )
    if rd.buf is not None:
        h.update(rd.buf[begin:end])
        return h.hexdigest()
    with open(rd.path, 'rb') as f:
        f.seek(begin)
        left = entry.length
        while left:
            data = f.read(min(block_size, left))
            if not data:
                raise ValueError(f'short read at offset {end - left}')
            h.update(data)
            left -= len(data)
    return h.hexdigest()


def hhdr_hash_type(ctype):
    """The hash type (1 << bit) of an 'HHnn' chunk type, or None if ctype is
    not a hash set header."""
    if len(ctype) == 4 and ctype[:2] == 'HH':
        return 1 << ((ord(ctype[2]) << 8) | ord(ctype[3]))
    return None


def chunk_name(ctype):
    """A printable name for a chunk type: 'TIVF', 'HHDR(tlsh)', 'HHDR(0x0013)'."""
    ht = hhdr_hash_type(ctype)
    if ht is None:
        return ctype
    bit = ht.bit_length() - 1
    name = HASH_NAMES[bit] if bit < len(HASH_NAMES) else f'0x{bit:04x}'
    return f'HHDR({name})'


def tlsh_sections(src):
    """The TLSH hash sets of an hset, as [TlshSection]. src is a path, a
    bytes-like object, or a table of contents from read_toc(). Raises
    ValueError on a TVEC chunk, which the format does not allow (it held
    the rows' embeddings, which are no longer stored)."""
    toc = src if isinstance(src, list) else read_toc(src)
    sections = []
    cur = None
    for e in toc:
        ht = hhdr_hash_type(e.type)
        if e.type == 'TVEC':
            raise ValueError(
                f'TVEC chunk at offset {e.offset}: not allowed in an hset '
                '(the stored TLSH embedding was removed from the format)'
            )
        if ht is not None:
            cur = None
            if ht == 1 << TLSH_HASH_BIT:
                cur = {'hhdr': e}
                sections.append(cur)
        elif cur is not None and e.type in ('HINT', 'HDAT', 'RIDX', 'TIVF'):
            cur[e.type.lower()] = e
        else:
            cur = None
    return [TlshSection(**{f: s.get(f) for f in TlshSection._fields}) for s in sections]


def _section(rd, section):
    sections = tlsh_sections(read_toc(rd.path if rd.path is not None else rd.buf))
    if not sections:
        raise ValueError('hset has no TLSH hash set')
    try:
        sec = sections[section]
    except IndexError:
        raise ValueError(f'hset has {len(sections)} TLSH hash set(s), no section {section}') from None
    if sec.hdat is None:
        raise ValueError('TLSH hash set has no HDAT chunk')
    if sec.hdat.length % TLSH_DIGEST_LENGTH != 0:
        raise ValueError(f'TLSH HDAT length {sec.hdat.length} is not a multiple of {TLSH_DIGEST_LENGTH}')
    return sec


def _hdat_count(sec):
    return sec.hdat.length // TLSH_DIGEST_LENGTH


def tivf_header(src, section=0):
    """The TIVF header of a TLSH hash set as a TivfHeader, or None when the
    hash set has no index. Only the header is decoded."""
    rd = _Reader(src)
    sec = _section(rd, section)
    if sec.tivf is None:
        return None
    if sec.tivf.length < TIVF_HEADER_LENGTH:
        raise ValueError('TIVF chunk shorter than its header')
    hdr = rd.read(sec.tivf.offset + CHUNK_HEADER_LENGTH, TIVF_HEADER_LENGTH)
    version, flags, dims, lists, _res0, n, _res1 = struct.unpack('<HHIIIQQ', hdr)
    return TivfHeader(version, flags, dims, lists, n)


def _numpy():
    try:
        import numpy
    except ImportError as e:
        raise ImportError(
            'hasher.hsvectors.load_tlsh_* need numpy (pip install numpy); '
            'the tlsh_*_rows functions are a pure-Python fallback'
        ) from e
    return numpy


def _view(rd, np, dtype, offset, shape):
    """A read-only array over the source: a memmap of the file, or a view of
    the buffer."""
    dt = np.dtype(dtype)
    count = 1
    for s in shape:
        count *= s
    if rd.path is not None:
        a = np.memmap(rd.path, dtype=dt, mode='r', offset=offset, shape=shape, order='C')
    else:
        a = np.frombuffer(rd.buf, dtype=dt, count=count, offset=offset).reshape(shape)
        a.flags.writeable = False
    return a


def load_tlsh_digests(src, section=0):
    """The HDAT rows of the section-th TLSH hash set as a read-only (n, 36)
    uint8 numpy array (memmap for a path), row r being the canonical digest
    of row r."""
    np = _numpy()
    rd = _Reader(src)
    sec = _section(rd, section)
    return _view(
        rd, np, np.uint8,
        sec.hdat.offset + CHUNK_HEADER_LENGTH,
        (_hdat_count(sec), TLSH_DIGEST_LENGTH)
    )


def _check_ridx(sec):
    n = _hdat_count(sec)
    if sec.ridx.length != n * 8:
        raise ValueError(f'RIDX has {sec.ridx.length} bytes, expected {n} u64 entries')
    return n


def load_tlsh_record_index(src, section=0):
    """The RIDX of the section-th TLSH hash set as a read-only (n,) uint64
    numpy array mapping each row to its record index, or None when the hash
    set has no RIDX chunk (a hashsets-only file)."""
    np = _numpy()
    rd = _Reader(src)
    sec = _section(rd, section)
    if sec.ridx is None:
        return None
    n = _check_ridx(sec)
    return _view(rd, np, '<u8', sec.ridx.offset + CHUNK_HEADER_LENGTH, (n,))


#
# pure-Python row access (no numpy); fine for small sets and tests
#

def tlsh_digest_rows(src, section=0):
    """The HDAT rows of a TLSH hash set as a list of 36-byte bytes."""
    rd = _Reader(src)
    sec = _section(rd, section)
    data = rd.read(sec.hdat.offset + CHUNK_HEADER_LENGTH, sec.hdat.length)
    return [data[i:i + TLSH_DIGEST_LENGTH] for i in range(0, len(data), TLSH_DIGEST_LENGTH)]


def tlsh_record_index_rows(src, section=0):
    """The RIDX of a TLSH hash set as a list of ints, or None without RIDX."""
    rd = _Reader(src)
    sec = _section(rd, section)
    if sec.ridx is None:
        return None
    n = _check_ridx(sec)
    data = rd.read(sec.ridx.offset + CHUNK_HEADER_LENGTH, sec.ridx.length)
    return list(struct.unpack(f'<{n}Q', data))


#
# TLSH hex codec for the canonical 36-byte row (include/hasher/tlsh.h):
#
#   0 L, 1 Q = (Q1 << 4) | Q2, 2 plane_hi[16], 18 plane_lo[16], 34 checksum,
#   35 reserved; bit i of a plane is bit 1 / bit 0 of bucket code i.
#
# The hex transport form is checksum and L with their nibbles swapped, Q,
# then the 32 body bytes in reverse order, body[j] packing bucket codes
# 4j..4j+3 at bit positions 2k.
#

def _swap_nibbles(b):
    return ((b & 0x0F) << 4) | (b >> 4)


def tlsh_hex(row):
    """Encode a 36-byte canonical TLSH row as 'T1' + 70 uppercase hex
    characters, or 'TNULL' for the all-zero null digest."""
    row = bytes(row)
    if len(row) != TLSH_DIGEST_LENGTH:
        raise ValueError(f'TLSH digest must be {TLSH_DIGEST_LENGTH} bytes, got {len(row)}')
    if not any(row):
        return 'TNULL'
    hi = row[2:18]
    lo = row[18:34]
    body = bytearray(32)
    for i in range(128):
        code = (((hi[i >> 3] >> (i & 7)) & 1) << 1) | ((lo[i >> 3] >> (i & 7)) & 1)
        body[i >> 2] |= code << (2 * (i & 3))
    raw = bytes([_swap_nibbles(row[34]), _swap_nibbles(row[0]), row[1]]) + bytes(body[::-1])
    return 'T1' + raw.hex().upper()


def tlsh_from_hex(s):
    """Decode a TLSH string ('T1' + 70 hex, bare 70 hex, or 'TNULL') into the
    36-byte canonical row; the inverse of tlsh_hex()."""
    if s.upper() == 'TNULL':
        return bytes(TLSH_DIGEST_LENGTH)
    if s[:2].upper() == 'T1':
        s = s[2:]
    if len(s) != 70:
        raise ValueError(f'bad TLSH string: {s!r}')
    raw = bytes.fromhex(s)
    body = raw[3:35][::-1]
    hi = bytearray(16)
    lo = bytearray(16)
    for i in range(128):
        code = (body[i >> 2] >> (2 * (i & 3))) & 3
        hi[i >> 3] |= (code >> 1) << (i & 7)
        lo[i >> 3] |= (code & 1) << (i & 7)
    return (bytes([_swap_nibbles(raw[1]), raw[2]]) + bytes(hi) + bytes(lo)
            + bytes([_swap_nibbles(raw[0]), 0]))
