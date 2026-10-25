#!/usr/bin/python3

"""
Print the table of contents (FTOC) of an hset file: the offset, type,
payload length and payload SHA-256 of every chunk, with the TIVF headers of
TLSH hash sets decoded. Pure Python; libhasher is not needed. A file with a
TVEC chunk (the stored embedding, no longer part of the format) gets its
table printed and then an error, as libhasher rejects it.

    hschunks.py corpus.hset

The per-chunk digests compare two hset files chunk by chunk, e.g. the same
rows built on two machines: the TIVF digests are equal iff the indexes are
byte-identical. Whole-file hashes (and the file's own SHA-256 after the
magic) differ by design, since the FHDR chunk carries the creation
timestamp. Chunks are read in blocks, so a file of any size is hashed
without holding it in memory.
"""

import os
import sys

try:
    from hasher import hsvectors
except ImportError:
    # libhasher is not installed; load hsvectors.py straight from the source tree
    import importlib.util
    _path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                         '..', 'python', 'hasher', 'hsvectors.py')
    _spec = importlib.util.spec_from_file_location('hsvectors', _path)
    hsvectors = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(hsvectors)


def main(path):
    toc = hsvectors.read_toc(path)
    print(f'{"offset":>12}  {"type":<12}  {"length":>12}  sha256')
    for e in toc:
        print(f'{e.offset:>12}  {hsvectors.chunk_name(e.type):<12}  {e.length:>12}  '
              f'{hsvectors.chunk_sha256(path, e)}')

    try:
        sections = hsvectors.tlsh_sections(toc)
    except ValueError as e:
        sys.exit(f'\n{path}: {e}')
    for i, sec in enumerate(sections):
        print(f'\nTLSH hash set {i}: {sec.hdat.length // hsvectors.TLSH_DIGEST_LENGTH} rows'
              f'{", RIDX" if sec.ridx else ""}')
        if sec.tivf:
            iv = hsvectors.tivf_header(path, i)
            print(f'  TIVF: version {iv.version}, flags {iv.flags}, dims {iv.dims}, '
                  f'lists {iv.lists}, n {iv.n}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
