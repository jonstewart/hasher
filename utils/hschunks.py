#!/usr/bin/python3

"""
Print the table of contents (FTOC) of an hset file: the offset, type and
payload length of every chunk, with the TVEC and TIVF headers of TLSH hash
sets decoded. Pure Python; libhasher is not needed.

    hschunks.py corpus.hset
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
    print(f'{"offset":>12}  {"type":<12}  {"length":>12}')
    for e in toc:
        print(f'{e.offset:>12}  {hsvectors.chunk_name(e.type):<12}  {e.length:>12}')

    for i, sec in enumerate(hsvectors.tlsh_sections(toc)):
        print(f'\nTLSH hash set {i}: {sec.hdat.length // hsvectors.TLSH_DIGEST_LENGTH} rows'
              f'{", RIDX" if sec.ridx else ""}')
        if sec.tvec:
            tv = hsvectors.tvec_header(path, i)
            print(f'  TVEC: version {tv.version}, variant {tv.variant}, flags {tv.flags}, '
                  f'dims {tv.dims}, n {tv.n}, dtype {tv.dtype}, data at {tv.data_offset} '
                  f'({"" if tv.data_offset % 4096 == 0 else "NOT "}4096-aligned)')
        if sec.tivf:
            iv = hsvectors.tivf_header(path, i)
            print(f'  TIVF: version {iv.version}, flags {iv.flags}, dims {iv.dims}, '
                  f'lists {iv.lists}, n {iv.n}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
