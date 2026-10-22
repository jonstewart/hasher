#!/usr/bin/python3

# dumps the hashes of a hashset as hexadecimal strings
# (TLSH hashes are printed in their "T1..." form)

import mmap
import sys

import hasher

with open(sys.argv[1], 'rb') as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mbuf:
        with hasher.HashSetInfo(mbuf) as hsinfo:
            i = hsinfo.hashset_off
            end = i + hsinfo.hash_length * hsinfo.hashset_size
            if hsinfo.hash_type == hasher.TLSH:
                to_str = hasher.tlsh_to_hex
            else:
                to_str = bytes.hex
            while i < end:
                print(to_str(mbuf[i:i+hsinfo.hash_length]))
                i += hsinfo.hash_length
