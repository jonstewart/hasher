# hset format documentation

Static HTML with inline SVG, generated from the libhasher sources by
`build/build.py` (Python 3, standard library only):

    python3 -I build/build.py          # writes index.html, lookup.html, tlsh.html, merge.html

| page | subject |
|---|---|
| `index.html` | the file: chunks, headers, records, hints, the TLSH row, TVEC and TIVF, byte by byte |
| `lookup.html` | bounded exact lookup: the expected-index line, the deviation walk, per-block bounds, the branchless window search, batching, the line-fitting candidates and the evaluation |
| `tlsh.html` | the TLSH digest and distance, the popcount kernel, the lower-bound embedding, cells, the TIVF index and its BISECT build, and the exact kNN search with a real traced query |
| `merge.html` | set operations by merging: two pointers, row maps, records, carrying the TIVF lists through a merge, coalescing and its bounds |

`build/data/` holds the inputs the figures are computed from, so that the
pages do not depend on the test fixtures (which the test suite regenerates):

- `fixtures.json`: bytes and statistics read from `test/good.hset`,
  `test/md5_sha1_a-b.hset` and `test/inc_master.hset`;
- `inc_master.hdat`, `inc_master.tivf`: the HDAT and TIVF payloads of the
  49 997-row TLSH set in `test/inc_master.hset`, over which `tlshlib.py`
  (a pure-Python model of the digest, kernel, header order and TIVF search)
  runs the queries, traces and histograms on the TLSH page, checking the
  indexed search against brute force every time.

The lookup page's plots are computed from MD5 digests of a counter; every
plotted quantity is labelled with its origin in the figure or its caption.
