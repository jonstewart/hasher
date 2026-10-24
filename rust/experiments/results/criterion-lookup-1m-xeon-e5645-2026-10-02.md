# Criterion lookup benchmark, 1 M SHA-1, Xeon E5645 (Westmere), 2026-10-02

Median ns per lookup (batch medians divided by the 4096-query batch size).
Variant names: `basic` = no table with the automatic search mode (recursive
interpolation for single, interpolating lanes for batch); `basic-binary` = no table,
bisection; `<model><bits>` = table at fixed bits with the default (8-ary) single search;
`-recursive` / `-binary` = single search mode override; `-auto` marks the table size
the default policy picks for this set.

| variant | single/miss | single/hit | batch/miss | batch/hit |
|---|---:|---:|---:|---:|
| basic | 418.2 | 432.2 | 193.3 | 176.8 |
| basic-binary | 554.3 | 566.1 | 482.1 | 424.8 |
| basic-recursive | 415.7 | 447.2 | 206.9 | 174.2 |
| block12 | 214.0 | 221.5 | 123.5 | 137.3 |
| block14-auto | 184.3 | 197.9 | 93.7 | 104.5 |
| block14-binary | 199.8 | 216.3 | 126.3 | 110.6 |
| block16 | 184.5 | 198.2 | 91.2 | 91.9 |
| block18 | 182.3 | 211.7 | 88.9 | 91.0 |
| block20 | 146.3 | 205.4 | 73.1 | 94.2 |
| block8-legacy | 313.7 | 324.6 | 186.5 | 165.3 |
| hull0-recursive | 417.6 | 448.0 | 237.5 | 201.3 |
| hull12 | 195.2 | 202.2 | 109.4 | 115.7 |
| hull12-recursive | 190.6 | 208.8 | 113.7 | 112.5 |
| hull14 | 181.0 | 183.4 | 95.9 | 93.5 |
| hull14-recursive | 178.9 | 192.3 | 95.3 | 99.1 |
| hull15-auto | 157.4 | 177.4 | 81.2 | 88.2 |
| hull15-binary | 162.0 | 175.3 | 111.0 | 100.1 |
| hull15-recursive | 163.9 | 179.3 | 83.2 | 87.9 |
| hull16 | 162.7 | 188.3 | 80.4 | 90.2 |
| hull18 | 158.5 | 207.7 | 84.1 | 90.0 |
| hull20 | 154.4 | 190.6 | 75.6 | 91.7 |
| hull8 | 303.1 | 306.2 | 175.7 | 151.8 |
| hull8-recursive | 257.5 | 279.1 | 194.5 | 171.7 |
