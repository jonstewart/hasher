-- The header-split diagnostic (@HS_CSV@, written by header_split.py): for
-- embed's results (TP: tlsh_dist <= d_k, FP: beyond d_k) and brute's results
-- that embed missed (MISS), the TLSH distance split into the header terms
-- (L, Q1, Q2; "length" is the L term alone) and the body + checksum rest.

create or replace table header_split as
select * from read_csv('@HS_CSV@', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'cat': 'varchar', 'rank': 'integer',
    'row_idx': 'bigint', 'tlsh_dist': 'integer', 'full_dist': 'integer',
    'header': 'integer', 'length': 'integer', 'rest': 'integer'});

create or replace table header_split_summary as
select qset, cat, count(*) as n,
       avg(tlsh_dist) as mean_tlsh, avg(header) as mean_header, avg(length) as mean_length,
       avg(header - length) as mean_quartile, avg(rest) as mean_rest,
       sum(header)::double / nullif(sum(tlsh_dist), 0) as header_share,
       avg((header > 0)::int) as frac_header_differs,
       avg((length > 0)::int) as frac_length_differs,
       median(header) as median_header
from header_split group by all;

create or replace table header_split_check as
select qset, count(*) as n,
       count(*) filter (where header + rest <> tlsh_dist) as sum_mismatch,
       count(*) filter (where full_dist <> tlsh_dist) as full_mismatch,
       count(*) filter (where length > header) as length_over_header
from header_split group by all;
