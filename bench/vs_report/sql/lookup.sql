-- Load the vs_lookup_eval CSVs (@FOUND_CSV@, @NOTFOUND_CSV@, substituted by
-- vs_report.py; either may be absent, in which case vs_report.py drops its
-- statements) and summarize them. Percentiles are nearest-rank, element
-- floor(q (n - 1)) of the sorted sample, which is quantile_disc and what the
-- program reports; stddev is the sample stddev. ns includes the timer overhead.

-- @FOUND@ create or replace table lookup_found as select i, found, ns from read_csv('@FOUND_CSV@', header = true, columns = {'i': 'bigint', 'sha256': 'varchar', 'found': 'integer', 'ns': 'double'});
-- @NOTFOUND@ create or replace table lookup_notfound as select i, sha256, found, ns from read_csv('@NOTFOUND_CSV@', header = true, columns = {'i': 'bigint', 'sha256': 'varchar', 'found': 'integer', 'ns': 'double'});

create or replace table lookup_all as
select 'found' as pass, i, found, ns from lookup_found
union all
select 'notfound', i, found, ns from lookup_notfound;

create or replace table lookup_stats as
select pass, count(*) as n, sum(found) as n_found,
       avg(ns) as mean, quantile_disc(ns, 0.5) as median, stddev_samp(ns) as stddev,
       quantile_disc(ns, 0.9) as p90, quantile_disc(ns, 0.99) as p99,
       quantile_disc(ns, 0.999) as p999, min(ns) as min, max(ns) as max,
       quantile_disc(ns, 0.25) as p25, quantile_disc(ns, 0.75) as p75,
       quantile_disc(ns, 0.01) as p01,
       sum((ns > 10000)::int) as over_10us, sum((ns > 100000)::int) as over_100us
from lookup_all group by all;

-- ECDF at fixed probabilities (the full sample is 9M rows); @PROBS@ is a
-- constant list literal, 0.001 .. 0.999
create or replace table lookup_ecdf as
select pass, unnest(@PROBS@) as p, unnest(quantile_disc(ns, @PROBS@)) as ns
from lookup_all group by pass;

-- log-binned histogram, 20 bins per decade
create or replace table lookup_hist as
select pass, floor(log10(greatest(ns, 1)) * 20)::int as bin, count(*) as n
from lookup_all group by all;
