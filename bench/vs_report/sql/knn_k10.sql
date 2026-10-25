-- A second vs_knn_eval run at the M5 benchmark's settings (@K10_DIR@, k =
-- @K10_K@, typically max_distance 144, brute and index, --no-analysis: no
-- hist.csv or deep.csv, d_k empty). With a distance bound a query can return
-- fewer than k results.

create or replace table k10_queries as
select * from read_csv('@K10_DIR@/queries.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'digest': 'varchar', 'lval': 'integer',
    'source_row': 'bigint', 'n_identical': 'bigint', 'd_k': 'integer',
    'count_lt': 'bigint', 'count_le': 'bigint', 'index_exact': 'boolean'});

create or replace table k10_timings as
select * from read_csv('@K10_DIR@/timings.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'method': 'varchar', 'ns': 'bigint',
    'n_results': 'integer', 'ivf_cells': 'bigint', 'ivf_lists': 'bigint',
    'ivf_rows': 'bigint'});

create or replace table k10_results as
select * from read_csv('@K10_DIR@/results.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'method': 'varchar', 'rank': 'integer',
    'row_idx': 'bigint', 'tlsh_dist': 'integer', 'emb_dist2': 'double'});

create or replace table k10_stats as
select qset, method, count(*) as n,
       avg(ns) / 1000 as mean_us, median(ns) / 1000 as median_us,
       stddev_samp(ns) / 1000 as stddev_us,
       quantile_disc(ns, 0.90) / 1000 as p90_us, quantile_disc(ns, 0.99) / 1000 as p99_us,
       min(ns) / 1000 as min_us, max(ns) / 1000 as max_us,
       avg(ivf_rows) as rows_mean, median(ivf_rows) as rows_median,
       avg(ivf_lists) as lists_mean, avg(ivf_cells) as cells_mean,
       avg(n_results) as mean_results,
       count(*) filter (where n_results < @K10_K@) as n_short,
       count(*) filter (where n_results = 0) as n_empty,
       median(ns) filter (where n_results = @K10_K@) / 1000 as median_us_full,
       median(ivf_rows) filter (where n_results = @K10_K@) as rows_median_full
from k10_timings group by all;

create or replace table k10_exactness as
with d as (
    select qset, qid, bool_and(b.tlsh_dist is not distinct from i.tlsh_dist) as dist_equal
    from (from k10_results where method = 'brute') b
    full outer join (from k10_results where method = 'index') i using (qset, qid, rank)
    group by all)
select q.qset, count(*) as n_queries,
       count(*) filter (where not q.index_exact) as row_mismatches,
       count(*) filter (where not coalesce(d.dist_equal, true)) as dist_mismatches,
       count(*) filter (where tb.n_results is distinct from ti.n_results) as count_mismatches
from k10_queries q left join d using (qset, qid)
left join (from k10_timings where method = 'brute') tb using (qset, qid)
left join (from k10_timings where method = 'index') ti using (qset, qid)
group by all;
