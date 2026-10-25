-- Per-configuration latency, speedup, index work and checks (cfg_* tables).
-- Statistics as in knn_metrics.sql: median() interpolates, p90 / p99 / p99.9
-- are quantile_disc, stddev is sample. n_short / n_empty: queries returning
-- fewer than k / no results (possible only with a distance bound).

create or replace table cfg_lat_stats as
select t.cfg, c.k, c.max_distance, t.qset, t.method, count(*) as n,
       avg(ns) / 1000 as mean_us, median(ns) / 1000 as median_us, stddev_samp(ns) / 1000 as stddev_us,
       quantile_disc(ns, 0.90) / 1000 as p90_us, quantile_disc(ns, 0.99) / 1000 as p99_us,
       quantile_disc(ns, 0.999) / 1000 as p999_us, min(ns) / 1000 as min_us, max(ns) / 1000 as max_us,
       avg(n_results) as mean_results,
       count(*) filter (where n_results < c.k) as n_short,
       count(*) filter (where n_results = 0) as n_empty
from cfg_timings t join cfg c using (cfg) group by all;

create or replace table cfg_speedup as
with p as (
    select cfg, qset, qid,
           max(ns) filter (where method = 'brute') / 1000.0 as slow,
           max(ns) filter (where method = 'index') / 1000.0 as fast
    from cfg_timings group by all)
select p.cfg, c.k, c.max_distance, p.qset, count(*) as n,
       avg(slow) / avg(fast) as ratio_of_means, median(slow) / median(fast) as ratio_of_medians,
       exp(avg(ln(slow / fast))) as paired_geomean, median(slow / fast) as paired_median,
       quantile_cont(slow / fast, 0.10) as paired_p10, quantile_cont(slow / fast, 0.90) as paired_p90,
       avg((fast < slow)::int) as frac_fast_wins
from p join cfg c using (cfg) where slow is not null and fast is not null group by all;

create or replace table cfg_index_work as
select t.cfg, c.k, c.max_distance, t.qset, count(*) as n,
       avg(ivf_rows) as rows_mean, median(ivf_rows) as rows_median,
       quantile_disc(ivf_rows, 0.99) as rows_p99, max(ivf_rows) as rows_max,
       avg(ivf_rows / @N_ROWS@) as frac_rows_mean,
       avg(ivf_lists) as lists_mean, avg(ivf_cells) as cells_mean,
       corr(ns, ivf_rows) as corr_us_rows,
       corr(ln(ns), ln(greatest(ivf_rows, 1))) as corr_log_us_rows,
       corr(ns, ivf_lists) as corr_us_lists, corr(ns, ivf_cells) as corr_us_cells,
       regr_slope(ns, ivf_rows) as ns_per_row_slope, regr_r2(ns, ivf_rows) as r2_rows
from cfg_timings t join cfg c using (cfg) where t.method = 'index' group by all;

-- brute vs index per run: rows (the program's index_exact), distances at every
-- rank, and result counts
create or replace table cfg_exactness as
with d as (
    select cfg, qset, qid, bool_and(b.tlsh_dist is not distinct from i.tlsh_dist) as dist_equal
    from (from cfg_results where method = 'brute') b
    full outer join (from cfg_results where method = 'index') i using (cfg, qset, qid, rank)
    group by all),
     nr as (
    select cfg, qset, qid, max(n_results) filter (where method = 'brute') as nb,
           max(n_results) filter (where method = 'index') as ni
    from cfg_timings group by all)
select q.cfg, q.qset, count(*) as n_queries,
       count(*) filter (where not q.index_exact) as row_mismatches,
       count(*) filter (where not coalesce(d.dist_equal, true)) as dist_mismatches,
       count(*) filter (where nr.nb is distinct from nr.ni) as count_mismatches
from cfg_queries q left join d using (cfg, qset, qid) left join nr using (cfg, qset, qid)
group by all;

-- the same queries in every run
create or replace table cfg_same_queries as
select q.cfg, q.qset, count(*) as n,
       count(*) filter (where m.digest is distinct from q.digest) as digest_mismatches
from cfg_queries q left join (from cfg_queries where cfg = 0) m using (qset, qid)
where q.cfg <> 0 group by all;

-- a bounded brute result must be the main run's brute top k (k <= the main
-- k) cut to tlsh_dist <= max_distance: same rows in the same order
create or replace table cfg_bound_check as
with c as (select * from cfg where cfg <> 0 and k <= (select k from cfg where cfg = 0)),
     want as (
    select c.cfg, r.qset, r.qid, r.rank, r.row_idx, r.tlsh_dist
    from c join cfg_results r on r.cfg = 0 and r.method = 'brute' and r.rank <= c.k
                              and r.tlsh_dist <= c.max_distance),
     got as (
    select r.cfg, r.qset, r.qid, r.rank, r.row_idx, r.tlsh_dist
    from cfg_results r join c using (cfg) where r.method = 'brute'),
     diff as (
    select coalesce(w.cfg, g.cfg) as cfg, coalesce(w.qset, g.qset) as qset, coalesce(w.qid, g.qid) as qid
    from want w full outer join got g
         on w.cfg = g.cfg and w.qset = g.qset and w.qid = g.qid and w.rank = g.rank
    where w.row_idx is distinct from g.row_idx or w.tlsh_dist is distinct from g.tlsh_dist)
select c.cfg, q.qset, count(distinct q.qid) as n_queries,
       count(distinct d.qid) as mismatched_queries,
       (select count(*) from want w where w.cfg = c.cfg and w.qset = q.qset) as rows_expected,
       (select count(*) from got g where g.cfg = c.cfg and g.qset = q.qset) as rows_got
from c join cfg_queries q on q.cfg = c.cfg
left join diff d on d.cfg = c.cfg and d.qset = q.qset and d.qid = q.qid
group by all;
