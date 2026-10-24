-- Derived tables for the kNN part of the report. Substituted by vs_report.py:
-- @K@ (k of the run), @N_ROWS@ (TLSH rows in run.json, null rows included,
-- as the program's distance histogram covers every row; the per-query
-- histogram sum is used where present) and @N_NONNULL@ (rows minus null rows).
--
-- Notation per query q: B = brute's top k (the TLSH ground truth), E = embed's
-- top k, D = embed's ranking to deep_k (E is its prefix), d_k = k-th smallest
-- TLSH distance, R = {rows: tlsh_dist <= d_k} (|R| = count_le >= k),
-- L = {rows: tlsh_dist < d_k} (|L| = count_lt < k).

-- ---------------------------------------------------------------- latency

create or replace table lat as
select qset, qid, method, ns, ns / 1000.0 as us, n_results,
       ivf_cells, ivf_lists, ivf_rows
from knn_timings;

-- median() interpolates (as the eval program's median does); p90/p99/p99.9
-- are nearest-rank, quantile_disc, as the program's p99; stddev is sample.
create or replace table lat_stats as
select qset, method, count(*) as n,
       avg(us) as mean_us, median(us) as median_us, stddev_samp(us) as stddev_us,
       quantile_disc(us, 0.90) as p90_us, quantile_disc(us, 0.99) as p99_us,
       quantile_disc(us, 0.999) as p999_us, min(us) as min_us, max(us) as max_us,
       quantile_disc(us, 0.25) as p25_us, quantile_disc(us, 0.75) as p75_us,
       quantile_disc(us, 0.01) as p01_us
from lat group by all;

create or replace table lat_wide as
select qset, qid,
       max(us) filter (where method = 'brute') as brute_us,
       max(us) filter (where method = 'index') as index_us,
       max(us) filter (where method = 'embed') as embed_us,
       max(ivf_rows) filter (where method = 'index') as ivf_rows,
       max(ivf_lists) filter (where method = 'index') as ivf_lists,
       max(ivf_cells) filter (where method = 'index') as ivf_cells
from lat group by all;

-- Speedup of `fast` over `slow`: ratio of means, of medians, and the
-- distribution of the per-query paired ratio slow_us / fast_us (> 1: fast wins).
create or replace table speedup as
with pairs as (
    select qset, 'index vs brute' as comparison, brute_us as slow, index_us as fast from lat_wide
    union all
    select qset, 'embed vs brute', brute_us, embed_us from lat_wide
    union all
    select qset, 'index vs embed', embed_us, index_us from lat_wide)
select qset, comparison, count(*) as n,
       avg(slow) / avg(fast) as ratio_of_means,
       median(slow) / median(fast) as ratio_of_medians,
       exp(avg(ln(slow / fast))) as paired_geomean,
       median(slow / fast) as paired_median,
       quantile_cont(slow / fast, 0.10) as paired_p10,
       quantile_cont(slow / fast, 0.90) as paired_p90,
       min(slow / fast) as paired_min, max(slow / fast) as paired_max,
       avg((fast < slow)::int) as frac_fast_wins
from pairs where slow is not null and fast is not null group by all;

-- ---------------------------------------------------------------- per-query frame

create or replace table qinfo as
with h as (select qset, qid, sum(n_rows) as n_hist from knn_hist group by all),
     b as (select qset, qid, count(*) as n_b, max(tlsh_dist) as b_kth,
                  avg(tlsh_dist) as b_mean_dist
           from knn_results where method = 'brute' group by all)
select q.*, coalesce(h.n_hist, @N_ROWS@) as n_rows, h.n_hist, b.n_b, b.b_kth, b.b_mean_dist
from knn_queries q left join h using (qset, qid) left join b using (qset, qid);

-- ---------------------------------------------------------------- validation

-- brute vs index: row identity (the program's index_exact) and distance
-- sequence (identical TLSH distance at every rank; ties may legally permute rows).
create or replace table exactness as
with d as (
    select b.qset, b.qid, bool_and(b.tlsh_dist = i.tlsh_dist) as dist_equal,
           count(*) as n_b, count(i.rank) as n_i
    from (from knn_results where method = 'brute') b
    left join (from knn_results where method = 'index') i using (qset, qid, rank)
    group by all)
select q.qset, count(*) as n_queries,
       sum((not q.index_exact)::int) as row_mismatches,
       sum((not coalesce(d.dist_equal and d.n_b = d.n_i, false))::int) as dist_mismatches
from knn_queries q left join d using (qset, qid) group by all;

-- Internal consistency checks, one row per check per qset.
create or replace table checks as
select qset, 'brute k-th distance = d_k' as check_name,
       sum((b_kth is distinct from d_k)::int) as failures, count(*) as n
from qinfo group by all
union all
select q.qset, 'count_le / count_lt agree with hist.csv',
       sum(((h.le is distinct from q.count_le) or (h.lt is distinct from q.count_lt))::int), count(*)
from knn_queries q left join (
    select h.qset, h.qid,
           sum(n_rows) filter (where h.tlsh_dist <= q.d_k) as le,
           coalesce(sum(n_rows) filter (where h.tlsh_dist < q.d_k), 0) as lt
    from knn_hist h join knn_queries q using (qset, qid) group by all) h using (qset, qid)
where exists (select 1 from knn_hist)
group by all
union all
select qset, 'hist.csv row total = rows in run.json',
       sum((n_hist is distinct from @N_ROWS@)::int), count(*)
from qinfo where exists (select 1 from knn_hist) group by all
union all
select e.qset, 'embed top k = prefix of deep ranking',
       count(*) filter (where d.row_idx is distinct from e.row_idx), count(distinct e.qid)
from (from knn_results where method = 'embed') e
left join knn_deep d using (qset, qid, rank) group by all
union all
select qset, 'every query returned k results (all methods)',
       sum((n_results <> least(@K@, @N_NONNULL@))::int), count(*)
from knn_timings group by all;

-- ---------------------------------------------------------------- IR metrics @k

create or replace table e_rows as
select e.qset, e.qid, e.rank, e.row_idx, e.tlsh_dist, e.emb_dist2,
       q.d_k, q.count_lt, q.count_le, q.n_b,
       b.rank as b_rank,
       (e.tlsh_dist <= q.d_k)::int as rel,
       (e.tlsh_dist < q.d_k)::int as must,
       -- graded gain for nDCG: 1 at distance 0, falling linearly to 1/(d_k+1)
       -- at d_k, 0 beyond d_k
       case when e.tlsh_dist <= q.d_k
            then (q.d_k + 1 - e.tlsh_dist)::double / (q.d_k + 1) else 0 end as gain
from (from knn_results where method = 'embed') e
join qinfo q using (qset, qid)
left join (from knn_results where method = 'brute') b
    on b.qset = e.qset and b.qid = e.qid and b.row_idx = e.row_idx;

create or replace table idcg as
select b.qset, b.qid,
       sum(((q.d_k + 1 - b.tlsh_dist)::double / (q.d_k + 1)) / log2(b.rank + 1)) as idcg
from knn_results b join knn_queries q using (qset, qid)
where b.method = 'brute' group by all;

-- Kendall tau-b and Spearman rho between emb_dist2 and tlsh_dist, over the
-- shared items (E and B) and over all of E. tau-b corrects for ties in both;
-- Spearman uses average ranks.
create or replace table rankcorr as
with s as (select qset, qid, row_idx, emb_dist2 as x, tlsh_dist::double as y,
                  b_rank is not null as shared from e_rows),
     tau as (
        select a.qset, a.qid, a_shared,
               sum(sign(a.x - c.x) * sign(a.y - c.y)) as s, count(*) as n0,
               sum((a.x = c.x)::int) as t1, sum((a.y = c.y)::int) as t2
        from (select *, true as a_shared from s where shared
              union all select *, false from s) a
        join s c on c.qset = a.qset and c.qid = a.qid and c.row_idx > a.row_idx
                 and (c.shared or not a.a_shared)
        group by all)
select t.qset, t.qid,
       max(case when t.a_shared then t.s / sqrt(nullif((t.n0 - t.t1) * (t.n0 - t.t2), 0)) end) as tau_shared,
       max(case when not t.a_shared then t.s / sqrt(nullif((t.n0 - t.t1) * (t.n0 - t.t2), 0)) end) as tau_all
from tau t group by all;

-- Spearman needs its own pass (window inside aggregate is not allowed).
create or replace table spearman as
with s as (select qset, qid, true as shared_only, emb_dist2 as x, tlsh_dist::double as y
           from e_rows where b_rank is not null
           union all
           select qset, qid, false, emb_dist2, tlsh_dist from e_rows
           union all
           -- over the whole deep ranking (deep_k rows): global metric agreement
           select qset, qid, null, emb_dist2, tlsh_dist from knn_deep),
     r as (select qset, qid, shared_only,
                  rank() over (partition by qset, qid, shared_only order by x)
                    + (count(*) over (partition by qset, qid, shared_only, x) - 1) / 2.0 as rx,
                  rank() over (partition by qset, qid, shared_only order by y)
                    + (count(*) over (partition by qset, qid, shared_only, y) - 1) / 2.0 as ry
           from s)
-- (corr is NaN when either side is constant; that is undefined, so null)
select qset, qid,
       nullif(corr(rx, ry) filter (where shared_only), 'nan'::double) as rho_shared,
       nullif(corr(rx, ry) filter (where not shared_only), 'nan'::double) as rho_all,
       nullif(corr(rx, ry) filter (where shared_only is null), 'nan'::double) as rho_deep
from r group by all;

-- Rank-biased overlap (Webber et al. 2010, extrapolated RBO_ext for two
-- lists of equal length kq) between E and B by row identity, p = 0.9, 0.98.
create or replace table rbo as
with m as (select qset, qid, greatest(rank, b_rank) as depth, count(*) as c
           from e_rows where b_rank is not null group by all),
     grid as (select qset, qid, n_b as kq, unnest(range(1, (n_b + 1)::bigint)) as d from qinfo),
     x as (select g.qset, g.qid, g.kq, g.d,
                  sum(coalesce(m.c, 0)) over (partition by g.qset, g.qid order by g.d) as xd
           from grid g left join m on m.qset = g.qset and m.qid = g.qid and m.depth = g.d)
select qset, qid,
       max(case when d = kq then xd / kq end) * pow(0.9, max(kq))
         + (1 - 0.9) / 0.9 * sum(xd / d * pow(0.9, d)) as rbo_90,
       max(case when d = kq then xd / kq end) * pow(0.98, max(kq))
         + (1 - 0.98) / 0.98 * sum(xd / d * pow(0.98, d)) as rbo_98
from x group by all;

create or replace table ir_q as
with base as (
    select qset, qid, count(*) as n_e, any_value(n_b) as n_b, any_value(d_k) as d_k,
           any_value(count_lt) as count_lt, any_value(count_le) as count_le,
           count(b_rank) as hits, sum(rel) as rel_hits, sum(must) as must_hits,
           max(tlsh_dist) as e_kth, avg(tlsh_dist) as e_mean_dist,
           sum(gain / log2(rank + 1)) as dcg
    from e_rows group by all),
     ap as (
    select qset, qid, sum(rel * cum_rel / rank) as ap_sum
    from (select *, sum(rel) over (partition by qset, qid order by rank) as cum_rel from e_rows)
    group by all)
select b.qset, b.qid, b.n_e, b.n_b, b.d_k, b.count_lt, b.count_le, b.hits, b.rel_hits,
       -- naive: overlap of row identities with brute's top k
       b.hits / b.n_e as p_naive,
       b.hits / b.n_b as r_naive,
       2 * b.hits / (b.n_e + b.n_b) as f1_naive,
       -- tie-aware: relevant = R
       b.rel_hits / b.n_e as p_tie,
       b.rel_hits / least(b.n_b, b.count_le) as r_tie,           -- of the k slots an exact answer fills
       b.rel_hits / b.count_le as r_tie_all,                     -- of every row in R (max k/|R|)
       coalesce(2 * (b.rel_hits / b.n_e) * (b.rel_hits / least(b.n_b, b.count_le))
         / nullif(b.rel_hits / b.n_e + b.rel_hits / least(b.n_b, b.count_le), 0), 0) as f1_tie,
       2 * b.rel_hits / (b.n_e + b.count_le) as f1_tie_all,
       b.must_hits / nullif(b.count_lt, 0) as r_must,           -- of L (rows every exact answer holds)
       ap.ap_sum / least(b.n_b, b.count_le) as ap_at_k,
       b.dcg / i.idcg as ndcg,
       b.e_kth, b.e_kth - b.d_k as kth_inflation,
       case when b.d_k > 0 then b.e_kth::double / b.d_k end as kth_ratio,
       b.e_mean_dist - q.b_mean_dist as mean_dist_inflation,
       rc.tau_shared, rc.tau_all, sp.rho_shared, sp.rho_all, sp.rho_deep,
       rb.rbo_90, rb.rbo_98
from base b join ap using (qset, qid) join idcg i using (qset, qid)
join qinfo q using (qset, qid)
left join rankcorr rc using (qset, qid) left join spearman sp using (qset, qid)
left join rbo rb using (qset, qid);

-- Distance error per rank i: embed's i-th result (in embed's order, and with
-- E re-sorted by TLSH distance) minus brute's i-th distance.
create or replace table dist_err as
with es as (select qset, qid, rank, tlsh_dist,
                   row_number() over (partition by qset, qid order by tlsh_dist, rank) as srank
            from e_rows),
     b as (select qset, qid, rank, tlsh_dist from knn_results where method = 'brute')
select es.qset, es.qid, es.rank as i,
       es.tlsh_dist - b1.tlsh_dist as delta_order,
       es2.tlsh_dist - b1.tlsh_dist as delta_sorted
from es join b b1 using (qset, qid, rank)
join es es2 on es2.qset = es.qset and es2.qid = es.qid and es2.srank = es.rank;

create or replace table dist_err_by_rank as
select qset, i, avg(delta_order) as mean_order, avg(delta_sorted) as mean_sorted,
       quantile_cont(delta_sorted, 0.1) as p10_sorted, quantile_cont(delta_sorted, 0.5) as p50_sorted,
       quantile_cont(delta_sorted, 0.9) as p90_sorted,
       avg((delta_order < 0)::int) as frac_order_negative
from dist_err group by all;

-- ---------------------------------------------------------------- recall@k' (deep)

-- recall@k' of the TLSH top k inside embed's top k': equivalently, the
-- recall of "take k' embedding candidates, re-rank them by TLSH, keep k".
create or replace table deep_curve_q as
with d as (
    select d.qset, d.qid, d.rank, (b.row_idx is not null)::int as hit,
           (d.tlsh_dist <= q.d_k)::int as rel, q.n_b, q.count_le
    from knn_deep d join qinfo q using (qset, qid)
    left join (from knn_results where method = 'brute') b
        on b.qset = d.qset and b.qid = d.qid and b.row_idx = d.row_idx)
select qset, qid, rank as kp,
       sum(hit) over w / n_b as r_naive,
       least(sum(rel) over w, least(n_b, count_le)) / least(n_b, count_le) as r_tie
from d window w as (partition by qset, qid order by rank);

create or replace table deep_curve as
select qset, kp, avg(r_naive) as r_naive, avg(r_tie) as r_tie,
       quantile_cont(r_tie, 0.1) as r_tie_p10, median(r_tie) as r_tie_p50,
       avg((r_tie >= 0.99)::int) as frac_tie_99, avg((r_tie >= 1)::int) as frac_tie_full,
       avg((r_naive >= 1)::int) as frac_naive_full
from deep_curve_q group by all;

-- depth needed per query (null: not reached within deep_k; right-censored)
create or replace table depth_needed as
select qset, qid,
       min(kp) filter (where r_tie >= 0.9) as kp_tie_90,
       min(kp) filter (where r_tie >= 0.99) as kp_tie_99,
       min(kp) filter (where r_tie >= 1) as kp_tie_full,
       min(kp) filter (where r_naive >= 1) as kp_naive_full
from deep_curve_q group by all;

-- ---------------------------------------------------------------- ROC / PR AUC

-- harmonic number minus (ln x + gamma): the asymptotic correction terms
create or replace macro hc(x) as 1 / (2 * x) - 1 / (12 * x * x) + 1 / (120 * x * x * x * x);

-- Score: -emb_dist2; label: tlsh_dist <= d_k; universe: every row in the set.
-- Only D (deep_k rows) is scored. Rows outside D rank below all of D (their
-- embedding distance is at least D's last); among themselves their order is
-- unknown, so two bounds: lower (conservative): every unscored relevant row
-- ranks last, below every unscored non-relevant row; upper: they rank first
-- among the unscored. Ties in emb_dist2 inside D get half credit in ROC AUC;
-- AP follows the ranking's order (ties by row index, as the method returns).
create or replace table auc_q as
with d as (
    select d.qset, d.qid, d.rank, d.emb_dist2, (d.tlsh_dist <= q.d_k)::int as pos
    from knn_deep d join qinfo q using (qset, qid)),
     tot as (
    select d.qset, d.qid, count(*) as n_d, sum(pos)::bigint as p_in, any_value(q.count_le) as p,
           any_value(q.n_rows) as n
    from d join qinfo q using (qset, qid) group by all),
     g as (select qset, qid, emb_dist2, sum(pos) as pos_v, sum(1 - pos) as neg_v
           from d group by all),
     roc as (
    select g.qset, g.qid,
           g.pos_v * ((t.n_d - t.p_in) - sum(g.neg_v) over w + 0.5 * g.neg_v) as pairs_in
    from g join tot t using (qset, qid)
    window w as (partition by g.qset, g.qid order by g.emb_dist2
                 rows between unbounded preceding and current row)),
     roc_sum as (select qset, qid, sum(pairs_in) as pairs_in from roc group by all),
     ap_in as (
    select qset, qid, sum(pos * cum_pos / rank) as s
    from (select *, sum(pos) over (partition by qset, qid order by rank) as cum_pos from d)
    group by all),
     tail as (
    select qset, qid, n_d, p_in, p, n, (p - p_in) as p_out,
           (n - p) - (n_d - p_in) as neg_out
    from tot),
     -- sum_{j=1..P} (a + j) / (b + j) = P - (b - a) (H(b + P) - H(b)), H the harmonic
     -- number, H(x) = ln x + gamma + 1/(2x) - 1/(12x^2) + 1/(120x^4) (b >= 1 here; the
     -- error is below 1/(252 b^6)); closed form, since P = |R| - p_in can be large
     ap_tail as (
    select qset, qid,
           p_out - ((n - p_out) - p_in) * (ln((n::double) / (n - p_out))
               + hc(n::double) - hc((n - p_out)::double)) as s_lo,
           p_out - (n_d - p_in) * (ln((n_d + p_out)::double / n_d)
               + hc((n_d + p_out)::double) - hc(n_d::double)) as s_hi
    from tail where p_out > 0)
select t.qset, t.qid, t.n_d, t.p, t.p_in, t.p_out, t.n, t.neg_out,
       t.p_in / t.p as frac_rel_scored,
       (r.pairs_in + t.p_in * t.neg_out) / (t.p * (t.n - t.p)) as roc_auc_lo,
       (r.pairs_in + t.p * t.neg_out) / (t.p * (t.n - t.p)) as roc_auc_hi,
       -- unscored rows tied at the bottom (half credit): the expected AUC
       -- under a random order of the unscored tail
       (r.pairs_in + (t.p_in + 0.5 * t.p_out) * t.neg_out) / (t.p * (t.n - t.p)) as roc_auc_tied,
       (a.s + coalesce(apt.s_lo, 0)) / t.p as pr_auc_lo,
       (a.s + coalesce(apt.s_hi, 0)) / t.p as pr_auc_hi
from tail t join roc_sum r using (qset, qid) join ap_in a using (qset, qid)
left join ap_tail apt using (qset, qid);

-- ---------------------------------------------------------------- aggregates

create or replace table ir_metric_long as
unpivot (select * exclude (n_e, n_b, d_k, count_lt, count_le, hits, rel_hits, e_kth)
         from ir_q join auc_q using (qset, qid)
         ) on columns(* exclude (qset, qid, n_d, p, p_in, p_out, n, neg_out))
into name metric value v;

create or replace table ir_summary as
select qset, metric, count(v) as n, avg(v) as mean, median(v) as median,
       stddev_samp(v) as stddev, quantile_cont(v, 0.1) as p10, quantile_cont(v, 0.9) as p90,
       min(v) as min, max(v) as max
from ir_metric_long group by all;

-- ---------------------------------------------------------------- index work & density

create or replace table index_work as
select w.qset, count(*) as n,
       avg(ivf_rows) as rows_mean, median(ivf_rows) as rows_median,
       quantile_disc(ivf_rows, 0.99) as rows_p99, max(ivf_rows) as rows_max,
       avg(ivf_rows / q.n_rows) as frac_rows_mean,
       avg(ivf_lists) as lists_mean, median(ivf_lists) as lists_median,
       avg(ivf_cells) as cells_mean, median(ivf_cells) as cells_median,
       corr(index_us, ivf_rows) as corr_us_rows,
       corr(ln(index_us), ln(greatest(ivf_rows, 1))) as corr_log_us_rows,
       corr(index_us, ivf_lists) as corr_us_lists,
       corr(index_us, ivf_cells) as corr_us_cells,
       regr_slope(index_us * 1000, ivf_rows) as ns_per_row_slope,
       regr_intercept(index_us, ivf_rows) as us_intercept,
       regr_r2(index_us, ivf_rows) as r2_rows
from lat_wide w join qinfo q using (qset, qid) group by all;

create or replace table density_corr as
with x as (select l.qset, l.method, l.us, q.count_le::double as count_le,
                  q.n_identical::double as n_identical, q.d_k::double as d_k
           from lat l join qinfo q using (qset, qid)),
     r as (select qset, method,
                  rank() over (partition by qset, method order by us) as r_us,
                  rank() over (partition by qset, method order by count_le)
                    + (count(*) over (partition by qset, method, count_le) - 1) / 2.0 as r_cle,
                  rank() over (partition by qset, method order by n_identical)
                    + (count(*) over (partition by qset, method, n_identical) - 1) / 2.0 as r_nid,
                  rank() over (partition by qset, method order by d_k)
                    + (count(*) over (partition by qset, method, d_k) - 1) / 2.0 as r_dk
           from x)
select qset, method, nullif(corr(r_us, r_cle), 'nan'::double) as rho_count_le,
       nullif(corr(r_us, r_nid), 'nan'::double) as rho_n_identical,
       nullif(corr(r_us, r_dk), 'nan'::double) as rho_d_k
from r group by all;

-- latency by d_k quintile within each query set
create or replace table density_bins as
with b as (select q.qset, q.qid, q.d_k, q.count_le, q.n_identical,
                  ntile(5) over (partition by q.qset order by q.d_k, q.qid) as bin
           from qinfo q)
select b.qset, b.bin, min(b.d_k) as d_k_min, max(b.d_k) as d_k_max,
       median(b.count_le) as count_le_median, avg((b.n_identical > 1)::int) as frac_dup,
       median(w.brute_us) as brute_us, median(w.index_us) as index_us,
       median(w.embed_us) as embed_us, median(w.ivf_rows) as ivf_rows,
       median(i.r_tie) as r_tie_median, avg(i.r_tie) as r_tie_mean
from b join lat_wide w using (qset, qid) join ir_q i using (qset, qid)
group by all;
