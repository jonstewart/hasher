-- Every kNN configuration in one set of tables, one cfg per run: cfg 0 is the
-- main vs_knn_eval run (knn_* tables), the others come from --knn-extra
-- directories (same queries, other k / max_distance, brute and index only,
-- loaded by knn_extra_load.sql). max_distance 4294967295 means unbounded.

create or replace table cfg (cfg integer, k integer, max_distance bigint, dir varchar);
create or replace table cfg_queries as
select 0 as cfg, * from knn_queries;
create or replace table cfg_timings as
select 0 as cfg, * from knn_timings;
create or replace table cfg_results as
select 0 as cfg, * from knn_results;
insert into cfg values (0, @K@, @T@, '@KNN_DIR@');
