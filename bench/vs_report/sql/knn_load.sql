-- Load one vs_knn_eval output directory (@KNN_DIR@, substituted by
-- vs_report.py) into tables with explicit types.

create or replace table knn_queries as
select * from read_csv('@KNN_DIR@/queries.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'digest': 'varchar', 'lval': 'integer',
    'source_row': 'bigint', 'n_identical': 'bigint', 'd_k': 'integer',
    'count_lt': 'bigint', 'count_le': 'bigint', 'index_exact': 'boolean'});

create or replace table knn_timings as
select * from read_csv('@KNN_DIR@/timings.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'method': 'varchar', 'ns': 'bigint',
    'n_results': 'integer', 'ivf_cells': 'bigint', 'ivf_lists': 'bigint',
    'ivf_rows': 'bigint'});

create or replace table knn_results as
select * from read_csv('@KNN_DIR@/results.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'method': 'varchar', 'rank': 'integer',
    'row_idx': 'bigint', 'tlsh_dist': 'integer', 'emb_dist2': 'double'});

create or replace table knn_deep as
select * from read_csv('@KNN_DIR@/deep.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'rank': 'integer', 'row_idx': 'bigint',
    'emb_dist2': 'double', 'tlsh_dist': 'integer'});

create or replace table knn_hist as
select * from read_csv('@KNN_DIR@/hist.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'tlsh_dist': 'integer', 'n_rows': 'bigint'});
