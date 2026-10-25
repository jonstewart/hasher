-- One --knn-extra run (@DIR@) as configuration @CFG@ (k @K@, max_distance @T@).
insert into cfg values (@CFG@, @K@, @T@, '@DIR@');
insert into cfg_queries
select @CFG@, * from read_csv('@DIR@/queries.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'digest': 'varchar', 'lval': 'integer',
    'source_row': 'bigint', 'n_identical': 'bigint', 'd_k': 'integer',
    'count_lt': 'bigint', 'count_le': 'bigint', 'index_exact': 'boolean'});
insert into cfg_timings
select @CFG@, * from read_csv('@DIR@/timings.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'method': 'varchar', 'ns': 'bigint',
    'n_results': 'integer', 'ivf_cells': 'bigint', 'ivf_lists': 'bigint',
    'ivf_rows': 'bigint'});
insert into cfg_results
select @CFG@, * from read_csv('@DIR@/results.csv', header = true, columns = {
    'qset': 'varchar', 'qid': 'integer', 'method': 'varchar', 'rank': 'integer',
    'row_idx': 'bigint', 'tlsh_dist': 'integer', 'emb_dist2': 'double'});
