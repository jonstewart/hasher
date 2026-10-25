#!/usr/bin/env python3
"""vs_report: load vs_knn_eval and vs_lookup_eval outputs into DuckDB, compute the
latency and information-retrieval metrics, and write a static, self-contained
HTML report with inline SVG charts.

Standard library only; DuckDB is driven through its CLI (`duckdb` on PATH, or
--duckdb). Run with `python3 -I`; the script adds its own directory to
sys.path for svgchart.py.

    python3 -I bench/vs_report/vs_report.py \\
        --knn /work/vs-eval/knn \\
        --found /work/vs-eval/lookup/lookup_found.csv \\
        --notfound /work/vs-eval/lookup/lookup_notfound.csv \\
        --out /work/vs-eval/report

Writes OUT/vs.duckdb (tables: knn_*, lat*, speedup, ir_q, ir_summary, auc_q,
deep_curve*, dist_err*, index_work, density_*, exactness, checks, lookup_*)
and OUT/index.html.
"""

import argparse
import datetime
import json
import math
import os
import re
import shutil
import subprocess
import sys
from html import escape

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script's directory off sys.path
sys.dont_write_bytecode = True  # no __pycache__ in the source tree
import svgchart as sc  # noqa: E402

SQL_DIR = os.path.join(HERE, 'sql')
BUILD_COMMIT = '5351b8d'   # configure: -O3 and -mpopcnt
CROWDSTRIKE_RECALL = 0.99
UNBOUNDED = 4294967295
M5_US = 13.0       # the user's M5 figure: kNN at 1M synthetic rows, k = 10, T = 144
M5_ROWS = 4659     # rows scanned per query at 1M, BISECT (docs/BENCHMARKS.md §9)
TEXT_COLUMNS = {'qset', 'method', 'metric', 'pass', 'comparison', 'check_name', 'which', 'sha256', 'digest'}
INT_RE = re.compile(r'^-?[0-9]+$')
METHODS = ['brute', 'index', 'embed']
METHOD_LABEL = {'brute': 'brute (TLSH)', 'index': 'index (TIVF)', 'embed': 'embed (Euclidean)'}


# ---------------------------------------------------------------- DuckDB CLI

class DuckDB:
    def __init__(self, exe, path, threads, memory):
        self.exe, self.path = exe, path
        self.settings = f"set threads = {threads}; set memory_limit = '{memory}';"

    def script(self, sql, what):
        r = subprocess.run([self.exe, '-bail', self.path], input=self.settings + '\n' + sql,
                           text=True, capture_output=True)
        if r.returncode != 0 or 'Error' in r.stderr:
            sys.exit(f'vs_report: DuckDB failed in {what}:\n{r.stderr}{r.stdout}')

    def q(self, sql):
        r = subprocess.run([self.exe, '-readonly', '-json', '-cmd', self.settings, self.path,
                            '-c', sql], text=True, capture_output=True)
        if r.returncode != 0 or r.stderr.strip():
            sys.exit(f'vs_report: query failed:\n{sql}\n{r.stderr}')
        out = r.stdout.strip()
        rows = json.loads(out) if out else []
        # the CLI writes HUGEINT (what sum() of integers returns) as a JSON string
        for row in rows:
            for key, v in row.items():
                if isinstance(v, str) and key not in TEXT_COLUMNS and INT_RE.match(v):
                    row[key] = int(v)
        return rows

    def has_table(self, name):
        return bool(self.q(f"select 1 from duckdb_tables() where table_name = '{name}'"))


def sql_str(path):
    return path.replace("'", "''")


def load_sql(name, subs):
    with open(os.path.join(SQL_DIR, name)) as f:
        s = f.read()
    for k, v in subs.items():
        s = s.replace(k, v)
    return s


# ---------------------------------------------------------------- formatting helpers

def isnum(v):
    return isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v))


def f3(v):
    return f'{v:.3f}' if isnum(v) else '–'


def f4(v):
    return f'{v:.4f}' if isnum(v) else '–'


def fint(v):
    return f'{v:,.0f}' if isnum(v) else '–'


def fpct(v, d=1):
    return f'{100 * v:.{d}f}%' if isnum(v) else '–'


def fx(v):
    """A speed ratio."""
    if not isnum(v):
        return '–'
    return f'{v:.3g}×' if v < 100 else f'{v:,.0f}×'


def us(v):
    return sc.fmt_us(v) if isnum(v) else '–'


def ns(v):
    return sc.fmt_ns(v) if isnum(v) else '–'


def tlabel(t):
    """A max_distance for display."""
    return 'none' if t is None or t >= UNBOUNDED else f'{t:,}'


def faster(x):
    """Wording for a speed ratio slow / fast."""
    return (f'{x:.3g}× faster than' if x >= 1.05 else
            f'{1 / x:.3g}× slower than' if x <= 1 / 1.05 else 'about as fast as')


def table(headers, rows, num_from=1, cls=''):
    """rows of preformatted strings (already escaped where needed)."""
    h = ''.join(f'<th class="{"num" if i >= num_from else ""}">{x}</th>' for i, x in enumerate(headers))
    body = ''.join('<tr>' + ''.join(f'<td class="{"num" if i >= num_from else ""}">{c}</td>'
                                    for i, c in enumerate(r)) + '</tr>' for r in rows)
    return f'<div class="tw"><table class="{cls}"><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table></div>'


def badge(ok):
    if ok is None:
        return '<span class="badge na">n/a</span>'
    if ok == 'warn':
        return '<span class="badge warnb"><span aria-hidden="true">!</span> check</span>'
    return ('<span class="badge pass"><span aria-hidden="true">✓</span> pass</span>' if ok else
            '<span class="badge fail"><span aria-hidden="true">✗</span> FAIL</span>')


def todo(text):
    return f'<span class="todo">[TO FINISH: {escape(text)}]</span>'


def figure(svg, caption, legend_html='', data_table=''):
    dt = (f'<details><summary>Data table</summary>{data_table}</details>' if data_table else '')
    return f'<figure>{legend_html}{svg}<figcaption>{caption}</figcaption>{dt}</figure>'


def by(rows, *keys):
    out = {}
    for r in rows:
        out[tuple(r[k] for k in keys) if len(keys) > 1 else r[keys[0]]] = r
    return out


def qset_order(qsets):
    pref = {'member': 0, 'random': 1}
    return sorted(qsets, key=lambda q: (pref.get(q, 9), q))


def load_json(path):
    if not path:
        return None
    with open(path) as f:
        return json.load(f)


def git(repo, *args):
    try:
        r = subprocess.run(['git', '-C', repo, *args], text=True, capture_output=True)
        return r.returncode, r.stdout.strip()
    except OSError:
        return 1, ''


# ---------------------------------------------------------------- load

def build_db(db, args, run):
    if args.knn:
        db.script(load_sql('knn_load.sql', {'@KNN_DIR@': sql_str(os.path.abspath(args.knn))}), 'knn_load.sql')
        if not os.path.exists(os.path.join(args.knn, 'hist.csv')):
            sys.exit('vs_report: hist.csv is required (run vs_knn_eval without --no-hist)')
        n_rows = run['hset']['tlsh_rows']
        db.script(load_sql('knn_metrics.sql', {
            '@K@': str(run['params']['k']), '@N_ROWS@': str(n_rows),
            '@N_NONNULL@': str(n_rows - run['hset'].get('null_rows', 0))}), 'knn_metrics.sql')
    if args.knn and args.hset:
        csv_path = os.path.join(args.out, 'header_split.csv')
        env = dict(os.environ)
        env['LD_LIBRARY_PATH'] = args.libdir + (':' + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
        cmd = [sys.executable, '-I', os.path.join(HERE, 'header_split.py'), '--hset', args.hset, '--knn', args.knn,
               '--out', csv_path, '--repo', args.repo,
               '--include-length', 'true' if run['params'].get('include_length', True) else 'false']
        r = subprocess.run(cmd, env=env)
        if r.returncode != 0:
            sys.exit('vs_report: header_split.py failed')
        db.script(load_sql('header_split.sql', {'@HS_CSV@': sql_str(os.path.abspath(csv_path))}), 'header_split.sql')
    if args.knn:
        sql = load_sql('knn_configs_init.sql', {'@K@': str(run['params']['k']),
                                                '@T@': str(run['params']['max_distance']),
                                                '@KNN_DIR@': sql_str(os.path.abspath(args.knn))})
        for i, (d, x) in enumerate(args.extra_runs, start=1):
            sql += load_sql('knn_extra_load.sql', {'@DIR@': sql_str(os.path.abspath(d)), '@CFG@': str(i),
                                                   '@K@': str(x['params']['k']),
                                                   '@T@': str(x['params']['max_distance'])})
        sql += load_sql('knn_configs.sql', {'@N_ROWS@': str(run['hset']['tlsh_rows'])})
        db.script(sql, 'knn_configs.sql')
    if args.found or args.notfound:
        s = load_sql('lookup.sql', {'@FOUND_CSV@': sql_str(os.path.abspath(args.found or '')),
                                    '@NOTFOUND_CSV@': sql_str(os.path.abspath(args.notfound or '')),
                                    '@PROBS@': '[' + ', '.join(f'{x / 1000:.3f}' for x in range(1, 1000)) + ']'})
        empty = ("create or replace table {} (i bigint, sha256 varchar, found integer, ns double);")
        s = s.replace('-- @FOUND@ ', '' if args.found else '-- ')
        s = s.replace('-- @NOTFOUND@ ', '' if args.notfound else '-- ')
        if not args.found:
            s = empty.format('lookup_found') + '\n' + s
        if not args.notfound:
            s = empty.format('lookup_notfound') + '\n' + s
        db.script(s, 'lookup.sql')


# ---------------------------------------------------------------- summary.txt cross-check

def parse_summary(path):
    """The eval program's printed summary: per set x method mean_us, and recall lines."""
    out = {'mean_us': {}, 'recall': {}, 'mismatch': {}}
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) >= 4 and p[1] in METHODS and p[2].isdigit():
                out['mean_us'][(p[0], p[1])] = float(p[3])
            m = re.match(r'(\S+): brute/index mismatches (\d+) of (\d+)', line)
            if m:
                out['mismatch'][m.group(1)] = int(m.group(2))
            m = re.match(r'(\S+): brute/index mismatches (\d+) of (\d+); embed recall@\d+ naive ([\d.]+), '
                         r'tie-aware ([\d.]+)', line)
            if m:
                out['recall'][m.group(1)] = (float(m.group(4)), float(m.group(5)))
    return out


# ---------------------------------------------------------------- the report

class Report:
    def __init__(self, db, args, run, meta_found, meta_notfound):
        self.db, self.args, self.run = db, args, run
        self.mf, self.mn = meta_found, meta_notfound
        self.sections = []      # (id, title, html)
        self.judgements = load_json(args.judgements) or {}
        self.build_costs = load_json(args.build_costs)
        self.corpus = load_json(args.corpus)
        self.validation = []    # (item, detail, ok)
        self.facts = {}

    def add(self, sid, title, body):
        self.sections.append((sid, title, body))

    # ------------------------------------------------------------ kNN

    def knn(self):
        db, run = self.db, self.run
        k = run['params']['k']
        n_rows = run['hset']['tlsh_rows']
        self.facts.update(k=k, n_rows=n_rows, deep_k=run['params'].get('deep_k', 1000))
        lat = db.q('from lat_stats')
        qsets = qset_order({r['qset'] for r in lat})
        self.qsets = qsets
        L = by(lat, 'qset', 'method')
        sp = by(db.q('from speedup'), 'qset', 'comparison')
        ex = by(db.q('from exactness'), 'qset')
        irs = by(db.q('from ir_summary'), 'qset', 'metric')
        self.L, self.sp, self.ex, self.irs = L, sp, ex, irs

        # ---- validation items
        for q in qsets:
            e = ex[q]
            self.validation.append((f'brute vs index, {q}: identical results (rows)',
                                    f'{fint(e["row_mismatches"])} of {fint(e["n_queries"])} queries differ',
                                    e['row_mismatches'] == 0))
            self.validation.append((f'brute vs index, {q}: identical distances at every rank',
                                    f'{fint(e["dist_mismatches"])} of {fint(e["n_queries"])} queries differ',
                                    e['dist_mismatches'] == 0))
        for c in db.q('from checks order by check_name, qset'):
            self.validation.append((f'{c["check_name"]}, {c["qset"]}',
                                    f'{fint(c["failures"])} failures of {fint(c["n"])}', c['failures'] == 0))
        summ = parse_summary(os.path.join(self.args.knn, 'summary.txt'))
        if summ['mean_us']:
            worst = max(abs(L[key]['mean_us'] - v) for key, v in summ['mean_us'].items() if key in L)
            self.validation.append(('latency means agree with the program\'s summary.txt',
                                    f'largest difference {worst:.2f} µs (summary prints 0.1 µs)', worst <= 0.1))
        if summ['recall']:
            worst = 0
            for q, (rn, rt) in summ['recall'].items():
                if (q, 'r_naive') in irs:
                    worst = max(worst, abs(irs[(q, 'r_naive')]['mean'] - rn), abs(irs[(q, 'r_tie')]['mean'] - rt))
            self.validation.append(('recall@k (naive, tie-aware) agrees with summary.txt',
                                    f'largest difference {worst:.5f} (summary prints 4 decimals)', worst <= 6e-5))
        self.validation.append(('hset fully resident in the page cache during timing',
                                f'{fpct(run["machine"].get("hset_resident_before_timing"))} before, '
                                f'{fpct(run["machine"].get("hset_resident_after_timing"))} after',
                                (run['machine'].get('hset_resident_after_timing') or 0) >= 0.999))

        self.knn_ir(qsets, irs, k)
        self.knn_latency(qsets, L, sp)
        self.knn_index_work(qsets)
        self.knn_density(qsets)

    def cfg_list(self):
        """The kNN configurations, main run first: [(cfg, k, max_distance)]."""
        return [(c['cfg'], c['k'], c['max_distance']) for c in self.db.q('from cfg order by cfg')]

    def knn_latency(self, qsets, L, sp):
        db, run = self.db, self.run
        n_rows = self.facts['n_rows']
        cfgs = self.cfg_list()
        CS = by(db.q('from cfg_lat_stats'), 'cfg', 'qset', 'method')
        rows = []
        for q in qsets:
            for c, k, t in cfgs:
                for m in METHODS:
                    r = CS.get((c, q, m))
                    if not r:
                        continue
                    rows.append([escape(q), fint(k), tlabel(t), METHOD_LABEL[m], fint(r['n']), us(r['mean_us']),
                                 us(r['median_us']), us(r['stddev_us']), us(r['p90_us']), us(r['p99_us']),
                                 us(r['p999_us']), us(r['min_us']), us(r['max_us']),
                                 f'{r["mean_us"] * 1000 / n_rows:.3g}', f'{r["mean_results"]:.3g}',
                                 fpct(r['n_short'] / r['n']), fpct(r['n_empty'] / r['n'])])
        t_lat = table(['set', 'k', 'max distance', 'method', 'n', 'mean', 'median', 'stddev', 'p90', 'p99',
                       'p99.9', 'min', 'max', 'ns/row', 'mean results', 'fewer than k', 'none'], rows, num_from=4)

        vals = by(db.q("select qset, method, list(us order by us) as v from lat group by all"), 'qset', 'method')
        panels = [{'title': f'{q} queries', 'series': [{'key': m, 'label': m, 'values': vals[(q, m)]['v']}
                                                     for m in METHODS if (q, m) in vals]} for q in qsets]
        leg = sc.legend([(m, METHOD_LABEL[m], 'line') for m in METHODS])
        main_k, main_t = cfgs[0][1], cfgs[0][2]
        cfg_note = (f' (the main run: k = {main_k}, max distance {tlabel(main_t)})' if len(cfgs) > 1 else '')
        fig_ecdf = figure(sc.ecdf(panels, sc.fmt_us, 'latency per query (log scale)', label='latency ECDF'),
                          f'Empirical CDF of per-query latency{cfg_note}, one line per method; log x axis, shared '
                          f'by both panels. Read across at 0.5 for the median.', leg)
        groups = [{'title': f'{q} queries', 'rows': [dict(L[(q, m)], key=m, label=m, p01=L[(q, m)]['p01_us'],
                                                          p25=L[(q, m)]['p25_us'], median=L[(q, m)]['median_us'],
                                                          p75=L[(q, m)]['p75_us'], p99=L[(q, m)]['p99_us'],
                                                          mean=L[(q, m)]['mean_us'], min=L[(q, m)]['min_us'],
                                                          max=L[(q, m)]['max_us'])
                                                     for m in METHODS if (q, m) in L]} for q in qsets]
        fig_box = figure(sc.boxes(groups, sc.fmt_us, 'latency per query (log scale)', label='latency summary'),
                         f'Box: p25–p75; tick: median; dot: mean; whiskers: p1–p99; end ticks: min and max'
                         f'{cfg_note}.')
        fig_thr = self.threshold_chart(qsets, cfgs, CS)

        CSP = by(db.q('from cfg_speedup'), 'cfg', 'qset')
        srows = []
        for q in qsets:
            for c, k, t in cfgs:
                comps = (('index vs brute', 'embed vs brute', 'index vs embed') if c == 0 else ('index vs brute',))
                for comp in comps:
                    s_ = sp.get((q, comp)) if c == 0 else CSP.get((c, q))
                    if s_:
                        srows.append([escape(q), fint(k), tlabel(t), comp, fx(s_['ratio_of_means']),
                                      fx(s_['ratio_of_medians']), fx(s_['paired_geomean']), fx(s_['paired_median']),
                                      fx(s_['paired_p10']), fx(s_['paired_p90']), fpct(s_['frac_fast_wins'])])
        t_sp = table(['set', 'k', 'max distance', 'A vs B', 'ratio of means', 'ratio of medians', 'paired geomean',
                      'paired median', 'paired p10', 'paired p90', 'A faster'], srows, num_from=4)
        tov = run.get('timer_overhead_ns', {})
        extra = ''
        if len(cfgs) > 1:
            extra = (f'<p>Rows with a max distance come from separate runs over the same queries, brute and index '
                     f'only (the embedding scan is not run with a bound); there a query returns fewer than k '
                     f'results when fewer than k rows lie within the bound, which the last three columns count. '
                     f'Methods lists the runs.</p>')
        self.add('knn-latency', 'kNN latency', f"""
<p>{fint(L[(qsets[0], 'brute')]['n'])} queries per set and method, each timed alone with
<code>steady_clock</code> around the kNN call only (for embed: embedding the query, scanning every
<code>TVEC</code> row and the top-k heap). Timer overhead {fint(tov.get('median'))} ns median, not subtracted.
p90 / p99 / p99.9 are nearest-rank; the median interpolates; stddev is the sample stddev; ns/row is the mean
divided by the {fint(n_rows)} rows.</p>{extra}
{t_lat}{fig_ecdf}{fig_box}{fig_thr}
<h3>Speedups</h3>
<p>Ratios are B's time over A's: above 1, method A is faster. "Paired" ratios are per query (the same
query timed by both methods): their geometric mean, median and 10th / 90th percentiles; "A faster" is the
share of queries where A took less time.</p>
{t_sp}""")

    def threshold_chart(self, qsets, cfgs, CS):
        """Index median / p99 and brute median against max_distance, for the runs at the main run's k."""
        main_k = cfgs[0][1]
        same_k = sorted([(t, c) for c, k, t in cfgs if k == main_k], key=lambda x: x[0])
        if len(same_k) < 2:
            return ''
        labels = [tlabel(t) for t, _ in same_k]
        panels = []
        for q in qsets:
            def series(m, field):
                pts, marks = [], []
                for i, (t, c) in enumerate(same_k):
                    r = CS.get((c, q, m))
                    if r:
                        pts.append((i, r[field]))
                        marks.append((i, r[field], f'{q}, {m}, max distance {labels[i]}: '
                                      f'{field.replace("_us", "")} {us(r[field])}'))
                return pts, marks
            ser = []
            for key, m, field, dash, lab in (('brute', 'brute', 'median_us', False, 'brute median'),
                                             ('index', 'index', 'median_us', False, 'index median'),
                                             ('index', 'index', 'p99_us', True, 'index p99')):
                pts, marks = series(m, field)
                ser.append({'key': key, 'label': lab, 'points': pts, 'marks': marks, 'dash': dash})
            panels.append({'title': f'{q} queries', 'series': ser})
        allv = [y for p in panels for s_ in p['series'] for _, y in s_['points'] if y]
        svg = sc.lines(panels, lambda v: labels[int(round(v))] if abs(v - round(v)) < 1e-6 and
                       0 <= round(v) < len(labels) else '', sc.fmt_us, 'max distance (k = %d)' % main_k,
                       'latency (log)', x_domain=(-0.3, len(labels) - 0.7), xticks=list(range(len(labels))),
                       log_y=True, y_domain=(min(allv) / 1.5, max(allv) * 1.5), label='latency vs max distance')
        return figure(svg, f'Index median and p99 latency and brute median latency against the distance bound, '
                           f'k = {main_k}; "none" is the main, unbounded run. One point per run; log y axis.',
                      sc.legend([('brute', 'brute median', 'line'), ('index', 'index median', 'line'),
                                 ('index', 'index p99', 'dash')]))

    def knn_index_work(self, qsets):
        db = self.db
        cfgs = self.cfg_list()
        IW = by(db.q('from cfg_index_work'), 'cfg', 'qset')
        rows = []
        for q in qsets:
            for c, k, t in cfgs:
                r = IW.get((c, q))
                if not r:
                    continue
                rows.append([escape(q), fint(k), tlabel(t), fint(r['rows_mean']), fint(r['rows_median']),
                             fint(r['rows_p99']), fint(r['rows_max']), fpct(r['frac_rows_mean'], 2),
                             fint(r['lists_mean']), fint(r['cells_mean']), f3(r['corr_us_rows']),
                             f3(r['corr_log_us_rows']), f3(r['corr_us_lists']), f3(r['corr_us_cells']),
                             f'{r["ns_per_row_slope"]:.3g}' if isnum(r['ns_per_row_slope']) else '–',
                             f3(r['r2_rows'])])
        t = table(['set', 'k', 'max distance', 'rows mean', 'rows median', 'rows p99', 'rows max', 'share of set',
                   'lists mean', 'cells mean', 'r(latency, rows)', 'r(log, log)', 'r(latency, lists)',
                   'r(latency, cells)', 'ns per row (slope)', 'R² rows'], rows, num_from=3)
        pts = db.q("select qset, qid, index_us, ivf_rows from lat_wide where index_us is not null")
        panels = [{'title': f'{q} queries', 'series': [{'key': 'index', 'label': 'index', 'points': [
            (p['ivf_rows'], p['index_us'], f'{q} #{p["qid"]}: {fint(p["ivf_rows"])} rows, {us(p["index_us"])}')
            for p in pts if p['qset'] == q]}]} for q in qsets]
        main_note = f' (main run: k = {cfgs[0][1]}, max distance {tlabel(cfgs[0][2])})' if len(cfgs) > 1 else ''
        fig = figure(sc.scatter(panels, sc.fmt_num, sc.fmt_us, 'rows scanned by the index (log)', 'latency (log)',
                                label='index latency vs rows scanned'),
                     f'Index latency against the rows it scanned{main_note} (from a second, untimed run of the '
                     f'same search); one dot per query, log–log.')
        self.facts['index_work'] = IW
        self.add('index-work', 'Index work', f"""
<p>For the TIVF index the program counts the header cells visited, the list bounds evaluated and the rows
scanned. A strong correlation between latency and rows scanned means the index's cost is its pruning
efficiency; the slope is the marginal cost of a scanned row (ns per row).</p>{t}{self.m5_note()}{fig}""")

    def m5_note(self):
        """The comparison with the M5 figure, when a k = 10, max distance 144 run is present."""
        db = self.db
        c = db.q('select cfg from cfg where k = 10 and max_distance = 144 order by cfg limit 1')
        if not c:
            return ''
        c = c[0]['cfg']
        st = by(db.q(f'from cfg_lat_stats where cfg = {c}'), 'qset', 'method')
        iw = by(db.q(f'from cfg_index_work where cfg = {c}'), 'qset')
        mi, mb, ri = st.get(('member', 'index')), st.get(('member', 'brute')), st.get(('random', 'index'))
        if not (mi and mb and 'member' in iw):
            return ''
        rows_med, rows_mean = iw['member']['rows_median'], iw['member']['rows_mean']
        n_rows = self.facts['n_rows']
        note = (f'<p><b>Against the M5 figure.</b> The M5 reference is ~{M5_US:g} µs per query on 1M synthetic '
                f'digests at k = 10, max distance 144; the repo\'s own figures for 1M rows are 8.3 µs (the minimum '
                f'of repeated passes) with {fint(M5_ROWS)} rows scanned per query for the default BISECT build '
                f'(4,848 for KMEANS; docs/BENCHMARKS.md §9, docs/TLSH_EMBEDDING.md §5). Here, at those settings on '
                f'{fint(n_rows)} real digests (the k = 10 rows of the tables), the index\'s median member query '
                f'takes {us(mi["median_us"])} (mean {us(mi["mean_us"])}) and scans {fint(rows_med)} rows (mean '
                f'{fint(rows_mean)}): {rows_med / M5_ROWS:.3g}× the M5\'s rows for {n_rows / 1e6:.3g}× the data, '
                f'about {mi["median_us"] * 1000 / rows_med:.3g} ns per scanned row against '
                f'{8.3 * 1000 / M5_ROWS:.2g}–{M5_US * 1000 / M5_ROWS:.2g} ns on the M5. Brute force takes '
                f'{us(mb["median_us"])}, so the index is {faster(mb["median_us"] / mi["median_us"])} brute by the '
                f'medians.')
        if ri and 'random' in iw:
            note += (f' Random queries are fast (median {us(ri["median_us"])}) because '
                     f'{fpct(ri["n_empty"] / ri["n"])} of them have no row within 144 at all and '
                     f'{fpct(ri["n_short"] / ri["n"])} have fewer than 10; the index prunes them almost at once '
                     f'(median {fint(iw["random"]["rows_median"])} rows scanned).')
        return note + '</p>'

    def knn_density(self, qsets):
        db = self.db
        dc = db.q('from density_corr')
        D = by(dc, 'qset', 'method')
        rows = [[escape(q), METHOD_LABEL[m], f3(D[(q, m)]['rho_count_le']), f3(D[(q, m)]['rho_n_identical']),
                 f3(D[(q, m)]['rho_d_k'])] for q in qsets for m in METHODS if (q, m) in D]
        t1 = table(['set', 'method', 'ρ(latency, count_le)', 'ρ(latency, n_identical)', 'ρ(latency, d_k)'],
                   rows, num_from=2)
        bins = db.q('from density_bins order by qset, bin')
        rows = [[escape(b['qset']), str(b['bin']), f'{b["d_k_min"]}–{b["d_k_max"]}', fint(b['count_le_median']),
                 fpct(b['frac_dup']), us(b['brute_us']), us(b['index_us']), us(b['embed_us']),
                 fint(b['ivf_rows']), f3(b['r_tie_mean'])] for b in bins]
        t2 = table(['set', 'd_k quintile', 'd_k range', 'count_le median', 'queries with duplicates',
                    'brute median', 'index median', 'embed median', 'index rows median',
                    'embed recall@k tie-aware, mean'], rows, num_from=1)
        pts = db.q("""select l.qset, l.qid, l.method, l.us, q.d_k, q.count_le from lat l join qinfo q
                      using (qset, qid)""")
        panels = [{'title': f'{q} queries', 'series': [{'key': m, 'label': m, 'points': [
            (p['d_k'], p['us'], f'{q} #{p["qid"]} {m}: d_k {p["d_k"]}, {us(p["us"])}')
            for p in pts if p['qset'] == q and p['method'] == m]} for m in METHODS]} for q in qsets]
        dks = [p['d_k'] for p in pts]
        fig1 = figure(sc.scatter(panels, lambda v: f'{v:g}', sc.fmt_us, 'd_k, the k-th TLSH distance',
                                 'latency (log)', log_x=False, x_domain=(0, max(dks) * 1.03),
                                 label='latency vs d_k'),
                      'Latency against d_k: a small d_k is a dense neighbourhood (a family or cluster around '
                      'the query). One dot per query and method.',
                      sc.legend([(m, METHOD_LABEL[m], 'dot') for m in METHODS]))
        panels = [{'title': f'{q} queries', 'series': [{'key': 'index', 'label': 'index', 'points': [
            (p['count_le'], p['us'], f'{q} #{p["qid"]}: count_le {fint(p["count_le"])}, {us(p["us"])}')
            for p in pts if p['qset'] == q and p['method'] == 'index']}]} for q in qsets]
        fig2 = figure(sc.scatter(panels, sc.fmt_num, sc.fmt_us, 'count_le: rows within d_k (log)',
                                 'index latency (log)', label='index latency vs cluster size'),
                      'Index latency against the size of the query\'s neighbourhood, count_le (rows at TLSH '
                      'distance ≤ d_k; ≥ k by definition, larger when many rows tie at d_k, e.g. duplicates).')
        self.add('density', 'Latency and cluster density', f"""
<p>Spearman rank correlations (ρ) between each method's latency and three measures of the query's
neighbourhood: count_le (rows within d_k), n_identical (rows with exactly the query's digest) and d_k itself.
Brute and embed scan every row, so they should not depend on the neighbourhood; the index prunes by
distance bounds, so it should get faster as d_k shrinks.</p>{t1}{t2}{fig1}{fig2}""")

    def knn_ir(self, qsets, irs, k):
        db = self.db
        deep_k = self.facts['deep_k']
        n_rows = self.facts['n_rows']
        metrics = [
            ('r_tie', f'recall@{k}, tie-aware'), ('p_tie', f'precision@{k}, tie-aware'),
            ('f1_tie', f'F1@{k}, tie-aware'), ('r_tie_all', f'recall over all of R (max k/|R|)'),
            ('f1_tie_all', 'F1 with recall over all of R'), ('r_must', 'recall of L (rows closer than d_k)'),
            ('r_naive', f'recall@{k}, naive'), ('p_naive', f'precision@{k}, naive'), ('f1_naive', f'F1@{k}, naive'),
            ('ap_at_k', f'AP@{k} (MAP = mean)'), ('ndcg', f'nDCG@{k}, graded'),
            ('rbo_90', 'RBO, p = 0.9'), ('rbo_98', 'RBO, p = 0.98'),
            ('tau_shared', 'Kendall τ-b, shared items'), ('rho_shared', 'Spearman ρ, shared items'),
            ('tau_all', f'Kendall τ-b, embed\'s top {k}'), ('rho_all', f'Spearman ρ, embed\'s top {k}'),
            ('rho_deep', f'Spearman ρ, embed\'s top {deep_k}'),
            ('roc_auc_lo', 'ROC AUC, lower bound'), ('roc_auc_tied', 'ROC AUC, unscored tied'),
            ('roc_auc_hi', 'ROC AUC, upper bound'), ('pr_auc_lo', 'PR AUC (AP), lower bound'),
            ('pr_auc_hi', 'PR AUC (AP), upper bound'), ('frac_rel_scored', f'share of R inside embed\'s top {deep_k}'),
            ('kth_inflation', 'k-th distance inflation (embed − brute)'),
            ('kth_ratio', 'k-th distance ratio (embed / brute, d_k > 0)'),
            ('mean_dist_inflation', 'mean distance inflation')]
        rows = []
        nq = by(db.q('select qset, count(*) as n from knn_queries group by all'), 'qset')
        for mkey, label in metrics:
            short = [f'{q} {fint(irs[(q, mkey)]["n"])}' for q in qsets
                     if (q, mkey) in irs and irs[(q, mkey)]['n'] != nq[q]['n']]
            row = [escape(label) + (f' <span class="nq">(n: {", ".join(short)})</span>' if short else '')]
            for q in qsets:
                s = irs.get((q, mkey))
                fm = f3 if not mkey.startswith(('kth', 'mean_dist')) else (lambda v: f'{v:.3g}' if isnum(v) else '–')
                if mkey.startswith('roc'):
                    fm = f4
                row += [fm(s['mean']), fm(s['median']), fm(s['p10']), fm(s['p90'])] if s else ['–'] * 4
            rows.append(row)
        hdr = ['metric'] + [f'{q} {c}' for q in qsets for c in ('mean', 'median', 'p10', 'p90')]
        t_ir = table(hdr, rows)

        # per-query recall distribution
        rq = db.q("select qset, r_tie, r_naive from ir_q")
        nb = 50
        panels = []
        for q in qsets:
            cnt = [0] * nb
            for r in rq:
                if r['qset'] == q:
                    cnt[min(int(r['r_tie'] * nb + 1e-9), nb - 1)] += 1
            panels.append({'title': f'{q} queries', 'key': 'embed',
                           'bins': [(i / nb, (i + 1) / nb, c) for i, c in enumerate(cnt)]})
        fig_rh = figure(sc.hist(panels, lambda v: f'{v:g}', f'per-query recall@{k}, tie-aware',
                                x_domain=(0, 1), label='per-query recall'),
                        f'Distribution of per-query tie-aware recall@{k} of embed; bins of 0.02, the last bin '
                        f'[0.98, 1] holding the queries at 0.99 and 1.')
        frac = by(db.q(f"""select qset, avg((r_tie >= 1)::int) as full, avg((r_tie >= 0.99)::int) as p99,
                           avg((r_tie >= 0.9)::int) as p90, avg((r_naive >= 1)::int) as nfull from ir_q
                           group by all"""), 'qset')
        t_frac = table(['set', 'queries with tie-aware recall = 1', '≥ 0.99', '≥ 0.9', 'naive recall = 1'],
                       [[escape(q), fpct(frac[q]['full']), fpct(frac[q]['p99']), fpct(frac[q]['p90']),
                         fpct(frac[q]['nfull'])] for q in qsets])

        # recall@k' curve
        dc = db.q('from deep_curve order by qset, kp')
        panels = []
        for q in qsets:
            pts = [r for r in dc if r['qset'] == q]
            marks = [(r['kp'], r['r_tie'], f'k\' = {r["kp"]}: mean tie-aware recall {r["r_tie"]:.4f}')
                     for r in pts if r['kp'] in (k, 2 * k, 5 * k, deep_k)]
            panels.append({'title': f'{q} queries', 'series': [
                {'key': 'muted', 'label': 'naive (row identity)', 'dash': True,
                 'points': [(r['kp'], r['r_naive']) for r in pts]},
                {'key': 'embed', 'label': 'tie-aware', 'points': [(r['kp'], r['r_tie']) for r in pts],
                 'marks': marks}],
                'bands': [{'key': 'embed', 'points': [(r['kp'], r['r_tie_p10'], r['r_tie_p50']) for r in pts]}]})
        fig_curve = figure(sc.lines(panels, lambda v: f'{v:g}', lambda v: f'{v:g}', 'k\', depth of the embedding '
                                    'ranking (log)', f'recall of the TLSH top {k}', log_x=True,
                                    y_domain=(0, 1.02), x_domain=(1, deep_k),
                                    refs=[(CROWDSTRIKE_RECALL, 'CrowdStrike: 0.99')], label='recall@k\''),
                           f'Mean recall of the TLSH top {k} within the embedding\'s top k\', k\' from 1 to {deep_k}: '
                           f'the recall of "fetch k\' candidates by embedding distance, re-rank them by TLSH, keep '
                           f'{k}". The wash spans the tie-aware p10 to median; dots at k\' = {k}, {2 * k}, {5 * k}, '
                           f'{deep_k}.', sc.legend([('embed', 'tie-aware (mean)', 'line'),
                                                    ('muted', 'naive (mean)', 'dash')]))
        sel = [r for r in dc if r['kp'] in (k // 10 or 1, k // 2, k, int(1.5 * k), 2 * k, 3 * k, 5 * k, deep_k)]
        t_curve = table(['set', 'k\'', 'naive', 'tie-aware', 'tie-aware p10', 'tie-aware median',
                         'queries at ≥ 0.99', 'queries complete'],
                        [[escape(r['qset']), fint(r['kp']), f4(r['r_naive']), f4(r['r_tie']), f3(r['r_tie_p10']),
                          f3(r['r_tie_p50']), fpct(r['frac_tie_99']), fpct(r['frac_tie_full'])] for r in sel])
        dn = by(db.q("""select qset, count(*) as n, count(kp_tie_99) as n99, median(kp_tie_99) as med99,
                          quantile_disc(kp_tie_99, 0.9) as p90_99, count(kp_tie_full) as nfull,
                          median(kp_tie_full) as medfull, quantile_disc(kp_tie_full, 0.9) as p90full,
                          max(kp_tie_full) as maxfull from depth_needed group by all"""), 'qset')
        t_depth = table(['set', 'queries', f'reach 0.99 within {deep_k}', 'median k\' for 0.99',
                         'p90 k\' for 0.99', f'reach 1.0 within {deep_k}', 'median k\' for 1.0', 'p90 k\' for 1.0',
                         'max k\' for 1.0'],
                        [[escape(q), fint(dn[q]['n']), fpct(dn[q]['n99'] / dn[q]['n']), fint(dn[q]['med99']),
                          fint(dn[q]['p90_99']), fpct(dn[q]['nfull'] / dn[q]['n']), fint(dn[q]['medfull']),
                          fint(dn[q]['p90full']), fint(dn[q]['maxfull'])] for q in qsets])
        self.facts['deep_curve'] = dc
        self.facts['depth'] = dn
        self.facts['frac'] = frac

        # distance error
        de = db.q('from dist_err_by_rank order by qset, i')
        panels = [{'title': f'{q} queries', 'series': [
            {'key': 'muted', 'label': 'in embed\'s order', 'dash': True,
             'points': [(r['i'], r['mean_order']) for r in de if r['qset'] == q]},
            {'key': 'embed', 'label': 'embed\'s results sorted by TLSH distance',
             'points': [(r['i'], r['mean_sorted']) for r in de if r['qset'] == q]}],
            'bands': [{'key': 'embed', 'points': [(r['i'], r['p10_sorted'], r['p90_sorted'])
                                                  for r in de if r['qset'] == q]}]} for q in qsets]
        fig_de = figure(sc.lines(panels, lambda v: f'{v:g}', lambda v: f'{v:g}', 'rank i', 'TLSH distance error',
                                 x_domain=(1, k), label='distance error by rank', share_y=False),
                        'TLSH distance of embed\'s i-th result minus brute\'s i-th distance, mean per rank. Solid: '
                        'embed\'s k results re-sorted by TLSH distance (never negative; wash p10–p90). Dashed: in '
                        'embed\'s own order (can be negative when embed puts a nearer row later). Each panel has its own y scale.',
                        sc.legend([('embed', 'sorted by TLSH distance (mean, p10–p90 wash)', 'line'),
                                   ('muted', 'embed order (mean)', 'dash')]))
        ki = db.q("select qset, kth_inflation as v from ir_q")
        panels = []
        widths = []
        for q in qsets:
            vmax = max([r['v'] for r in ki if r['qset'] == q] + [1])
            width = max(1, math.ceil((vmax + 1) / 40))
            widths.append(f'{q} {width}')
            nbins = math.ceil((vmax + 1) / width)
            cnt = [0] * nbins
            for r in ki:
                if r['qset'] == q:
                    cnt[int(r['v'] // width)] += 1
            panels.append({'title': f'{q} queries', 'key': 'embed',
                           'bins': [(i * width, (i + 1) * width, c) for i, c in enumerate(cnt)]})
        fig_ki = figure(sc.hist(panels, lambda v: f'{v:g}', 'k-th distance inflation (TLSH distance units)',
                                share_x=False, label='k-th distance inflation'),
                        f'Per query: the largest TLSH distance among embed\'s {k} results minus d_k. 0 means '
                        f'embed\'s worst result is as close as the true k-th neighbour. Each panel has its own x '
                        f'scale; bin widths {", ".join(widths)}.')

        # PR curve examples
        ex = db.q("""with r as (select qset, qid, pr_auc_lo,
                         row_number() over (partition by qset order by pr_auc_lo, qid) as rn,
                         count(*) over (partition by qset) as n from auc_q)
                     select qset, qid, pr_auc_lo, case when rn = (n + 1) // 2 then 'median' else 'p10' end as which
                     from r where rn = (n + 1) // 2 or rn = greatest(1, (n + 9) // 10)""")
        keys = ', '.join(f"('{e['qset']}', {e['qid']})" for e in ex)
        prs = db.q(f"""select d.qset, d.qid, d.rank,
                         sum((d.tlsh_dist <= q.d_k)::int) over w as cum, q.count_le
                       from knn_deep d join qinfo q using (qset, qid)
                       where (d.qset, d.qid) in ({keys})
                       window w as (partition by d.qset, d.qid order by d.rank)
                       order by d.qset, d.qid, d.rank""") if ex else []
        panels = []
        notes = []
        for q in qsets:
            series = []
            for which, key, dash in (('median', 'embed', False), ('p10', 'muted', True)):
                e = next((e for e in ex if e['qset'] == q and e['which'] == which), None)
                if not e:
                    continue
                qr = [r for r in prs if r['qset'] == q and r['qid'] == e['qid']]
                # the curve ends at the last relevant row inside the recorded depth
                last = max((i for i, r in enumerate(qr) if r['cum'] > (qr[i - 1]['cum'] if i else 0)),
                           default=-1)
                pts = [(r['cum'] / r['count_le'], r['cum'] / r['rank']) for r in qr[:last + 1]]
                kp = [(r['cum'] / r['count_le'], r['cum'] / r['rank'], f'rank {k}: recall '
                       f'{r["cum"] / r["count_le"]:.3f}, precision {r["cum"] / r["rank"]:.3f}')
                      for r in qr[:last + 1] if r['rank'] == k]
                series.append({'key': key, 'dash': dash, 'points': pts, 'marks': kp,
                               'label': f'{which} AP query #{e["qid"]} (AP lower bound {e["pr_auc_lo"]:.3f})'})
                notes.append(f'{q} {which}-AP query #{e["qid"]}: AP lower bound {e["pr_auc_lo"]:.3f}'
                             + ('' if last >= 0 else f', no relevant row in the top {deep_k} (no curve)'))
            panels.append({'title': f'{q} queries', 'series': series})
        fig_pr = figure(sc.lines(panels, lambda v: f'{v:g}', lambda v: f'{v:g}', 'recall (of R)', 'precision',
                                 x_domain=(0, 1), y_domain=(0, 1.02), label='PR curves'),
                        f'Precision–recall along the embedding ranking (to depth {deep_k}) for the query at the median '
                        f'of the AP lower bound and the one at its 10th percentile; relevant = TLSH distance ≤ d_k. The '
                        f'dot marks rank {k}; each curve ends at the last relevant row inside depth {deep_k}, and one '
                        f'that ends short of recall 1 has relevant rows beyond that depth (see the AUC bounds). '
                        f'{escape("; ".join(notes))}.',
                        sc.legend([('embed', 'median-AP query', 'line'), ('muted', '10th-percentile-AP query', 'dash')]))

        defs = self.definitions(k, deep_k, n_rows)
        self.add('ir', f'Embedding kNN as retrieval: embed against the TLSH ground truth', f"""
{defs}
<h3>Summary over queries</h3>
<p>Per-query values aggregated over the queries of each set; where a metric is undefined for some
queries, the number of queries it covers is given in parentheses.</p>{t_ir}{t_frac}{fig_rh}
<h3>How deep must the embedding ranking go?</h3>{fig_curve}{t_curve}{t_depth}
<h3>Distance error</h3>{fig_de}{fig_ki}
<h3>Ranking quality: an example PR curve</h3>{fig_pr}{self.header_split_html(qsets)}""")

    def header_split_html(self, qsets):
        """The header-split diagnostic (--hset): where embed's errors come from."""
        db = self.db
        if not db.has_table('header_split_summary'):
            return ''
        S = by(db.q('from header_split_summary'), 'qset', 'cat')
        for c in db.q('from header_split_check order by qset'):
            self.validation.append((f'header split, {c["qset"]}: header + body/checksum rest = tlsh_dist',
                                    f'{fint(c["sum_mismatch"])} of {fint(c["n"])} rows differ; library distance '
                                    f'differs from tlsh_dist on {fint(c["full_mismatch"])}',
                                    c['sum_mismatch'] == 0 and c['full_mismatch'] == 0
                                    and c['length_over_header'] == 0))
        label = {'FP': 'FP: embed result beyond d<sub>k</sub>', 'TP': 'TP: embed result within d<sub>k</sub>',
                 'MISS': 'MISS: brute result embed missed'}
        rows = []
        for q in qsets:
            for c in ('FP', 'MISS', 'TP'):
                r = S.get((q, c))
                if r:
                    rows.append([escape(q), label[c], fint(r['n']), f'{r["mean_tlsh"]:.1f}', f'{r["mean_header"]:.1f}',
                                 f'{r["mean_length"]:.1f}', f'{r["mean_quartile"]:.1f}', f'{r["mean_rest"]:.1f}',
                                 f3(r['header_share']), fpct(r['frac_header_differs']),
                                 fpct(r['frac_length_differs'])])
        t = table(['set', 'rows', 'n', 'mean TLSH distance', 'mean header cost', 'of which L', 'of which Q1, Q2',
                   'mean body + checksum', 'header share', 'header differs', 'L differs'], rows, num_from=2)
        q0 = qsets[0]
        fp, miss, tp = S.get((q0, 'FP')), S.get((q0, 'MISS')), S.get((q0, 'TP'))
        prose = ''
        if fp and miss and tp:
            prose = (f'<p>On the {escape(q0)} set, {fpct(fp["frac_header_differs"])} of embed\'s false positives '
                     f'have a header different from the query\'s, and the header terms make up '
                     f'{fp["mean_header"]:.1f} TLSH units ({fpct(fp["header_share"], 0)}) of their distance on '
                     f'average ({fp["mean_length"]:.1f} from the length, {fp["mean_quartile"]:.1f} from the '
                     f'quartile ratios), while the true neighbours embed misses carry only '
                     f'{miss["mean_header"]:.1f} units of header cost ({fpct(miss["header_share"], 0)}) and the '
                     f'true positives {tp["mean_header"]:.1f}. Embed trades rows whose header matches the query and '
                     f'whose body differs a little more for rows with a closer body and a different length or '
                     f'quartile ratio, which TLSH charges heavily.</p>')
        return f"""
<h3>Why embed misses: the header terms</h3>
<p>The embedding is a lower bound on TLSH distance built for safe pruning, and its header coordinates are
much weaker than TLSH's header terms (docs/TLSH_EMBEDDING.md §1): a length difference of k costs k² in the
embedding against TLSH's 12k for k ≥ 2 (4 against 24 at k = 2), and a quartile-ratio step of 2 costs a chord²
of 3.85 against 12 (8.11 against 24 for a step of 3). The table splits the TLSH distance of each row into the
header terms (L, Q1, Q2) and the body + checksum rest, through the library:
header = tlsh_diff(q, r<sub>header</sub> + q<sub>body</sub>), rest = tlsh_diff(q, q<sub>header</sub> +
r<sub>body</sub>); the two add up to the row's TLSH distance (checked in Validation). "Header share" is the
total header cost over the total distance of the rows.</p>{t}{prose}"""

    def knn_extra_checks(self):
        """Validation of the --knn-extra runs: exactness, same queries, bounded = cut unbounded, summary.txt."""
        db = self.db
        cfgs = {c: (k, t) for c, k, t in self.cfg_list()}
        EX = db.q('from cfg_exactness where cfg <> 0 order by cfg, qset')
        SQ = by(db.q('from cfg_same_queries'), 'cfg', 'qset')
        BC = by(db.q('from cfg_bound_check'), 'cfg', 'qset')
        CS = by(db.q('from cfg_lat_stats'), 'cfg', 'qset', 'method')
        for e in EX:
            c, q = e['cfg'], e['qset']
            k, t = cfgs[c]
            name = f'k = {k}, max distance {tlabel(t)}, {q}'
            self.validation.append((f'{name}: brute vs index identical (rows, distances, counts)',
                                    f'rows differ on {fint(e["row_mismatches"])}, distances on '
                                    f'{fint(e["dist_mismatches"])}, result counts on {fint(e["count_mismatches"])} '
                                    f'of {fint(e["n_queries"])} queries',
                                    e['row_mismatches'] == 0 and e['dist_mismatches'] == 0
                                    and e['count_mismatches'] == 0))
            sq = SQ.get((c, q))
            if sq:
                self.validation.append((f'{name}: same query digests as the main run',
                                        f'{fint(sq["digest_mismatches"])} of {fint(sq["n"])} differ',
                                        sq['digest_mismatches'] == 0 and sq['n'] == e['n_queries']))
            b = BC.get((c, q))
            if b:
                self.validation.append((f'{name}: brute = the main run\'s brute top {k} cut to distance ≤ '
                                        f'{tlabel(t)}',
                                        f'{fint(b["mismatched_queries"])} of {fint(b["n_queries"])} queries differ; '
                                        f'{fint(b["rows_got"])} rows against {fint(b["rows_expected"])} expected',
                                        b['mismatched_queries'] == 0 and b['rows_got'] == b['rows_expected']))
        for i, (d, x) in enumerate(self.args.extra_runs, start=1):
            k, t = cfgs[i]
            summ = parse_summary(os.path.join(d, 'summary.txt'))
            if summ['mean_us']:
                worst = max(abs(CS[(i, key[0], key[1])]['mean_us'] - v) for key, v in summ['mean_us'].items()
                            if (i, key[0], key[1]) in CS)
                self.validation.append((f'k = {k}, max distance {tlabel(t)}: latency means agree with its '
                                        f'summary.txt', f'largest difference {worst:.2f} µs', worst <= 0.1))
            if summ['mismatch']:
                self.validation.append((f'k = {k}, max distance {tlabel(t)}: no mismatches in its summary.txt',
                                        ', '.join(f'{q} {n}' for q, n in summ['mismatch'].items()),
                                        all(n == 0 for n in summ['mismatch'].values())))

    def definitions(self, k, deep_k, n_rows):
        return f"""
<details class="defs" open><summary>Definitions</summary>
<p>For a query: <b>B</b> is brute's top k (k = {k}; the ground truth, ties at the k-th distance broken by
row index), <b>E</b> is embed's top k, <b>D</b> is the embedding ranking to depth {deep_k} (E is its
prefix), <b>d<sub>k</sub></b> is the k-th smallest TLSH distance, <b>R</b> = rows with TLSH distance
≤ d<sub>k</sub> (|R| = count_le ≥ k) and <b>L</b> = rows with distance &lt; d<sub>k</sub>
(|L| = count_lt &lt; k). Every exact kNN answer contains L and is filled from R; when |R| &gt; k there are
several exact answers and B is only one of them.</p>
<ul>
<li><b>Naive</b> precision, recall and F1 count rows of E that are also rows of B: |E∩B|/|E|, |E∩B|/|B|.
With |E| = |B| = k they are equal. They penalize embed for choosing a different, equally close tied row.</li>
<li><b>Tie-aware precision@k</b> = |E∩R| / |E|: the share of embed's results that belong to some exact answer.
<b>Tie-aware recall@k</b> = |E∩R| / min(k, |R|) = |E∩R| / k: the share of the k answer slots filled with
rows an exact answer could hold (the measure the eval program prints). With |E| = k these two are equal by
construction; so is their F1.</li>
<li><b>Recall over all of R</b> = |E∩R| / |R| treats every tied row as relevant. It is below the tie-aware
recall whenever |R| &gt; k and cannot exceed k/|R|, so it is reported for completeness and is not a
target. Its F1 with tie-aware precision is also shown. <b>Recall of L</b> = |E∩L| / |L| (undefined when
L is empty) asks whether embed keeps the rows strictly closer than d<sub>k</sub>, which every exact answer
must hold.</li>
<li><b>Recall@k'</b> = |D<sub>1..k'</sub>∩B| / k (naive) or min(k, |D<sub>1..k'</sub>∩R|) / k (tie-aware),
for k' = 1 … {deep_k}: the recall after re-ranking embed's top k' candidates by exact TLSH distance and
keeping k. "k' needed" is the smallest depth reaching a given recall for a query; queries that do not reach
it within {deep_k} are counted as not reaching it (censored), not dropped.</li>
<li><b>AP@k</b> = (1 / min(k, |R|)) Σ<sub>i ≤ k, E<sub>i</sub> ∈ R</sub> P@i, binary relevance R; MAP is its
mean. <b>nDCG@k</b> uses the graded gain g(d) = (d<sub>k</sub> + 1 − d) / (d<sub>k</sub> + 1) for d ≤ d<sub>k</sub>
and 0 beyond (1 at distance 0, falling linearly), the discount 1/log<sub>2</sub>(i + 1), normalized by
brute's DCG (the ideal ordering).</li>
<li><b>RBO</b> (rank-biased overlap, Webber et al. 2010, extrapolated RBO<sub>ext</sub> for two lists of
length k) between E and B by row identity, persistence p = 0.9 (weights the top ~10) and 0.98 (the top
~50). Like the naive measures it counts a tied substitute as a miss.</li>
<li><b>Kendall τ-b</b> and <b>Spearman ρ</b> (average ranks) between squared embedding distance and TLSH
distance, over the shared items E∩B (ordering agreement where both lists agree on membership), over all
of E, and (ρ only) over all of D. τ-b corrects for ties on both sides; undefined (and excluded) when
fewer than two items or one side is constant.</li>
<li><b>ROC AUC and PR AUC</b> per query: score = −(embedding distance), label = TLSH distance ≤ d<sub>k</sub>,
universe = all {fint(n_rows)} rows. Only D is scored. Unscored rows rank below all of D (their embedding
distance is at least D's last); their order among themselves is unknown, so the <b>lower bound</b> puts
every unscored relevant row last (below every unscored irrelevant row) and the <b>upper bound</b> puts them
first among the unscored; for ROC the <b>tied</b> value gives the unscored rows half credit (the expected
value under a random order). Ties in embedding distance inside D get half credit in ROC AUC; AP follows the
ranking's order. PR AUC is average precision over the full ranking. With millions of irrelevant rows, ROC
AUC is dominated by easy negatives and is close to 1 whenever the relevant rows are inside D; PR AUC is the
informative one.</li>
<li><b>Distance error</b>: for rank i, TLSH distance of embed's i-th result minus brute's i-th (in embed's
order, and with embed's results re-sorted by TLSH distance, which is never negative). <b>k-th distance
inflation</b> = max TLSH distance in E − d<sub>k</sub>; the ratio divides instead (d<sub>k</sub> &gt; 0).</li>
</ul></details>"""

    # ------------------------------------------------------------ lookup

    def lookup(self):
        db = self.db
        st = by(db.q('from lookup_stats'), 'pass')
        self.LK = st
        mf, mn = self.mf or {}, self.mn or {}
        passes = [p for p in ('found', 'notfound') if p in st]
        rows = []
        for p in passes:
            s = st[p]
            rows.append([p, fint(s['n']), fint(s['n_found']), ns(s['mean']), ns(s['median']), ns(s['stddev']),
                         ns(s['p90']), ns(s['p99']), ns(s['p999']), ns(s['min']), ns(s['max']),
                         fint(s['over_10us']),
                         ns((mf if p == 'found' else mn).get('aggregate_mean_ns'))])
        t = table(['pass', 'n', 'found', 'mean', 'median', 'stddev', 'p90', 'p99', 'p99.9', 'min', 'max',
                   '> 10 µs', 'aggregate mean (no per-query timer)'], rows)
        ec = db.q('select pass, list(ns order by p) as v from lookup_ecdf group by all')
        E = by(ec, 'pass')
        panels = [{'title': 'SHA-256 lookups', 'series': [
            {'key': p, 'label': p, 'values': E[p]['v']} for p in passes if p in E]}]
        fig1 = figure(sc.ecdf(panels, sc.fmt_ns, 'latency per lookup (log scale)', label='lookup ECDF'),
                      'Empirical CDF of per-lookup latency (drawn from 999 quantiles of each pass); log x axis.',
                      sc.legend([(p, {'found': 'found (every stored SHA-256)',
                                      'notfound': 'not found (uniform random SHA-256)'}[p], 'line') for p in passes]))
        hs = db.q('select pass, bin, n from lookup_hist order by pass, bin')
        panels = []
        for p in passes:
            tot = sum(h['n'] for h in hs if h['pass'] == p) or 1
            panels.append({'title': p, 'key': p, 'bins': [(10 ** (h['bin'] / 20), 10 ** ((h['bin'] + 1) / 20),
                                                           h['n'] / tot) for h in hs if h['pass'] == p]})
        allb = [b for pn in panels for b in pn['bins']]
        fig2 = figure(sc.hist(panels, sc.fmt_ns, 'latency (log scale, 20 bins per decade)', 'share of lookups (log)',
                              log_x=True, log_y=True, x_domain=(min(b[0] for b in allb), max(b[1] for b in allb)),
                              yfmt=lambda v: f'{v:g}' if v >= 0.001 else f'{v:.0e}'.replace('e-0', 'e-'),
                              label='lookup histogram'),
                      'Share of lookups per log-spaced latency bin, log y so that the tail shows. The bins beyond '
                      'a few µs are mostly the VM\'s interference (see the noise floor), not the lookup.')
        # timer and noise
        nrows = []
        for p, m in (('found', mf), ('notfound', mn)):
            if not m:
                continue
            to = m.get('timer_overhead_ns', {})
            nf = m.get('noise_floor', {})
            secs = nf.get('secs') or 1
            it = m.get('interference', {})
            nrows.append([p, escape(str(m.get('timer'))), f'{to.get("median", "–")} / {to.get("p99", "–")}',
                          f'{nf.get("gaps_over_5us", 0) / secs:,.0f} /s', f'{nf.get("gaps_over_10us", 0) / secs:,.0f} /s',
                          ns(nf.get('median_gap_over_5us_ns')), ns(nf.get('max_gap_ns')),
                          escape(str(m.get('cpu_affinity'))),
                          f'{it.get("involuntary_ctxsw", "–")} / {it.get("major_faults", "–")}'])
        t2 = table(['pass', 'timer', 'timer overhead ns (median / p99)', 'gaps > 5 µs', 'gaps > 10 µs',
                    'median gap > 5 µs', 'max gap', 'pinned CPU', 'invol. ctx switches / major faults'], nrows)

        # assertions
        if mf:
            ok = (st.get('found', {}).get('n') == mf.get('queries') == mf.get('found') == mf.get('list_count')
                  and st['found']['n_found'] == st['found']['n'])
            self.validation.append(('lookup: every stored SHA-256 found',
                                    f'{fint(st["found"]["n_found"])} found of {fint(st["found"]["n"])} queried; '
                                    f'list {fint(mf.get("list_count"))}, sha256 rows {fint(mf.get("sha256_count"))}, '
                                    f'records {fint(mf.get("record_count"))}', ok))
            self.validation.append(('lookup: the whole exported list was queried (no --limit)',
                                    f'limit {mf.get("limit")}, list {fint(mf.get("list_count"))} = sha256 rows '
                                    f'{fint(mf.get("sha256_count"))}',
                                    not mf.get('limit') and mf.get('list_count') == mf.get('sha256_count')))
            self.facts['lookup_found_ok'] = ok
        if mn:
            n = st.get('notfound', {}).get('n')
            clean = (n == mn.get('queries') and n >= 10000 and not mn.get('lookup_bug')
                     and mn.get('checked_against_list') and not mn.get('inject_hits'))
            hits = st['notfound']['n_found']
            # a hit that the program verified against the exported list is a genuine
            # SHA-256 collision: not a lookup failure, but worth a look
            ok = (clean and hits == 0 and mn.get('found') == 0 and not mn.get('collisions')) or \
                ('warn' if clean and hits == mn.get('found') == len(mn.get('collisions') or []) else False)
            self.validation.append(('lookup: no uniformly random SHA-256 found',
                                    f'{fint(st["notfound"]["n_found"])} found of {fint(n)}; collisions '
                                    f'{len(mn.get("collisions") or [])}, lookup bug {mn.get("lookup_bug")}, checked '
                                    f'against the list {mn.get("checked_against_list")}, seed {mn.get("seed")}', ok))
            self.facts['lookup_notfound_ok'] = ok
        for p, m in (('found', mf), ('notfound', mn)):
            if m and p in st and m.get('stats_ns'):
                a, b = st[p], m['stats_ns']
                ok = abs(a['mean'] - b['mean']) <= 0.01 * b['mean'] and a['median'] == b['median'] \
                    and a['p99'] == b['p99'] and a['n'] == b['n']
                self.validation.append((f'lookup {p}: CSV statistics agree with the program\'s meta.json',
                                        f'mean {a["mean"]:.1f} vs {b["mean"]:.1f} ns, median {a["median"]:.0f} vs '
                                        f'{b["median"]:.0f}, p99 {a["p99"]:.0f} vs {b["p99"]:.0f}', ok))
        hpaths = {m.get('hset_path') for m in (mf, mn) if m}
        if self.run and hpaths:
            same_size = {m.get('hset_size') for m in (mf, mn) if m} == {self.run['hset']['size_bytes']}
            self.validation.append(('lookup and kNN runs used the same hset (by size)',
                                    f'{", ".join(escape(str(h)) for h in hpaths)} vs '
                                    f'{escape(self.run["hset"]["path"])}', True if same_size else 'warn'))

        self.add('lookup', 'SHA-256 lookups (step 2)', f"""
<p>Every SHA-256 stored in the hset, exported and shuffled, looked up once each (<i>found</i>), and
uniformly random SHA-256 values (<i>notfound</i>), each lookup timed alone through
<code>sfhash_hashset_lookup</code>. ns includes the timer overhead. Percentiles are nearest-rank (element
⌊q(n − 1)⌋, as the program reports).</p>{t}{fig1}{fig2}
<h3>Timer and noise floor</h3>
<p>Measured by the program before each pass: an empty timed region 1M times, and back-to-back clock reads
for a few seconds, counting the gaps where the CPU was taken away.</p>{t2}""")

    # ------------------------------------------------------------ answers

    def threshold_sentence(self, q):
        """One generated sentence on the bounded runs at the main run's k, for set q."""
        cfgs = self.cfg_list()
        main_k = cfgs[0][1]
        bounded = sorted([(t, c) for c, k, t in cfgs[1:] if k == main_k and t < UNBOUNDED])
        if not bounded:
            return ''
        CS = by(self.db.q(f"from cfg_lat_stats where qset = '{q}'"), 'cfg', 'method')
        parts, bru, short = [], [], []
        for t, c in bounded:
            i, b = CS.get((c, 'index')), CS.get((c, 'brute'))
            if not (i and b):
                continue
            parts.append(f'{us(i["median_us"])} at max distance {tlabel(t)}')
            bru.append(b['median_us'])
            short.append(fpct(i['n_short'] / i['n'], 0))
        if not parts:
            return ''
        none_all = all(CS[(c, 'index')]['n_empty'] == CS[(c, 'index')]['n'] for _, c in bounded if (c, 'index') in CS)
        return (f' With a distance bound (k = {main_k}) the index\'s median falls to {", ".join(parts)}, against '
                f'brute medians of {us(min(bru))}–{us(max(bru))}; {" / ".join(short)} of the queries return fewer '
                f'than k results' + (' (none of them returns any)' if none_all else '') + '.')

    def build_cost_rows(self):
        """--build-costs: the variants, and TVEC / TIVF as differences from the TLSH-only build."""
        b = self.build_costs
        if not b or not b.get('variants'):
            return None
        V = b['variants']
        base = next((v for v in V if not v.get('options')), None)
        if base is None:
            return None
        out = {'base': {'wall': base['wall_s'], 'user': base['user_s'], 'bytes': base['bytes']}}
        rows = []
        for v in V:
            d = {'wall': v['wall_s'] - base['wall_s'], 'user': v['user_s'] - base['user_s'],
                 'bytes': v['bytes'] - base['bytes']}
            if v.get('options') == 1:
                out['tvec'] = d
            elif v.get('options') == 2:
                out['tivf'] = d
            rows.append([escape(v['name']), str(v.get('options', '')), f'{v["wall_s"]:,.2f} s', f'{v["user_s"]:,.2f} s',
                         f'{v["maxrss_kb"] / 2**20:,.2f} GiB' if v['maxrss_kb'] >= 2**20 else
                         f'{v["maxrss_kb"] / 1024:,.0f} MiB', f'{v["bytes"]:,}',
                         '–' if v is base else f'{d["wall"]:+,.2f} s',
                         '–' if v is base else f'{d["user"]:+,.2f} s',
                         '–' if v is base else f'{d["bytes"] / 1e6:+,.1f} MB'])
        t = table(['build', 'options', 'wall', 'user CPU', 'max RSS', 'file bytes', 'wall over none',
                   'CPU over none', 'size over none'], rows, num_from=2)
        rows_note = ''
        hrows = (self.run or {}).get('hset', {}).get('tlsh_rows')
        if b.get('rows') and hrows and b['rows'] != hrows:
            rows_note = (f' The builds hold {fint(b["rows"])} rows: the {fint(b.get("input_digests"))} input '
                         f'digests with duplicates collapsed, against {fint(hrows)} TLSH rows in the evaluated '
                         f'hset (which keeps one row per record), so they understate its costs by about '
                         f'{fpct(hrows / b["rows"] - 1)}.')
        out['table'] = (t + f'<p class="note">{escape(b.get("description", ""))}.{rows_note}</p>')
        return out

    def judgement(self, key, placeholder):
        j = self.judgements.get(key)
        if j:
            return (f'<div class="judgement authored"><p class="jlabel">Author\'s judgement</p>{j}</div>')
        return f'<p class="judgement">Judgement: {todo(placeholder)}</p>'

    def answers(self):
        F, k = self.facts, self.facts.get('k')
        out = []
        tiles = []
        if hasattr(self, 'L'):
            irs, sp, L = self.irs, self.sp, self.L
            dc = F['deep_curve']
            q1 = []
            for q in self.qsets:
                r = irs[(q, 'r_tie')]
                rn = irs[(q, 'r_naive')]
                fr = F['frac'][q]
                if r['mean'] >= CROWDSTRIKE_RECALL:
                    verdict = 'meets'
                elif r['mean'] >= 0.95:
                    verdict = 'is close to, but below,'
                elif r['mean'] >= 0.8:
                    verdict = 'falls short of'
                else:
                    verdict = 'falls far short of'
                reach = next((d['kp'] for d in dc if d['qset'] == q and d['r_tie'] >= CROWDSTRIKE_RECALL), None)
                reach_s = (f'Re-ranking the embedding\'s top k\' candidates by exact TLSH distance reaches a mean '
                           f'tie-aware recall of 0.99 at k\' = {reach} ({reach / k:.3g}× k).' if reach else
                           f'Even re-ranking the embedding\'s top {F["deep_k"]} candidates by TLSH does not reach a mean '
                           f'tie-aware recall of 0.99 (it reaches '
                           f'{max(d["r_tie"] for d in dc if d["qset"] == q):.3f}).')
                q1.append(f"""<p><b>{escape(q)} queries.</b> Embed's mean recall@{k} against TLSH is
<b>{r['mean']:.3f}</b> tie-aware (median {r['median']:.3f}; p10 {r['p10']:.3f}) and {rn['mean']:.3f} naive,
which {verdict} the &gt;0.99 CrowdStrike reported. {fpct(fr['p99'])} of queries reach 0.99 and
{fpct(fr['full'])} are complete. nDCG@{k} is {irs[(q, 'ndcg')]['mean']:.3f}, AP@{k}
{irs[(q, 'ap_at_k')]['mean']:.3f}, and the worst of embed's results is on average
{irs[(q, 'kth_inflation')]['mean']:.3g} TLSH units further than the true k-th neighbour (median
{irs[(q, 'kth_inflation')]['median']:.3g}). {reach_s}</p>""")
                tiles.append((f'embed recall@{k}, {q} (tie-aware)', f'{r["mean"]:.3f}',
                              f'naive {rn["mean"]:.3f}; target &gt; 0.99'))
            exact_all = all(self.ex[q]['row_mismatches'] == 0 for q in self.qsets)
            nq = sum(self.ex[q]['n_queries'] for q in self.qsets)
            nmis = sum(self.ex[q]['row_mismatches'] for q in self.qsets)
            idx_s = (f'The TIVF index uses the embedding only as a pruning bound and returned exactly brute\'s '
                     f'results for all {fint(nq)} queries, so its recall is 1.' if exact_all else
                     f'<b>The TIVF index, which should be exact, differed from brute on {fint(nmis)} of {fint(nq)} '
                     f'queries</b>; see Validation.')
            out.append(f"""<section class="answer"><h3>1. Do kNN results from the embeddings match TLSH closely
enough?</h3>
<p><b>Index (exact).</b> {idx_s}</p>
<p><b>Pure embedding kNN (approximate).</b></p>{''.join(q1)}
{self.judgement('q1', 'is this close enough for the intended use (e.g. family triage vs exact '
                                'near-duplicate search)? Weigh the member set, which resembles queries for samples '
                                'like those in the set, against the random set, which probes far-away client '
                                'queries (see Caveats).')}
</section>""")

            n_rows = F['n_rows']
            q2 = []
            for q in self.qsets:
                ib, eb, ie = sp[(q, 'index vs brute')], sp[(q, 'embed vs brute')], sp[(q, 'index vs embed')]

                q2.append(f"""<p><b>{escape(q)} queries.</b> Brute TLSH takes {us(L[(q, 'brute')]['mean_us'])} per
query on average (median {us(L[(q, 'brute')]['median_us'])}); the index takes {us(L[(q, 'index')]['mean_us'])}
(median {us(L[(q, 'index')]['median_us'])}, p99 {us(L[(q, 'index')]['p99_us'])}): {faster(ib['ratio_of_means'])}
brute by the means, {faster(ib['paired_geomean'])} by the per-query geometric mean, and faster on
{fpct(ib['frac_fast_wins'])} of queries. The pure embedding scan takes {us(L[(q, 'embed')]['mean_us'])}:
{faster(eb['ratio_of_means'])} brute ({L[(q, 'embed')]['mean_us'] * 1000 / n_rows:.3g} against
{L[(q, 'brute')]['mean_us'] * 1000 / n_rows:.3g} ns per row).{self.threshold_sentence(q)}</p>""")
                tiles.append((f'index speedup over brute, {q}', fx(ib['paired_geomean']),
                              f'per-query geomean; means {fx(ib["ratio_of_means"])}'))
            for q in self.qsets[:1]:
                eb = sp[(q, 'embed vs brute')]
                tiles.append((f'embed speed vs brute, {q}', fx(eb['ratio_of_means']), 'ratio of means; &lt; 1× is slower'))
            hset = self.run['hset']
            tvec = n_rows * 264 * 4
            cost = (f'<p><b>Construction cost.</b> The hset is {hset["size_bytes"] / 2**30:.2f} GiB for '
                    f'{fint(hset["tlsh_rows"])} TLSH rows; the TVEC vectors alone are {fint(n_rows)} × 264 float32 = '
                    f'{tvec / 2**30:.2f} GiB ({fpct(tvec / hset["size_bytes"])} of the file), and TIVF has '
                    f'{fint(hset.get("ivf_lists"))} lists. ')
            bc = self.build_cost_rows()
            tivf_s = self.args.build_seconds or (bc['tivf']['wall'] if bc and bc.get('tivf') else None)
            if bc:
                parts = []
                if bc.get('tivf'):
                    parts.append(f'adding TIVF costs {bc["tivf"]["wall"]:,.0f} s of wall time '
                                 f'({bc["tivf"]["user"]:,.0f} extra CPU-seconds, multithreaded) and '
                                 f'{bc["tivf"]["bytes"] / 1e6:,.1f} MB')
                if bc.get('tvec'):
                    parts.append(f'adding TVEC costs {bc["tvec"]["wall"]:,.0f} s and '
                                 f'{bc["tvec"]["bytes"] / 1e9:,.2f} GB')
                cost += (f'Measured separately (table below), over a TLSH-only build of '
                         f'{bc["base"]["wall"]:,.0f} s, ' + '; '.join(parts) + '. ')
                rec = (self.build_costs or {}).get('records_build')
                if rec and rec.get('wall_s'):
                    cost += (f'The full records hset build ({escape(rec.get("tool", ""))}) took '
                             f'{rec["wall_s"]:,.0f} s. ')
            if tivf_s:
                save = (L[(self.qsets[0], 'brute')]['mean_us'] - L[(self.qsets[0], 'index')]['mean_us']) / 1e6
                cost += (f'At the {self.qsets[0]} set\'s mean saving of {save * 1e3:.3g} ms per query, the index '
                         f'repays its {tivf_s:,.0f} s of build time after about {tivf_s / save:,.0f} queries'
                         if save > 0 else 'The index saves no time per query on average, so its build is never '
                         'repaid')
                cost += '.</p>'
            else:
                cost += (todo('the TIVF build time (pass --build-costs FILE or --build-seconds S to compute the '
                              'number of queries that repay it)') + '</p>')
            if bc:
                cost += bc['table']
            ib0 = sp[(self.qsets[0], 'index vs brute')]
            eb0 = sp[(self.qsets[0], 'embed vs brute')]
            out.append(f"""<section class="answer"><h3>2. Do the embeddings give enough of a speed win to justify
their construction?</h3>{''.join(q2)}{cost}
<p>In short, on the {escape(self.qsets[0])} set the exact index is {faster(ib0['paired_geomean'])} brute per query
(geometric mean) and the approximate embedding scan is {faster(eb0['ratio_of_means'])} brute, so the
embeddings pay for themselves {'through the index' if ib0['paired_geomean'] > 1.05 else 'in neither use'}
{'and not as a kNN method of their own' if eb0['ratio_of_means'] < 1.05 else 'and also as a kNN method of their own'}
on this hardware.</p>
{self.judgement('q2', 'is the index speedup enough to justify the build time and the storage, and how '
                                'does it compare with the M5 figure (~13 µs at 1M synthetic, k = 10, T = 144) given '
                                'k = 100 and unbounded distance here?')}
</section>""")
        if hasattr(self, 'LK'):
            f = self.LK.get('found')
            if f:
                tiles.append(('SHA-256 lookup, found (median)', ns(f['median']),
                              f'mean {ns(f["mean"])}, p99 {ns(f["p99"])}'))
            okf, okn = self.facts.get('lookup_found_ok'), self.facts.get('lookup_notfound_ok')
            state = ('FAIL' if okf is False or okn is False else 'check' if 'warn' in (okf, okn) else
                     'pass' if okf is True and okn is True else 'incomplete')
            tiles.append(('lookup assertions', state, 'all stored found; no random found'))
        tiles_html = '<div class="tiles">' + ''.join(
            f'<div class="tile"><div class="tl">{escape(a)}</div><div class="tv">{b}</div>'
            f'<div class="ts">{c}</div></div>' for a, b, c in tiles) + '</div>'
        return tiles_html + ''.join(out)

    # ------------------------------------------------------------ methods, caveats, appendix

    def methods(self):
        run, mf = self.run or {}, self.mf or {}
        mach = run.get('machine', {})
        commit = run.get('git_commit', '')
        repo = self.args.repo
        has_flags = None
        if commit:
            c = commit.replace('-dirty', '')
            rc, _ = git(repo, 'merge-base', '--is-ancestor', BUILD_COMMIT, c)
            has_flags = rc == 0
        flag_note = ('' if has_flags else
                     f'<p class="warn"><b>Note:</b> the kNN run records commit <code>{escape(commit)}</code>, '
                     f'which does not contain {BUILD_COMMIT} (the -O3 / -mpopcnt build); its brute and index '
                     f'timings predate that fix.</p>' if has_flags is False else '')
        wr = run.get('warmup', {})
        reads = ', '.join(f'{r["mib_per_s"]:,.0f}' for r in wr.get('file_reads', []))
        rows = [
            ['CPU', escape(mach.get('cpu') or mf.get('cpu_model', '–'))],
            ['VM', f'{mach.get("online_cpus", "–")} vCPUs, MemTotal {(mach.get("mem_total_kb") or mf.get("mem_total_kb") or 0) / 2**20:.1f} GiB'
                   f' ({fint(mach.get("mem_total_kb") or mf.get("mem_total_kb"))} kB), kernel {escape(str(mach.get("kernel", "–")))}'],
            ['Build', f'libhasher at commit <code>{escape(commit or "–")}</code> (kNN run), binary built '
                      f'{escape(str(run.get("binary_built", "–")))}; intended flags -O3 -mpopcnt (configure as of '
                      f'{BUILD_COMMIT})'],
            ['hset', f'{escape(str(run.get("hset", {}).get("path", "–")))} ({escape(str(run.get("hset", {}).get("name", "")))}), '
                     f'{run.get("hset", {}).get("size_bytes", 0) / 2**30:.2f} GiB, {fint(run.get("hset", {}).get("tlsh_rows"))} TLSH rows, '
                     f'{fint(run.get("hset", {}).get("null_rows"))} null'],
            ['kNN parameters', escape(json.dumps(run.get('params', {})))],
            ['Seeds', escape(json.dumps(run.get('seeds', {})))],
            ['kNN warm-up', f'file streamed {len(wr.get("file_reads", []))}× (MiB/s per pass: {reads}), mmap '
                            f'MAP_POPULATE {wr.get("mmap_populate")}, {wr.get("queries_per_set_method")} untimed '
                            f'queries per set × method; residency {fpct(mach.get("hset_resident_before_timing"))} / '
                            f'{fpct(mach.get("hset_resident_after_timing"))}; MemAvailable '
                            f'{fint((mach.get("mem_available_kb_before_timing") or 0) / 1024)} MiB'],
            ['kNN timing', f'steady_clock, timer overhead {run.get("timer_overhead_ns", {}).get("median", "–")} ns '
                           f'median (not subtracted); timing thread pinned to CPU {mach.get("pin_cpu", "–")}; analysis '
                           f'pass on {mach.get("analysis_threads", "–")} threads, untimed'],
            ['Lookup warm-up', f'{mf.get("warm_reads", "–")} file reads, every page touched, '
                               f'{fint(mf.get("warmup_queries"))} untimed lookups; pinned CPU {escape(str(mf.get("cpu_affinity", "–")))}; '
                               f'clocksource {escape(str(mf.get("clocksource", "–")))}' if mf else '–'],
            ['VM noise floor', 'every CPU loses 5–20 µs about 1,250–1,700 times a second (1000 Hz tick, other '
                               'interrupts and VM exits; measured per pass in the lookup section). Percentiles up to '
                               'p99 measure the code; p99.9 and max measure the platform.'],
            ['Dates', f'kNN {escape(str(run.get("date", "–")))}; lookup {escape(str(mf.get("date", "–")))}'],
        ] + [
            [f'kNN run, k = {x["params"]["k"]}, max distance {tlabel(x["params"]["max_distance"])}',
             f'{escape(str(x.get("date", "–")))}, commit <code>{escape(str(x.get("git_commit", "–"))[:12])}</code>; '
             f'methods {escape(", ".join(x["params"].get("methods", [])))}; same seeds as the main run: '
             f'{x.get("seeds", {}).get("member") == run.get("seeds", {}).get("member") and x.get("seeds", {}).get("random") == run.get("seeds", {}).get("random")}; '
             f'{len(x.get("warmup", {}).get("file_reads", []))} file read(s), '
             f'{x.get("warmup", {}).get("queries_per_set_method", "–")} warm-up queries per set × method; timing '
             f'thread on CPU {x.get("machine", {}).get("pin_cpu", "–")}; residency '
             f'{fpct(x.get("machine", {}).get("hset_resident_after_timing"))} after timing; analysis pass '
             f'{"skipped" if not x.get("analysis_seconds") else "run"}']
            for d, x in self.args.extra_runs
        ]
        return flag_note + table(['', ''], rows, num_from=99, cls='kv wrap') + self.corpus_html()

    def corpus_html(self):
        c = self.corpus
        if not c:
            return ''
        s = (f'<h3>Corpus</h3><p>{fint(c["zips"])} zip archives ({escape(c.get("name", ""))}) with '
             f'{fint(c["entries"])} entries, hashed into {fint(c["records"])} records')
        lost = c['entries'] - c['records']
        if lost:
            s += (f'; {fint(lost)} entries were lost to {escape(c.get("lost_cause", "damage"))} in '
                  f'{escape(c.get("lost_zip", "?"))}')
        s += (f'. {fint(c["tnull"])} samples have no TLSH digest (TNULL), leaving '
              f'{fint(c["records"] - c["tnull"])} TLSH rows, of which {fint(c["distinct_tlsh"])} are distinct '
              f'digests. ')
        s += ('No SHA-256 occurs twice. ' if c.get('duplicate_sha256') == 0 else
              f'{fint(c.get("duplicate_sha256"))} duplicate SHA-256 values. ')
        s += ' '.join(c.get('notes', [])) + '</p>'
        hrows = (self.run or {}).get('hset', {}).get('tlsh_rows')
        if hrows is not None:
            self.validation.append(('corpus: records − TNULL = TLSH rows in the hset',
                                    f'{fint(c["records"])} − {fint(c["tnull"])} = {fint(c["records"] - c["tnull"])}; '
                                    f'hset {fint(hrows)}', c['records'] - c['tnull'] == hrows))
        if self.mf:
            self.validation.append(('corpus: records = SHA-256 rows looked up',
                                    f'{fint(c["records"])} records; {fint(self.mf.get("sha256_count"))} SHA-256 rows',
                                    c['records'] == self.mf.get('sha256_count')))
        return s

    def caveats(self):
        syn = ('<li><b>This sample report is built from SYNTHETIC data</b> (generated digests and hsets); '
               'its numbers say nothing about real malware and are only a check of the pipeline.</li>'
               if self.args.synthetic else '')
        nn = (self.run or {}).get('hset', {}).get('null_rows') or 0
        if nn:
            syn += (f'<li><b>Null TLSH rows.</b> The set has {fint(nn)} null TLSH rows (samples without a TLSH '
                    f'digest, e.g. too small). The program\'s distance histogram, and so the AUC universe and the '
                    f'ns/row figures, include them.</li>')
        return f"""<ul>{syn}
<li><b>Random queries are far from the data.</b> Their L byte (log length) is uniform over 0–255, so most
lie far from every stored digest (median d<sub>k</sub> {self.median_dk('random')} here, against
{self.median_dk('member')} for member queries), well past the embedding's 144 cap: the embedding's
squared distance bounds TLSH distance only up to 144 (and the L coordinate is linear where TLSH charges 12
per unit beyond 1), so its ranking among far rows carries little information. Poor embed recall on random
queries is expected and says little about client queries that resemble the data; TLSH scores above ~100
carry little similarity information anyway.</li>
<li><b>Ties.</b> Exact duplicates and equal distances are common in real malware. Naive measures and RBO
count a tied substitute as a miss; the tie-aware measures do not. B's choice among tied rows is by row
index, an arbitrary order.</li>
<li><b>Truncated ranking.</b> The embedding ranking is recorded to depth {self.facts.get('deep_k', 1000)}; relevant
rows beyond it are unscored. The AUC bounds and the censored depth statistics handle this conservatively,
and the share of R inside the recorded depth is reported.</li>
<li><b>One machine, one VM.</b> Timings are single-threaded on a shared 16-vCPU VM (Westmere, no AVX), with
the hset in the page cache; other work on the VM (the scan, other agents) adds noise mostly to the tails.
The embedding scan reads 1,056 bytes per row and is memory-bound; brute TLSH reads 36.</li>
<li><b>k = 100, unbounded distance.</b> The index's pruning depends on the distance bound; a smaller k or a
max_distance (e.g. 144) would prune far more, so these index timings are not comparable with the M5 figure
(k = 10, T = 144){'; the runs with a distance bound in the tables show how much a bound prunes' if self.args.extra_runs else ''}.</li></ul>"""

    def median_dk(self, q):
        r = self.db.q(f"select median(d_k) as m from knn_queries where qset = '{q}'") if hasattr(self, 'L') else []
        return f'{r[0]["m"]:.0f}' if r and isnum(r[0]['m']) else '–'

    def appendix(self):
        run, mf, mn = self.run or {}, self.mf or {}, self.mn or {}
        cmds = []
        if run.get('argv'):
            cmds.append('# kNN eval (as recorded in run.json)\n' + ' '.join(run['argv']).replace(' --', ' \\\n    --'))
        for d, x in self.args.extra_runs:
            if x.get('argv'):
                cmds.append(f'# kNN eval, k = {x["params"]["k"]}, max distance {tlabel(x["params"]["max_distance"])} '
                            f'(run.json, {x.get("date", "?")})\n'
                            + ' '.join(x['argv']).replace(' --', ' \\\n    --'))
        if self.args.hset and self.args.knn:
            cmds.append(f'# header split (run by vs_report with --hset)\nLD_LIBRARY_PATH={self.args.libdir} '
                        f'python3 -I bench/vs_report/header_split.py --hset {self.args.hset} \\\n'
                        f'    --knn {self.args.knn} --out {os.path.join(self.args.out, "header_split.csv")}')
        cmds.append('# lookup eval (step 2)\nE=/work/bench/vs_lookup_eval; H=<vs.hset>; D=/work/vs-eval\n'
                    'taskset -c 3 $E export $H --out $D/vs_sha256.txt\n'
                    'taskset -c 3 $E found $H --list $D/vs_sha256.txt --csv $D/lookup/lookup_found.csv '
                    '--warm-reads 3 --warmup-queries all --catch-bench 100000\n'
                    'taskset -c 3 $E notfound $H --list $D/vs_sha256.txt --csv $D/lookup/lookup_notfound.csv '
                    '--warm-reads 3 --warmup-queries 100000')
        for m in (mf, mn):
            if m:
                cmds.append(f'#   {m.get("subcommand")} recorded: hset {m.get("hset_path")}, csv {m.get("csv")}, '
                            f'seed {m.get("seed", "-")}, date {m.get("date")}')
        argv = ['python3', '-I', sys.argv[0]]
        for a in sys.argv[1:]:
            if a.startswith('--'):
                argv.append(' \\\n    ' + a)
            else:
                argv.append(' ' + a)
        cmds.append('# this report\n' + argv[0] + ' ' + argv[1] + ' ' + argv[2] + ''.join(argv[3:]))
        cmds.append(f'# explore the tables\nduckdb -readonly {self.args.db}\n'
                    "  -- e.g. select qset, metric, mean, median from ir_summary order by metric;")
        rc, head = git(self.args.repo, 'rev-parse', '--short', 'HEAD')
        return (f'<pre>{escape(chr(10).join(cmds))}</pre><p>Report code: <code>bench/vs_report/</code> at '
                f'<code>{escape(head or "?")}</code>; SQL in <code>bench/vs_report/sql/</code>. All tables named in '
                f'the SQL are in the DuckDB file above.</p>')

    # ------------------------------------------------------------ page

    def html(self):
        answers = self.answers()
        methods = self.methods()      # adds the corpus checks
        note_tail = ('; passages marked <span class="todo">[TO FINISH]</span> need a human judgement.'
                     if 'class="todo"' in answers else '; the judgements are the author\'s and labelled as such.')
        val_rows = [[escape(a), b, badge(ok)] for a, b, ok in self.validation]
        n_fail = sum(1 for *_, ok in self.validation if ok is False)
        n_warn = sum(1 for *_, ok in self.validation if ok == 'warn')
        val = (f'<p>{len(self.validation) - n_fail - n_warn} of {len(self.validation)} checks pass'
               f'{f", {n_fail} FAIL" if n_fail else ""}{f", {n_warn} to check" if n_warn else ""}.</p>' +
               table(['check', 'detail', 'result'], val_rows, num_from=99, cls='wrap'))
        nav = [('answers', 'Answers'), ('validation', 'Validation')] + [(s, t) for s, t, _ in self.sections] + \
              [('methods', 'Methods'), ('caveats', 'Caveats'), ('repro', 'Reproducibility')]
        navh = ''.join(f'<a href="#{a}">{escape(b)}</a>' for a, b in nav)
        secs = ''.join(f'<section id="{s}"><h2>{escape(t)}</h2>{b}</section>' for s, t, b in self.sections)
        banner = ('<p class="banner">SYNTHETIC DATA: a pipeline check, not results. Regenerate from the real '
                  'VirusShare outputs.</p>' if self.args.synthetic else '')
        src = []
        if self.args.knn:
            src.append(f'kNN: <code>{escape(os.path.abspath(self.args.knn))}</code>')
        if self.args.found:
            src.append(f'lookup found: <code>{escape(os.path.abspath(self.args.found))}</code>')
        if self.args.notfound:
            src.append(f'lookup notfound: <code>{escape(os.path.abspath(self.args.notfound))}</code>')
        gen = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        with open(os.path.join(HERE, 'report.css')) as f:
            css = f.read()
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(self.args.title)}</title><style>{css}</style></head>
<body><main>
<header><h1>{escape(self.args.title)}</h1>{banner}
<p class="sub">Generated {gen} by <code>bench/vs_report</code>. {' · '.join(src)}</p>
<nav>{navh}</nav></header>
<section id="answers"><h2>Answers</h2>
<p class="note">The prose below is generated from the computed numbers{note_tail}</p>{answers}</section>
<section id="validation"><h2>Validation</h2>{val}</section>
{secs}
<section id="methods"><h2>Methods</h2>{methods}
<p>Three kNN methods per query: <b>brute</b>, the TLSH distance to every row (exact, the ground truth);
<b>index</b>, the TIVF search, which uses the embedding only as a lower bound to prune lists and cells and
returns exactly brute's answer; <b>embed</b>, the CrowdStrike-style approximate kNN, squared Euclidean
distance from the query's embedding to every row's 264-float vector, top k by that distance. Query sets:
<b>member</b>, rows sampled without replacement from the set (the query is that row's digest, which is
itself in the answer); <b>random</b>, uniformly random valid digests standing in for client queries. Each
set × method is warmed with untimed queries drawn apart from the measured ones. The relevance data
(distance histograms and the embedding ranking to depth {self.facts.get('deep_k', 1000)}) come from an untimed
analysis pass over every row.</p></section>
<section id="caveats"><h2>Caveats</h2>{self.caveats()}</section>
<section id="repro"><h2>Reproducibility</h2>{self.appendix()}</section>
</main></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--knn', help='vs_knn_eval output directory (queries/timings/results/deep/hist.csv, run.json)')
    ap.add_argument('--found', help='vs_lookup_eval found CSV (its .meta.json beside it)')
    ap.add_argument('--notfound', help='vs_lookup_eval notfound CSV (its .meta.json beside it)')
    ap.add_argument('--out', default='/work/vs-eval/report', help='output directory (default %(default)s)')
    ap.add_argument('--db', help='DuckDB file (default OUT/vs.duckdb)')
    ap.add_argument('--title', default='VirusShare reality check: TLSH kNN and SHA-256 lookups')
    ap.add_argument('--synthetic', action='store_true', help='mark the report as built from synthetic data')
    ap.add_argument('--build-seconds', type=float,
                    help='extra build time of the TIVF index, for the break-even (default: from --build-costs)')
    ap.add_argument('--build-costs', help='JSON: mkhashset builds with and without TVEC / TIVF (see README)')
    ap.add_argument('--judgements', help='JSON {"q1": html, "q2": html}: the author\'s judgements')
    ap.add_argument('--corpus', help='JSON: corpus counts for the Methods section')
    ap.add_argument('--knn-extra', action='append', default=[], metavar='DIR',
                    help='another vs_knn_eval run over the same queries (other k / --max-distance, brute and '
                         'index, --no-analysis is fine); repeatable; its rows join the latency, speedup and '
                         'index-work tables')
    ap.add_argument('--knn-k10', help='same as --knn-extra (kept for older command lines)')
    ap.add_argument('--hset', help='the evaluated hset, for the header-split diagnostic (needs libhasher)')
    ap.add_argument('--libdir', help='directory of libhasher.so for --hset (default REPO/src/lib/.libs)')
    ap.add_argument('--threads', type=int, default=4, help='DuckDB threads (default %(default)s)')
    ap.add_argument('--memory', default='8GB', help='DuckDB memory_limit (default %(default)s)')
    ap.add_argument('--duckdb', default=shutil.which('duckdb') or 'duckdb', help='DuckDB CLI')
    ap.add_argument('--repo', default=os.path.normpath(os.path.join(HERE, '..', '..')), help='git repo for commit checks')
    ap.add_argument('--reuse-db', action='store_true', help='skip loading; report from an existing --db')
    args = ap.parse_args()
    if not (args.knn or args.found or args.notfound):
        ap.error('give at least one of --knn, --found, --notfound')
    os.makedirs(args.out, exist_ok=True)
    args.db = args.db or os.path.join(args.out, 'vs.duckdb')
    args.libdir = args.libdir or os.path.join(args.repo, 'src', 'lib', '.libs')

    run = None
    if args.knn:
        with open(os.path.join(args.knn, 'run.json')) as f:
            run = json.load(f)
    extra = args.knn_extra + ([args.knn_k10] if args.knn_k10 else [])
    if extra and not args.knn:
        ap.error('--knn-extra needs --knn')
    runs = []
    for d in extra:
        with open(os.path.join(d, 'run.json')) as f:
            runs.append((d, json.load(f)))
    # the main run's k first, by distance bound; then other k
    if run:
        runs.sort(key=lambda r: (r[1]['params']['k'] != run['params']['k'], -r[1]['params']['k'],
                                 r[1]['params']['max_distance']))
    args.extra_runs = runs

    def meta(csv):
        if not csv:
            return None
        p = csv + '.meta.json'
        if not os.path.exists(p):
            sys.exit(f'vs_report: missing {p}')
        with open(p) as f:
            return json.load(f)
    mf, mn = meta(args.found), meta(args.notfound)

    db = DuckDB(args.duckdb, args.db, args.threads, args.memory)
    if not args.reuse_db:
        if os.path.exists(args.db):
            os.remove(args.db)
        build_db(db, args, run)
    rep = Report(db, args, run, mf, mn)
    if args.knn:
        rep.knn()
    if args.extra_runs:
        rep.knn_extra_checks()
    if args.found or args.notfound:
        rep.lookup()
    out = os.path.join(args.out, 'index.html')
    with open(out, 'w') as f:
        f.write(rep.html())
    n_fail = sum(1 for *_, ok in rep.validation if ok is False)
    n_warn = sum(1 for *_, ok in rep.validation if ok == 'warn')
    print(f'vs_report: wrote {out} ({os.path.getsize(out) / 1024:,.0f} KiB) and {args.db}; '
          f'{len(rep.validation) - n_fail - n_warn} of {len(rep.validation)} checks pass, {n_fail} fail, '
          f'{n_warn} to check')
    for item, detail, ok in rep.validation:
        if ok is False or ok == 'warn':
            print(f'  {"FAIL" if ok is False else "check"}: {item}: {re.sub("<[^>]+>", "", detail)}')
    return 1 if n_fail else 0


if __name__ == '__main__':
    sys.exit(main())
