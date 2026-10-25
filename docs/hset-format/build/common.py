"""Page template, stylesheet and small HTML helpers."""
from html import escape
import re

CSS = r"""
:root {
  --paper: #fffff8; --ink: #222; --ink2: #555; --gray: #888; --rule: #c8c4b8;
  --accent: #b5473a; --link: #3d6b8e; --hi: #f6d9c9;
  --serif: "Palatino Linotype", Palatino, "Book Antiqua", "URW Palladio L", "TeX Gyre Pagella", Georgia, serif;
  --mono: "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", "Liberation Mono", monospace;
}
html { background: var(--paper); }
body {
  margin: 0; color: var(--ink); background: var(--paper);
  font-family: var(--serif); font-size: 1.125rem; line-height: 1.2;
  -webkit-font-smoothing: antialiased; counter-reset: fig sidenote;
}
article { max-width: 62rem; margin: 0 auto; padding: 1.5rem 1.5rem 6rem 1.5rem; position: relative; }
nav.top { font-variant: small-caps; letter-spacing: .04em; font-size: 1rem; color: var(--ink2);
  border-bottom: 1px solid var(--rule); padding: .4rem 0 .5rem; margin-bottom: 2.5rem; display: flex; gap: 1.6rem; flex-wrap: wrap; }
nav.top a { color: var(--ink2); text-decoration: none; }
nav.top a.here { color: var(--ink); border-bottom: 2px solid var(--accent); }
nav.top .spacer { flex: 1; }
h1 { font-weight: normal; font-size: 2.6rem; line-height: 1.1; margin: 0 0 .4rem 0; letter-spacing: -.01em; max-width: 44rem; }
p.subtitle { font-style: italic; font-size: 1.35rem; color: var(--ink2); margin: 0 0 2.2rem 0; max-width: 40rem; line-height: 1.2; }
h2 { font-weight: normal; font-style: italic; font-size: 1.75rem; line-height: 1.15; margin: 3rem 0 .8rem 0; max-width: 40rem; }
h2 .num { font-style: normal; color: var(--gray); margin-right: .6rem; font-size: 1.3rem; }
h3 { font-weight: normal; font-style: italic; font-size: 1.3rem; margin: 2rem 0 .5rem 0; max-width: 40rem; }
p, ul, ol, dl, .text { max-width: 37rem; }
p { margin: 0 0 .85rem 0; }
li { margin-bottom: .25rem; }
a { color: var(--link); text-decoration: none; border-bottom: 1px solid #c9d5de; }
a:hover { border-bottom-color: var(--link); }
code, kbd, samp { font-family: var(--mono); font-size: .86em; }
pre { font-family: var(--mono); font-size: .85rem; line-height: 1.3; background: #f6f4ec; padding: .7rem .9rem; border-left: 2px solid var(--rule); max-width: 36rem; overflow-x: auto; }
em.term { font-style: italic; }
.sc { font-variant: small-caps; letter-spacing: .03em; }
.marginnote, .sidenote { float: right; clear: right; width: 20rem; margin-right: -23rem; margin-top: .1rem; margin-bottom: .6rem;
  font-size: .9rem; line-height: 1.2; color: #444; position: relative; }
.sidenote::before { content: counter(sidenote) " "; font-size: .75rem; position: relative; top: -.35em; color: var(--accent); }
.snref { counter-increment: sidenote; font-size: .72em; vertical-align: super; color: var(--accent); margin-left: .05em; }
.snref::after { content: counter(sidenote); }
figure { margin: 1.4rem 0 1.8rem 0; max-width: 62rem; counter-increment: fig; }
figure.col { max-width: 37rem; }
figure.wide { max-width: 62rem; }
figure svg { display: block; width: 100%; height: auto; overflow: visible; }
figure svg text { font-family: var(--serif); }
figure svg text.mono { font-family: var(--mono); }
figcaption { font-size: .92rem; line-height: 1.25; color: var(--ink2); margin-top: .5rem; max-width: 46rem; }
figcaption::before { content: "Figure " counter(fig) ". "; font-variant: small-caps; color: var(--ink); letter-spacing: .03em; }
figure.plain figcaption::before { content: ""; }
table { border-collapse: collapse; font-variant-numeric: tabular-nums; font-size: .95rem; margin: .8rem 0 1.4rem 0; }
table.text { max-width: 37rem; }
th, td { padding: .25rem .8rem .25rem 0; text-align: left; vertical-align: top; line-height: 1.2; }
th { font-weight: normal; font-style: italic; color: var(--ink2); border-bottom: 1px solid var(--ink2); }
td.n, th.n { text-align: right; }
tbody tr:last-child td { border-bottom: 1px solid var(--ink2); }
td code { font-size: .85em; }
.hdr { display: flex; justify-content: space-between; align-items: baseline; }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; max-width: 62rem; align-items: start; }
.note { font-size: .95rem; color: var(--ink2); border-left: 2px solid var(--rule); padding-left: .8rem; max-width: 36rem; }
.key { display: inline-block; width: .8em; height: .8em; vertical-align: -.1em; border: 1px solid #777; margin-right: .3em; }
.toc { max-width: 37rem; margin: 0 0 2rem 0; padding: 0; list-style: none; columns: 2; column-gap: 2rem; font-size: 1rem; }
.toc li { break-inside: avoid; margin: 0 0 .25rem 0; }
.toc li a { border: none; }
.toc li span.n { color: var(--gray); display: inline-block; width: 1.6rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: 1.4rem; max-width: 62rem; margin: 1.6rem 0 2.4rem 0; }
.card { border-top: 2px solid var(--ink); padding-top: .6rem; }
.card h3 { margin: 0 0 .4rem 0; font-size: 1.25rem; }
.card p { font-size: 1rem; }
.card a { border: none; }
.rule { border: none; border-top: 1px solid var(--rule); max-width: 62rem; margin: 3rem 0; }
footer { margin-top: 4rem; color: var(--gray); font-size: .9rem; border-top: 1px solid var(--rule); padding-top: .6rem; max-width: 37rem; }
@media (max-width: 86rem) {
  .sidenote, .marginnote { float: none; width: auto; margin: .3rem 0 .8rem 1.6rem; display: block; max-width: 33rem; font-size: .9rem; color: #444; }
}
@media (max-width: 40rem) {
  body { font-size: 1.05rem; } article { padding: 1rem; } h1 { font-size: 2rem; }
  .row2 { grid-template-columns: 1fr; } .toc { columns: 1; }
}
@media print { .sidenote { float: none; margin: .3rem 0 .6rem 1.4rem; width: auto; } nav.top { display: none; } }
"""

PAGES = [
    ('index.html', 'The file'),
    ('lookup.html', 'Exact lookup'),
    ('tlsh.html', 'TLSH, embedding and index'),
    ('merge.html', 'Set operations'),
]


def nav(active):
    links = []
    for href, title in PAGES:
        cls = ' class="here"' if href == active else ''
        links.append(f'<a href="{href}"{cls}>{title}</a>')
    return '<nav class="top">' + ''.join(links) + '<span class="spacer"></span><span>hset format</span></nav>'


def page(active, title, subtitle, body):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} · hset</title>
<style>{CSS}</style>
</head>
<body>
<article>
{nav(active)}
<h1>{title}</h1>
<p class="subtitle">{subtitle}</p>
{body}
<footer>hset format documentation, generated from the libhasher sources by <code>docs/hset-format/build/build.py</code>. Byte values shown are read from real files in <code>test/</code>; plotted data are computed by the generator and labelled as such.</footer>
</article>
</body>
</html>
"""


def fig(svg, caption, cls='', width=None):
    cls = 'wide' if cls == 'col' else cls
    c = f' class="{cls}"' if cls else ''
    if width is None and svg.w < 760:
        # small diagrams: scale them up a little, never to the full column width
        width = f'{int(svg.w * 1.35)}px'
    return f'<figure{c}>{svg.render(width=width)}<figcaption>{caption}</figcaption></figure>'


def fig_html(inner, caption, cls=''):
    c = f' class="{cls}"' if cls else ''
    return f'<figure{c}>{inner}<figcaption>{caption}</figcaption></figure>'


def sn(text):
    """A numbered sidenote. Place right after the word it annotates."""
    return f'<span class="snref"></span><span class="sidenote">{text}</span>'


def mn(text):
    return f'<span class="marginnote">{text}</span>'


def h2(num, text, anchor=None):
    a = anchor or re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
    return f'<h2 id="{a}"><span class="num">{num}</span>{text}</h2>'


def h3(text, anchor=None):
    a = anchor or re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
    return f'<h3 id="{a}">{text}</h3>'


def table(headers, rows, numeric=(), cls='', mono=()):
    out = [f'<table class="{cls}"><thead><tr>']
    for i, hname in enumerate(headers):
        out.append(f'<th class="{"n" if i in numeric else ""}">{hname}</th>')
    out.append('</tr></thead><tbody>')
    for r in rows:
        out.append('<tr>')
        for i, v in enumerate(r):
            c = ' class="n"' if i in numeric else ''
            v = f'<code>{v}</code>' if i in mono else v
            out.append(f'<td{c}>{v}</td>')
        out.append('</tr>')
    out.append('</tbody></table>')
    return ''.join(out)
