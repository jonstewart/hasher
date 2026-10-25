#!/usr/bin/env python3
"""Generate the hset format documentation (static HTML with inline SVG)."""
import os, sys, importlib
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

PAGES = [('page_format', 'index.html'), ('page_lookup', 'lookup.html'), ('page_tlsh', 'tlsh.html'), ('page_merge', 'merge.html')]

def main(only=None):
    for mod, out in PAGES:
        if only and mod != only and out != only:
            continue
        try:
            m = importlib.import_module(mod)
        except ModuleNotFoundError as e:
            if e.name == mod:
                print(f'skip {out}: {mod} not written yet')
                continue
            raise
        html = m.build()
        with open(os.path.join(OUT, out), 'w') as f:
            f.write(html)
        print(f'wrote {out}: {len(html):,} bytes')

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else None)
