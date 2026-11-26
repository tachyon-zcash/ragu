"""Merge two standalone qa/bench campaigns (different ranks, so different proof
identities) into the runner's comparison-table format: before -> after per
mode, plus both campaigns' proof shapes side by side.

Usage: python3 compare_campaigns.py BEFORE_DIR AFTER_DIR BEFORE_LABEL AFTER_LABEL
"""
import json
import statistics
import sys
from pathlib import Path

OPERATIONS = [
    ("Finalize + bootstrap (once)", "finalize", None),
    ("Seed one leaf", "seed", "wallet"),
    ("Decompress one wallet proof", "decompress", "aggregator"),
    ("Verify uncompressed", "verify_uncompressed", None),
    ("Fuse two children", "fuse", None),
    ("Compress", "compress", None),
    ("Verify compressed", "verify_compressed", None),
]


def load(out):
    out = Path(out)
    manifest = json.loads((out / 'manifest.json').read_text())
    results = json.loads((out / 'results.json').read_text())
    cases = {(c['mode'], c['asm']): c for c in manifest['cases'] if c['role'] == 'candidate'}
    shapes = {}
    for path in sorted((out / 'raw').glob('measure-*.jsonl')):
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get('kind') == 'shape' and row['label'] in ('leaf_0', 'parent'):
                shapes.setdefault(row['profile'], row)
        if len(shapes) == 2:
            break
    resources = json.loads((out / 'resources.json').read_text())
    return manifest, results, cases, shapes, resources


def compare(before, after):
    return f"{before:.3f} → {after:.3f} s ({100 * (after / before - 1):+.0f}%, {before / after:.2f}×)"


def size(count):
    return f"{count / 1e6:.2f} MB" if count >= 1e6 else f"{count / 1e3:.2f} KB"


def table(header, rows):
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]
    fmt = lambda r: '  '.join(c.ljust(w) if i == 0 else c.rjust(w) for i, (c, w) in enumerate(zip(r, widths))).rstrip()
    return '\n'.join([fmt(header), '  '.join('-' * w for w in widths)] + [fmt(r) for r in rows])


def main():
    before_dir, after_dir, lb, la = sys.argv[1:5]
    mb, rb, cb, sb, resb = load(before_dir)
    ma, ra, ca, sa, resa = load(after_dir)
    modes = [m for m in ('single', 'multi') if (m, True) in cb and (m, True) in ca]
    def mode_label(m):
        return 'single' if m == 'single' else f"{cb[(m, True)]['workers']} workers"
    out = []
    for profile, title in (('wallet', f'Standard profile (wallet, {lb} → {la})'),
                           ('aggregator', f'Aggregator profile ({lb} → {la})')):
        rows = []
        for label, step, applies in OPERATIONS:
            if applies not in (None, profile):
                continue
            cells = []
            for m in modes:
                key = profile + '/' + step
                cells.append(compare(rb[cb[(m, True)]['id']][key]['median'],
                                     ra[ca[(m, True)]['id']][key]['median']))
            rows.append([label] + cells)
        out += ['### ' + title, '', table(['Operation'] + [mode_label(m) for m in modes], rows), '']
    fields = [
        ('Polynomial coefficient capacity', lambda s: f"{1 << s['rank']:,}"),
        ('Dense coefficient size per polynomial', lambda s: size((1 << s['rank']) * 32)),
        ('Polynomials per proof', lambda s: str(s['polynomials'])),
        ('IPA rounds per curve', lambda s: str(s['rank'])),
        ('Compressed points', lambda s: str(s['points'])),
        ('Compressed scalars', lambda s: str(s['scalars'])),
        ('Compressed wire size', lambda s: size(s['compressed_bytes'])),
        ('Uncompressed wire size', lambda s: size(s['ordinary_bytes'])),
    ]
    header = ['Field', f'Wallet {lb}', f'Wallet {la}', f'Aggregator {lb}', f'Aggregator {la}']
    rows = [[label, f(sb['wallet']), f(sa['wallet']), f(sb['aggregator']), f(sa['aggregator'])]
            for label, f in fields]
    out += ['### Proof shape', '', table(header, rows), '']
    def rss(resources, manifest, m):
        case = next(c for c in manifest['cases'] if c['mode'] == m and c['asm'] and c['role'] == 'candidate')
        vals = [r['peak_rss_bytes'] for r in resources
                if r['selected'] and r['run'].endswith(case['id']) and r['peak_rss_bytes'] is not None]
        return statistics.median(vals) if vals else None
    rows = []
    for m in modes:
        b, a = rss(resb, mb, m), rss(resa, ma, m)
        if b and a:
            rows.append([f'Whole-process peak RSS, {mode_label(m)}', size(b), size(a), f"{100 * (a / b - 1):+.0f}%"])
    if rows:
        out += ['### Memory', '', table(['Measure', lb, la, 'Change'], rows), '']
    print('\n'.join(out).rstrip())


if __name__ == '__main__':
    main()
