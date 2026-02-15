#!/usr/bin/env python3
"""ErrSight CLI — Audit error paths for sensitive data leakage."""
import argparse
import json
import sys
from pathlib import Path
from typing import List

from errsight import Finding, scan_file

SEV_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def _fmt_text(findings: List[Finding]) -> str:
    if not findings:
        return '\u2705 No sensitive data leakage found in error paths.'
    lines = [f'\u26a0\ufe0f  Found {len(findings)} issue(s):\n']
    for f in findings:
        lines.append(f'  [{f.severity}] {f.file}:{f.line} ({f.rule})')
        lines.append(f'    {f.message}\n')
    return '\n'.join(lines)


def _fmt_json(findings: List[Finding]) -> str:
    return json.dumps([vars(f) for f in findings], indent=2)


def main(argv: List[str] = None) -> int:
    ap = argparse.ArgumentParser(prog='errsight',
                                 description='Error path security auditor')
    ap.add_argument('paths', nargs='+', help='Files or dirs to scan')
    ap.add_argument('--format', choices=['text', 'json'], default='text')
    ap.add_argument('--fail-on', choices=['HIGH', 'MEDIUM', 'LOW'],
                    default='HIGH', help='Exit 1 if severity >= threshold')
    args = ap.parse_args(argv)

    results: List[Finding] = []
    for target in args.paths:
        p = Path(target)
        files = list(p.rglob('*.py')) if p.is_dir() else [p]
        for f in files:
            try:
                results.extend(scan_file(str(f)))
            except SyntaxError as exc:
                print(f'Skipping {f}: {exc}', file=sys.stderr)

    print(_fmt_json(results) if args.format == 'json' else _fmt_text(results))

    threshold = SEV_ORDER.get(args.fail_on, 2)
    if any(SEV_ORDER.get(f.severity, 0) >= threshold for f in results):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
