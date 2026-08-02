#!/usr/bin/env python3
"""Assemble index.html from parts/ (SPEC-2 §0).

    python3 scripts/build_page.py            # rebuild index.html in place
    python3 scripts/build_page.py --check    # verify index.html matches parts/

Deterministic concatenation, idempotent. parts/shell.html carries five
placeholders — <!--PART:CSS-->, <!--PART:CORE-->, <!--PART:LIVE-->,
<!--PART:CASES-->, <!--PART:CAREER--> — each replaced by the matching file
under parts/. Mode parts that do not exist yet (live.js, cases.js,
career.js) are treated as empty. The <script id="game-data"> block is
preserved verbatim from the existing output file when present, so
scripts/build_data.py --inject keeps working unchanged on the built file;
when the output file does not exist (or has no block), the shell's
placeholder sample is used.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PARTS_DIR = REPO_ROOT / "parts"

# marker -> (part filename, required)
PARTS = [
    ("<!--PART:CSS-->", "page.css", True),
    ("<!--PART:CORE-->", "core.js", True),
    ("<!--PART:LIVE-->", "live.js", False),
    ("<!--PART:CASES-->", "cases.js", False),
    ("<!--PART:CAREER-->", "career.js", False),
]

# Same pattern build_data.py uses for --inject; keep the two in lockstep.
DATA_BLOCK_RE = re.compile(
    r'(<script id="game-data" type="application/json">)(.*?)(</script>)',
    re.DOTALL)


def read_part(name: str, required: bool) -> str:
    path = PARTS_DIR / name
    if not path.is_file():
        if required:
            raise SystemExit(f"build_page: missing required part {path}")
        return ""  # §0: absent mode parts are empty
    return path.read_text()


def assemble(out_path: Path) -> str:
    shell_path = PARTS_DIR / "shell.html"
    if not shell_path.is_file():
        raise SystemExit(f"build_page: missing {shell_path}")
    html = shell_path.read_text()

    for marker, fname, required in PARTS:
        n = html.count(marker)
        if n != 1:
            raise SystemExit(
                f"build_page: marker {marker} appears {n} times in "
                f"parts/shell.html; expected exactly once")
        content = read_part(fname, required).rstrip("\n")
        html = html.replace(marker, content)

    if not DATA_BLOCK_RE.search(html):
        raise SystemExit(
            'build_page: parts/shell.html has no <script id="game-data" '
            'type="application/json"> block')

    # Preserve the data block already committed in the output file, if any —
    # build_data.py --inject writes there, and a rebuild must not undo it.
    if out_path.is_file():
        m_out = DATA_BLOCK_RE.search(out_path.read_text())
        if m_out:
            block = m_out.group(2)
            html = DATA_BLOCK_RE.sub(
                lambda m: m.group(1) + block + m.group(3), html, count=1)

    payload = DATA_BLOCK_RE.search(html).group(2)
    try:
        json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"build_page: game-data block is not valid JSON: {exc}")

    return html


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(REPO_ROOT / "index.html"),
                    help="output file (default: index.html at the repo root)")
    ap.add_argument("--check", action="store_true",
                    help="verify the output file matches parts/; write nothing")
    args = ap.parse_args(argv)

    out_path = Path(args.out).expanduser().resolve()
    built = assemble(out_path)

    if args.check:
        if not out_path.is_file():
            print(f"--check: {out_path} does not exist; run build_page.py first",
                  file=sys.stderr)
            return 1
        current = out_path.read_text()
        if current != built:
            cur_lines = current.splitlines()
            new_lines = built.splitlines()
            first = next(
                (i for i, (a, b) in enumerate(zip(cur_lines, new_lines), 1)
                 if a != b),
                min(len(cur_lines), len(new_lines)) + 1)
            print(f"--check: {out_path} does not match parts/ "
                  f"(first difference at line {first}; "
                  f"{len(cur_lines)} vs {len(new_lines)} lines)",
                  file=sys.stderr)
            return 1
        print(f"--check: {out_path} matches parts/")
        return 0

    if out_path.is_file() and out_path.read_text() == built:
        print(f"{out_path} already up to date")
        return 0
    out_path.write_text(built)
    print(f"wrote {out_path} ({len(built)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
