"""Render README.md to a self-contained HTML page.

GitHub will render the README itself; this exists so the document can be
proof-read as it will look, without pushing anything. Ported from the `assay`
sibling's script, minus the figure inlining this repo has no need for yet.

Usage:  python3 scripts/make_preview.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "README.preview.html"

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a2230;--muted:#5b6675;--line:#dde2e9;
      --chip:#eef1f5;--accent:#2563eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:16px/1.62 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.page{max-width:920px;margin:24px auto 48px;padding:44px 30px 110px;
  background:var(--card);border-radius:14px;
  box-shadow:0 1px 3px rgba(26,34,48,.07)}
h1{font-size:32px;letter-spacing:-.02em;margin:0 0 6px;font-weight:680}
h2{font-size:22px;margin:46px 0 12px;padding-top:24px;
  border-top:1px solid var(--line);letter-spacing:-.01em;font-weight:650}
h3{font-size:17px;margin:28px 0 8px;font-weight:650}
p{margin:0 0 15px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{background:var(--chip);padding:.15em .4em;border-radius:5px;
  font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:var(--chip);padding:15px 18px;border-radius:9px;
  overflow-x:auto;border:1px solid var(--line)}
pre code{background:none;padding:0;font-size:12.5px;line-height:1.55}
table{border-collapse:collapse;width:100%;margin:8px 0 22px;font-size:14px;
  font-variant-numeric:tabular-nums;display:block;overflow-x:auto}
@media(min-width:700px){table{display:table}}
th{text-align:left;background:var(--chip);font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;color:var(--muted);padding:9px 11px;
  border:1px solid var(--line)}
td{padding:9px 11px;border:1px solid var(--line)}
blockquote{margin:22px 0;padding:16px 20px;background:var(--chip);
  border:1px solid var(--line);border-left:3px solid var(--accent);
  border-radius:10px}
blockquote p:last-child{margin-bottom:0}
hr{border:0;height:0;margin:0}
ul{margin:0 0 15px;padding-left:22px}
li{margin-bottom:6px}
strong{font-weight:650}
sub{display:block;color:var(--muted);font-size:13.5px;line-height:1.55;
  margin:0 0 15px}
"""


def main() -> int:
    try:
        import markdown
    except ImportError:
        print("needs `pip install markdown`")
        return 1

    src = (ROOT / "README.md").read_text(encoding="utf-8")
    body = markdown.markdown(src, extensions=["tables", "fenced_code", "attr_list"])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>trigger-discipline — README</title><style>{CSS}</style></head>"
        f'<body><div class="page">{body}</div></body></html>',
        encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
