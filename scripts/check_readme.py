#!/usr/bin/env python3
"""Verify that README.md's rules match the shipped data.

The sibling projects learned this the hard way: a hand-typed number beside a
generated artifact drifts, and every individually-correct edit can still leave
the pair contradictory. This gate asserts the README's scoring table, tab
durations, band scale, floor, and quoted refusal copy against
data/game_data.json, and that no answer-key token leaks into the README.

Text-only, like hunt's check_identifiers.py: it cannot read a screenshot.
Exit nonzero on any failure.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAILURES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)


def main() -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    flat = " ".join(readme.split())
    meta = json.loads((ROOT / "data" / "game_data.json").read_text(encoding="utf-8"))["meta"]

    # --- scoring table -----------------------------------------------------
    want = {
        "Ban a threat-actor account": meta["scoring"]["ban_actor"],
        "Clear a benign account": meta["scoring"]["clear_benign"],
        "Monitor an actor": meta["scoring"]["monitor_actor"],
        "Monitor a benign account": meta["scoring"]["monitor_benign"],
        "Miss an actor (clear, or never decide)": meta["scoring"]["miss_actor"],
        "Ban a benign account": meta["scoring"]["ban_benign"],
    }
    for label, pts in want.items():
        rendered = f"+{pts}" if pts > 0 else f"−{abs(pts)}"  # minus sign, as typeset
        row = re.compile(r"\*{0,2}" + re.escape(label) + r"\*{0,2}\s*\|\s*\*{0,2}" + re.escape(rendered) + r"\*{0,2}\s*\|")
        if not row.search(readme):
            fail(f"scoring row mismatch: {label!r} should show {rendered}")

    # the prose ratio: one false ban vs correct clears
    r_actor = abs(meta["scoring"]["ban_benign"]) / meta["scoring"]["ban_actor"]
    r_clear = abs(meta["scoring"]["ban_benign"]) / meta["scoring"]["clear_benign"]
    if "two and a half caught actors" in flat and r_actor != 2.5:
        fail(f"prose says 'two and a half caught actors' but ratio = {r_actor}")
    if "five correct clears" in flat and r_clear != 5.0:
        fail(f"prose says 'five correct clears' but ratio = {r_clear}")

    # --- tab durations -----------------------------------------------------
    tabs = meta["tab_costs"]
    if tabs["content"] != 0 or "| Content | nothing |" not in readme:
        fail("Content tab row should say 'nothing' and data cost 0")
    for name, key in [("Account file", "account"), ("Behavior", "behavior"),
                      ("Network", "network"), ("Pipeline read", "pipeline")]:
        if f"| {name} | {tabs[key]}h |" not in readme:
            fail(f"tab row mismatch: {name} should show {tabs[key]}h")

    # --- bands and floor ---------------------------------------------------
    bands = meta["bands"]
    floor = meta["policy"]["floor_band"]
    triple = (f"likely = {bands['likely']:.2f}, very likely = {bands['very likely']:.2f}, "
              f"almost certain = {bands['almost certain']:.2f}")
    if triple not in flat:
        fail(f"band scale line should read: ({triple})")
    if f"policy floor of *{floor}*" not in flat:
        fail(f"floor band should be stated as {floor!r}")
    if f"{bands[floor]:.2f}" not in flat:
        fail(f"floor probability {bands[floor]:.2f} missing")

    # --- quoted refusal copy (blockquote reflows; compare word streams) ----
    quoted = " ".join(
        line.strip().lstrip("> ").strip() for line in readme.splitlines() if line.strip().startswith(">")
    )
    content_only = meta["policy"]["refusals"]["content_only"]
    if " ".join(content_only.split()) not in " ".join(quoted.split()):
        fail("content-only refusal blockquote does not match the emitted copy verbatim")
    overlap = "an overlap is an observation, not a link"
    if overlap not in meta["policy"]["refusals"]["infra_only_case"] or overlap not in flat:
        fail("case-link refusal fragment missing or drifted")

    # --- answer-key leak guard --------------------------------------------
    for tok in ("acct_LF", "acct_CD", "acct_RA", "acct_SK", "acct_NEG", "acct_BG",
                "lure_factory", "capability_dev", "recon_automation", "stolen_key",
                "zero actors", "no actors"):
        if tok in readme:
            fail(f"answer-key/spoiler token in README: {tok!r}")


    # --- figures: every file used, every reference resolvable ------------
    refs = set(re.findall(r"\(docs/figures/([^)]+)\)", readme))
    figdir = ROOT / "docs" / "figures"
    on_disk = {f.name for f in figdir.iterdir()} if figdir.exists() else set()
    for missing in sorted(refs - on_disk):
        fail(f"README references a figure that does not exist: {missing}")
    for orphan in sorted(on_disk - refs):
        fail(f"figure on disk that no section uses: {orphan}")
    for m in re.finditer(r"!\[([^\]]*)\]\(docs/figures/", readme):
        if len(m.group(1)) < 25:
            fail(f"figure alt text too thin to stand in for the image: {m.group(1)!r}")

    # --- cross-links -------------------------------------------------------
    for url in ("github.com/abognar-git/model-abuse-hunt",
                "github.com/abognar-git/alert-triage-copilot",
                "github.com/abognar-git/assay"):
        if url not in readme:
            fail(f"missing sibling link: {url}")

    if FAILURES:
        print(f"check_readme: {len(FAILURES)} FAILURE(S)")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("check_readme: OK (scoring, tabs, bands, refusal copy, leak guard, links)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
