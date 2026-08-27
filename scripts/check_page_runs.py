#!/usr/bin/env python3
"""Load the built page and play it. The gate nothing else was doing.

Both shipped gates read source. `build_page.py --check` proves index.html
matches parts/, and `check_readme.py` proves the prose and the data agree.
Neither ever loads the artifact, so a one-line change that makes the game
throw on every render passes CI green and ships. That happened in a QA pass
against this repo: a rendering-fatal edit went through both gates.

This runs the file the way a player gets it - from file://, no server, no
network - drives every shift to a report, and fails on any uncaught
exception, any console error, or a shift that does not reach its report.

    python3 scripts/check_page_runs.py            # every shift
    python3 scripts/check_page_runs.py --shift s7 # one of them

Chrome is required. On a machine without it the gate SKIPS rather than
passes silently, and says so on stderr: a gate that quietly does nothing is
worse than no gate, because the green tick then means nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "index.html"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
]

# Everything the harness reports comes back inside this one element, so a
# crash that stops the script mid-way is visible as a MISSING report rather
# than as a pass.
HARNESS = """
<script>
(function () {
  var errors = [];
  window.addEventListener('error', function (e) {
    errors.push('uncaught: ' + (e.message || e.type));
  });
  window.addEventListener('unhandledrejection', function (e) {
    errors.push('unhandled rejection: ' + e.reason);
  });
  ['error', 'warn'].forEach(function (level) {
    var orig = console[level];
    console[level] = function () {
      errors.push('console.' + level + ': ' +
        [].slice.call(arguments).map(String).join(' '));
      return orig.apply(console, arguments);
    };
  });
  window.addEventListener('load', function () {
    var report = { shifts: [], errors: errors };
    try {
      var ids = __SHIFTS__;
      function tick() {
        var c = document.getElementById('btn-continue');
        if (c && !c.hidden && c.offsetParent !== null) { c.click(); }
      }
      ids.forEach(function (id) {
        var row = { id: id };

        /* Coverage pass. The play-through below only ever waits and clears,
           so until this ran not one evidence panel was rendered by the
           gate: every tabContent/tabAccount/tabBehavior/tabNetwork/
           tabPipeline path, and everything they call, was shipping
           unexercised. Done on its own load so the hours it spends do not
           move the numbers the play-through reports. */
        Game.loadShift(id);
        document.getElementById('btn-start').click();
        for (var pw = 0; pw < 40; pw++) {
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'w', bubbles: true}));
          tick();
        }
        var seats = document.querySelectorAll('#queue-list li button');
        var panels = 0;
        for (var q = 0; q < seats.length && q < 6; q++) {
          seats[q].click();
          for (var d = 1; d <= 5; d++) {
            document.dispatchEvent(new KeyboardEvent('keydown',
              {key: String(d), bubbles: true}));
            /* Count THIS panel's body, not the document's. The first version
               asked whether any '#tabpanel .ev-body > *' existed, which is
               true as soon as the free Content panel has rendered - so it
               counted five per account unconditionally and reported a
               constant 300 whatever the panels did. */
            var sec = document.getElementById('tabpanel')
              .querySelectorAll('.ev-panel')[d - 1];
            var body = sec && sec.querySelector('.ev-body');
            if (body && body.children.length) { panels += 1; }
          }
        }
        row.panels = panels;

        /* The enforcement path. Everything above reads; the play-through
           below only ever clears. Until this ran, BAN, the policy refusals,
           the confidence band, MONITOR, the policy-gap flag and the whole
           case board were never exercised by any gate - the half of the
           game the project is actually about. */
        var acts = { refused: 0, banned: 0, monitored: 0, flagged: 0, cased: 0 };
        /* Its own load, and only as much waiting as it takes for a queue to
           exist. The panel pass above spends forty hours, which on a 32-hour
           shift ends the day before a verdict can be reached - the first
           version of this sweep silently did nothing on nine shifts out of
           ten. */
        Game.loadShift(id);
        document.getElementById('btn-start').click();
        for (var aw = 0; aw < 24; aw++) {
          if (document.querySelectorAll('#queue-list li button').length >= 3) { break; }
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'w', bubbles: true}));
          tick();
        }
        var seats2 = document.querySelectorAll('#queue-list li button');
        for (var t = 0; t < seats2.length && t < 4; t++) {
          seats2[t].click();
          var before = document.getElementById('notice').textContent;
          /* a ban with nothing cited must be refused by the policy */
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'b', bubbles: true}));
          if (document.getElementById('notice').textContent !== before) { acts.refused += 1; }
          /* Buy a non-content panel first. On a live shift only Content is
             open, and a ban citing content alone is refused - correctly - so
             the sweep never reached the band picker on nine shifts. Cite
             from Behavior, which is what the policy actually asks for. */
          document.dispatchEvent(new KeyboardEvent('keydown', {key: '3', bubbles: true}));
          var body = document.getElementById('panelbody-behavior');
          var boxes = body ? [].slice.call(
            body.querySelectorAll('input[type=checkbox]'))
            .filter(function (c) { return c.offsetParent !== null; }) : [];
          for (var bi = 0; bi < boxes.length && bi < 3; bi++) { boxes[bi].click(); }
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'b', bubbles: true}));
          var picker = document.getElementById('band-picker');
          if (picker && !picker.hidden) {
            document.dispatchEvent(new KeyboardEvent('keydown', {key: '1', bubbles: true}));
            acts.banned += 1;
          }
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'g', bubbles: true}));
          if (document.querySelector('.btn-flag.on')) { acts.flagged += 1; }
          tick();
        }
        if (seats2.length > 4) {
          seats2[4].click();
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'm', bubbles: true}));
          if (document.querySelector('#queue-list .verdict-chip, #queue-list .v-monitor')
              || document.getElementById('hud-progress').textContent.indexOf('0/') !== 0) {
            acts.monitored += 1;
          }
          tick();
        }
        var caseBtn = document.getElementById('casebar');
        if (caseBtn && !caseBtn.hidden) {
          var seats3 = document.querySelectorAll('#queue-list li button');
          for (var ci = 0; ci < seats3.length && ci < 2; ci++) {
            seats3[ci].click();
            document.dispatchEvent(new KeyboardEvent('keydown', {key: 'a', bubbles: true}));
          }
          if (caseBtn.textContent.indexOf('Case 1') >= 0) { acts.cased += 1; }
        }
        row.acts = acts;

        Game.loadShift(id);
        document.getElementById('btn-start').click();
        row.opening = document.querySelectorAll('#queue-list li').length;
        for (var w = 0; w < 80; w++) {
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'w', bubbles: true}));
          tick();
        }
        row.queue = document.querySelectorAll('#queue-list li').length;
        for (var k = 0; k < 200; k++) {
          document.dispatchEvent(new KeyboardEvent('keydown', {key: 'c', bubbles: true}));
          tick();
        }
        var eb = document.getElementById('btn-endshift');
        if (eb && !eb.hidden) {
          eb.click();
          var cf = document.getElementById('btn-end-confirm');
          if (cf) { cf.click(); }
        }
        var rep = document.getElementById('screen-report');
        row.report = !!rep && !rep.hidden;
        var txt = (rep && rep.innerText) || '';
        row.nan = txt.indexOf('NaN') >= 0;
        row.undef = txt.indexOf('undefined') >= 0;
        row.empty = txt.trim().length < 40;
        report.shifts.push(row);
      });
    } catch (e) {
      report.fatal = String(e && e.stack || e);
    }
    var pre = document.createElement('pre');
    pre.id = 'smoke-report';
    pre.textContent = JSON.stringify(report);
    document.body.appendChild(pre);
  });
})();
</script>
"""


def chrome() -> str | None:
    for c in CHROME_CANDIDATES:
        if Path(c).is_file():
            return c
    return shutil.which("google-chrome") or shutil.which("chromium")


def shift_ids() -> list[str]:
    m = re.search(r'<script id="game-data" type="application/json">(.*?)</script>',
                  PAGE.read_text(encoding="utf-8"), re.DOTALL)
    if not m:
        raise SystemExit("check_page_runs: index.html has no game-data block")
    return [s["id"] for s in json.loads(m.group(1))["shifts"]]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--shift", action="append", help="only these shift ids")
    args = ap.parse_args()

    exe = chrome()
    if not exe:
        print("check_page_runs: SKIPPED - no Chrome on this machine. This gate "
              "proves the built page runs; without a browser it proves nothing "
              "and is not claiming to.", file=sys.stderr)
        return 0
    if not PAGE.is_file():
        print(f"check_page_runs: {PAGE} does not exist", file=sys.stderr)
        return 1

    ids = args.shift or shift_ids()
    html = PAGE.read_text(encoding="utf-8").replace(
        "</body>", HARNESS.replace("__SHIFTS__", json.dumps(ids)) + "</body>")

    with tempfile.TemporaryDirectory() as td:
        probe = Path(td) / "smoke.html"
        probe.write_text(html, encoding="utf-8")
        try:
            out = subprocess.run(
                [exe, "--headless=new", "--disable-gpu", "--no-sandbox",
                 "--virtual-time-budget=40000", "--dump-dom", f"file://{probe}"],
                capture_output=True, text=True, timeout=180).stdout
        except subprocess.TimeoutExpired:
            print("check_page_runs: the page did not finish in 180s", file=sys.stderr)
            return 1

    m = re.search(r'<pre id="smoke-report">(.*?)</pre>', out, re.DOTALL)
    if not m:
        print("check_page_runs: the harness never reported - the page did not "
              "finish loading, or threw before the report was written",
              file=sys.stderr)
        return 1

    import html as _html
    report = json.loads(_html.unescape(m.group(1)))
    failures: list[str] = []

    if report.get("fatal"):
        failures.append(f"threw while playing: {report['fatal'][:400]}")
    for e in report.get("errors", []):
        failures.append(e[:300])
    for row in report.get("shifts", []):
        sid = row["id"]
        if not row.get("report"):
            failures.append(f"{sid}: never reached its shift report")
        if row.get("empty"):
            failures.append(f"{sid}: the report rendered empty")
        if row.get("nan"):
            failures.append(f"{sid}: the report contains NaN")
        if row.get("undef"):
            failures.append(f"{sid}: the report contains 'undefined'")
        if row.get("opening", 0) == 0 and row.get("queue", 0) > 0:
            failures.append(f"{sid}: opens on an empty queue - nothing to look "
                            f"at until the player guesses at the clock")
        # Coverage, asserted rather than assumed: a sweep that quietly stops
        # rendering panels reports zero errors, which reads as a pass.
        if row.get("panels", 0) < 5:
            failures.append(f"{sid}: only {row.get('panels', 0)} evidence "
                            f"panels rendered during the coverage pass; the "
                            f"panel renderers are going untested")
        acts = row.get("acts") or {}
        if not acts.get("refused"):
            failures.append(f"{sid}: a ban citing nothing was not refused - "
                            f"the policy's first rule went unexercised")
        if not acts.get("banned"):
            failures.append(f"{sid}: no ban reached the confidence band "
                            f"picker; the enforcement path is untested")
        if not acts.get("flagged"):
            failures.append(f"{sid}: the policy-gap flag never engaged")

    if failures:
        print(f"check_page_runs: {len(failures)} FAILURE(S)\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    n = len(report.get("shifts", []))
    print(f"check_page_runs: OK ({n} shifts played to a report from file://, "
          f"no console errors, no uncaught exceptions; "
          f"{sum(r.get('panels', 0) for r in report.get('shifts', []))} evidence panels, "
          f"{sum((r.get('acts') or {}).get('banned', 0) for r in report.get('shifts', []))} bans, "
          f"{sum((r.get('acts') or {}).get('refused', 0) for r in report.get('shifts', []))} policy refusals)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
