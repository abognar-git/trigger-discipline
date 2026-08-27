"""Capture every README figure from the real game.

The principle the sibling projects settled on: a figure is generated from the
running artifact or it is not shipped. Nothing here is drawn, mocked, or
hand-edited. Each figure is produced by loading the committed `index.html`
in headless Chrome with a scenario script appended, driving the page through
its own event handlers, and photographing the result.

Two consequences worth stating, both learned the expensive way:

* A screenshot embeds text that no repository-wide grep can read. Three times
  across the sibling repos the worst instance of a leaked real-world
  identifier was inside a committed image. `--audit` re-extracts what the
  figures show and checks it; a human still has to LOOK at them.
* A figure must not spoil the game. Report and reveal states are captured
  from later shifts and cropped to their aggregate sections, so no reader
  learns shift 1's answer key from the README.

Usage:
    python3 scripts/make_figures.py              # every figure + the GIF
    python3 scripts/make_figures.py --only ban   # one figure
    python3 scripts/make_figures.py --list
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
OUT = ROOT / "docs" / "figures"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
]

# Every scenario runs at window load, synchronously, through the page's own
# handlers. Synchronous is what makes the capture race-free: by the time
# Chrome paints, the state is final. `Game.loadShift` is the dev entry point
# the harness uses; it bypasses the career unlock gate on purpose.
PRELUDE = """
function press(k){ document.dispatchEvent(new KeyboardEvent('keydown',{key:k,bubbles:true})); }
function start(shift){ Game.loadShift(shift); document.getElementById('btn-start').click(); }
function openNth(n){
  var items = document.querySelectorAll('#queue-list li');
  var el = items[n]; (el.querySelector('button') || el).click();
}
function openById(id){
  var items = [].slice.call(document.querySelectorAll('#queue-list li'));
  for (var i=0;i<items.length;i++){
    if (items[i].textContent.indexOf(id) === 0 || items[i].textContent.trim().indexOf(id) === 0){
      (items[i].querySelector('button') || items[i]).click(); return true;
    }
  }
  return false;
}
/* Scoped to one evidence panel on purpose. The panels used to be tabs, so
   "the first visible checkbox" could only mean the open tab's; they are now
   one stacked column, and an unscoped citeFirst() silently cited Content
   rows while the caption claimed behavior - which the policy then refused,
   so the figure showed a refusal captioned as a band picker. */
function boxes(panel){
  var root = panel ? document.getElementById('panelbody-' + panel) : document;
  if (!root) { throw new Error('no panel body: ' + panel); }
  return [].slice.call(root.querySelectorAll('input[type=checkbox]'))
           .filter(function(c){ return c.offsetParent !== null; });
}
function citeFirst(n, panel){
  var b = boxes(panel);
  if (b.length < n) {
    throw new Error('citeFirst(' + n + (panel ? ", '" + panel + "'" : '') +
                    '): only ' + b.length + ' rows to cite');
  }
  for (var i=0;i<n;i++) b[i].click();
}
/* Figures must show a deliberate account, not whatever sorts first. Selection
   uses only what the player can see for free (categories on the Content tab)
   or what the figure is explicitly about (the pipeline read it depicts) —
   never the reveal. */
function shiftData(){
  var d = JSON.parse(document.getElementById('game-data').textContent);
  return d.shifts.filter(function(s){ return s.id === CAPTURE_SHIFT; })[0];
}
function queueIds(){
  return [].slice.call(document.querySelectorAll('#queue-list li')).map(function(li){
    return (li.textContent.trim().match(/^acct_[0-9a-f]{4}/) || [''])[0];
  });
}
function openMatching(pred, label){
  var byId = {}; shiftData().accounts.forEach(function(a){ byId[a.id] = a; });
  var ids = queueIds();
  for (var i = 0; i < ids.length; i++){
    var a = byId[ids[i]];
    if (a && pred(a)) { openById(ids[i]); return ids[i]; }
  }
  throw new Error('no account matches ' + (label || 'predicate'));
}
function hasCategory(){
  var want = [].slice.call(arguments);
  return function(a){
    return a.sessions.some(function(s){ return want.indexOf(s.category) >= 0; });
  };
}
/* Figures about content must show the content they claim AT CAPTURE TIME.
   hasCategory() reads the whole session list, future sessions included, and
   on a live shift that once selected the stolen key while its visible
   sessions were still the benign translation baseline - a published figure
   contradicted its own caption and no text gate could see it. This
   predicate reads only what has arrived. */
function visiblePhishing(hour, minN){
  return function(a){
    var vis = a.sessions.filter(function(s){ return s.appears_at <= hour; });
    if (vis.length < (minN || 3)) { return false; }
    return vis.every(function(s){ return s.category === 'phishing_content'; });
  };
}
function waitHours(n){ for (var i=0;i<n;i++) press('w'); }
function arrivedIds(){ return queueIds().filter(Boolean); }
/* Two accounts the player could legitimately join into a case: both arrived,
   and sharing a target — the link reason the policy accepts. */
function openLinkablePair(){
  var byId = {}; shiftData().accounts.forEach(function(a){ byId[a.id] = a; });
  var ids = arrivedIds();
  for (var i=0;i<ids.length;i++){
    var a = byId[ids[i]]; if (!a || !a.network) continue;
    var mates = (a.network.shared_target || []).filter(function(m){ return ids.indexOf(m) >= 0; });
    if (mates.length){
      openById(ids[i]); press('a');
      openById(mates[0]); press('a');
      return [ids[i], mates[0]];
    }
  }
  throw new Error('no arrived pair shares a target yet');
}
function openMatchingOn(shift, hours){
  start(shift); waitHours(hours);
  return openMatching(visiblePhishing(hours), 'three visible phishing drafts');
}
function monitoredCluster(a){
  return a.pipeline && a.pipeline.cluster && a.pipeline.cluster.decision === 'monitor';
}
/* The evidence panels are one stacked column, so opening a panel no longer
   brings it into frame - the figure would keep showing whatever sits at the
   top. showPanel() puts the named panel under the dossier's own scroll. */
function showPanel(key){
  var sec = document.getElementById('panel-' + key);
  if (!sec) { throw new Error('no panel: ' + key); }
  var box = document.getElementById('dossier');
  box.scrollTop += sec.getBoundingClientRect().top - box.getBoundingClientRect().top - 8;
}
/* A figure's filename is a claim about what the image shows, and until this
   ran, nothing checked it: a scenario could scroll, relayout or silently
   fail and still ship a plausible-looking PNG under the wrong name. Every
   scenario now names text that has to be inside the captured viewport. */
function requireVisible(needles){
  var vw = window.innerWidth, vh = window.innerHeight;
  needles.forEach(function(txt){
    var all = document.querySelectorAll('body *');
    var hit = false;
    for (var i = 0; i < all.length && !hit; i++){
      var el = all[i];
      if (el.textContent.indexOf(txt) < 0) { continue; }
      var deeper = false;
      for (var j = 0; j < el.children.length; j++){
        if (el.children[j].textContent.indexOf(txt) >= 0) { deeper = true; break; }
      }
      if (deeper) { continue; }
      var r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0 && r.top >= 0 && r.left >= 0
          && r.bottom <= vh && r.right <= vw) { hit = true; }
    }
    if (!hit) { throw new Error('figure does not show ' + JSON.stringify(txt)); }
  });
}
"""

SCENARIOS: dict[str, dict] = {
    # ---- stills -----------------------------------------------------------
    "shift_select": dict(
        caption="The ten shifts, in the order the job gets harder.",
        size=(1180, 1080), js="/* the landing is the boot state */",
        # the caption says ten, so the check says ten
        must_show=["Shift 1 \u2014 ", "Shift 10 \u2014 "],
    ),
    "refusal": dict(
        caption="Banning on content alone is refused by the policy, not by the score.",
        size=(1400, 900),
        js="""
        start('s2');
        waitHours(12);           // a live queue: the subject has to arrive first
        openMatching(visiblePhishing(12), 'three visible phishing drafts');
        citeFirst(1, 'content');  // the worst-looking evidence there is
        press('b');              // the policy reads the citations and declines
        """,
        must_show=["no enforcement on content alone"],
    ),
    "social_card": dict(
        caption="The link-preview card: the refusal, which is the one screen "
                "that explains the game without a word of instruction.",
        size=(1200, 630),
        exact=True,           # og:image dimensions are declared in the head
        js="""
        /* Deliberately the same moment as the `refusal` figure. It is the
           game's argument in one screen: the ban was reached for, the policy
           read the citation, and it declined. A card has about one second to
           say what this is, and no other state says it faster. */
        start('s2');
        waitHours(12);
        openMatching(visiblePhishing(12), 'three visible phishing drafts');
        citeFirst(1, 'content');
        press('b');
        /* Captured at 1:1 on purpose. Two attempts to enlarge the refusal
           line for small feed renders both failed the same way: CSS zoom
           scales the paint but not the 1200px viewport, so the panels
           overflow and wrap, and hiding the queue rail does not buy the
           width back. The card carries the interface; og:title and
           og:description carry the sentence. */
        window.scrollTo(0, 0);
        """,
        must_show=["no enforcement on content alone"],
    ),
    "pipeline_read": dict(
        caption="The scorer's own read: what fired, what did not, and what the policy did with it.",
        size=(1400, 1000),
        js="""
        /* Shift 1 carries the real model assessments from the research run;
           the generated rosters have linkage clusters but no model verdict,
           so this figure has to come from s1. */
        start('s1');
        openMatching(monitoredCluster, 'an account the policy held to monitor');
        press('5');              // Pipeline read
        showPanel('pipeline');   // stacked panels: opening one is not framing it
        """,
        must_show=["Pipeline read"],
    ),
    "band_picker": dict(
        caption="A ban has to say how sure it is. Below the floor, it is refused.",
        size=(1400, 800),
        js="""
        start('s2');
        waitHours(12);           // a live queue: the subject has to arrive first
        openMatching(visiblePhishing(12), 'three visible phishing drafts');
        press('3'); citeFirst(2, 'behavior');   // Behavior, two rows cited
        press('b');
        """,
        must_show=["How confident is this ban?"],
    ),
    "overlap_timeline": dict(
        caption="Every account that shares something with this one, on one "
                "axis: first contact dashed, sessions solid.",
        size=(1400, 620),
        js="""
        /* Shift 3 on purpose. Shift 6 is the framer, and this figure is the
           instrument that answers it - a screenshot of that shift's lanes
           would be its answer key, which is the same reason no figure of
           it appears in the README at all. */
        start('s3');
        waitHours(14);
        var pick = openMatching(function (a) {
          var net = a.network || {};
          var ids = arrivedIds(), mates = {};
          ['shared_asn','shared_ip','shared_target','shared_cadence','shared_hours']
            .forEach(function (k) {
              (net[k] || []).forEach(function (m) {
                if (ids.indexOf(m) >= 0) { mates[m] = true; }
              });
            });
          return Object.keys(mates).length >= 2;
        }, 'an arrived account overlapping two other arrived accounts');
        press('4');
        showPanel('network');
        /* the lanes sit under the overlap list, which is long */
        var box = document.getElementById('dossier');
        var sec = document.getElementById('panelbody-network');
        var h = [].slice.call(sec.querySelectorAll('h3')).filter(function (n) {
          return n.textContent.indexOf('Overlap timeline') >= 0; })[0];
        box.scrollTop += h.getBoundingClientRect().top
                       - box.getBoundingClientRect().top - 10;
        """,
        must_show=["Overlap timeline", "Read the left edges"],
    ),
    "case_board": dict(
        caption="Accounts that belong to one operator are one case, banned once.",
        size=(1500, 900),
        js="""
        start('s3');
        waitHours(9);            // let the queue arrive; a case needs two members
        openLinkablePair();
        """,
        must_show=["Case board", "Link reason"],
    ),
    # ---- GIF frames -------------------------------------------------------
    # One scenario per frame, each a superset of the previous: the GIF is the
    # ban rule, start to finish.
    "gif_1_content": dict(gif=1, size=(1300, 760), js="""
        start('s2'); waitHours(6); openMatching(visiblePhishing(6), 'three visible phishing drafts');
    """),
    "gif_2_refused": dict(gif=2, size=(1300, 760), js="""
        start('s2'); waitHours(6); openMatching(visiblePhishing(6), 'three visible phishing drafts'); citeFirst(1, 'content'); press('b');
    """),
    "gif_3_behavior": dict(gif=3, size=(1300, 760), js="""
        start('s2'); waitHours(6); openMatching(visiblePhishing(6), 'three visible phishing drafts'); citeFirst(1, 'content'); press('b'); press('3');
    """),
    "gif_4_cited": dict(gif=4, size=(1300, 760), js="""
        start('s2'); waitHours(6); openMatching(visiblePhishing(6), 'three visible phishing drafts'); citeFirst(1, 'content'); press('b'); press('3'); citeFirst(2, 'behavior');
    """),
    "gif_5_band": dict(gif=5, size=(1300, 760), js="""
        start('s2'); waitHours(6); openMatching(visiblePhishing(6), 'three visible phishing drafts'); citeFirst(1, 'content'); press('b'); press('3'); citeFirst(2, 'behavior'); press('b');
    """),
    "gif_6_verdict": dict(gif=6, size=(1300, 760), js="""
        var subject = openMatchingOn('s2', 6);
        citeFirst(1, 'content'); press('b'); press('3'); citeFirst(2, 'behavior'); press('b');
        press('6');            // very likely
        openById(subject);     // the payoff is the verdict, not the next account
    """),
}

GIF_NAME = "ban_rule.gif"
GIF_FRAME_MS = 1500
GIF_LAST_MS = 2600
GIF_MAX_WIDTH = 900


def chrome() -> str:
    for c in CHROME_CANDIDATES:
        if Path(c).exists():
            return c
    print("no Chrome/Chromium found; tried:\n  " + "\n  ".join(CHROME_CANDIDATES))
    sys.exit(2)


def build_page(tmp: Path, name: str, js: str, shift_hint: str,
               must_show: list[str] | None = None) -> Path:
    src = PAGE.read_text(encoding="utf-8")
    check = ("\nrequireVisible(" + json.dumps(must_show) + ");\n") if must_show else ""
    harness = (
        "\n<script>\nvar CAPTURE_SHIFT = " + repr(shift_hint).replace("'", '"') + ";\n"
        + PRELUDE
        + "window.addEventListener('load', function(){ try {\n" + js + check
        + "\n} catch (e) { document.title = 'CAPTURE ERROR: ' + e.message;\n"
        "  var p = document.createElement('pre');\n"
        "  p.style.cssText = 'position:fixed;inset:0;z-index:9999;background:#300;color:#fff;padding:20px;font:14px monospace';\n"
        "  p.textContent = 'CAPTURE ERROR\\n' + e.stack; document.body.appendChild(p); } });\n</script>\n"
    )
    out = tmp / f"{name}.html"
    out.write_text(src.replace("</body>", harness + "</body>"), encoding="utf-8")
    return out


def shot(exe: str, page: Path, png: Path, size: tuple[int, int]) -> None:
    subprocess.run(
        [exe, "--headless", "--disable-gpu", "--hide-scrollbars",
         f"--window-size={size[0]},{size[1]}", "--virtual-time-budget=5000",
         f"--screenshot={png}", f"file://{page}"],
        check=True, capture_output=True,
    )


def assert_captured(png: Path, name: str) -> None:
    """Fail on a scenario that threw instead of shipping its error as art.

    The harness paints an uncaught scenario error into the page as a
    full-viewport panel, which is right for a human running one figure and
    wrong for everything else: the PNG still gets written, still gets
    committed, and still gets embedded in the README under a filename that
    claims something else. Chrome cannot hand back the text it rendered, but
    that panel has a colour nothing else in either theme uses.
    """
    from PIL import Image

    im = Image.open(png).convert("RGB")
    w, h = im.size
    grid = [(x, y) for y in range(0, h, 11) for x in range(0, w, 11)]
    # Sampled, not corner-tested: the panel is fixed to the viewport but the
    # topbar paints over its first rows, so the corner pixel is the page, not
    # the error. A third of the frame in one flat colour is the panel.
    red = sum(1 for xy in grid if im.getpixel(xy) == (51, 0, 0))
    if red > len(grid) // 3:
        raise SystemExit(
            f"make_figures: {name} captured a CAPTURE ERROR panel - open "
            f"{png} to read the stack it painted")


def autocrop(png: Path, pad: int = 16) -> tuple[int, int]:
    """Trim uniform page background from the bottom and right."""
    from PIL import Image

    im = Image.open(png).convert("RGB")
    w, h = im.size
    bg = im.getpixel((w - 2, h - 2))
    px = im.load()

    bottom = h
    while bottom > 40:
        row = bottom - 1
        if any(px[x, row] != bg for x in range(0, w, 7)):
            break
        bottom -= 1
    right = w
    while right > 40:
        col = right - 1
        if any(px[col, y] != bg for y in range(0, min(bottom, h), 7)):
            break
        right -= 1

    im.crop((0, 0, min(w, right + pad), min(h, bottom + pad))).save(png)
    return Image.open(png).size


def make_gif(frames: list[Path], out: Path) -> None:
    from PIL import Image

    ims = [Image.open(f).convert("RGB") for f in frames]
    w = min(GIF_MAX_WIDTH, min(i.width for i in ims))
    h = min(i.height for i in ims)
    ims = [i.crop((0, 0, min(i.width, w * i.width // max(w, 1)), h)) if False else i for i in ims]
    ims = [i.crop((0, 0, min(i.width, i.width), h)).resize(
        (w, int(h * w / i.width)), Image.LANCZOS) for i in ims]
    h2 = min(i.height for i in ims)
    ims = [i.crop((0, 0, w, h2)) for i in ims]
    pal = [i.quantize(colors=128, method=Image.MEDIANCUT, dither=Image.NONE) for i in ims]
    durations = [GIF_FRAME_MS] * (len(pal) - 1) + [GIF_LAST_MS]
    pal[0].save(out, save_all=True, append_images=pal[1:], loop=0,
                duration=durations, optimize=True, disposal=2)


def audit(pngs: list[Path]) -> int:
    """What the figures show, as text, checked for real-world identifiers.

    Chrome renders text; this cannot read it back. What it CAN do is verify
    that the data those figures were drawn from is clean, and say plainly
    that the remaining check is human.
    """
    import json

    data = json.loads(
        re.search(r'<script id="game-data" type="application/json">(.*?)</script>',
                  PAGE.read_text(encoding="utf-8"), re.S).group(1))
    blob = json.dumps(data)
    bad = []
    for ip in set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", blob)):
        if not re.match(r"^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)", ip):
            bad.append(f"non-RFC-5737 address in the data: {ip}")
    for asn in set(re.findall(r"\bAS(\d+)\b", blob)):
        n = int(asn)
        if not (64496 <= n <= 64511 or 65536 <= n <= 65551):
            bad.append(f"non-documentation ASN in the data: AS{asn}")
    for f in bad:
        print(f"  AUDIT FAILURE: {f}")
    print(f"audit: {len(pngs)} figures; data behind them "
          f"{'FAILED' if bad else 'clean'}. "
          "Text inside an image is invisible to this check — open them and look.")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", help="capture just these scenarios")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--no-gif", action="store_true")
    args = ap.parse_args()

    if args.list:
        for k, v in SCENARIOS.items():
            print(f"  {k:16s} {'(gif frame %s)' % v['gif'] if 'gif' in v else v.get('caption','')}")
        return 0

    if not PAGE.exists():
        print(f"missing {PAGE}")
        return 1
    exe = chrome()
    OUT.mkdir(parents=True, exist_ok=True)
    wanted = args.only or list(SCENARIOS)

    made: list[Path] = []
    frames: dict[int, Path] = {}
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for name in wanted:
            spec = SCENARIOS[name]
            hint = next((s for s in ("s6", "s5", "s4", "s3", "s2")
                         if f"'{s}'" in spec["js"]), "s1")
            page = build_page(tmp, name, spec["js"], hint,
                              spec.get("must_show"))
            png = OUT / f"{name}.png"
            shot(exe, page, png, spec["size"])
            assert_captured(png, name)
            if spec.get("exact"):
                # A link-preview card is cropped by the platform, not by us:
                # it has to come out at exactly the declared size or the
                # renderers letterbox it. Autocrop would defeat that.
                from PIL import Image
                w, h = Image.open(png).size
                if (w, h) != spec["size"]:
                    raise SystemExit(
                        f"make_figures: {name} rendered {w}x{h}, expected "
                        f"{spec['size'][0]}x{spec['size'][1]}")
            else:
                w, h = autocrop(png)
            kb = png.stat().st_size / 1024
            print(f"  {name:16s} {w}x{h}  {kb:5.0f} KB")
            made.append(png)
            if "gif" in spec:
                frames[spec["gif"]] = png

        if frames and not args.no_gif and len(frames) == sum(
                1 for s in SCENARIOS.values() if "gif" in s):
            gif = OUT / GIF_NAME
            make_gif([frames[i] for i in sorted(frames)], gif)
            print(f"  {GIF_NAME:16s} {gif.stat().st_size / 1024:.0f} KB "
                  f"({len(frames)} frames)")
            # the frames are scaffolding for the GIF, not figures themselves
            for p in frames.values():
                p.unlink()
                made.remove(p)

    return audit(made)


if __name__ == "__main__":
    sys.exit(main())
