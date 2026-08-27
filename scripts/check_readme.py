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


DATA_BLOCK_RE = re.compile(
    r'<script id="game-data" type="application/json">.*?</script>', re.DOTALL)


def main() -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    flat = " ".join(readme.split())
    payload = json.loads((ROOT / "data" / "game_data.json").read_text(encoding="utf-8"))
    meta = payload["meta"]

    # --- the shipped page carries the data this gate is checking ------------
    # Everything below reads data/game_data.json. The GAME reads the block
    # embedded in index.html, and build_data.py writes the two in separate
    # steps (`--out`, then `--inject`). Skip the second and this gate goes
    # green over a stale page: it happened while shift 7 was being added, and
    # the whole file passed while index.html still shipped six shifts. Same
    # class as the figures that kept the old identifiers after the fixtures
    # were corrected — a check that reads the source, not the artifact.
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    m = re.search(r'<script id="game-data" type="application/json">(.*?)</script>',
                  page, re.DOTALL)
    if not m:
        fail("index.html has no game-data block")
    else:
        try:
            embedded = json.loads(m.group(1))
        except json.JSONDecodeError as exc:
            embedded = None
            fail(f"index.html's game-data block is not valid JSON: {exc}")
        if embedded is not None and embedded != payload:
            n_page = len(embedded.get("shifts", []))
            n_file = len(payload.get("shifts", []))
            detail = (f"{n_page} shifts vs {n_file}" if n_page != n_file
                      else "same shift count, different content")
            fail("index.html's game-data block does not match "
                 f"data/game_data.json ({detail}) - run "
                 "`python3 scripts/build_data.py --inject index.html`")

    # --- shift count -------------------------------------------------------
    # The staleness class this gate exists for: the career grew a shift and
    # the README kept saying five. The count must be stated in words, and no
    # WRONG word-form may survive anywhere in the prose.
    n_shifts = len(payload["shifts"])
    words = {4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight",
             9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}
    right = words.get(n_shifts, str(n_shifts))
    low = flat.lower()
    if f"{right} shifts" not in low:
        fail(f"README never states the shift count in words ('{right} shifts')")
    for n, w in words.items():
        if n != n_shifts and f"{w} shifts" in low:
            fail(f"README says '{w} shifts' but the data ships {n_shifts}")

    # --- shift subtitles ---------------------------------------------------
    # Every subtitle opens by counting the queue, and two of them had drifted
    # off it: shift 7 said nine where the card said eight (the ninth is a
    # respawn, so it is not scheduled), shift 9 said ten and shipped nine.
    # The landing shows subtitle and count on the same card, so the two
    # contradicted each other in a published figure.
    n_words = {v: k for k, v in words.items()}
    n_words.update({"thirteen": 13, "fourteen": 14, "fifteen": 15,
                    "sixteen": 16, "twenty-three": 23, "twenty-six": 26,
                    "fifty-three": 53})
    for sh in payload["shifts"]:
        sub = (sh.get("subtitle") or "").strip()
        c = sh.get("counts") or {}
        n = c.get("scheduled", len(sh.get("accounts") or []))
        m = re.match(r"([A-Za-z-]+|\d+) accounts?\b", sub)
        if not m:
            continue          # a subtitle that does not open on a count
        tok = m.group(1)
        said = int(tok) if tok.isdigit() else n_words.get(tok.lower())
        if said is None:
            fail(f"{sh['id']} subtitle opens with an uncountable {tok!r}")
        elif said != n:
            fail(f"{sh['id']} subtitle says {tok} accounts; the shift "
                 f"schedules {n}")

    # --- README ordinals ---------------------------------------------------
    # The README points at shifts by position ("the sixth shift stages the
    # framing experiment"), and position is the one thing that moves when a
    # shift is inserted. It already had: the framer shift was described as
    # "the last day", true when the career ended at six.
    ordinals = ["first", "second", "third", "fourth", "fifth",
                "sixth", "seventh", "eighth", "ninth", "tenth"]
    shifts = payload["shifts"]
    titles = {(sh.get("title") or "").lower(): i for i, sh in enumerate(shifts)}
    def ordinal_before(phrase: str, want: str) -> bool:
        """The ordinal has to sit in the same clause as the claim.

        Asking whether the right ordinal appears anywhere in the README is
        not a check: 'the sixth shift' also names a row in the evidence
        table, so a wrong ordinal on the prose line stayed green.
        """
        i = low.find(phrase)
        if i < 0:
            return True
        return f"the {want} shift" in low[max(0, i - 70):i + len(phrase)]

    for title, phrase in (("the aimed link", "stages the research's framing"),):
        i = titles.get(title)
        if i is None:
            fail(f"README describes a shift titled {title!r}; the data has none")
            continue
        want = ordinals[i] if i < len(ordinals) else str(i + 1)
        if not ordinal_before(phrase, want):
            fail(f"README places {title!r} wrongly: it is shift {i + 1}, so "
                 f"the line about it must say 'the {want} shift'")
    # Appeals start at one shift and the README names which.
    first_appeal = next((i for i, sh in enumerate(shifts)
                         if (sh.get("flags") or {}).get("appeals")), None)
    if first_appeal is not None and not ordinal_before(
            "files an appeal", ordinals[first_appeal]):
        fail(f"README describes the appeals round but not as 'on the "
             f"{ordinals[first_appeal]} shift'; appeals first run on shift "
             f"{first_appeal + 1}")

    # --- palette -----------------------------------------------------------
    # The light palette is written twice - once for prefers-color-scheme and
    # once for the manual toggle - because a rule inside a media query and a
    # rule outside it cannot be merged. Two copies of thirteen colours is a
    # standing invitation to change one; this asserts they stay identical,
    # that neither theme is missing a token the other has, and that every
    # foreground still clears AA on both grounds. The last one is not
    # theoretical: --warn shipped at 4.49 in light and was found by
    # measuring, not by looking.
    css = (ROOT / "parts" / "page.css").read_text(encoding="utf-8")

    def tokens(block: str) -> dict[str, str]:
        return dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;}]+?)\s*[;}]", block))

    def block_after(pattern: str) -> str:
        m = re.search(pattern + r"\s*\{(.*?)\}", css, re.S | re.M)
        return m.group(1) if m else ""

    dark = tokens(block_after(r"^:root(?=\s*\{)"))
    light_media = tokens(block_after(r':root:not\(\[data-theme="dark"\]\)'))
    light_attr = tokens(block_after(r':root\[data-theme="light"\]'))

    if not dark or not light_media or not light_attr:
        fail("palette: could not read the three :root blocks in page.css")
    else:
        if light_media != light_attr:
            diff = sorted(set(light_media.items()) ^ set(light_attr.items()))
            fail("palette: the two light blocks disagree - "
                 + ", ".join(f"{k}={v}" for k, v in diff[:6]))
        colours = {k for k in dark if k not in ("--mono", "--sans")}
        if colours != set(light_media):
            only_dark = sorted(colours - set(light_media))
            only_light = sorted(set(light_media) - colours)
            fail("palette: themes define different tokens - "
                 f"dark only {only_dark}, light only {only_light}")

        def lum(hexv: str) -> float | None:
            m = re.fullmatch(r"#([0-9a-fA-F]{6})", hexv.strip())
            if not m:
                return None
            v = m.group(1)
            out = []
            for i in (0, 2, 4):
                c = int(v[i:i + 2], 16) / 255
                out.append(c / 12.92 if c <= 0.03928
                           else ((c + 0.055) / 1.055) ** 2.4)
            return 0.2126 * out[0] + 0.7152 * out[1] + 0.0722 * out[2]

        def ratio(a: str, b: str) -> float | None:
            la, lb = lum(a), lum(b)
            if la is None or lb is None:
                return None
            hi, lo = max(la, lb), min(la, lb)
            return (hi + 0.05) / (lo + 0.05)

        # --panel-2 is a real surface (verdict buttons, the nested wash, table
        # heads) and the *-dim tokens exist only to be painted under their own
        # foreground. Measuring only --bg and --panel left the three verdict
        # chips - the controls the game is operated with - unmeasured on the
        # ground they actually sit on.
        pairs = [(fg, bg)
                 for fg in ("--text", "--muted", "--accent", "--ban",
                            "--clear", "--warn")
                 for bg in ("--bg", "--panel", "--panel-2")]
        pairs += [("--ban", "--ban-dim"), ("--clear", "--clear-dim"),
                  ("--warn", "--warn-dim")]
        for name, pal in (("dark", dark), ("light", light_media)):
            for fg, bgname in pairs:
                r = ratio(pal.get(fg, ""), pal.get(bgname, ""))
                if r is None:
                    fail(f"palette: {name} {fg} or {bgname} is not a 6-digit hex")
                elif r < 4.5:
                    fail(f"palette: {name} {fg} on {bgname} is {r:.2f}, "
                         f"under the 4.5 AA floor")

    # --- the landing's one uncomputed claim ---------------------------------
    # The landing counts everything it states off the fixture except one
    # clause: that the accounts a content filter flags and the accounts that
    # are actually threat actors are NOT the same accounts. The page cannot
    # check that - it has no access to the labels and must not - so it is
    # checked here. It is also the sentence the design study got wrong: it
    # said nine of the flagged accounts were actors, and eight are.
    first = payload["shifts"][0]
    off_cats = {"malware_dev", "exploit_help", "phishing_content", "spam_content"}
    flagged, actors = set(), set()
    for acc in first.get("accounts") or []:
        cats = [x.get("category") for x in (acc.get("sessions") or [])]
        if any(c in off_cats for c in cats):
            flagged.add(acc["id"])
        rev = acc.get("reveal") or {}
        if rev.get("truth") == "malicious" or rev.get("actor"):
            actors.add(acc["id"])
    if not flagged or not actors:
        fail("landing: the first shift has no content-flagged accounts or no "
             "actors, so the landing's whole argument is vacuous")
    else:
        if not (actors - flagged):
            fail("landing: every threat actor in the first shift also fails "
                 "on content, so 'not the same accounts' is false - content "
                 "would be sufficient and the screen would be lying")
        if not (flagged - actors):
            fail("landing: every content-flagged account in the first shift "
                 "is a threat actor, so 'not the same accounts' is false")
        n_mal = (first.get("counts") or {}).get("malicious")
        if n_mal is not None and n_mal != len(actors):
            fail(f"landing: counts.malicious says {n_mal} but {len(actors)} "
                 f"accounts carry an actor label; the landing renders the "
                 f"former")

    # --- unrendered templates ----------------------------------------------
    # Four prompts shipped to the player reading "for the {org} bug-bounty
    # submission": a pool string used without .format(). Nothing caught it,
    # because a brace is valid text everywhere else in the payload.
    braces = []
    for sh in payload["shifts"]:
        for acc in sh.get("accounts") or []:
            for sess in acc.get("sessions") or []:
                for k, v in sess.items():
                    if isinstance(v, str) and re.search(r"\{[a-z_]+\}", v):
                        braces.append(f"{sh['id']}/{acc['id']}/{k}: {v[:60]}")
            for k in ("notes",):
                v = (acc.get("reveal") or {}).get(k) or ""
                if isinstance(v, str) and re.search(r"\{[a-z_]+\}", v):
                    braces.append(f"{sh['id']}/{acc['id']}/reveal.{k}")
    for b in braces[:6]:
        fail(f"an unrendered template placeholder ships to the player - {b}")

    # --- the GIF's own numbers ---------------------------------------------
    # The sub-caption states a frame count and a shift beside a career that
    # has a different number of shifts, which reads as a stale claim even
    # when it is true. Both halves are checked against the artifact and the
    # scenario list so it can be trusted at a glance.
    gif = ROOT / "docs" / "figures" / "ban_rule.gif"
    if gif.is_file():
        try:
            from PIL import Image
            im = Image.open(gif)
            frames = 0
            try:
                while True:
                    im.seek(frames)
                    frames += 1
            except EOFError:
                pass
        except Exception:
            frames = 0
        if frames:
            wordn = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
                     7: "seven", 8: "eight"}.get(frames, str(frames))
            if f"{wordn} frames" not in low:
                fail(f"README's GIF caption must say '{wordn} frames' - "
                     f"ban_rule.gif has {frames}")
        figs = (ROOT / "scripts" / "make_figures.py").read_text(encoding="utf-8")
        shifts_used = set(re.findall(r"start\('(s\d+)'\)",
                                     figs[figs.find('"gif_1_content"'):]))
        if len(shifts_used) == 1:
            n = int(shifts_used.pop()[1:])
            name = ordinals[n - 1] if n - 1 < len(ordinals) else str(n)
            if f"on the {name} shift" not in low:
                fail(f"README's GIF caption must say the frames come from "
                     f"the {name} shift")

    # --- the archetype split -----------------------------------------------
    # The README stated it twice and had it backwards both times: "five come
    # from hunt itself and four are modelled on published threat reports",
    # while reveal.provenance.extension says four and five. The data knows;
    # the prose has to agree with it.
    own, ext = set(), set()
    for sh in payload["shifts"]:
        for acc in sh.get("accounts") or []:
            rev = acc.get("reveal") or {}
            name, prov = rev.get("actor"), rev.get("provenance")
            if not name or not prov:
                continue
            (ext if prov.get("extension") else own).add(name)
    if own and ext:
        w = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
             7: "seven", 8: "eight", 9: "nine", 10: "ten"}
        n_own, n_ext = w.get(len(own), str(len(own))), w.get(len(ext), str(len(ext)))
        if f"{n_own} come from `hunt` itself and {n_ext} are modelled" not in readme:
            fail(f"README must say '{n_own} come from `hunt` itself and "
                 f"{n_ext} are modelled on published threat reports' - the "
                 f"provenance flags say {len(own)} and {len(ext)}")
        if f"that project's {n_own} archetypes plus {n_ext} taken" not in flat:
            fail(f"README must say \"that project's {n_own} archetypes plus "
                 f"{n_ext} taken from published threat reports\"")

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

    # --- the newer gates, same discipline: fragment in the emitted copy AND
    # the story stated in the README -----------------------------------------
    for key, frag in (("topic_only", "topic in disguise"),
                      ("style_link", "links every account here or none"),
                      ("below_strength_floor", "Presence is not strength."),
                      ("thin_rate", "Strength is not sample size.")):
        if frag not in meta["policy"]["refusals"][key]:
            fail(f"refusal fragment {frag!r} drifted out of the emitted {key} copy")
    for story in ("presence is not strength", "strength is not sample size",
                  "topic in disguise"):
        if story not in low:
            fail(f"README no longer tells the story: {story!r}")
    mc = meta["policy"]["corroboration_min_contribution"]
    mo = meta["policy"]["corroboration_min_observations"]
    if f"corroboration floor of {mc}" not in flat:
        fail(f"README should quote the imported corroboration floor {mc}")
    if f"at least {mo} observations" not in flat:
        fail(f"README should quote the imported observation minimum {mo}")
    t = meta["topic"]
    if f"{t['content_weight']} or {t['policy_share']}" not in flat:
        fail("README should state the two topic shares as the data ships them")
    jm = str(meta["judge"]["margin"]).replace("-", "−")
    if jm not in flat:
        fail(f"README should quote the judge's measured margin {jm}")

    # --- answer-key leak guard --------------------------------------------
    # Two things were wrong with this guard. It listed five archetype names
    # by hand and nine ship, so four new ones were never checked; and it read
    # README.md only, while the same tokens would ship inside index.html,
    # which is the file a player actually has. The names come from the data
    # now, and the page is scanned with its data block removed - `reveal`
    # legitimately carries the answer key, and a player reading it out of
    # devtools is a convention this game accepts, not a leak.
    actor_names = sorted({a["reveal"]["actor"] for sh in payload["shifts"]
                          for a in sh["accounts"] if a["reveal"].get("actor")})
    # Persona names are NOT spoilers and must not be listed here: the intro
    # screen names the innocent archetypes out loud - a pentester, a
    # journalist, a novelist, a CTF student - because knowing WHO the
    # innocents are and still not being able to pick them is the game.
    # The generator ids encode the answer - acct_LF01 is a lure_factory
    # burner - so their stems are spoilers. Strip the trailing counter and
    # keep only stems long enough to mean something: rsplit on "_" turns
    # acct_LF01 into a bare "acct", which matches every id on the page.
    id_prefixes = sorted({stem for stem in
                          (re.sub(r"\d+$", "", a["reveal"].get("original_id", ""))
                           for sh in payload["shifts"] for a in sh["accounts"])
                          if len(stem) > 6})
    # Two lists, because the two files leak differently. An archetype name
    # or a generator id stem is a spoiler wherever it appears. "no actors" is
    # a spoiler only in the README, where it would give away a shift's
    # contents; in the page it is a career-dashboard fallback that means the
    # PLAYER has not met one yet.
    spoilers_page = actor_names + id_prefixes
    spoilers_readme = spoilers_page + ["zero actors", "no actors"]

    page_prose = DATA_BLOCK_RE.sub("", page) if DATA_BLOCK_RE.search(page) else page
    for tok in spoilers_readme:
        if tok in readme:
            fail(f"answer-key/spoiler token in README: {tok!r}")
    for tok in spoilers_page:
        if tok in page_prose:
            fail(f"answer-key/spoiler token in the shipped page, outside the "
                 f"data block: {tok!r}")


    # --- figures: every file used, every reference resolvable ------------
    refs = set(re.findall(r"\(docs/figures/([^)]+)\)", readme))
    figdir = ROOT / "docs" / "figures"
    on_disk = {f.name for f in figdir.iterdir()} if figdir.exists() else set()
    for missing in sorted(refs - on_disk):
        fail(f"README references a figure that does not exist: {missing}")
    # The social card is the one figure the README does not carry: its
    # consumer is the og:image tag in parts/shell.html, which is what a
    # pasted link renders. Checked against the shell rather than exempted,
    # so renaming the file without fixing the tag still fails here — a
    # broken og:image is invisible until someone posts the link.
    # Read the filename out of the og:image tag itself, not out of the file
    # as a whole: the first version of this check asked whether the name
    # appeared anywhere in shell.html, and the prose comment above the tag
    # satisfied it while the tag pointed somewhere else.
    shell = (ROOT / "parts" / "shell.html").read_text(encoding="utf-8")
    og = re.search(r'<meta\s+property="og:image"\s+content="([^"]+)"', shell)
    if not og:
        fail("parts/shell.html has no og:image tag; a pasted link renders bare")
    else:
        og_name = og.group(1).rsplit("/", 1)[-1]
        if og_name not in on_disk:
            fail(f"og:image points at {og_name}, which is not in docs/figures "
                 f"(run: python3 scripts/make_figures.py --only social_card)")
        refs = refs | {og_name}

    for orphan in sorted(on_disk - refs):
        fail(f"figure on disk that no section uses: {orphan}")
    for m in re.finditer(r"!\[([^\]]*)\]\(docs/figures/", readme):
        if len(m.group(1)) < 25:
            fail(f"figure alt text too thin to stand in for the image: {m.group(1)!r}")


    # --- identifier hygiene, on the artifact ---------------------------------
    # hunt runs a repo-wide identifier gate on every push and this repo ran
    # none, which is the wrong way round: hunt's fixtures are checked at the
    # point they are written, and THIS repo is where they are rendered into a
    # page, a data file and seven images. The rule has been broken at least
    # four times across the two repos, twice inside committed figures.
    #
    # The predicates are hunt's own, imported rather than restated - the
    # documentation space is two ASN ranges and three IP prefixes and
    # remembering only the 16-bit range is exactly how a scan comes back
    # falsely clean.
    ident_bad = []
    try:
        import importlib.util
        hunt_gt = ROOT.parent / "hunt" / "scripts" / "generate_telemetry.py"
        spec = importlib.util.spec_from_file_location("_hunt_gt", hunt_gt)
        gt = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(gt)
        except SystemExit:
            pass
        is_doc_asn, is_doc_ip = gt._is_doc_asn, gt._is_doc_ip
    except Exception as exc:                       # no sibling checkout
        print(f"check_readme: NOTE - identifier gate skipped, hunt not readable ({exc})",
              file=sys.stderr)
        is_doc_asn = is_doc_ip = None

    if is_doc_asn is not None:
        ip_re = re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])")
        asn_re = re.compile(r"\bAS\d{3,6}\b")
        skip_suffix = {".png", ".gif", ".jpg", ".jpeg", ".ico", ".woff", ".woff2"}
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix.lower() in skip_suffix:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(ROOT)
            for m in ip_re.finditer(text):
                if not is_doc_ip(m.group(0)):
                    ident_bad.append(f"{rel}: IP {m.group(0)}")
            for m in asn_re.finditer(text):
                if not is_doc_asn(m.group(0)):
                    ident_bad.append(f"{rel}: {m.group(0)}")
        for bad in sorted(set(ident_bad))[:12]:
            fail(f"identifier outside RFC 5398 / RFC 5737 documentation space - {bad}")
        if len(set(ident_bad)) > 12:
            fail(f"...and {len(set(ident_bad)) - 12} more identifiers outside documentation space")

    # --- one file, no external requests --------------------------------------
    # A stated property of the artifact with nothing enforcing it: the page
    # must load from file:// with no network. Anything that fetches - a font,
    # a script, an image, a stylesheet, a pixel - breaks it silently, because
    # a developer testing over http:// would never notice.
    # Attributes, quoted or not. The original required src="..." with double
    # quotes, which HTML lets you omit and CSS never writes at all.
    attr_re = re.compile(
        r"""(?:src|href|srcset|poster)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""")
    # Markup only. Script bodies are not markup, and looking for the nearest
    # preceding "<" inside one finds a less-than operator: the page's own
    # `link.href = 'https://' + repo` read as an external request because the
    # "<" it anchored to was `if (x < 0)`.
    markup = re.sub(r"<script\b[^>]*>.*?</script\s*>", "<script></script>",
                    page, flags=re.S | re.I)
    for m in attr_re.finditer(markup):
        url = m.group(1).strip("\"'")
        if not url.startswith(("http://", "https://", "//")):
            continue
        tag_start = markup.rfind("<", 0, m.start())
        if tag_start < 0:
            continue
        # It has to be an attribute inside an open tag. Without this the
        # script's own `link.href = 'https://' + repo` reads as one, which is
        # a property assignment building an anchor, not a request.
        if ">" in markup[tag_start:m.start()]:
            continue
        name = re.match(r"<\s*([a-zA-Z0-9-]+)", markup[tag_start:tag_start + 20])
        # anchors are links the reader clicks, not requests the page makes
        if name and name.group(1).lower() == "a":
            continue
        fail(f"index.html would make an external request: {url[:70]}")
    # CSS url(), in all three quoting forms. A webfont is written
    # src: url('https://...'), and the literal test for "url(http" could not
    # see past the quote.
    url_re = re.compile(r"""url\(\s*("[^"]*"|'[^']*'|[^)]*)\s*\)""")
    for m in url_re.finditer(page):
        url = m.group(1).strip().strip("\"'")
        if url.startswith(("http://", "https://", "//")):
            fail(f"index.html has a remote CSS url(): {url[:70]}")
    if "@import" in page:
        fail("index.html has a stylesheet import - it must load from file://")
    # Anything that fetches at runtime. The page is hand-written and needs
    # none of these; if one appears it is either a remote call or a reason to
    # widen this list on purpose.
    for token in ("XMLHttpRequest", "new WebSocket", "new EventSource",
                  "navigator.sendBeacon", "importScripts("):
        if token in page:
            fail(f"index.html contains {token} - the page must make no "
                 f"requests at all, and nothing in it needs one")

    # --- cross-links -------------------------------------------------------
    for url in ("github.com/abognar-git/model-abuse-hunt",
                "github.com/abognar-git/alert-triage-copilot",
                "github.com/abognar-git/pyrite-assay"):
        if url not in readme:
            fail(f"missing sibling link: {url}")

    if FAILURES:
        print(f"check_readme: {len(FAILURES)} FAILURE(S)")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("check_readme: OK (shift count, subtitles, ordinals, archetypes, gif, templates, landing, palette, scoring, tabs, bands, refusal copy, "
          "bulletin stories, leak guard, figures, links, page data, "
          "identifiers, offline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
