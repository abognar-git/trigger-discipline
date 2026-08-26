# trigger-discipline — SPEC v3: the findings program

Extends SPEC.md and SPEC-2.md (both stay authoritative where not
contradicted). Nine features, built 2026-08-03, every one pointing at a
measured `hunt` finding or at a limitation `hunt` states about itself — with
one deliberate exception (§4) and one labeled desk affordance (§9).

**Provenance of the slate.** A 37-idea / 4-lens / 3-judge panel produced the
candidates; the author's standing rule for this repo held: only mechanics
grounded in `hunt` shipped. Ideas grounded in the sibling repos (`triage`,
`pyrite`) were cut on that rule, whatever their scores. Where a feature
needed a number `hunt` does not export as a constant, the number is defended
by a build assertion over the data, never by the author's taste (§4).

**Standing disciplines, unchanged from v1/v2:** single committed
`index.html` built from `parts/`; data injected by `build_data.py`, which
imports hunt's scorer, linker, band map, policy constants and identifier
predicates and restates nothing; reveal-vault anti-leak rules extended to
every new reveal-side field; deterministic builds; the node harness drives
the page's own handlers and prints its own assertion count — this file
deliberately pins none, because a pinned count was stale within the hour of
its first draft; figures captured from the running artifact by
`make_figures.py`, never drawn.

## 1. The two definitions of "topic", and the flag (finding #20)

- Pipeline read renders a strip on EVERY account (uniformity is the
  anti-tell): the account's score under both of the research's shipped
  definitions of topic — content only (0.06 of the weight vector) and
  content + capability trajectory (0.28, `policy.py`'s corroboration list) —
  and what remains against the lead line without each. `meta.topic` carries
  the set and both shares, imported from `signals.TOPIC_DERIVED_SIGNALS` /
  `topic_share()`; the UI recomputes per-account numbers from the breakdown
  it already shows.
- `G` — FLAG POLICY GAP. An annotation, not a verdict: the record is open on
  any account, decided or not, and it never scores or gates. The report
  section closes with the research's own posture: its alternatives were
  measured, published, and deliberately not adopted.

## 2. Twelve runs, one band (finding #24)

Every assessment cluster carries `stability`: the band and decision
histograms from `hunt data/reps.json`, attached only where the subject-id
set matches a measured one. The cluster head renders "across 12 runs — band:
… · decision: …". The decision column held every run on every cluster; the
band on the hardest account is a 50/50 coin flip, and the single band above
the line is one draw. Generated rosters carry `stability: null` — a
histogram against different accounts would be a caption on someone else's
measurement.

## 3. The designed pair (dual-use twins, finding #25's texture)

A twin pair is DERIVED, not declared: one malicious and one benign scheduled
account whose automation cadence fires on the same interval. At most one per
shift, none on the quiet day; the pair object lives reveal-side on both
members, composed from the emitted rows. The shift report renders the two
columns with the player's verdicts stamped, and when both got the same
verdict it names the diverging tab the player never opened. Carriers per
shift are asserted (2/2/2/0/2/0).

## 4. Two inadmissible link channels (finding #17)

- **Style** is offered for every case and always refused, with THIS queue's
  measured numbers appended: `build_data` computes the full pairwise style
  matrix per shift through `hunt src/linkage.py` and emits it
  (`shift.style`); `check()` recomputes every pair and fails on drift. The
  refusal skeleton lives in `REFUSALS["style_link"]`.
- **Hours** are on the menu and the policy ACCEPTS them. hunt swept the
  channel and adopted no threshold — it false-merges the planted hard
  negatives at every one — so there is no constant to import.
  `TIME_LINK_THRESHOLD = 0.90` is this file's own number, and its only
  honest defense is the property `check()` asserts: at this cut the channel
  stays sparse, and on every case shift with actors it offers at least one
  mixed-truth pair. The s3 briefing states the deviation; the −25 teaches
  it. **This is the one place the game's policy knowingly departs from
  hunt's, and the README says so.**
- `network.shared_hours` is emitted like every other overlap (peers from the
  scheduled roster; hour vectors from `linkage.hour_vector`).

## 5. Topic-derived citation gate (finding #20, fidelity fix)

The shipped refusal copy ("cite behavior, infrastructure, or the scorer")
was looser than the instrument's own enforcement rule. Closed: a ban whose
only non-content citation is a pipeline signal row in
`TOPIC_DERIVED_SIGNALS` is refused (`REFUSALS["topic_only"]`), those rows
are marked `topic-derived` in the signal table, and the cite counter warns
("all topic-derived") before the refusal does. The harness asserts every
actor keeps a legal ban path.

## 6. Policy bulletins (findings #5 and #21)

`meta.policy.patches` names two patches and their activation shifts;
constants import from `hunt src/policy.py`.

| patch | active from | rule | the measured story |
|---|---|---|---|
| `strength_floor` | s3 | a cited signal row below `CORROBORATION_MIN_CONTRIBUTION` (0.06) cannot carry a ban | a 0.04 automation blip once counted as corroboration — presence is not strength |
| `min_observations` | s4 | a cited rate row under `CORROBORATION_MIN_OBSERVATIONS` (4) cannot carry a ban | one refusal in one session once scored full strength — strength is not sample size |

The bulletin renders on the activation shift's briefing; earlier shifts run
the pre-patch world on purpose, so the same citation passes on s3 and
bounces on s5 — the fix made playable. Every rate row shows its denominator
(`n=`) from shift 1; the bulletin only enforces what the eye could always
read. `check()` asserts each activation shift contains an account the patch
actually bounces. Refusals append the cited row's own numbers.
Deferred: the retro panel ("m of your n past bans would bounce today") —
career storage holds no per-ban citations yet.

## 7. The second opinion (finding #18)

Assessment clusters carry `second_opinion`: the decorrelated judge's verdict
on THAT assessment, verbatim from `hunt data/judge.json` (sound on the wrong
assessment and on the lure cell; weak/dual_use on the other three actor
clusters). A free button reveals it; it never scores, blocks, or warns — the
offer is the mechanic. If the player used it, the report's "You vs the
advisor" section lays their verdicts beside the advisor's words and quotes
the measured basis: margin −0.75, inverted; the closing count ("found fault
with 3 of the 4 actor assessments and rated the wrong one sound") is
computed from the clusters and the reveal, never typed. `meta.judge`
carries the discrimination block. The s1 briefing offers without endorsing.

## 8. Shift 6 — "The aimed link" (finding #25)

`framing.json`'s actor-clone construction, staged as a roster and run
through the real linker:

- 16 accounts (15 scheduled + the cell's respawn burner): a three-burner
  lure cell on one egress; an awareness trainer with weeks of history whose
  sessions name her own employer; a framer created hours before the shift
  that copies the cell's ASN and IP, the trainer's target org and topic, and
  the trainer's working hours, one day later; ten ordinary accounts.
- `build_actors` — imported, not restated — puts the trainer in the actors'
  cluster, exactly as the measurement says it must (`victim_enforced: true`
  in the artifact's actor-clone arm). `check()` fails the build if the frame
  does not stage.
- **The first-seen column**: for every identifier overlap (ASN, IP, target),
  `network.first_seen` dates when EACH side was first seen with any shared
  token — signup timestamp for signup identifiers, session timestamps
  otherwise. No oracle, only order. `check()` re-derives the whole column
  from the emitted rows and asserts the victim precedes the framer on the
  shared target.
- The framer's hour profile matches the victim's exactly, so the §4 hour
  channel offers the merge — the frame hands you the trap, and the correct
  play (action the framer, clear the victim) is worth 95 of 95.
- Career: sixth card, landing copy "Seven shifts", completion line and
  dashboard follow the data; `ACTOR_NAMES` gains `framer`, whose provenance
  cites `stress_framing.py` rather than a threat report, because that is
  what it is.

## 9. Between cases, and the fold (desk affordance — exception tier)

Not a finding: an affordance over the link machinery the board already runs,
at the picker's exact disclosure level (player-visible network lists, no
reveal access, no scoring or policy change). Reviewed by a three-lens panel
before building; all semantic claims verified against code and data.

- With the active case open and non-empty and another open non-empty case on
  the board: one line per other case — which members touch which, on what
  channel; when every cross-edge runs through one account, the line names it
  ("touches this case only through …" — single-point linkage is the weakest
  attribution a desk accepts, and it is the entire s6 frame); the line ends
  with the union verdict ("Merged, … would hold across every member." /
  "Merged, no reason would hold."). Footer, load-bearing: *"The pipeline
  chains overlaps pair by pair; a case ban stands on one reason that holds
  across every member."* — the union connectivity rule and the pipeline's
  transitive chaining genuinely diverge (the s6 five-account union holds
  NOTHING while the pipeline cluster holds all five), and that divergence is
  the lesson, not a bug.
- **Fold Case N in**: the existing move-semantics, batched. Survivor is the
  active case; the folded case's number is never reissued (monotonic
  counter); `activeIdx` is fixed up across the splice; `pendingBand` resets;
  selections are pruned against the union; provenance persists on the case
  ("Absorbed Case 2 (2 members) at hour 11."). Banned cases can neither fold
  nor be folded. A fold can never manufacture a link reason — the picker
  recomputes over the union and refuses as before, which funnels the player
  into the measured lessons rather than around them.

## 10. Harness and gates (the teeth, extended)

- `scratch/harness.js`: scenarios for every feature above — the pre-patch →
  post-patch bulletin arc, the style refusal with this-queue numbers, the
  hour-channel merge settling at −25, the advisor bait and its report, the
  staged frame (direction evidence incl. the rendered first-seen ORDER, the
  trap, the correct play), the fold (splice bookkeeping, naming, provenance,
  refusal preservation), and the next-event jump (banned-account session
  hours are not events; a respawn's landing hour is). All green at this
  writing; the run prints the count.
- `build_data.py check()`: meta.topic recompute; stability histograms sum to
  reps with single-valued decisions; per-shift style-matrix recompute; hour
  sparsity + mixed-truth trap on case shifts; bulletin bounce accounts on
  activation shifts; twin-carrier counts; first-seen re-derivation; the s6
  frame staging.
- `scripts/check_readme.py`: shift count in words (no wrong word-form
  survives), the new refusal fragments in the emitted copy AND their stories
  in the prose, the imported floors quoted, the two topic shares, the judge
  margin, figure reference closure both ways.
- `scripts/make_figures.py`: the shift-hint scan knows s6, and the
  content-figure scenarios select by sessions VISIBLE at capture time
  (`visiblePhishing`) — the whole-list predicate had put the stolen key's
  benign baseline under a "three phishing drafts" caption on the published
  README, and no text gate could see it. Two s6 captures (`first_seen`,
  `between_cases`) were built and then DELETED before commit: with the
  per-shift id remap being deterministic, a screenshot of the frame plus a
  caption naming its sides is the climax shift's answer key. The README
  says so where the figures would have been. Standing rule held again this
  pass, three times over: a capture error, a silently-empty board and a
  caption contradiction all shipped as images before a human LOOKED.

## 11. Amendment A2 — the next-event jump (pacing affordance)

Nobody mashes W thirty times to reach hour 33, and nothing in the design
wants them to: the shift LENGTH is load-bearing (it prices evidence, stages
the late-drift and framing lessons, and denominates "What ran while you
read"), but the keypress grind between events carries no lesson at all.

`⇧W` / the **Next event** control jumps the clock to the next thing that
happens — the earliest future static arrival, session hour, or dynamic
(respawn) arrival, all computed from the same player-visible data the
arrival engine runs on — or to the end of the shift when nothing is left.
The jump spends exactly the hours it skips, attributed to waiting like any
W; the landing state is identical to pressing W that many times, so the
affordance removes keypresses, never information, and cannot route around a
lesson. Hidden on the clockless first day. The harness walks a whole shift
on jumps alone and asserts every landing is an event hour or the wall.
