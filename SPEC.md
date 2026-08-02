# trigger-discipline — game design spec (v1)

**Name:** `trigger-discipline`. Sibling of `assay` / `triage` / `hunt` (same author, same craft rules).
The name is from hunt's finding #26 — "the gate that cannot see": a human reviewer shown only
the queue card upholds 5/5 unsound enforcement cards. In this game **the player IS the human
gate**, and gets what that reviewer never had: the evidence, at a price.

## 1. Concept

You are the enforcement reviewer at an AI platform's trust & safety desk. 23 accounts are in
your queue. 9 of them belong to 4 real threat-actor archetypes (each grounded in OpenAI's
published threat reports); 14 are innocent — and 8 of those innocents were *designed* to look
guilty on content (pentester, phishing-awareness trainer, CTF student, detection engineer,
journalist, SRE automation, novelist, VPN coincidence). For each account you must decide:
**BAN** or **CLEAR**.

The pedagogical spine (hunt's thesis made playable): **what someone asks an AI tells you
almost nothing; how they behave tells you almost everything.** Content is free to look at and
misleading. Behavioral/infra evidence costs investigation time, and your time is budgeted.

Nothing is auto-banned. You are the gate. The actor you miss comes back tomorrow; the
innocent you ban has no easy way back (hunt finding #19: the wrongly-clustered bystander
cannot get out, because `coordination` is not a fact you can produce a document against).

## 2. Data (all real fixtures from the `hunt` repo, transformed)

Source: `/Users/host/Claude - Projects/hunt` — `data/accounts.jsonl` (23), `data/sessions.jsonl`
(98), `data/ground_truth.jsonl`, `data/findings.jsonl` (5 clusters: 4 enforce, 1 monitor),
`src/signals.py` (deterministic scorer; import it, do not reimplement).

### Data contract — one JSON object embedded in `index.html` inside
`<script id="game-data" type="application/json">…</script>`:

```jsonc
{
  "meta": {
    "source_repo": "github.com/abognar-git/model-abuse-hunt",
    "source_commit": "<hunt HEAD sha>",
    "built": "<UTC date>",
    "generator": "scripts/build_data.py",
    "counts": {"accounts": 23, "malicious": 9, "benign": 14, "sessions": 98}
  },
  "accounts": [
    {
      "id": "acct_9f3a",                  // REMAPPED — see §7 (original ids leak ground truth)
      "profile": {                        // = accounts.jsonl row, ids remapped
        "created_at": "...", "email_kind": "freemail", "payment": "none",
        "phone_verified": false, "signup_country": "RO", "signup_asn": "AS64497",
        "signup_ip": "198.51.100.44", "primary_channel": "chatgpt"
      },
      "sessions": [                       // chronological; session_id dropped
        {"ts": "...", "channel": "...", "category": "...", "prompt_excerpt": "...",
         "disposition": "refused|completed", "src_ip": "...", "asn": "...",
         "country": "...", "target_ref": "..."}
      ],
      "pipeline": {                       // computed via hunt's src/signals.py + findings.jsonl
        "risk": 0.327,
        "lead": true,                     // risk >= signals.LEAD_THRESHOLD
        "signals": [                      // per-signal breakdown from score_account, nonzero first
          {"name": "burner_infra", "value": 0.08, "note": "<the evidence string signals.py emits>"}
        ],
        "cluster": {                      // null if account appears in no findings row
          "assessment": "malicious_abuse", "confidence_band": "almost certain",
          "decision": "enforce|monitor", "summary": "...",
          "members": ["acct_...remapped ids"]
        }
      },
      "network": {                        // precomputed cross-account overlaps (player pays to see)
        "shared_asn": ["acct_..."], "shared_ip": ["acct_..."], "shared_target": ["acct_..."]
      },
      "reveal": {                         // NEVER rendered before the decision
        "truth": "malicious|benign",
        "actor": "lure_factory|capability_dev|recon_automation|stolen_key|null",
        "persona": "pentester|...|null",
        "original_id": "acct_LF01",
        "tell": "<1-3 sentences: what actually separates this account — §6>",
        "provenance": {"source": "...", "case": "..."}   // from ground_truth, null for backgrounds
      }
    }
  ]
}
```

## 3. Game flow

1. **Intro screen.** The fiction (3 short paragraphs max), the scoring table, the budget, one
   rule highlighted: *"Nothing here is auto-banned. The pipeline flags; you decide."* Start
   button. Seed shown; `?seed=N` in URL reorders the queue (mulberry32; default 1337).
2. **Queue.** Sidebar lists all 23 accounts (remapped id + channel + session count + decided
   state). Order = seeded shuffle. Click to open; auto-advance to next undecided after a verdict.
3. **Dossier.** Evidence tabs; verdict buttons BAN / CLEAR always visible.
4. **Reveal interstitial** after every verdict: truth, points delta, the tell, provenance quote
   ("this archetype is drawn from: …"), original hunt id. Continue = Enter.
5. **Final report** after 23 verdicts (or "end shift early" — remaining undecided accounts
   count as CLEAR, i.e. no action taken).

## 4. Evidence economics (the mechanic that carries the thesis)

Budget: **BUDGET = 32 hours** for the whole shift. Costs per account (each pays once,
stays unlocked):

| Tab | Cost | Contents |
|---|---|---|
| **Content** | free | prompt excerpts + category + disposition per session. What a content filter sees. |
| **Account file** | 1h | signup age, email kind, payment, phone verification |
| **Behavior** | 2h | session timeline (cadence visual), volume, refusal rate, category mix over time |
| **Network** | 2h | ASN/IP/country per session + which OTHER queue accounts share infra or targets |
| **Pipeline read** | 2h | scorer risk + per-signal breakdown; cluster assessment + policy decision if one exists |

Full workup = 7h → ~4 accounts. The design intent: ordinary users are clearable on free
content; the 8 hard negatives and 9 actors are exactly where content misleads and the paid
tabs pay off. Spending nothing and banning on content is the losing strategy — by design.

## 5. Scoring

| Outcome | Points |
|---|---|
| Ban a threat-actor account | **+10** |
| Clear a benign account | **+5** |
| Miss an actor (clear/skip) | **−10** |
| **Ban a benign account** | **−25** |

Max **160** (9×10 + 14×5). Ban-everything = −260. Clear-everything = −20. The asymmetry is
the point and the intro says so: a missed actor returns, a wrongly banned person mostly
cannot argue their way back in. Unspent hours: no points (stated — investigation time is not the score).

Rank titles: ≥150 "The gate that can see" · ≥110 "Corroborated" · ≥60 "Monitor" ·
≥0 "Needs investigation" · <0 "False-accusation machine".

## 6. Reveal "tells" (drafts — builder MUST verify each against the fixtures and correct)

- **LF01–05** (lure_factory): five burners created days apart, freemail, no phone/payment,
  same higher-risk ASN, same target org; each kept individually quiet — the volume is
  distributed so no single account looks busy.
- **CD01** (capability_dev): escalating exploit-development arc, refusal farming, burner infra.
- **CD02** (capability_dev): the quiet second account — sits ~0.002 under the lead line;
  found via the cluster, not its own score.
- **RA01** (recon_automation): 18 sessions at machine-tight cadence, recon categories, burner infra.
- **SK01** (stolen_key): an aged, verified account whose behavior *drifts* mid-history — new
  hours, new categories, new ASN. The account is legitimate; its key stopped being.
- **NEG_pentest**: offensive content, but verified payment, phone, corporate email, stable
  infra, named engagement targets. Content is a self-claim; infrastructure is not.
- **NEG_trainer**: writes phishing emails for awareness training — same topic, same victim-org
  vocabulary as the lure factory. Cheapest account to frame ($0 in hunt's finding #25).
- **NEG_ctf**: exploit help at student volume and student hours.
- **NEG_detection**: the detection engineer. Hunt's own model called this account
  `malicious_abuse`; the policy layer held it to *monitor*. If you banned it, you did what
  the model wanted and the policy refused.
- **NEG_journalist**: asks how attacks work, never how to run one — reporting, not tooling.
- **NEG_sre**: 18 sessions of tight-cadence automation — the twin of RA01. The difference is
  everything else: benign categories, corporate account, aged history.
- **NEG_vpncoincidence**: shares a VPN ASN with an actor. Under naive linking this account
  reaches `enforce` (hunt's console demos it). A link needs a reason, not an overlap.
- **BG01–06**: ordinary users. If you spent hours here, that was the cost of not trusting
  the free view.

## 7. Anti-leak rules (hard requirements)

1. **Remap account ids** — originals (`acct_LF01`, `acct_NEG_pentest`, `acct_BG03`) encode the
   answer. `"acct_" + sha256(orig + "|trigger-discipline-v1").hexdigest()[:4]`, assert uniqueness, assert
   `^acct_[0-9a-f]{4}$`. Remap in ALL player-visible strings too (cluster member lists,
   assessment prose — grep every string for `acct_`). `session_id` dropped entirely.
2. **`reveal` is the only place** ground truth (label, actor, persona, notes, provenance,
   original id) may appear. Build script must assert: the serialized player-visible portion
   (everything minus `reveal`) contains no original id and no actor name
   (`lure_factory|capability_dev|recon_automation|stolen_key`). NOTE: prompt excerpts
   legitimately contain words like "pentest" — that is *content*, i.e. a self-claim; do NOT
   flag free-text words, only ids and actor names.
3. **Identifier hygiene** (standing rule, broken 6× across the siblings): every IP must be in
   RFC 5737 ranges, every ASN in 64496–64511. Reuse hunt's `scripts/check_identifiers.py`
   predicates by import if importable, else assert with local regex. The build FAILS on
   violation, it does not warn.
4. UI must never branch on `reveal` before the verdict is committed (no "the truth was
   preloaded into the DOM" leak for a curious dev-tools user — acceptable: data block contains
   it; NOT acceptable: any pre-verdict visual difference derived from it).

## 8. Final report screen

- Score + rank title + confusion matrix (banned/cleared × actor/benign).
- **You vs the pipeline:** hunt's shipped pipeline surfaces 9/9 malicious with 0/14 false
  accusations — but forwards *every* enforcement to a human. "The pipeline's job was to make
  your job possible. Your job was the hard part."
- **You vs the card-only reviewer** (finding #26): a reviewer shown only the queue card upheld
  5/5 unsound cards. Show what the player's evidence spending bought vs that baseline.
- **The base-rate kicker** (finding #16): if player FP > 0 — "your false-ban rate here was
  x/14. At a realistic 0.1% abuse prevalence, a queue with your rates would be ~N% innocent"
  (compute: FP·(1−p) / (FP·(1−p) + TPR·p), p=0.001, rates from the player's own confusion
  matrix). If FP = 0 — "0/14 is not a rate: with 14 innocents, the data only licenses 'under
  21%' (Wilson 95% upper bound). Hunt's own 0/14 has the same asterisk."
- Budget audit: hours spent per tab type; "your most expensive mistake" (the banned benign
  with the most/least evidence bought, whichever is the better story).
- Play-again with new seed; link to the hunt repo ("every account here is a real fixture from
  the instrument this game is built on").

## 9. UI / craft requirements

- **One committed file: `index.html`.** Self-contained, stdlib-of-the-web only: vanilla JS,
  inline CSS, zero external requests (no fonts, no CDN, no analytics). Works from `file://`.
- Dark theme default (SOC desk), light via `prefers-color-scheme` + manual toggle. System
  sans stack (`-apple-system, "Segoe UI", Roboto, …`) — **no serif** (author's standing rule).
- Keyboard-first: `B` ban, `C` clear, `1–5` tabs, `Enter` continue, arrows navigate queue.
  Focus states visible; `aria-live="polite"` on the reveal; `prefers-reduced-motion` respected.
- Layout: queue sidebar left, dossier main, header = hours remaining + progress + running
  score. Mobile: single-column (queue collapses to a strip); desktop is the primary target.
- Tone of all copy: hunt's README voice — plain, declarative, a little dry. No emoji, no
  gamer-speak. The reveal cards may quote provenance verbatim.
- Footer: "All 23 accounts are synthetic fixtures from model-abuse-hunt; identifiers are
  RFC-reserved. MIT."

## 10. Build tooling

`scripts/build_data.py` (stdlib only, Python ≥3.11):
- `--hunt PATH` (default: sibling `../hunt`), `--out data/game_data.json`,
  `--inject index.html` (replace the `<script id="game-data">` block in place, byte-exact
  otherwise), `--check` (run all assertions, write nothing).
- Imports hunt's `src.signals` via `sys.path` (do not copy the scorer — drift is how the
  siblings got burned; see hunt finding on restated definitions).
- Provenance header in the JSON (`meta`), same discipline as the siblings' emitted tables.
- Deterministic: same hunt checkout → byte-identical output.
- All §7 assertions run on every build; exit nonzero on any failure.

Out of scope for v1 (candidates for later): daily-seed challenge mode, generated extra
rosters via hunt's `generate_telemetry.py`, a "card-only mode" that recreates finding #26
literally, shareable end-screen image.
