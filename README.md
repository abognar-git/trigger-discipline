# trigger-discipline

**A queue of accounts on an AI platform. Some belong to criminals. Most only
look like they do. You decide who gets banned — and every account you get
wrong is a person.**

<sub>**How to read this.** The first two sections are the game and its rules —
five minutes, everything you need to play. The rest is where the game comes
from: every mechanic in it is a measured finding from a sibling research
project, and the table at the bottom says which.</sub>

> ### ▶ [Play it in the browser](https://abognar-git.github.io/trigger-discipline/)
>
> No install, no account, nothing to run. One file, five shifts, about fifteen
> minutes for the first one.

---

## What this is

![The ban rule, start to finish: a ban on content alone is refused, the Behavior tab is opened and cited, a confidence band is given, and the verdict lands.](docs/figures/ban_rule.gif)

<sub>Six real states of the running game, shift 2. Every figure in this file
is captured from the committed `index.html` by `scripts/make_figures.py`,
driven through the game's own handlers. Nothing here is mocked or
retouched.</sub>

`trigger-discipline` is a playable version of the hardest seat in platform trust &
safety: the human reviewer. A pipeline scores accounts and flags leads, but
nothing here is auto-banned — the pipeline flags, you decide.

*Trigger discipline* is the range rule that keeps a finger off the trigger
until the decision to fire has actually been made. Here the trigger is BAN, and
the queue is built to make you reach for it early. Several innocents look
exactly like the people you are looking for — a penetration tester, a
phishing-awareness trainer, a CTF student, a detection engineer, a journalist,
a novelist. On *content* — the words they typed at the model — they are
indistinguishable from the actors. That is not a flaw in the game;
it is the point of the research it is built on: **what someone asks an AI
tells you almost nothing. How they behave tells you almost everything.**

You play five shifts, in the order the job gets harder. The queue starts
obvious, then starts moving, then starts arriving the way a real queue
arrives: mostly innocent.

![The shift select screen: five shifts, each unlocking the next.](docs/figures/shift_select.png)

## The rules

For every account you make one call, from three:

| verdict | key | what it takes |
|---|---|---|
| **BAN** | `B` | evidence — see below |
| **MONITOR** | `M` | nothing |
| **CLEAR** | `C` | nothing |

### The ban rule

A ban is the only verdict with requirements, and it has two. Both are
enforced by the in-game policy, and both are lifted from the research
pipeline's real enforcement rules:

1. **A ban must cite evidence, and content alone is not evidence.**
    Every evidence row in an opened evidence tab has a checkbox; checking it cites that
    row. When you press BAN, the policy reads your citations, and at least one
    must come from a non-content tab — Account file, Behavior, Network, or
    Pipeline read. Cite only prompt excerpts (or nothing) and the ban is
    refused:

    > Refused: no enforcement on content alone. What they asked proves
    > interest, not abuse. Cite behavior, infrastructure, or the scorer.

    The refusal costs nothing. It is the policy telling you that you cannot
    yet prove what you believe.

    ![An account whose every prompt is offensive content; the ban is still refused, because content is not evidence of abuse.](docs/figures/refusal.png)

    <sub>Three phishing drafts, and the policy still declines. Content this
    bad is exactly why the rule exists: another account in the same queue
    asks for the same thing and runs a staff awareness campaign.</sub>

2. **A ban must state how sure you are, and "not very" is not enough.**
    After citing, you pick a confidence band on the intelligence-community
    scale the pipeline itself uses (likely = 0.70, very likely = 0.85, almost
    certain = 0.95). Below the policy floor of *likely*, the ban is refused.
    The band is a claim, and the shift report scores it: your Brier score
    shows whether your "almost certain" means anything.

    ![The confidence band picker, with the policy floor marked.](docs/figures/band_picker.png)

MONITOR and CLEAR need no justification. The asymmetry is deliberate: a
no-action decision is cheap to be wrong about, a ban is not.

### Scoring

| outcome | points |
|---|---|
| Ban a threat-actor account | **+10** |
| Clear a benign account | **+5** |
| Monitor an actor | **+2** |
| Monitor a benign account | **−2** |
| Miss an actor (clear, or never decide) | **−10** |
| **Ban a benign account** | **−25** |

One false ban erases two and a half caught actors, or five correct clears.
That ratio is the thesis of the scoring: the actor you miss comes back
tomorrow, and the innocent you
ban has no easy way back — in the research project this game is built on,
a wrongly clustered account *could not appeal its way out*, because the
accusation was not a fact anyone could produce a document against.

### Evidence, and what it takes

Looking is never forbidden — it takes time. The shift has a fixed length,
the clock only runs forward, and while you read, the queue keeps arriving
and the actors keep operating.

| tab | takes | contents |
|---|---|---|
| Content | nothing | prompt excerpts, category, refused or completed — what a content filter sees |
| Account file | 1h | signup age, email kind, payment, phone verification |
| Behavior | 2h | session timeline, cadence, volume, refusal rate, category mix |
| Network | 2h | infrastructure per session, and which other queue accounts share it |
| Pipeline read | 2h | the scorer's risk breakdown; cluster assessment and policy decision if one exists |

![The Pipeline read tab: the scorer's risk breakdown, the signals that did not fire, and the policy's own decision.](docs/figures/pipeline_read.png)

<sub>The most expensive tab, and the one that argues with itself: the model
called this account malicious abuse, and the policy held it to monitor. Signals
that did not fire are shown too — silence is evidence about an account.</sub>

Each tab opens once per account and stays open; refreshes are free. On the
first shift the clock is off entirely — read everything, learn what each tab
is worth. From the second shift on, time is the only pressure the game ever
applies. The end-of-shift report shows *what ran while you read*: the
malicious sessions that landed between an actor's arrival and your ban. It
is not scored. It is just true.

### Later shifts add, in order

- **A live queue.** Accounts and sessions arrive over the shift. A decided
  account that receives new evidence reopens, and you may change that verdict
  once. Some accounts are clean for the first twenty hours.
- **Cases.** Accounts that belong to one operator are one case (`A` adds an
  account to a case). A case with two or more members is banned once — one
  link reason, one band, every member. The policy refuses a case linked only
  by shared infrastructure ("an overlap is an observation, not a link"),
  and it is right to: one of the innocents shares a VPN with three actors.
  Ban half a cluster and the operator returns on a fresh burner with new
  infrastructure — and the same objective, because money buys anonymity,
  not a different objective.
![The case board: two accounts joined into one case, with only the link reasons that actually hold offered.](docs/figures/case_board.png)

<sub>Shift 3, hour 9, queue still arriving. The link-reason picker offers only
what holds between these two members, and a case linked by infrastructure
alone is refused.</sub>

- **Appeals.** On the last shift, everyone you banned files an appeal
  nominating a fact for independent verification. Some appeals verify and
  are lies anyway. One cannot be resolved in either direction — and the
  round will show you why that is the worst outcome on the board.

### Keys

`B` ban · `M` monitor · `C` clear · `1`–`5` evidence tabs · `A` case
add/remove · `W` wait 1h · `Enter` continue · arrows move through the queue ·
`?seed=N` in the URL reorders a shift's queue.

## Where the game comes from

Every account is a synthetic fixture from
[`model-abuse-hunt`](https://github.com/abognar-git/model-abuse-hunt), a
research project that built and then attacked an abuse-hunting pipeline for
an AI platform. The game imports that project's scorer, its confidence-band
scale, and its policy constants directly from source — nothing is restated —
and account ids are remapped so the fixtures' answer key cannot leak.
Identifiers are RFC-reserved throughout (documentation IP ranges, ASNs,
`.example` domains): nothing in the data collides with a real network or a
real company.

Each mechanic is a measured finding there, not a game-design invention:

| mechanic in the game | finding in `hunt` |
|---|---|
| Content is free and misleading | topic carries ~0.06 of the risk score; behavior and infrastructure carry the rest |
| A ban must cite non-content evidence | policy rule: no enforcement on content alone |
| Confidence bands, the 0.70 floor, Brier scoring | the pipeline's own band on its hardest account was a 50/50 coin flip across 12 reps |
| −25 for a false ban | false-accusation rate is the metric that matters, and 0/14 is a sample, not a rate |
| MONITOR as the pressured hedge | the model called the detection engineer malicious; the policy held it to monitor |
| The account that is clean until hour 18 | a stolen key is detectable only as divergence from the account's own baseline |
| "An overlap is an observation, not a link" | the false-merge guard: two strangers behind one VPN are not one actor |
| Respawn with new infrastructure, same objective | the evasion cost frontier: ~$101 buys anonymity; objective and history are unbuyable |
| The appeal that cannot be resolved | `coordination` is not a fact you can produce a document against |
| The career dashboard's base-rate section | at realistic prevalence, an enforce queue with a small false-positive rate is mostly innocent people |

The trilogy behind it: [`triage`](https://github.com/abognar-git/alert-triage-copilot)
(the defender's pipeline under attack), `hunt` (the platform hunting for
misuse), [`pyrite`](https://github.com/abognar-git/pyrite-assay) (what a refusal is
actually worth). This game is the fourth angle: the human the other three
keep concluding you need.

## What this is not

The fixtures are synthetic and labeled by their author; the game inherits
that. Session `category` labels are given, not derived — the same caveat
`hunt` states about itself up front. Your score measures your play against
this dataset, not your competence as an analyst; twenty-three accounts is a
queue, not a benchmark.

## Running it yourself

Open `index.html`. That is the whole game — one file, no server, no network
requests, works from `file://`.

To rebuild it from source:

```bash
python3 scripts/build_data.py --hunt ../hunt --inject index.html   # data from hunt fixtures
python3 scripts/build_page.py --check                              # page matches parts/
python3 scripts/check_readme.py                                    # this file matches the data
node scratch/harness.js                                            # full sim suite
```

`build_data.py` requires a checkout of `model-abuse-hunt` beside this repo;
it imports the scorer and predicates from there and refuses to restate them.

## License

MIT.
