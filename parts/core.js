/* =========================================================================
   trigger-discipline — parts/core.js
   State, the reveal vault, queue/dossier/tabs, verdicts, citations, bands,
   policy checks, scoring, interstitials, the per-shift report, the case-ban
   commit path and the respawn trigger (SPEC-2 §3), and the mode registry
   (Game.registerMode). Assembled into index.html by scripts/build_page.py.
   Reads data contract v3 (meta.contract === 3). v3 narrowed the pipeline
   signal rows: `weight` and `intensity` were never read here and `weight`
   is hunt's own constant per signal name, so shipping it on every row was
   shipping a lookup table one entry at a time. A signal that did not fire
   now carries its name and, where it has one, its denominator; an absent
   `value` means zero, which is what a signal that did not fire contributes.

   SPEC-2 §8 (Amendment A1) — one clock, forward only. A shift's `budget`
   field is its LENGTH in hours: the clock runs 0 -> length and the shift
   ends when it arrives there. Opening evidence TAKES time instead of
   spending it, so nothing is ever refused for lack of hours; there is no
   wall, and no refusal copy for one. On a shift whose flags.live is false
   there is no clock at all — every tab is free and instant, no hours in the
   HUD, no hours audit in the report. The per-tab open-once machinery and
   the citation gate are unchanged on every shift; only the time dimension
   goes away.
========================================================================= */
(function () {
'use strict';

/* =========================================================================
   data load — contract v2 (SPEC-2 §5)
========================================================================= */
var RAW = JSON.parse(document.getElementById('game-data').textContent);
var META = RAW.meta || {};
/* §5 puts shifts at the top level; tolerate meta.shifts from older drafts. */
var SHIFTS = RAW.shifts || META.shifts || [];
var BANDS = META.bands || {};
var POLICY = META.policy || {};

function bootError(msg) {
  var intro = document.getElementById('screen-intro');
  if (intro) { intro.textContent = msg; }
  throw new Error(msg);
}
if (META.contract !== 3) {
  bootError('Data block is contract v' + (META.contract || 1) +
    '; this build reads contract v3. Rebuild with scripts/build_data.py.');
}
if (!SHIFTS.length || !(SHIFTS[0].accounts || []).length) {
  bootError('No shifts in the data block. Rebuild with scripts/build_data.py.');
}

/* Bands, ascending by probability. The probabilities are hunt's own
   calibration mapping, emitted by build_data into meta.bands — nothing
   here restates one. */
var BAND_LIST = Object.keys(BANDS).map(function (name) {
  return { name: name, label: name.replace(/_/g, ' '), p: Number(BANDS[name]) };
}).sort(function (a, b) { return a.p - b.p; });
if (!BAND_LIST.length) {
  bootError('meta.bands is missing or empty; contract v2 requires it.');
}
var FLOOR_BAND = POLICY.floor_band;
if (!(FLOOR_BAND in BANDS)) {
  bootError('meta.policy.floor_band ("' + FLOOR_BAND +
    '") is not in meta.bands; the policy floor is unresolvable.');
}
var FLOOR_P = Number(BANDS[FLOOR_BAND]);

/* §1 — the two policy refusals, verbatim. A refusal costs nothing. */
var REFUSE_CONTENT = 'Refused: no enforcement on content alone. What they ' +
  'asked proves interest, not abuse. Cite behavior, infrastructure, or the scorer.';
var REFUSE_FLOOR = 'Refused: below the confidence floor.';
/* Finding #20 — hunt's own policy excludes the topic-derived scorer rows
   from corroboration; the game's gate was looser than the instrument's rule
   until this closed the gap. Which rows those are comes from META.topic,
   imported from hunt's signals module by build_data. */
var REFUSE_TOPIC = 'Refused: that scorer row is topic in disguise — the ' +
  'policy’s corroboration rule excludes it. Cite behavior, infrastructure, ' +
  'or a non-topic signal.';
/* Findings #5 and #21 — the policy bulletins. Each is a measured hunt fix;
   the constants come from meta (imported from hunt policy.py), the patch
   activates on the shift meta names, and earlier shifts run the pre-patch
   world on purpose. Skeletons static; the gate appends the cited row's own
   numbers. */
var REFUSE_WEAK = 'Refused: that signal is below the corroboration floor. ' +
  'Presence is not strength.';
var REFUSE_THIN = 'Refused: a rate from that few observations is not ' +
  'corroboration. Strength is not sample size.';
var PATCHES = POLICY.patches || [];
var MIN_CONTRIB = Number(POLICY.corroboration_min_contribution);
var MIN_OBS = Number(POLICY.corroboration_min_observations);

function shiftIdx(id) {
  var i = -1;
  SHIFTS.forEach(function (s, n) { if (s.id === id) { i = n; } });
  return i;
}
function patchActive(pid) {
  if (!SHIFT) { return false; }
  var from = null;
  PATCHES.forEach(function (p) { if (p.id === pid) { from = p.active_from; } });
  return from !== null && shiftIdx(SHIFT.id) >= shiftIdx(from);
}

/* Per-tab DURATIONS (SPEC-2 §8): how long opening the tab takes when a
   clock is running. Not a price — nothing is ever refused for lack of
   hours, and on a clockless shift these are all effectively zero. Mirrors
   meta.tab_costs in the data block. */
var TABS = [
  { key: 'content',  label: 'Content',       hours: 0 },
  { key: 'account',  label: 'Account file',  hours: 1 },
  { key: 'behavior', label: 'Behavior',      hours: 2 },
  { key: 'network',  label: 'Network',       hours: 2 },
  { key: 'pipeline', label: 'Pipeline read', hours: 2 }
];
var PAID_TABS = TABS.filter(function (t) { return t.hours > 0; })
                    .map(function (t) { return t.key; });
var POINTS = {
  banActor: 10, clearBenign: 5,
  monitorActor: 2, monitorBenign: -2,
  missActor: -10, banBenign: -25
};
var RANKS = [
  [150, 'The gate that can see'],
  [110, 'Corroborated'],
  [60,  'Monitor'],
  [0,   'Needs investigation'],
  [-Infinity, 'False-accusation machine']
];

/* verdicts: id -> {verdict:'ban'|'monitor'|'clear', points, band, p,
   citations, auto, reverdict} — declared before the vault because the
   accessor below gates on it. Reassigned per shift by initShift. */
var verdicts = new Map();

/* live-shift engine state (SPEC-2 §2) — all reset per shift by initShift.
   In a non-live shift every account and session appears at hour 0, so all
   of this reduces to the v1 behavior. */
var arrivalAt = new Map();     /* id -> shift hour the account actually arrived */
var seenCount = new Map();     /* id -> visible session count at last advance */
var reopenGrants = new Map();  /* id -> true: one free re-verdict available */
var reverdictUsed = new Set(); /* ids whose single free re-verdict is used */
var banCutoff = new Map();     /* id -> elapsed hour of the ban; sessions freeze there */
var SETTLED = false;           /* live shifts score at shiftEnd, not per verdict */
var respawnFired = new Set();  /* actors whose respawn fired this shift (SPEC-2 §3: once per actor) */

/* =========================================================================
   reveal vault — SPEC v1 §7.4, extended to every shift (SPEC-2 §0)
   INVARIANT: nothing under an account's `reveal` key is read, rendered, or
   branched on before that account's verdict is committed. The data block
   necessarily carries the truth; this section quarantines it. At load,
   every account's `reveal` in every shift is detached into the closed-over
   map below, so account objects passed to any rendering code — and to any
   registered mode via ctx.data — no longer contain it. The ONLY ways to
   read the truth are revealFor(id), which throws unless a verdict for that
   id is committed — and, on a live shift, unless the shift has settled,
   because a live verdict is not final until shiftEnd — and
   revealAllFor(report), which throws unless handed the report object
   emitted with the shiftEnd event. One more consumer lives below:
   maybeRespawn, the SPEC-2 §3 respawn trigger, which consults the vault
   but returns nothing and renders nothing — its only observable effect is
   a future arrival, which is the mechanic the spec defines on the truth.
   No code outside this section touches the vault.
========================================================================= */
var TRUTH_VAULT = new Map();
(function seal() {
  SHIFTS.forEach(function (sh) {
    (sh.accounts || []).forEach(function (a) {
      TRUTH_VAULT.set((sh.id || 's?') + '/' + a.id, a.reveal || null);
      delete a.reveal;
    });
  });
})();
var REPORT_TOKEN = null;
function revealFor(id) {
  if (!verdicts.has(id)) { throw new Error('sealed until verdict: ' + id); }
  if (liveActive() && !SETTLED) {
    /* SPEC-2 §2: in a live shift a verdict is not final until the shift
       ends (new sessions may reopen it), so the truth stays sealed too. */
    throw new Error('sealed until shiftEnd: live-shift verdicts settle at end of shift');
  }
  return TRUTH_VAULT.get(SHIFT.id + '/' + id);
}
function revealAllFor(report) {
  if (!REPORT_TOKEN || report !== REPORT_TOKEN) {
    throw new Error('sealed until shiftEnd: revealAllFor takes the report ' +
      'object emitted with the shiftEnd event');
  }
  var out = {};
  ACCOUNTS.forEach(function (a) {
    out[a.id] = TRUTH_VAULT.get(SHIFT.id + '/' + a.id);
  });
  return out;
}
/* The respawn trigger — SPEC-2 §3, the $101 lesson. Evaluated at every
   banCommitted, on case shifts only: if the banned account belongs to an
   actor with >=1 unbanned member on the platform, and that actor's respawn
   has not fired this shift, the respawn is scheduled to arrive delay_h
   (+4h) from now through the live engine's scheduler
   (state.dynamicArrivals). Full-cluster bans never trigger it: a case ban
   records every member verdict before any banCommitted fires, so by
   evaluation time no member is left. The truth consulted here never
   escapes — a new account simply arrives later, exactly what the fiction
   says the platform would see. */
function maybeRespawn(bannedId) {
  if (!SHIFT || !SHIFT.flags || !SHIFT.flags.cases) { return; }
  var truth = TRUTH_VAULT.get(SHIFT.id + '/' + bannedId);
  if (!truth || truth.truth !== 'malicious' || !truth.actor) { return; }
  var actor = truth.actor;
  if (respawnFired.has(actor)) { return; }
  var respawn = null;
  var membersLeft = 0;
  ACCOUNTS.forEach(function (a) {
    var t = TRUTH_VAULT.get(SHIFT.id + '/' + a.id) || {};
    if (a.respawn && t.respawn_of === actor) { respawn = a; return; }
    if (t.actor !== actor || a.id === bannedId) { return; }
    if (effectiveArrival(a) === null) { return; }  /* not on the platform this shift */
    var v = verdicts.get(a.id);
    if (!v || v.verdict !== 'ban') { membersLeft += 1; }
  });
  if (!respawn || effectiveArrival(respawn) !== null) { return; }
  if (membersLeft < 1) { return; }
  respawnFired.add(actor);
  var delay = Number(respawn.respawn && respawn.respawn.delay_h);
  if (!Number.isFinite(delay) || delay <= 0) { delay = 4; }
  state.dynamicArrivals.set(respawn.id, elapsedHours() + delay);
}
/* ======================= end reveal vault ================================ */

/* =========================================================================
   seeded shuffle — mulberry32, ?seed=N, default 1337
========================================================================= */
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    var t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
var seedParam = parseInt(new URLSearchParams(location.search).get('seed'), 10);
var SEED = Number.isFinite(seedParam) ? seedParam : 1337;
function shuffled(ids, seed) {
  var rng = mulberry32(seed);
  var arr = ids.slice();
  for (var i = arr.length - 1; i > 0; i--) {
    var j = Math.floor(rng() * (i + 1));
    var tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
  }
  return arr;
}

/* =========================================================================
   per-shift state
========================================================================= */
var SHIFT = null;
var ACCOUNTS = [];
var byId = new Map();
var SHIFT_END = 0;      /* latest session ts in the roster (for account age) */
var arrived = new Set();

var state = {
  phase: 'intro',            /* intro | play | interstitial | confirm-end | report */
  shiftId: null,
  order: [],
  currentId: null,
  elapsed: 0,               /* SPEC-2 §8: where the clock is, 0 -> length */
  length: 0,                /* shift length in hours (the data's `budget`) */
  score: 0,
  activeTab: 'content',
  pendingBanId: null,        /* account whose band picker is open */
  unlocked: new Map(),       /* id -> Set of tab keys */
  citations: new Map(),      /* id -> Map(citeKey -> {tab, label}) */
  hoursByAccount: new Map(), /* id -> hours the clock ran here (live shifts only) */
  audit: {},                 /* tabKey -> {opens, hours} */
  autoCleared: 0,
  queueFlags: new Map(),     /* id -> {label, cls, sticky} — set by modes, rendered by the queue */
  dynamicArrivals: new Map() /* id -> shift hour, for accounts scheduled at play time (respawns) */
};

function initShift(shift) {
  SHIFT = shift;
  ACCOUNTS = shift.accounts || [];
  byId = new Map();
  ACCOUNTS.forEach(function (a) { byId.set(a.id, a); });
  verdicts = new Map();
  REPORT_TOKEN = null;
  arrived = new Set();
  SHIFT_END = 0;
  ACCOUNTS.forEach(function (a) {
    (a.sessions || []).forEach(function (s) {
      var t = Date.parse(s.ts);
      if (t > SHIFT_END) { SHIFT_END = t; }
    });
  });
  state.phase = 'intro';
  state.shiftId = shift.id;
  state.order = shuffled(ACCOUNTS.map(function (a) { return a.id; }), SEED);
  state.currentId = null;
  /* SPEC-2 §8: the data's `budget` is the shift's LENGTH, not a spend cap. */
  state.length = Number(shift.budget) || 0;
  state.elapsed = 0;
  state.score = 0;
  state.activeTab = 'content';
  state.pendingBanId = null;
  state.unlocked = new Map();
  state.citations = new Map();
  state.hoursByAccount = new Map();
  state.audit = {};
  state.autoCleared = 0;
  state.queueFlags = new Map();
  state.dynamicArrivals = new Map();
  state.policyFlags = new Set();   /* finding #20 — annotations, never scored */
  state.secondOpinions = new Set(); /* finding #18 — who took the bait */
  arrivalAt = new Map();
  seenCount = new Map();
  reopenGrants = new Map();
  reverdictUsed = new Set();
  banCutoff = new Map();
  SETTLED = false;
  respawnFired = new Set();
  TABS.forEach(function (t) { state.audit[t.key] = { opens: 0, hours: 0 }; });
  ACCOUNTS.forEach(function (a) {
    state.unlocked.set(a.id, new Set(['content']));
    state.citations.set(a.id, new Map());
    state.hoursByAccount.set(a.id, 0);
  });
}

/* =========================================================================
   small helpers
========================================================================= */
function $(id) { return document.getElementById(id); }
function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) { n.className = cls; }
  if (text !== undefined && text !== null) { n.textContent = text; }
  return n;
}
function frag() { return document.createDocumentFragment(); }
function fmtTs(iso) { return iso ? iso.replace('T', ' ').replace(':00Z', 'Z') : '—'; }
function fmtPts(n) { return (n >= 0 ? '+' : '−') + Math.abs(n); }
function fmtScore(n) { return (n < 0 ? '−' : '') + Math.abs(n); }
function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }
function setText(id, txt) { var n = $(id); if (n) { n.textContent = txt; } }
/* Category grouping is presentational only (tick colors); the scorer's own
   read of categories arrives through pipeline.signals, not from this. */
var OFFENSIVE = { malware_dev: 1, exploit_help: 1, phishing_content: 1, spam_content: 1 };
function catClass(c) {
  if (OFFENSIVE[c]) { return 'cat-off'; }
  if (c === 'recon') { return 'cat-recon'; }
  return 'cat-benign';
}

/* =========================================================================
   live-shift engine (SPEC-2 §2) — one clock. Elapsed hours gate which
   accounts are in the queue and which sessions are visible. In non-live
   shifts everything appears at hour 0 and these reduce to identity.
========================================================================= */
function liveActive() { return !!(SHIFT && SHIFT.flags && SHIFT.flags.live); }
/* SPEC-2 §8: the clock exists only on a live shift. On shift 1 there is no
   clock at all — every tab is free and instant, and nothing advances. */
function clockRunning() { return liveActive(); }
function elapsedHours() { return state.elapsed; }
function hoursLeft() { return Math.max(0, state.length - state.elapsed); }
/* When the account arrives: its appears_at if scheduled; a play-time hour
   from state.dynamicArrivals if a mode scheduled it (respawns); else never. */
function effectiveArrival(a) {
  if (a.appears_at !== null && a.appears_at !== undefined) { return Number(a.appears_at) || 0; }
  return state.dynamicArrivals.has(a.id) ? state.dynamicArrivals.get(a.id) : null;
}
/* Session hours are absolute shift hours for scheduled accounts and
   relative to arrival for play-time-scheduled ones (contract v2). */
function sessionHour(a, s) {
  var base = (a.appears_at === null || a.appears_at === undefined)
    ? (arrivalAt.get(a.id) || 0) : 0;
  return base + (Number(s.appears_at) || 0);
}
/* The sessions the player can currently see. A banned account stops
   producing telemetry: its sessions freeze at the hour of the ban. */
function visibleSessions(a) {
  var ss = a.sessions || [];
  if (!liveActive()) { return ss; }
  var cap = elapsedHours();
  if (banCutoff.has(a.id)) { cap = Math.min(cap, banCutoff.get(a.id)); }
  var out = [];
  for (var i = 0; i < ss.length; i++) {
    if (sessionHour(a, ss[i]) <= cap) { out.push(ss[i]); }
  }
  return out;
}
/* A verdict can be placed (or, with an unused reopen grant, replaced). */
function decidable(id) { return !verdicts.has(id) || reopenGrants.has(id); }
/* How many of the four non-content tabs are open on this account. Under
   SPEC-2 §8 this — not hours — is the clock-independent measure of how
   much of the record a verdict actually rests on. */
function paidTabsOpened(id) {
  var owned = state.unlocked.get(id);
  if (!owned) { return 0; }
  var n = 0;
  PAID_TABS.forEach(function (k) { if (owned.has(k)) { n += 1; } });
  return n;
}
function paidTabsOpenedTotal() {
  var n = 0;
  ACCOUNTS.forEach(function (a) { n += paidTabsOpened(a.id); });
  return n;
}
function pointsFor(verdict, isActor) {
  return verdict === 'ban'
    ? (isActor ? POINTS.banActor : POINTS.banBenign)
    : verdict === 'monitor'
      ? (isActor ? POINTS.monitorActor : POINTS.monitorBenign)
      : (isActor ? POINTS.missActor : POINTS.clearBenign);
}
/* An unscheduled account (appears_at null — e.g. a respawn whose trigger
   never fired) that never arrived is outside this shift's reckoning. */
function inShiftScope(id) {
  if (arrived.has(id)) { return true; }
  var a = byId.get(id);
  return !(a && (a.appears_at === null || a.appears_at === undefined));
}
function rosterSize() {
  var n = 0;
  ACCOUNTS.forEach(function (a) { if (inShiftScope(a.id)) { n += 1; } });
  return n;
}

/* =========================================================================
   mode registry + events — SPEC-2 §0
   Core emits: 'shiftStart','arrival','tabOpened','verdict','banCommitted',
   'shiftEnd'. Mode parts (live.js, cases.js, career.js) register with
   Game.registerMode(name, {init(ctx), onEvent(ev, ctx)}). When no mode is
   registered every emit is a no-op. Modes receive the sealed data only;
   the vault rule above applies to them in full.
========================================================================= */
var MODES = new Map();
var CLOCK = {
  elapsed: function () { return state.elapsed; },
  length: function () { return state.length; },
  left: function () { return hoursLeft(); },
  /* SPEC-2 §8: advance the clock. ALWAYS succeeds — there is no budget to
     run out of, only a shift to run out. The clock stops at the shift's
     length; endIfOver() then closes the shift. auditKey attributes the time
     in the report's clock audit; new keys (e.g. 'wait') are created on
     first use, and opens are counted even on a clockless shift so the
     report can still say what was read. */
  spend: function (hrs, auditKey) {
    hrs = Number(hrs) || 0;
    if (hrs < 0) { hrs = 0; }
    if (auditKey) {
      if (!state.audit[auditKey]) { state.audit[auditKey] = { opens: 0, hours: 0 }; }
      state.audit[auditKey].opens += 1;
      if (clockRunning()) { state.audit[auditKey].hours += hrs; }
    }
    if (clockRunning() && hrs > 0) {
      state.elapsed = Math.min(state.length, state.elapsed + hrs);
    }
    renderHud();
    emitNewArrivals();
    return true;
  },
  /* SPEC-2 §8: a live shift ends when the clock reaches its length — the
     old exhaustion path, now reached by arriving rather than by running
     out. Callers that advance the clock (openTab in core, the Wait action
     in live.js) invoke this after their own work so the shift never ends
     mid-render. No-op on a shift with no clock. */
  endIfOver: function () {
    if (clockRunning() && state.phase === 'play' && state.elapsed >= state.length) {
      finishShift(false);
      return true;
    }
    return false;
  }
};
var UI = null; /* assigned before boot, below */
function makeCtx() {
  return { state: state, data: { meta: META, shifts: SHIFTS }, shift: SHIFT,
           clock: CLOCK, ui: UI };
}
function logModeError(name, where, e) {
  if (typeof console !== 'undefined' && console.error) {
    console.error('mode "' + name + '" failed in ' + where + ':', e);
  }
}
function registerMode(name, mode) {
  if (!name || typeof name !== 'string' || MODES.has(name)) { return false; }
  MODES.set(name, mode || {});
  if (mode && typeof mode.init === 'function') {
    try { mode.init(makeCtx()); } catch (e) { logModeError(name, 'init', e); }
  }
  return true;
}
function emit(type, payload) {
  if (!MODES.size) { return; }
  var ev = { type: type };
  if (payload) {
    Object.keys(payload).forEach(function (k) { ev[k] = payload[k]; });
  }
  MODES.forEach(function (mode, name) {
    if (mode && typeof mode.onEvent === 'function') {
      try { mode.onEvent(ev, makeCtx()); } catch (e) { logModeError(name, type, e); }
    }
  });
}
/* An account arrives when the clock reaches its appears_at (0 in non-live
   shifts, so everything arrives at shiftStart). Emitted once per account.
   Sessions landing later on an already-arrived account emit 'newSessions';
   if that account is decided — and not banned, a banned account produces
   no telemetry — it earns its one free re-verdict (SPEC-2 §2). Only new
   evidence reopens a verdict, and only once. */
function emitNewArrivals() {
  if (state.phase === 'intro') { return; }
  var elapsed = elapsedHours();
  state.order.forEach(function (id) {
    var a = byId.get(id);
    if (!a) { return; }
    if (!arrived.has(id)) {
      var at = effectiveArrival(a);
      if (at === null || at > elapsed) { return; }
      arrived.add(id);
      arrivalAt.set(id, at);
      seenCount.set(id, visibleSessions(a).length);
      emit('arrival', { id: id, at: at });
      return;
    }
    var vis = visibleSessions(a).length;
    var prev = seenCount.get(id) || 0;
    if (vis <= prev) { return; }
    seenCount.set(id, vis);
    var reopened = false;
    if (verdicts.has(id) && liveActive() && !reverdictUsed.has(id) && !reopenGrants.has(id)) {
      reopenGrants.set(id, true);
      reopened = true;
    }
    emit('newSessions', { id: id, count: vis - prev,
                          decided: verdicts.has(id), reopened: reopened });
  });
}

function loadShift(shiftId) {
  var sh = null;
  SHIFTS.forEach(function (s) { if (s.id === shiftId) { sh = s; } });
  if (!sh) { throw new Error('no such shift: ' + shiftId); }
  $('overlay').hidden = true;
  setModalOpen(false);
  $('overlay-end').hidden = true;
  setModalOpen(false);
  $('screen-play').hidden = true;
  $('screen-report').hidden = true;
  $('hud').hidden = true;
  $('btn-endshift').hidden = true;
  initShift(sh);
  renderIntro();
  $('screen-intro').hidden = false;
  return true;
}

window.Game = {
  registerMode: registerMode,
  revealFor: revealFor,
  revealAllFor: revealAllFor,
  loadShift: loadShift,
  banCase: caseBan
};

/* =========================================================================
   theme: default dark; prefers-color-scheme light gives light; manual
   toggle cycles auto -> dark -> light.
========================================================================= */
var THEME_MODES = ['auto', 'dark', 'light'];
var themeIdx = 0;
try {
  var storedTheme = localStorage.getItem('trigger-discipline-theme');
  if (storedTheme && THEME_MODES.indexOf(storedTheme) > 0) { themeIdx = THEME_MODES.indexOf(storedTheme); }
} catch (e) { /* file:// storage may be unavailable; auto is fine */ }
function applyTheme() {
  var mode = THEME_MODES[themeIdx];
  if (mode === 'auto') { document.documentElement.removeAttribute('data-theme'); }
  else { document.documentElement.setAttribute('data-theme', mode); }
  $('btn-theme').textContent = 'Theme: ' + mode;
  try { localStorage.setItem('trigger-discipline-theme', mode); } catch (e) { /* ignore */ }
}
$('btn-theme').addEventListener('click', function () {
  themeIdx = (themeIdx + 1) % THEME_MODES.length;
  applyTheme();
});
applyTheme();

/* =========================================================================
   intro / shift briefing
========================================================================= */
function renderIntro() {
  /* A shift that ships briefing paragraphs replaces the static fiction;
     shift 1's briefing IS the v1 intro text once the data agent lands. */
  var brief = SHIFT.briefing || [];
  if (brief.length) {
    var box = $('intro-fiction');
    if (box) {
      box.textContent = '';
      /* The first paragraph is the situation and it stays open; the rest is
         the shift's fine print, which a returning player wants and a first
         visitor is reading instead of playing. Same words, one click away. */
      box.appendChild(el('p', null, brief[0]));
      if (brief.length > 1) {
        var more = el('details', 'brief-more');
        more.appendChild(el('summary', null,
          'The rest of the briefing (' + plural(brief.length - 1, 'paragraph') + ')'));
        brief.slice(1).forEach(function (para) { more.appendChild(el('p', null, para)); });
        box.appendChild(more);
      }
      /* Findings #5/#21 — a policy bulletin lands between shifts, on the
         briefing of the shift it activates on. The constants are meta's
         (imported from hunt policy.py); the stories are the measured bugs
         the patches fixed. */
      PATCHES.forEach(function (p) {
        if (p.active_from !== SHIFT.id) { return; }
        var bb = el('div', 'bulletin-box');
        var made = false;
        if (p.id === 'strength_floor') {
          bb.appendChild(el('p', 'bulletin-title', 'Policy bulletin — corroboration floor'));
          bb.appendChild(el('p', 'small',
            'Effective this shift: a scorer signal below ' + MIN_CONTRIB +
            ' no longer carries a ban on its own. A 0.04 automation blip once ' +
            'counted as corroboration. Presence is not strength.'));
          made = true;
        } else if (p.id === 'min_observations') {
          bb.appendChild(el('p', 'bulletin-title', 'Policy bulletin — rate denominators'));
          bb.appendChild(el('p', 'small',
            'Effective this shift: a rate-derived signal needs at least ' +
            plural(MIN_OBS, 'observation') + ' to carry a ban. One refusal in ' +
            'one session once scored full strength. Strength is not sample size.'));
          made = true;
        }
        if (made) { box.appendChild(bb); }
      });
    }
  }
  setText('intro-shift', (SHIFT.title || '') +
    (SHIFT.subtitle ? ' — ' + SHIFT.subtitle : ''));
  var c = SHIFT.counts || META.counts || {};
  var nAcc = c.scheduled != null ? c.scheduled
    : (c.accounts != null ? c.accounts : ACCOUNTS.length);
  var nMal = c.malicious != null ? c.malicious : '?';
  var nBen = c.benign != null ? c.benign : '?';
  setText('intro-counts',
    plural(nAcc, 'account') + ' are in your queue. ' + nMal + ' of them belong to real ' +
    'threat-actor archetypes; ' + nBen + ' are innocent, and some of those were designed ' +
    'to look guilty on content.');
  if (liveActive()) {
    /* SPEC-2 §4: a live queue arrives as it arrives — announcing a maximum
       would announce the day's composition, and on some shifts that IS the
       test. The report states the maximum once the day is over. */
    setText('intro-max', 'unknown until the queue finishes arriving');
  } else {
    var maxScore = (typeof nMal === 'number' && typeof nBen === 'number')
      ? (nMal * POINTS.banActor + nBen * POINTS.clearBenign) : null;
    setText('intro-max', maxScore != null ? String(maxScore) : 'n/a');
  }
  /* SPEC-2 §8: one clock, and only on a live shift. There is no spend cap
     to announce, so this states the shift's length and how the clock moves. */
  setText('intro-clock', clockRunning()
    ? 'The shift runs ' + state.length + ' hours. Opening evidence advances the clock — ' +
      'the account file takes 1h, the other three take 2h each — and the shift ends when ' +
      'the clock reaches ' + state.length + '. Nothing is ever refused for lack of hours.'
    : 'Today the clock is off. Every tab is free and opens instantly.');
  setText('intro-seed', String(SEED));
}

/* =========================================================================
   HUD
========================================================================= */
function renderHud() {
  /* SPEC-2 §8: no clock on a non-live shift means no hours in the HUD. */
  var hoursEl = $('hud-hours');
  hoursEl.hidden = !clockRunning();
  hoursEl.textContent = clockRunning()
    ? 'hour ' + state.elapsed + ' of ' + state.length + ' · ' + hoursLeft() + 'h left'
    : '';
  hoursEl.className = (clockRunning() && hoursLeft() <= 4) ? 'low' : '';
  $('hud-progress').textContent = verdicts.size + '/' + rosterSize() + ' decided';
  $('hud-score').textContent = (liveActive() && !SETTLED)
    ? 'score at shift end'
    : 'score ' + fmtScore(state.score);
}

/* =========================================================================
   queue sidebar
========================================================================= */
function verdictLabel(v) {
  return v === 'ban' ? 'BANNED' : v === 'monitor' ? 'MONITORED' : 'CLEARED';
}
function verdictClass(v) {
  return v === 'ban' ? 'v-ban' : v === 'monitor' ? 'v-monitor' : 'v-clear';
}
function renderQueue() {
  var list = $('queue-list');
  list.textContent = '';
  var f = frag();
  state.order.forEach(function (id) {
    if (!arrived.has(id)) { return; }   /* not in the queue until it arrives */
    var a = byId.get(id);
    var li = el('li');
    var b = el('button');
    b.setAttribute('data-acct', id);
    if (id === state.currentId) { b.setAttribute('aria-current', 'true'); }
    var v = verdicts.get(id);
    if (v) { b.classList.add('done'); }
    var line1 = el('div');
    line1.appendChild(el('span', 'qid', id));
    if (v) {
      line1.appendChild(el('span', 'qverdict ' + verdictClass(v.verdict),
        ' ' + verdictLabel(v.verdict)));
    }
    var qf = state.queueFlags.get(id);
    if (qf) { line1.appendChild(el('span', 'qflag ' + (qf.cls || ''), qf.label)); }
    b.appendChild(line1);
    var meta = el('div', 'qmeta');
    meta.appendChild(el('span', null, (a.profile && a.profile.primary_channel) || '—'));
    meta.appendChild(el('span', null, plural(visibleSessions(a).length, 'session')));
    b.appendChild(meta);
    b.addEventListener('click', function () { openAccount(id); });
    li.appendChild(b);
    f.appendChild(li);
  });
  list.appendChild(f);
  scrollQueueToCurrent();
}

/* =========================================================================
   citations — §1: every evidence row rendered in an opened evidence tab
   is citable; a ban must cite at least one row from a non-content tab.
   SPEC-2 §8 removed the price, not the gate: the counter below talks about
   what a citation came FROM, which is what the policy actually reads.
========================================================================= */
function citeKey(tab, key) { return tab + ':' + key; }
function citationList(id) {
  var m = state.citations.get(id) || new Map();
  var out = [];
  m.forEach(function (v, k) { out.push({ key: k, tab: v.tab, label: v.label }); });
  return out;
}
/* Finding #20 — paid citations that hunt's policy would accept as
   corroboration: everything non-content EXCEPT a pipeline signal row whose
   signal is topic-derived. Topic in a different column is still topic. */
function nonTopicPaidCiteCount(id) {
  var names = (META.topic && META.topic.signals) || [];
  var n = 0;
  (state.citations.get(id) || new Map()).forEach(function (v, k) {
    if (v.tab === 'content') { return; }
    var m = /^pipeline:signal:(.+)$/.exec(k);
    if (m && names.indexOf(m[1]) >= 0) { return; }
    n += 1;
  });
  return n;
}

function paidCiteCount(id) {
  var n = 0;
  (state.citations.get(id) || new Map()).forEach(function (v) {
    if (v.tab !== 'content') { n += 1; }
  });
  return n;
}
function toggleCite(id, tab, key, label, on) {
  var m = state.citations.get(id);
  if (!m) { return; }
  var k = citeKey(tab, key);
  if (on) { m.set(k, { tab: tab, label: label }); } else { m.delete(k); }
  renderCiteCount();
}
function citeBox(a, tab, key, label) {
  var cb = el('input', 'cite-box');
  cb.type = 'checkbox';
  cb.setAttribute('aria-label', 'Cite: ' + label);
  var m = state.citations.get(a.id);
  cb.checked = !!(m && m.has(citeKey(tab, key)));
  cb.disabled = !decidable(a.id);
  cb.addEventListener('change', function () {
    toggleCite(a.id, tab, key, label, cb.checked);
  });
  return cb;
}
function renderCiteCount() {
  var n = $('cite-count');
  if (!n) { return; }
  var id = state.currentId;
  var total = id ? (state.citations.get(id) || new Map()).size : 0;
  var paid = id ? paidCiteCount(id) : 0;
  n.textContent = total
    ? (total + ' cited · ' + paid + ' non-content' +
       (paid > 0 && nonTopicPaidCiteCount(id) === 0 ? ' — all topic-derived' : ''))
    : 'nothing cited';
}

/* =========================================================================
   dossier
========================================================================= */
/* Finding #20 — FLAG POLICY GAP. An annotation, not a verdict: sometimes the
   ambiguous object is the policy itself, and the honest move is to put that
   on the record instead of pretending a verdict resolves it. Never scored,
   never gates anything; the report lists it and stops there. */
function togglePolicyFlag(id) {
  if (!byId.has(id) || !arrived.has(id)) { return; }
  if (state.policyFlags.has(id)) { state.policyFlags.delete(id); }
  else { state.policyFlags.add(id); }
  renderDossier();
}

/* The queue never scrolled to the account it had just opened, on either
   layout: on a phone the rail is a horizontal strip and the current account
   could sit off the end of it, and on a long desktop queue the highlight
   was below the fold. Keyboard navigation through the queue had the same
   problem. `nearest` so it does not jump when the row is already visible. */
function scrollQueueToCurrent() {
  /* aria-current sits on the BUTTON, not the li — the first version of this
     selector looked for it on the row and silently matched nothing. */
  var cur = document.querySelector('#queue-list [aria-current="true"]');
  var row = cur && (cur.closest ? cur.closest('li') : null);
  var target = row || cur;
  if (target && target.scrollIntoView) {
    target.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }
}

function openAccount(id) {
  if (!byId.has(id) || !arrived.has(id)) { return; }
  var qf = state.queueFlags.get(id);
  if (qf && !qf.sticky) { state.queueFlags.delete(id); }
  state.currentId = id;
  state.activeTab = 'content';   /* free view first, every time */
  state.pendingBanId = null;
  renderQueue();
  renderDossier();
  setNotice('');
}

function renderDossier() {
  var a = byId.get(state.currentId);
  var head = $('dossier-head');
  head.textContent = '';
  if (!a) { renderBandPicker(); emit('dossierRendered', { id: null }); return; }
  var h2 = el('h2', null, a.id);
  h2.setAttribute('tabindex', '-1');
  head.appendChild(h2);
  var metaBits = [
    ((a.profile && a.profile.primary_channel) || '—'),
    plural(visibleSessions(a).length, 'session'),
    paidTabsOpened(a.id) + ' of ' + PAID_TABS.length + ' evidence tabs open'
  ];
  /* SPEC-2 §8: hours only exist where a clock does. */
  if (clockRunning()) { metaBits.push(state.hoursByAccount.get(a.id) + 'h here'); }
  head.appendChild(el('span', 'meta', metaBits.join(' · ')));

  var bar = el('div');
  bar.id = 'verdict-bar';
  var v = verdicts.get(a.id);
  if (v && !reopenGrants.has(a.id)) {
    var chipTxt = verdictLabel(v.verdict) +
      (v.verdict === 'ban' && v.band ? ' (' + v.band.replace(/_/g, ' ') + ')' : '') +
      (v.points === null ? ' · settles at shift end' : ' · ' + fmtPts(v.points));
    bar.appendChild(el('span', 'verdict-chip ' + verdictClass(v.verdict), chipTxt));
  } else {
    if (v) {
      /* reopened: the standing verdict shows, and may be changed once */
      bar.appendChild(el('span', 'verdict-chip ' + verdictClass(v.verdict),
        verdictLabel(v.verdict)));
      bar.appendChild(el('span', 'meta',
        'reopened — new sessions arrived after this verdict; you may change it once, free'));
    }
    var count = el('span');
    count.id = 'cite-count';
    bar.appendChild(count);
    var banBtn = el('button', 'btn-ban', 'BAN');
    banBtn.appendChild(el('kbd', null, 'B'));
    banBtn.addEventListener('click', function () { requestBan(a.id); });
    var monBtn = el('button', 'btn-monitor', 'MONITOR');
    monBtn.appendChild(el('kbd', null, 'M'));
    monBtn.addEventListener('click', function () {
      closeBandPicker();
      commitVerdict(a.id, 'monitor');
    });
    var clearBtn = el('button', 'btn-clear', 'CLEAR');
    clearBtn.appendChild(el('kbd', null, 'C'));
    clearBtn.addEventListener('click', function () {
      closeBandPicker();
      commitVerdict(a.id, 'clear');
    });
    bar.appendChild(banBtn);
    bar.appendChild(monBtn);
    bar.appendChild(clearBtn);
  }
  head.appendChild(bar);

  /* finding #20 — the annotation row renders for every account, decided or
     not: a flag that only appeared on borderline accounts would be a tell. */
  var fRow = el('div');
  fRow.id = 'flag-row';
  var isFlagged = state.policyFlags.has(a.id);
  var fBtn = el('button', 'btn-flag' + (isFlagged ? ' on' : ''),
    isFlagged ? 'POLICY GAP ON RECORD' : 'FLAG POLICY GAP');
  fBtn.title = 'Sometimes the ambiguous thing is the policy, not the account — ' +
    'the scorer itself ships two definitions of "topic". Flagging puts that ' +
    'ambiguity on the record for the shift report. It never scores, never ' +
    'gates, and the verdict is still yours to make.';
  fBtn.appendChild(el('kbd', null, 'G'));
  fBtn.addEventListener('click', function () { togglePolicyFlag(a.id); });
  fRow.appendChild(fBtn);
  fRow.appendChild(el('span', 'meta', isFlagged
    ? 'on the record — the verdict is still yours'
    : 'annotation, not a verdict; never scored'));
  head.appendChild(fRow);

  renderBandPicker();
  renderCiteCount();
  renderTabBar();
  renderTabPanel();
  /* modes may append dossier actions (e.g. the case board's add/remove);
     the dossier is rebuilt on every render, so this fires every time */
  emit('dossierRendered', { id: a.id });
}

function renderTabBar() {
  var a = byId.get(state.currentId);
  var bar = $('tabbar');
  bar.textContent = '';
  if (!a) { return; }
  var owned = state.unlocked.get(a.id);
  TABS.forEach(function (t, i) {
    var b = el('button');
    b.appendChild(el('kbd', null, String(i + 1)));
    b.appendChild(document.createTextNode(' ' + t.label + ' '));
    /* SPEC-2 §8: the chip is a duration, and only where a clock runs.
       Without one every tab reads free, opened or not. */
    if (t.hours === 0) { b.appendChild(el('span', 'paid', 'free')); }
    else if (owned.has(t.key)) { b.appendChild(el('span', 'paid', 'open')); }
    else if (clockRunning()) { b.appendChild(el('span', 'cost', t.hours + 'h')); }
    else { b.appendChild(el('span', 'paid', 'free')); }
    if (t.key === state.activeTab) { b.setAttribute('aria-current', 'true'); }
    b.addEventListener('click', function () { openTab(t.key); });
    bar.appendChild(b);
  });
}

function setNotice(msg) { $('notice').textContent = msg || ''; }

function openTab(key) {
  var a = byId.get(state.currentId);
  if (!a) { return; }
  var tab = null;
  TABS.forEach(function (t) { if (t.key === key) { tab = t; } });
  if (!tab) { return; }
  var owned = state.unlocked.get(a.id);
  var paidNow = false;
  if (!owned.has(key)) {
    if (!decidable(a.id)) {
      setNotice('Verdict recorded. Evidence you did not open stays sealed.');
      return;
    }
    /* SPEC-2 §8: opening always succeeds. On a live shift it takes time;
       on a clockless one it takes nothing. There is no refusal here. */
    CLOCK.spend(tab.hours, key);
    owned.add(key);
    if (clockRunning()) {
      state.hoursByAccount.set(a.id, state.hoursByAccount.get(a.id) + tab.hours);
    }
    paidNow = true;
  }
  state.activeTab = key;
  setNotice('');
  renderDossier();
  emit('tabOpened', { id: a.id, tab: key, hours: tab.hours, paid: paidNow });
  CLOCK.endIfOver();
}

/* ---- tab panels. None of these reads anything a content filter, an
   account system, or the pipeline would not hand over — and none reads
   the vault (§7.4). Every row in an opened tab carries a citation box. -- */

function renderTabPanel() {
  var a = byId.get(state.currentId);
  var panel = $('tabpanel');
  panel.textContent = '';
  if (!a) { return; }
  var fn = { content: tabContent, account: tabAccount, behavior: tabBehavior,
             network: tabNetwork, pipeline: tabPipeline }[state.activeTab];
  panel.appendChild(fn(a));
}

function tabContent(a) {
  var f = frag();
  f.appendChild(el('h3', null, 'Content — what a content filter sees'));
  f.appendChild(el('p', 'small dim',
    'Prompt excerpts, category, and whether the model refused. Free, and free ' +
    'for a reason: cited content never carries a ban on its own.'));
  visibleSessions(a).forEach(function (s, i) {
    var d = el('div', 'sess');
    d.appendChild(citeBox(a, 'content', 'sess:' + i,
      'content — session ' + fmtTs(s.ts) + ', ' + s.category + ', ' + s.disposition));
    var body = el('div', 'sess-body');
    var chips = el('div');
    chips.appendChild(el('span', 'chip ' + catClass(s.category), s.category));
    chips.appendChild(el('span', 'chip' + (s.disposition === 'refused' ? ' refused' : ''), s.disposition));
    body.appendChild(chips);
    body.appendChild(el('div', 'excerpt', '“' + (s.prompt_excerpt || '') + '”'));
    d.appendChild(body);
    f.appendChild(d);
  });
  if (!visibleSessions(a).length) { f.appendChild(el('p', 'dim', 'No sessions on file.')); }
  return f;
}

function tabAccount(a) {
  var f = frag();
  var p = a.profile || {};
  f.appendChild(el('h3', null, 'Account file'));
  var created = Date.parse(p.created_at);
  var ageDays = (SHIFT_END && created) ? Math.max(0, Math.floor((SHIFT_END - created) / 86400000)) : null;
  var rows = [
    ['created', fmtTs(p.created_at) + (ageDays !== null ? '  (' + plural(ageDays, 'day') + ' old at end of shift)' : '')],
    ['email', p.email_kind || '—'],
    ['payment', p.payment || '—'],
    ['phone verified', p.phone_verified ? 'yes' : 'no']
  ];
  var t = el('table');
  rows.forEach(function (r) {
    var tr = el('tr');
    var tdc = el('td', 'citecell');
    tdc.appendChild(citeBox(a, 'account', r[0], 'account file — ' + r[0] + ': ' + r[1]));
    tr.appendChild(tdc);
    tr.appendChild(el('th', null, r[0]));
    tr.appendChild(el('td', 'mono', r[1]));
    t.appendChild(tr);
  });
  f.appendChild(t);
  return f;
}

function tabBehavior(a) {
  var f = frag();
  f.appendChild(el('h3', null, 'Behavior'));
  var ss = visibleSessions(a).slice();
  if (!ss.length) { f.appendChild(el('p', 'dim', 'No sessions on file.')); return f; }
  var times = ss.map(function (s) { return Date.parse(s.ts); });
  var t0 = Math.min.apply(null, times), t1 = Math.max.apply(null, times);
  var spanDays = (t1 - t0) / 86400000;

  var stats = el('div', 'statrow');
  function stat(key, k, v) {
    var d = el('div', 'stat');
    d.appendChild(citeBox(a, 'behavior', key, 'behavior — ' + k + ': ' + v));
    var inner = el('div');
    inner.appendChild(el('div', 'k', k));
    inner.appendChild(el('div', 'v', v));
    d.appendChild(inner);
    return d;
  }
  stats.appendChild(stat('volume', 'volume', ss.length + ' sessions / ' + spanDays.toFixed(1) + ' days'));
  var refused = ss.filter(function (s) { return s.disposition === 'refused'; }).length;
  stats.appendChild(stat('refusal', 'refusal rate', refused + '/' + ss.length + ' (' + Math.round(100 * refused / ss.length) + '%)'));
  if (ss.length > 1) {
    var gaps = [];
    for (var i = 1; i < times.length; i++) { gaps.push((times[i] - times[i - 1]) / 60000); }
    gaps.sort(function (x, y) { return x - y; });
    var median = gaps[Math.floor(gaps.length / 2)];
    var mean = gaps.reduce(function (s, g) { return s + g; }, 0) / gaps.length;
    var sd = Math.sqrt(gaps.reduce(function (s, g) { return s + (g - mean) * (g - mean); }, 0) / gaps.length);
    stats.appendChild(stat('cadence', 'cadence', 'median gap ' + Math.round(median) + ' min · σ ' + sd.toFixed(1) + ' min'));
  } else {
    stats.appendChild(stat('cadence', 'cadence', 'single session'));
  }
  f.appendChild(stats);

  /* timeline (decorative; the numbers above carry the same information) */
  var W = 600, H = 56, PAD = 16;
  var svgParts = ['<svg class="tl" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-hidden="true">'];
  svgParts.push('<line class="axis" x1="' + PAD + '" y1="' + (H / 2) + '" x2="' + (W - PAD) + '" y2="' + (H / 2) + '" stroke-width="1"/>');
  ss.forEach(function (s) {
    var t = Date.parse(s.ts);
    var x = (t1 === t0) ? W / 2 : PAD + (t - t0) / (t1 - t0) * (W - 2 * PAD);
    svgParts.push('<line class="tick ' + catClass(s.category) + '" x1="' + x.toFixed(1) +
      '" y1="14" x2="' + x.toFixed(1) + '" y2="' + (H - 14) + '" stroke-width="2"/>');
  });
  svgParts.push('</svg>');
  var svgWrap = el('div');
  svgWrap.innerHTML = svgParts.join('');   /* numeric values and fixed class names only */
  f.appendChild(svgWrap);
  var axisNote = el('p', 'small dim', 'first session ' + fmtTs(ss[0].ts) + ' · last ' + fmtTs(ss[ss.length - 1].ts));
  f.appendChild(axisNote);

  f.appendChild(el('h3', null, 'Category mix over time'));
  var strip = el('div', 'seqstrip');
  ss.forEach(function (s) {
    var i = el('i', catClass(s.category));
    i.title = s.category + ' · ' + fmtTs(s.ts);
    strip.appendChild(i);
  });
  f.appendChild(strip);
  var counts = {};
  ss.forEach(function (s) { counts[s.category] = (counts[s.category] || 0) + 1; });
  var mix = Object.keys(counts).map(function (c) { return c + ' ×' + counts[c]; }).join(' · ');
  var mixRow = el('div', 'overlap-row');
  mixRow.appendChild(citeBox(a, 'behavior', 'mix', 'behavior — category mix: ' + mix));
  var mixBody = el('div', 'overlap-body');
  mixBody.appendChild(el('p', 'small mono', mix));
  mixRow.appendChild(mixBody);
  f.appendChild(mixRow);
  return f;
}

function acctChip(id) {
  /* an account referenced before it has arrived is a name, not a link */
  if (byId.has(id) && arrived.has(id)) {
    var b = el('button', 'acct-link', id);
    b.addEventListener('click', function () { openAccount(id); });
    return b;
  }
  return el('span', 'mono small', id);
}

function tabNetwork(a) {
  var f = frag();
  f.appendChild(el('h3', null, 'Network'));
  var ss = visibleSessions(a);
  var t = el('table');
  var hr = el('tr');
  ['', 'ts', 'src ip', 'asn', 'country'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
  t.appendChild(hr);
  ss.forEach(function (s, i) {
    var tr = el('tr');
    var tdc = el('td', 'citecell');
    tdc.appendChild(citeBox(a, 'network', 'sess:' + i,
      'network — session ' + fmtTs(s.ts) + ' via ' + (s.src_ip || '—') + ' ' +
      (s.asn || '—') + ' ' + (s.country || '—')));
    tr.appendChild(tdc);
    tr.appendChild(el('td', 'mono small', fmtTs(s.ts)));
    tr.appendChild(el('td', 'mono small', s.src_ip || '—'));
    tr.appendChild(el('td', 'mono small', s.asn || '—'));
    tr.appendChild(el('td', 'mono small', s.country || '—'));
    t.appendChild(tr);
  });
  f.appendChild(t);

  f.appendChild(el('h3', null, 'Overlaps with other queue accounts'));
  var net = a.network || {};
  var kinds = [
    ['shared_asn', 'same ASN'],
    ['shared_ip', 'same IP'],
    ['shared_target', 'same target org'],
    ['shared_cadence', 'same automation cadence'],
    ['shared_hours', 'same active hours']
  ];
  var any = false;
  kinds.forEach(function (k) {
    var ids = net[k[0]] || [];
    if (!ids.length) { return; }
    any = true;
    var row = el('div', 'overlap-row');
    row.appendChild(citeBox(a, 'network', k[0],
      'network — ' + k[1] + ': ' + ids.join(' ')));
    var body = el('div', 'overlap-body');
    var line = el('p');
    line.appendChild(el('span', 'dim small', k[1] + ': '));
    ids.forEach(function (id) { line.appendChild(acctChip(id)); line.appendChild(document.createTextNode(' ')); });
    body.appendChild(line);
    /* Finding #25 — the first-seen column. An overlap says two accounts
       touched the same thing; the order says who touched it first. Derived
       from timestamps already in the rows; identifier kinds only. */
    var fsAll = (net.first_seen || {})[k[0]];
    if (fsAll) {
      ids.forEach(function (id) {
        var fs = fsAll[id];
        if (!fs) { return; }
        body.appendChild(el('p', 'small dim',
          'first seen with the shared token — this account ' + fmtTs(fs[0]) +
          ' · ' + id + ' ' + fmtTs(fs[1])));
      });
    }
    row.appendChild(body);
    f.appendChild(row);
  });
  if (!any) {
    f.appendChild(el('p', 'dim', 'No other queue account shares infrastructure or targets with this one.'));
  } else {
    f.appendChild(el('p', 'small dim', 'An overlap is an observation, not a link. Thousands of unrelated people share a VPN exit.'));
  }
  return f;
}


/* --- where this risk sits in the queue it came from ---------------------
   The score has always been shown against the lead threshold and never
   against the population, which is the one comparison this project argues
   for everywhere else: a number without its base rate is not a finding.
   Computed over the accounts that have ARRIVED, because the queue the
   player is working is the only population they can actually see. */
function riskContext(a) {
  var mine = Number((a.pipeline || {}).risk || 0);
  var thr = Number((a.pipeline || {}).lead_threshold || 0);
  /* Rows, not bare numbers: several accounts in a quiet queue score exactly
     the same, and marking the subject by value marks all of them. */
  var pop = [];
  ACCOUNTS.forEach(function (x) {
    if (!arrived.has(x.id) || !inShiftScope(x.id)) { return; }
    pop.push({ id: x.id, r: Number((x.pipeline || {}).risk || 0) });
  });
  if (pop.length < 2) { return null; }
  pop.sort(function (x, y) { return x.r - y.r; });
  var vals = pop.map(function (x) { return x.r; });
  return {
    n: pop.length,
    pct: Math.round(100 * vals.filter(function (r) { return r < mine; }).length / pop.length),
    over: vals.filter(function (r) { return r >= thr; }).length,
    median: vals[Math.floor(vals.length / 2)],
    max: vals[vals.length - 1],
    pop: pop, id: a.id, mine: mine, thr: thr
  };
}

function riskStrip(ctx) {
  /* One tick per arrived account, ordered by risk. The subject is marked,
     the lead line is drawn where it actually falls, and the whole thing is
     a picture of the sentence beneath it. */
  var wrap = el('div', 'riskdist');
  var span = Math.max(ctx.max, ctx.thr) || 1;
  ctx.pop.forEach(function (row) {
    var i = el('i');
    i.style.height = Math.max(2, Math.round(row.r / span * 16)) + 'px';
    if (row.id === ctx.id) { i.className = 'me'; }
    else if (row.r >= ctx.thr) { i.className = 'over'; }
    i.title = row.id + ' — ' + row.r.toFixed(3);
    wrap.appendChild(i);
  });
  return wrap;
}

function tabPipeline(a) {
  var f = frag();
  f.appendChild(el('h3', null, 'Pipeline read'));
  var pl = a.pipeline || {};
  var riskRow = el('div', 'risk-row');
  riskRow.appendChild(citeBox(a, 'pipeline', 'risk',
    'pipeline — risk ' + Number(pl.risk || 0).toFixed(3) + ', ' +
    (pl.lead ? 'LEAD' : 'below the lead line')));
  var riskLine = el('p', 'riskline', 'risk ' + Number(pl.risk || 0).toFixed(3) + ' ');
  riskLine.appendChild(pl.lead
    ? el('span', 'badge-lead', 'LEAD')
    : el('span', 'badge-nolead', 'below the lead line'));
  riskRow.appendChild(riskLine);
  f.appendChild(riskRow);
  f.appendChild(el('p', 'small dim', 'A lead is a queue entry, never a verdict.'));

  /* The base rate, on the same screen as the score. */
  var ctx = riskContext(a);
  if (ctx) {
    var ctxRow = el('div', 'risk-context');
    ctxRow.appendChild(riskStrip(ctx));
    var line = el('p', 'small dim');
    line.appendChild(document.createTextNode('Percentile '));
    line.appendChild(el('strong', null, String(ctx.pct)));
    line.appendChild(document.createTextNode(
      ' of the ' + plural(ctx.n, 'account') + ' that have arrived · '));
    line.appendChild(el('strong', null, String(ctx.over)));
    line.appendChild(document.createTextNode(
      ' of them are already over the lead line · median '));
    line.appendChild(el('strong', 'mono', ctx.median.toFixed(3)));
    line.appendChild(document.createTextNode('.'));
    ctxRow.appendChild(line);
    f.appendChild(ctxRow);
  }

  /* Finding #20 — the two shipped definitions of "topic". Both accountings
     recompute from numbers already on this screen; META.topic carries hunt's
     own signal set and weight shares, imported by build_data — the strip
     renders on every account, because a strip that only appeared where the
     definitions disagree would be a tell. */
  if (META.topic) {
    var tp = META.topic;
    var risk = Number(pl.risk || 0);
    var lthr = Number(pl.lead_threshold || 0);
    var defs = [
      { label: 'content only — the headline’s definition',
        share: Number(tp.content_weight),
        own: Number(pl.content_only_score || 0) },
      { label: 'content + capability trajectory — the policy’s list',
        share: Number(tp.policy_share),
        own: Number(pl.topic_derived_score || 0) }
    ];
    var tbox = el('div', 'topic-box');
    tbox.appendChild(el('p', 'small dim',
      'What counts as topic? The research ships two answers, and they are not the same number.'));
    var tt = el('table');
    var thd = el('tr');
    ['definition', 'of the weight vector', 'this account', 'without it'].forEach(function (h) {
      thd.appendChild(el('th', null, h));
    });
    tt.appendChild(thd);
    var leadsWithout = [];
    defs.forEach(function (d) {
      var rest = Math.max(0, risk - d.own);
      var still = rest >= lthr;
      leadsWithout.push(still);
      var tr = el('tr');
      tr.appendChild(el('td', 'small', d.label));
      tr.appendChild(el('td', 'mono small', d.share.toFixed(2)));
      tr.appendChild(el('td', 'mono small', d.own.toFixed(3)));
      tr.appendChild(el('td', 'mono small',
        rest.toFixed(3) + (still ? ' — still a lead' : ' — below the line')));
      tt.appendChild(tr);
    });
    tbox.appendChild(tt);
    if (leadsWithout[0] !== leadsWithout[1]) {
      tbox.appendChild(el('p', 'small',
        'The two definitions disagree about whether this account leads without its ' +
        'topic signals. The headline uses the first, the policy’s corroboration rule ' +
        'the second; which number you quote depends on which file you read.'));
    }
    f.appendChild(tbox);
  }

  var sigs = pl.signals || [];
  if (sigs.length) {
    var t = el('table');
    var hr = el('tr');
    ['', 'signal', 'value', 'evidence'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
    t.appendChild(hr);
    sigs.forEach(function (s) {
      var tr = el('tr');
      var quiet = !s.note;
      var tdc = el('td', 'citecell');
      tdc.appendChild(citeBox(a, 'pipeline', 'signal:' + s.name,
        'pipeline — signal ' + s.name + ' ' + Number(s.value).toFixed(3) + ': ' +
        (s.note || 'did not fire')));
      tr.appendChild(tdc);
      var tdName = el('td', quiet ? 'mono small dim' : 'mono small', s.name);
      if (META.topic && (META.topic.signals || []).indexOf(s.name) >= 0) {
        /* finding #20 — the row the citation gate will not accept alone */
        tdName.appendChild(el('span', 'dim small', ' · topic-derived'));
      }
      tr.appendChild(tdName);
      /* contract 3: a signal that did not fire ships its name and, where
         it has one, its denominator. Absent value means zero. */
      var tdVal = el('td', quiet ? 'mono small dim' : 'mono small', Number(s.value || 0).toFixed(3));
      if (s.n_observations !== null && s.n_observations !== undefined) {
        /* finding #21 — a rate carries its denominator on its face. Reading
           it is the craft the bulletin later enforces. */
        tdVal.appendChild(el('span', 'dim small', ' n=' + s.n_observations));
      }
      tr.appendChild(tdVal);
      /* A signal that did not fire is evidence too: it is the scorer saying it looked
         and found nothing. Rendering the whole vector makes the silence visible. */
      tr.appendChild(el('td', quiet ? 'small dim' : 'small', s.note || 'did not fire'));
      t.appendChild(tr);
    });
    f.appendChild(t);
  } else {
    f.appendChild(el('p', 'dim', 'No nonzero signals. The scorer has nothing to say about this account.'));
  }

  var cl = pl.cluster;
  if (cl) {
    var box = el('div', 'cluster-box');
    var headRow = el('div', 'overlap-row');
    headRow.appendChild(citeBox(a, 'pipeline', 'cluster',
      'pipeline — cluster ' + cl.assessment + ' (' + (cl.confidence_band || 'no band') +
      '), policy ' + (cl.decision || '—')));
    var headBody = el('div', 'overlap-body');
    var head = el('p');
    head.appendChild(el('span', 'mono', cl.assessment + ' '));
    head.appendChild(el('span', 'dim small', '(' + (cl.confidence_band || 'no band') + ') · policy: '));
    head.appendChild(el('span', cl.decision === 'enforce' ? 'dec-enforce' : 'dec-monitor',
      String(cl.decision || '').toUpperCase()));
    headBody.appendChild(head);
    /* Finding #24 — the same assessment, run 12 times. The decision column
       held every run on every cluster; the band is the part that moves, and
       on the hardest account it was a coin flip. The histogram is measured
       (hunt data/reps.json); the band in the line above is one draw from it. */
    if (cl.stability) {
      var st = cl.stability;
      var bandTxt = Object.keys(st.bands).sort(function (x, y) {
        return st.bands[y] - st.bands[x];
      }).map(function (k) { return k + ' ×' + st.bands[k]; }).join(', ');
      var decTxt = Object.keys(st.decisions).map(function (k) {
        return k + ' ×' + st.decisions[k];
      }).join(', ');
      var wobbles = Object.keys(st.bands).length > 1;
      headBody.appendChild(el('p', 'small dim',
        'across ' + st.reps + ' runs — band: ' + bandTxt + ' · decision: ' + decTxt +
        (wobbles
          ? '. The decision is the stable column; the band above is one draw.'
          : '. Both columns held every run.')));
    }
    headRow.appendChild(headBody);
    box.appendChild(headRow);
    if (cl.summary) { box.appendChild(el('p', 'small', cl.summary)); }
    /* Finding #18 — the second opinion. Free, never scored, never blocking:
       the verdict shown is the measured artifact's own (hunt data/judge.json,
       decorrelated run), and the report is where its margin gets quoted. The
       UI endorses nothing; the offer IS the mechanic. */
    if (cl.second_opinion) {
      var so = cl.second_opinion;
      if (state.secondOpinions.has(a.id)) {
        box.appendChild(el('p', 'advisor-line small',
          'Advisor (' + so.judge_model + ', decorrelated, ' +
          plural(so.reps, 'run') + '): ' + so.overall +
          (so.failed && so.failed.length
            ? ' — failed: ' + so.failed.join(', ')
            : ' — 0 failures')));
      } else {
        var sop = el('p', 'small');
        var sob = el('button', 'btn-advisor', 'Request a second opinion');
        sob.addEventListener('click', function () {
          state.secondOpinions.add(a.id);
          renderTabPanel();
        });
        sop.appendChild(sob);
        sop.appendChild(el('span', 'dim small',
          ' free — an automated review of this assessment'));
        box.appendChild(sop);
      }
    }
    var mem = el('p');
    mem.appendChild(el('span', 'dim small', 'cluster members: '));
    (cl.members || []).forEach(function (id) { mem.appendChild(acctChip(id)); mem.appendChild(document.createTextNode(' ')); });
    box.appendChild(mem);
    f.appendChild(box);
  } else {
    f.appendChild(el('p', 'dim', 'No cluster. Attribution links this account to nothing.'));
  }
  return f;
}

/* =========================================================================
   the ban flow — §1: citation gate, then band, then commit
========================================================================= */
/* The cited non-content rows, with each pipeline SIGNAL row resolved against
   the account's own breakdown so the gate can read its strength and its
   denominator. Non-signal rows (account file, behavior, network, the risk
   and cluster rows) carry no value and are not what #5/#21 patched. */
function citedPaidRows(id) {
  var a = byId.get(id);
  var sigs = ((a && a.pipeline) || {}).signals || [];
  var rows = [];
  (state.citations.get(id) || new Map()).forEach(function (v, k) {
    if (v.tab === 'content') { return; }
    var m = /^pipeline:signal:(.+)$/.exec(k);
    var row = { signal: m ? m[1] : null, value: null, nObs: null };
    if (row.signal) {
      sigs.forEach(function (s) {
        if (s.name === row.signal) {
          row.value = Number(s.value);
          row.nObs = (s.n_observations === null || s.n_observations === undefined)
            ? null : Number(s.n_observations);
        }
      });
    }
    rows.push(row);
  });
  return rows;
}

function requestBan(id) {
  if (!decidable(id)) { return; }
  if (paidCiteCount(id) < 1) { setNotice(REFUSE_CONTENT); return; }
  /* finding #20: a ban whose only non-content evidence is a topic-derived
     scorer row is topic-only enforcement with extra steps */
  if (nonTopicPaidCiteCount(id) < 1) { setNotice(REFUSE_TOPIC); return; }
  /* findings #5/#21: under the active bulletins, a cited signal row must
     clear the strength floor, and a rate row must clear its denominator.
     One valid non-topic row anywhere carries the ban. */
  var topicNames = (META.topic && META.topic.signals) || [];
  var weakFail = null, thinFail = null;
  var valid = citedPaidRows(id).some(function (r) {
    if (!r.signal) { return true; }
    if (topicNames.indexOf(r.signal) >= 0) { return false; }
    if (patchActive('strength_floor') && r.value !== null && r.value < MIN_CONTRIB) {
      weakFail = r;
      return false;
    }
    if (patchActive('min_observations') && r.nObs !== null && r.nObs < MIN_OBS) {
      thinFail = r;
      return false;
    }
    return true;
  });
  if (!valid) {
    setNotice(weakFail
      ? REFUSE_WEAK + ' Cited: ' + weakFail.signal + ' at ' +
        weakFail.value.toFixed(3) + '; the floor is ' + MIN_CONTRIB + '.'
      : REFUSE_THIN + ' Cited: ' + thinFail.signal + ' over ' +
        plural(thinFail.nObs, 'observation') + '; the floor is ' + MIN_OBS + '.');
    return;
  }
  setNotice('');
  state.pendingBanId = id;
  renderBandPicker();
}
function closeBandPicker() {
  if (state.pendingBanId === null) { return; }
  state.pendingBanId = null;
  renderBandPicker();
}
function chooseBand(id, bandName) {
  if (!decidable(id)) { closeBandPicker(); return; }
  if (Number(BANDS[bandName]) < FLOOR_P) { setNotice(REFUSE_FLOOR); return; }
  closeBandPicker();
  setNotice('');
  commitVerdict(id, 'ban', { band: bandName });
}
function renderBandPicker() {
  var box = $('band-picker');
  var id = state.pendingBanId;
  box.textContent = '';
  if (id === null || id !== state.currentId) { box.hidden = true; return; }
  box.hidden = false;
  box.appendChild(el('p', 'bp-title',
    'How confident is this ban? The band is a claim; the shift report scores it.'));
  var row = el('div', 'bp-bands');
  BAND_LIST.forEach(function (b, i) {
    var btn = el('button');
    btn.appendChild(el('kbd', null, String(i + 1)));
    btn.appendChild(document.createTextNode(' ' + b.label + ' '));
    btn.appendChild(el('span', 'band-p', 'P ' + b.p.toFixed(2)));
    btn.addEventListener('click', function () { chooseBand(id, b.name); });
    row.appendChild(btn);
  });
  var cancel = el('button', null, 'Cancel ');
  cancel.appendChild(el('kbd', null, 'Esc'));
  cancel.addEventListener('click', closeBandPicker);
  row.appendChild(cancel);
  box.appendChild(row);
  box.appendChild(el('p', 'bp-floor', 'Policy floor: “' +
    FLOOR_BAND.replace(/_/g, ' ') + '” (P ' + FLOOR_P.toFixed(2) +
    '). Below it, the ban is refused.'));
}

/* =========================================================================
   verdicts + interstitial. revealFor() is legal from here on because the
   verdict is committed on the first line.
========================================================================= */
function commitVerdict(id, verdict, opts) {
  opts = opts || {};
  var prev = verdicts.get(id);
  if (prev) {
    /* only new evidence reopens a verdict, and only once — never regret */
    if (!reopenGrants.has(id)) { return; }
    reopenGrants.delete(id);
    reverdictUsed.add(id);
  }
  if (state.pendingBanId === id) { state.pendingBanId = null; renderBandPicker(); }
  var rec = {
    verdict: verdict,
    points: 0,
    auto: !!opts.auto,
    reverdict: !!prev,
    band: opts.band || null,
    p: opts.band ? Number(BANDS[opts.band]) : null,
    citations: citationList(id)
  };
  verdicts.set(id, rec);
  if (verdict === 'ban') { banCutoff.set(id, elapsedHours()); }
  if (liveActive() && !SETTLED) {
    /* SPEC-2 §2: in a live shift the final verdict scores at shiftEnd.
       No reveal, no points, no interstitial — the queue keeps moving. */
    rec.points = null;
    renderHud();
    renderQueue();
    emit('verdict', { id: id, verdict: verdict, band: rec.band, points: null,
                      auto: rec.auto, reverdict: rec.reverdict });
    if (verdict === 'ban') {
      emit('banCommitted', { id: id, band: rec.band, citations: rec.citations.slice() });
      maybeRespawn(id);
    }
    if (!opts.auto) { advanceAfterVerdict(); }
    return;
  }
  var truth = revealFor(id);
  var isActor = truth && truth.truth === 'malicious';
  var points = pointsFor(verdict, isActor);
  rec.points = points;
  state.score += points;
  renderHud();
  renderQueue();
  emit('verdict', { id: id, verdict: verdict, band: rec.band, points: points,
                    auto: rec.auto, reverdict: rec.reverdict });
  if (verdict === 'ban') {
    emit('banCommitted', { id: id, band: rec.band, citations: rec.citations.slice() });
    maybeRespawn(id);
  }
  if (!opts.auto) { showInterstitial(id, verdict, points, truth, rec); }
}

/* Live shifts have no interstitial: move to the next undecided account, or
   hold position while the queue waits on scheduled arrivals, or end. */
function advanceAfterVerdict() {
  var next = nextUndecided();
  if (next !== null) {
    openAccount(next);
    var h2 = $('dossier-head').querySelector('h2');
    if (h2) { h2.focus(); }
    return;
  }
  var morePending = state.order.some(function (id) {
    return !arrived.has(id) && effectiveArrival(byId.get(id)) !== null;
  });
  if (morePending && hoursLeft() > 0) {
    renderDossier();
    setNotice('The queue is clear for now. Wait (W) advances the clock.');
    return;
  }
  finishShift(false);
}

/* =========================================================================
   case bans — SPEC-2 §3. A case with >=2 members is banned once: one
   citation of a link reason plus one band, applied to every member, scored
   per member on the same table. parts/cases.js owns the board, computes
   which link reasons hold, and carries the refusal copy; this is the
   mechanical commit path, and it re-checks every policy gate (fail closed)
   so nothing can commit a case ban the policy would refuse. Returns
   {ok:true, banned:[ids], skipped:[ids]} or {ok:false, refused:code} with
   codes: cases-off | phase | args | members | band | floor | link | decided.
========================================================================= */
function caseBan(ids, bandName, reasons) {
  if (!SHIFT || !SHIFT.flags || !SHIFT.flags.cases) { return { ok: false, refused: 'cases-off' }; }
  if (state.phase !== 'play') { return { ok: false, refused: 'phase' }; }
  if (!Array.isArray(ids) || !Array.isArray(reasons)) { return { ok: false, refused: 'args' }; }
  var members = [];
  ids.forEach(function (id) {
    if (byId.has(id) && arrived.has(id) && members.indexOf(id) < 0) { members.push(id); }
  });
  var minMembers = Number(POLICY.case_min_members) || 2;
  if (members.length < minMembers) { return { ok: false, refused: 'members' }; }
  if (!(bandName in BANDS)) { return { ok: false, refused: 'band' }; }
  if (Number(BANDS[bandName]) < FLOOR_P) { return { ok: false, refused: 'floor' }; }
  /* §3: an overlap is an observation, not a link — shared_asn or shared_ip
     alone never carries a case ban. The lists come from the policy in the
     data block; nothing here restates hunt's link semantics. */
  var sufficient = POLICY.sufficient_link_reasons || ['shared_target', 'shared_cadence'];
  if (!reasons.length || !reasons.some(function (r) { return sufficient.indexOf(r) >= 0; })) {
    return { ok: false, refused: 'link' };
  }
  var targets = members.filter(decidable);
  if (!targets.length) { return { ok: false, refused: 'decided' }; }

  /* Phase 1 — record every member verdict before any event fires. The
     respawn trigger at each banCommitted therefore sees the whole batch:
     a full-cluster case ban leaves no member unbanned and never triggers
     a respawn (SPEC-2 §3). */
  var kindLabels = { shared_asn: 'same ASN', shared_ip: 'same IP',
                     shared_target: 'same target org',
                     shared_cadence: 'same automation cadence',
                     shared_hours: 'same active hours' };
  var linkLabel = 'case link — ' +
    reasons.map(function (r) { return kindLabels[r] || r; }).join(' + ') +
    ' across ' + members.length + ' accounts';
  targets.forEach(function (id) {
    var prev = verdicts.get(id);
    if (prev) {
      /* a decided member is only here through an unused reopen grant */
      reopenGrants.delete(id);
      reverdictUsed.add(id);
    }
    var cm = state.citations.get(id);
    if (cm) { cm.set(citeKey('case', 'link'), { tab: 'case', label: linkLabel }); }
    verdicts.set(id, {
      verdict: 'ban', points: 0, auto: false, reverdict: !!prev,
      band: bandName, p: Number(BANDS[bandName]),
      citations: citationList(id), caseBan: true
    });
    banCutoff.set(id, elapsedHours());
  });

  /* Phase 2 — score (or defer, in a live shift) and emit, per member. */
  var deferred = liveActive() && !SETTLED;
  targets.forEach(function (id) {
    var rec = verdicts.get(id);
    if (deferred) {
      rec.points = null;
    } else {
      var truth = revealFor(id);
      var isActor = truth && truth.truth === 'malicious';
      rec.points = pointsFor('ban', isActor);
      state.score += rec.points;
    }
    emit('verdict', { id: id, verdict: 'ban', band: rec.band, points: rec.points,
                      auto: false, reverdict: rec.reverdict, caseBan: true });
    emit('banCommitted', { id: id, band: rec.band, citations: rec.citations.slice(),
                           caseBan: true });
    maybeRespawn(id);
  });

  if (state.pendingBanId !== null && !decidable(state.pendingBanId)) { state.pendingBanId = null; }
  renderHud();
  renderQueue();
  var skipped = members.filter(function (id) { return targets.indexOf(id) < 0; });
  /* If the open account was decided by this ban, move on the way a single
     live verdict would; otherwise stay put and just refresh. No
     interstitials either way — a case ban is one action, and on the live
     shifts that carry cases the grading lands in the report. */
  if (liveActive() && state.currentId &&
      verdicts.has(state.currentId) && !reopenGrants.has(state.currentId)) {
    advanceAfterVerdict();
  } else {
    renderDossier();
  }
  return { ok: true, banned: targets.slice(), skipped: skipped };
}

function showInterstitial(id, verdict, points, truth, rec) {
  state.phase = 'interstitial';
  var body = $('int-body');
  body.textContent = '';
  var isActor = truth && truth.truth === 'malicious';
  var title, cls;
  if (verdict === 'ban' && isActor) { title = 'Correct ban'; cls = 'good'; }
  else if (verdict === 'ban' && !isActor) { title = 'False accusation'; cls = 'bad'; }
  else if (verdict === 'monitor' && isActor) { title = 'Monitored an actor'; cls = 'mid'; }
  else if (verdict === 'monitor' && !isActor) { title = 'Monitored an innocent'; cls = 'mid'; }
  else if (verdict === 'clear' && !isActor) { title = 'Cleared correctly'; cls = 'good'; }
  else { title = 'Missed actor'; cls = 'bad'; }
  var h = el('h2', cls, title);
  h.id = 'int-title';
  body.appendChild(h);

  var truthLine = el('p');
  truthLine.appendChild(el('span', 'mono', id + ' '));
  if (isActor) {
    truthLine.appendChild(document.createTextNode('was a threat actor: '));
    truthLine.appendChild(el('span', 'mono', truth.actor || 'unknown'));
  } else {
    truthLine.appendChild(document.createTextNode('was benign'));
    if (truth && truth.persona) {
      truthLine.appendChild(document.createTextNode(' — persona: '));
      truthLine.appendChild(el('span', 'mono', truth.persona));
    }
  }
  body.appendChild(truthLine);

  var delta = el('p', 'delta', fmtPts(points) + '  ·  score ' + fmtScore(state.score));
  body.appendChild(delta);
  if (verdict === 'ban' && rec && rec.band) {
    body.appendChild(el('p', 'small dim',
      'Banned at “' + rec.band.replace(/_/g, ' ') + '” — you claimed P ' +
      rec.p.toFixed(2) + '. The shift report scores that claim.'));
  }
  if (verdict === 'ban' && !isActor) {
    body.appendChild(el('p', 'small', 'That is the expensive mistake, because it is the hard one to undo.'));
  }
  if (verdict === 'clear' && isActor) {
    body.appendChild(el('p', 'small dim', 'The actor comes back tomorrow.'));
  }
  if (verdict === 'monitor' && isActor) {
    body.appendChild(el('p', 'small dim', 'Monitoring keeps them in sight. It also keeps them on the platform.'));
  }
  if (verdict === 'monitor' && !isActor) {
    body.appendChild(el('p', 'small dim', 'The hedge on an innocent costs a little and buys nothing.'));
  }

  if (truth && truth.tell) {
    body.appendChild(el('p', null, truth.tell));
  }
  if (truth && truth.provenance) {
    var prov = el('p', 'provenance',
      'This archetype is drawn from: ' + (truth.provenance.source || '') +
      (truth.provenance.case ? ' — ' + truth.provenance.case : ''));
    body.appendChild(prov);
  }
  if (truth && truth.original_id) {
    body.appendChild(el('p', 'small dim mono', 'hunt fixture ' + truth.original_id));
  }

  $('overlay').hidden = false;
  setModalOpen(true);
  $('btn-continue').focus();
}

function continueFromInterstitial() {
  if (state.phase !== 'interstitial') { return; }
  $('overlay').hidden = true;
  setModalOpen(false);
  var next = nextUndecided();
  if (next === null) { finishShift(false); return; }
  state.phase = 'play';
  openAccount(next);
  var h2 = $('dossier-head').querySelector('h2');
  if (h2) { h2.focus(); }
}

function nextUndecided() {
  var order = state.order.filter(function (id) { return arrived.has(id); });
  if (!order.length) { return null; }
  var start = Math.max(0, order.indexOf(state.currentId));
  for (var k = 1; k <= order.length; k++) {
    var id = order[(start + k) % order.length];
    if (!verdicts.has(id)) { return id; }
  }
  return null;
}


/* --- modal background ---------------------------------------------------
   Both overlays declare aria-modal="true" and neither made the page behind
   them inert, so a keyboard user could Tab straight out of the dialog into
   the queue underneath and operate it - which is exactly the thing
   aria-modal promises a screen reader is not possible. `inert` is the one
   line that makes the promise true, and it removes the background from the
   tab order and the accessibility tree together. */
function setModalOpen(open) {
  var main = document.querySelector('main');
  var bar = $('topbar');
  [main, bar].forEach(function (n) {
    if (!n) { return; }
    if (open) { n.setAttribute('inert', ''); }
    else { n.removeAttribute('inert'); }
  });
}

/* =========================================================================
   end of shift + report (SPEC v1 §8, amended by SPEC-2 §1)
========================================================================= */
function finishShift(early) {
  /* remaining undecided accounts count as CLEAR — no action taken. An
     unscheduled account that never arrived is not part of the shift. */
  state.autoCleared = 0;
  state.pendingBanId = null;
  state.order.forEach(function (id) {
    if (verdicts.has(id) || !inShiftScope(id)) { return; }
    commitVerdict(id, 'clear', { auto: true });
    state.autoCleared += 1;
  });
  if (liveActive() && !SETTLED) {
    /* deferred scoring settles now; revealFor unseals behind it */
    SETTLED = true;
    state.order.forEach(function (id) {
      var rec = verdicts.get(id);
      if (!rec || rec.points !== null) { return; }
      var truth = revealFor(id);
      var isActor = truth && truth.truth === 'malicious';
      rec.points = pointsFor(rec.verdict, isActor);
      state.score += rec.points;
    });
  }
  state.phase = 'report';
  $('screen-play').hidden = true;
  $('hud').hidden = true;
  $('btn-endshift').hidden = true;
  var report = buildReport();
  REPORT_TOKEN = report;
  renderReport(report);
  $('screen-report').hidden = false;
  emit('shiftEnd', { report: report });
  window.scrollTo(0, 0);
}

function wilsonUpperZero(n) {
  /* Wilson 95% upper bound for 0 successes in n trials: z^2 / (n + z^2) */
  var z2 = 1.96 * 1.96;
  return z2 / (n + z2);
}

/* The report object is also the capability token for revealAllFor. */
function buildReport() {
  var m = { banActor: 0, banBenign: 0, monActor: 0, monBenign: 0,
            clearActor: 0, clearBenign: 0 };
  var actorN = 0, benignN = 0;
  var bannedBenign = [];
  var rows = [];
  var bans = [];
  state.order.forEach(function (id) {
    var v = verdicts.get(id);
    if (!v) { return; }   /* unscheduled, never arrived: outside the shift */
    var truth = revealFor(id);
    var isActor = truth && truth.truth === 'malicious';
    if (isActor) { actorN += 1; } else { benignN += 1; }
    if (v.verdict === 'ban') {
      if (isActor) { m.banActor += 1; } else { m.banBenign += 1; bannedBenign.push(id); }
      bans.push({ id: id, band: v.band, p: v.p, outcome: isActor ? 1 : 0 });
    } else if (v.verdict === 'monitor') {
      if (isActor) { m.monActor += 1; } else { m.monBenign += 1; }
    } else {
      if (isActor) { m.clearActor += 1; } else { m.clearBenign += 1; }
    }
    /* SPEC-2 §8: the display-only "What ran while you read" section needs
       three clock facts per account — when it arrived, when (if ever) a ban
       froze its telemetry, and the shift hour of each of its sessions. None
       of it is truth; the truth still comes from revealAllFor. */
    var acct = byId.get(id) || {};
    rows.push({ id: id, verdict: v.verdict, band: v.band, p: v.p,
                points: v.points, auto: v.auto, reverdict: !!v.reverdict,
                citations: v.citations,
                arrivedAt: arrivalAt.has(id) ? arrivalAt.get(id) : null,
                banAt: banCutoff.has(id) ? banCutoff.get(id) : null,
                sessionHours: (acct.sessions || []).map(function (s) {
                  return sessionHour(acct, s);
                }) });
  });
  var brierScore = null;
  if (bans.length) {
    brierScore = bans.reduce(function (s, b) {
      return s + (b.p - b.outcome) * (b.p - b.outcome);
    }, 0) / bans.length;
  }
  var byBand = {};
  bans.forEach(function (b) {
    if (!byBand[b.band]) { byBand[b.band] = { band: b.band, p: b.p, n: 0, actors: 0 }; }
    byBand[b.band].n += 1;
    byBand[b.band].actors += b.outcome;
  });
  var reliability = BAND_LIST
    .filter(function (b) { return byBand[b.name]; })
    .map(function (b) {
      var r = byBand[b.name];
      return { band: b.name, label: b.label, claimed: r.p, n: r.n,
               actors: r.actors, observed: r.actors / r.n };
    });
  return {
    shiftId: SHIFT.id,
    seed: SEED,
    score: state.score,
    /* SPEC-2 §8: length is the shift, elapsed is where the clock stopped.
       On a clockless shift both are facts about the fiction, not the play:
       elapsed stays 0 and `live` says why. */
    live: clockRunning(),
    length: state.length,
    elapsed: state.elapsed,
    tabsOpened: paidTabsOpenedTotal(),
    autoCleared: state.autoCleared,
    counts: { actors: actorN, benign: benignN },
    matrix: m,
    verdicts: rows,
    bannedBenign: bannedBenign,
    policyFlags: state.order.filter(function (id) {
      return state.policyFlags.has(id);
    }),
    secondOpinions: state.order.filter(function (id) {
      return state.secondOpinions.has(id);
    }),
    brier: { n: bans.length, score: brierScore, reliability: reliability }
  };
}

/* =========================================================================
   the shareable result

   Three rules, and they are the whole design:

   (1) Counts, never a map. The squares are grouped by outcome, not left in
       queue order, so a result posted publicly cannot be read back as an
       answer key by the next person to open the link. This is the same
       constraint make_figures.py works under for the README figures.
   (2) The false bans are in it, always, including the zero. A score you can
       post without the harm beside it is exactly the reading of this game
       that the game exists to argue against.
   (3) No boast line, no rank, no adjective. The numbers are the claim.
========================================================================= */
function squares(ch, n) { return n > 0 ? new Array(n + 1).join(ch) : ''; }

function shareText(rep) {
  var m = rep.matrix;
  var actorN = rep.counts.actors, benignN = rep.counts.benign;
  var caught = m.banActor, hedged = m.monActor, missed = m.clearActor;
  var falseBans = m.banBenign;
  var lines = [];

  lines.push('trigger-discipline — ' + (SHIFT.title || SHIFT.id));
  lines.push('');
  /* A long roster would wrap into noise on every platform; past two dozen
     the squares stop being a glance and the counts carry it alone. */
  if (actorN <= 24) {
    lines.push(squares('🟩', caught) + squares('🟨', hedged) + squares('🟥', missed));
  }
  lines.push(caught + ' of ' + plural(actorN, 'actor') + ' banned' +
    (hedged ? ', ' + hedged + ' monitored' : '') +
    (missed ? ', ' + missed + ' missed' : ''));
  lines.push('');
  lines.push((falseBans > 0 ? squares('🟥', Math.min(falseBans, 24)) : '⬛') + ' ' +
    falseBans + ' of ' + plural(benignN, 'innocent') + ' banned');
  lines.push('');
  lines.push(rep.brier.n
    ? 'Brier ' + rep.brier.score.toFixed(3) + ' over ' + plural(rep.brier.n, 'ban') +
      ' — 0.250 is a coin flip'
    : 'No bans, so no confidence to score');
  lines.push('');
  lines.push(location.origin + location.pathname);
  return lines.join('\n');
}

function appendShareControl(parent, rep) {
  var p = el('p', 'share-row');
  var btn = el('button', 'btn-share', 'Copy result');
  var note = el('span', 'small dim share-note', '');
  var box = null;   /* the manual fallback, built only if it is needed */

  function fallback(text) {
    if (box) { box.select(); return; }
    box = document.createElement('textarea');
    box.className = 'share-fallback';
    box.readOnly = true;
    box.rows = 9;
    box.value = text;
    parent.appendChild(box);
    box.select();
    note.textContent = 'Clipboard blocked — copy it from here.';
  }

  btn.addEventListener('click', function () {
    var text = shareText(rep);
    /* navigator.clipboard is absent on http:// origins and in some
       in-app browsers, and can reject even where it exists. Every path
       ends with the player holding the text. */
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        note.textContent = 'Copied.';
      }, function () { fallback(text); });
    } else {
      fallback(text);
    }
  });

  p.appendChild(btn);
  p.appendChild(note);
  parent.appendChild(p);
}

function renderReport(rep) {
  var root = $('screen-report');
  root.textContent = '';

  var m = rep.matrix;
  var actorN = rep.counts.actors, benignN = rep.counts.benign;
  var TP = m.banActor, FP = m.banBenign;
  var maxScore = actorN * POINTS.banActor + benignN * POINTS.clearBenign;
  var rank = RANKS.find(function (r) { return rep.score >= r[0]; })[1];

  root.appendChild(el('h1', null, 'Shift report'));
  if (rep.autoCleared > 0) {
    root.appendChild(el('p', 'dim small',
      plural(rep.autoCleared, 'account') + ' left undecided at end of shift, recorded as cleared — no action taken.'));
  }

  /* --- score --- */
  var sScore = el('section');
  sScore.appendChild(el('h2', null, 'Score'));
  sScore.appendChild(el('p', 'score-line', fmtScore(rep.score) + ' of ' + maxScore));
  sScore.appendChild(el('p', 'rank-line', 'Rank: ' + rank));
  /* Here rather than at the foot of the report: this is where the number is,
     and the report runs several screens past it. */
  appendShareControl(sScore, rep);
  root.appendChild(sScore);

  /* --- confusion matrix (3 verdicts × 2 truths) --- */
  var sMx = el('section');
  /* live.js inserts SPEC-2 §8's "What ran while you read" directly after
     this section, so it is the one report section with a stable id. */
  sMx.id = 'sec-matrix';
  sMx.appendChild(el('h2', null, 'Confusion matrix'));
  var t = el('table', 'matrix');
  var hr = el('tr');
  [' ', 'threat actor', 'benign'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
  t.appendChild(hr);
  var r1 = el('tr');
  r1.appendChild(el('th', null, 'banned'));
  r1.appendChild(el('td', 'n', TP + ' correct'));
  r1.appendChild(el('td', 'n' + (FP > 0 ? ' hot' : ''), FP + ' false ban' + (FP === 1 ? '' : 's')));
  t.appendChild(r1);
  var rM = el('tr');
  rM.appendChild(el('th', null, 'monitored'));
  rM.appendChild(el('td', 'n', m.monActor + ' hedged'));
  rM.appendChild(el('td', 'n', m.monBenign + ' watched'));
  t.appendChild(rM);
  var r2 = el('tr');
  r2.appendChild(el('th', null, 'cleared'));
  r2.appendChild(el('td', 'n', m.clearActor + ' missed'));
  r2.appendChild(el('td', 'n', m.clearBenign + ' correct'));
  t.appendChild(r2);
  sMx.appendChild(t);
  sMx.appendChild(el('p', 'small dim',
    'You banned ' + TP + '/' + actorN + ' actors, falsely banned ' + FP + '/' + benignN +
    ' innocents, and monitored ' + plural(m.monActor + m.monBenign, 'account') + '.'));
  root.appendChild(sMx);

  /* --- calibration (§1: Brier + reliability + the coin-flip anecdote) --- */
  var sCal = el('section');
  sCal.appendChild(el('h2', null, 'Calibration'));
  if (!rep.brier.n) {
    sCal.appendChild(el('p', null,
      'No bans, so no claims to score. A confidence band only means something ' +
      'once an outcome checks it.'));
  } else {
    sCal.appendChild(el('p', null,
      'Brier score across your ' + plural(rep.brier.n, 'ban') + ': ' +
      rep.brier.score.toFixed(3) +
      '. Zero is clairvoyance; 0.250 is what banning on a coin flip earns.'));
    var ct = el('table');
    var chr = el('tr');
    ['band', 'claimed P', 'bans', 'actors', 'observed P'].forEach(function (h) {
      chr.appendChild(el('th', null, h));
    });
    ct.appendChild(chr);
    rep.brier.reliability.forEach(function (r) {
      var tr = el('tr');
      tr.appendChild(el('td', null, r.label));
      tr.appendChild(el('td', 'mono', r.claimed.toFixed(2)));
      tr.appendChild(el('td', 'mono', String(r.n)));
      tr.appendChild(el('td', 'mono', String(r.actors)));
      tr.appendChild(el('td', 'mono', r.observed.toFixed(2)));
      ct.appendChild(tr);
    });
    sCal.appendChild(ct);
  }
  sCal.appendChild(el('p', 'small dim',
    'Hunt ran its own model twelve times on the detection engineer; the band it ' +
    'produced was a 50/50 coin flip across those reps (finding #24). ' +
    (rep.brier.n
      ? 'Your table above rests on ' + plural(rep.brier.n, 'ban') +
        ' — small-sample discipline applies to your calibration the same way it ' +
        'applies to a 0/14 false-ban rate.'
      : 'Small-sample discipline applies here too.')));
  root.appendChild(sCal);

  /* --- you vs the pipeline --- */
  var surfacedMal = 0, malTotal = 0, enforcedBenign = 0;
  var cardScore = 0, cardBans = 0, cardTP = 0, cardFP = 0, cardMon = 0;
  state.order.forEach(function (id) {
    if (!verdicts.has(id)) { return; }   /* outside the shift's reckoning */
    var a = byId.get(id);
    var truth = revealFor(id);
    var isActor = truth && truth.truth === 'malicious';
    var pl = a.pipeline || {};
    var dec = pl.cluster ? pl.cluster.decision : null;
    if (isActor) {
      malTotal += 1;
      if (pl.lead || pl.cluster) { surfacedMal += 1; }
    } else if (dec === 'enforce') {
      enforcedBenign += 1;
    }
    /* the card-only reviewer upholds every policy card and touches nothing else */
    if (dec === 'enforce') {
      cardBans += 1;
      if (isActor) { cardScore += POINTS.banActor; cardTP += 1; }
      else { cardScore += POINTS.banBenign; cardFP += 1; }
    } else if (dec === 'monitor') {
      cardMon += 1;
      cardScore += isActor ? POINTS.monitorActor : POINTS.monitorBenign;
    } else {
      cardScore += isActor ? POINTS.missActor : POINTS.clearBenign;
    }
  });
  var sPipe = el('section');
  sPipe.appendChild(el('h2', null, 'You vs the pipeline'));
  sPipe.appendChild(el('p', null,
    'The shipped pipeline surfaces ' + surfacedMal + '/' + malTotal + ' malicious accounts with ' +
    enforcedBenign + '/' + benignN + ' false accusations — and forwards every enforcement to a human.'));
  sPipe.appendChild(el('p', null,
    'The pipeline’s job was to make your job possible. Your job was the hard part.'));
  root.appendChild(sPipe);

  /* --- you vs the card-only reviewer (finding #26) --- */
  var sCard = el('section');
  sCard.appendChild(el('h2', null, 'You vs the card-only reviewer'));
  sCard.appendChild(el('p', null,
    'Hunt’s finding #26: a reviewer shown only the queue card upheld 5/5 unsound enforcement ' +
    'cards. The gate that cannot see can only sign.'));
  sCard.appendChild(el('p', null,
    'Card-only review of this queue — uphold every policy card, touch nothing else — bans ' +
    plural(cardBans, 'account') + ' (' + plural(cardTP, 'actor') + ', ' + cardFP +
    ' innocent) and monitors ' + cardMon + ' for a score of ' + fmtScore(cardScore) +
    ', without opening one evidence tab.'));
  sCard.appendChild(el('p', null,
    'You opened ' + plural(rep.tabsOpened, 'evidence tab') + ' and scored ' +
    fmtScore(rep.score) +
    '. The difference between those two numbers is what looking bought. On this queue the cards happen ' +
    'to be sound; the card-only reviewer’s method cannot tell you when they are not.'));
  root.appendChild(sCard);

  /* --- the base-rate kicker (finding #16) --- */
  var sBase = el('section');
  sBase.appendChild(el('h2', null, 'The base-rate kicker'));
  if (FP > 0) {
    var p = 0.001;
    var fpr = FP / benignN;
    var tpr = actorN > 0 ? TP / actorN : 0;
    var denom = fpr * (1 - p) + tpr * p;
    var innocentShare = denom > 0 ? (fpr * (1 - p)) / denom : 1;
    sBase.appendChild(el('p', null,
      'Your false-ban rate here was ' + FP + '/' + benignN + '. At a realistic 0.1% abuse prevalence, ' +
      'a queue with your rates would be ~' + (100 * innocentShare).toFixed(1) + '% innocent.'));
    sBase.appendChild(el('p', 'small dim',
      'Computed from your own confusion matrix: FPR·(1−p) / (FPR·(1−p) + TPR·p) ' +
      'with p = 0.001, FPR = ' + FP + '/' + benignN + ', TPR = ' + TP + '/' + actorN + '.'));
  } else {
    var ub = wilsonUpperZero(benignN);
    sBase.appendChild(el('p', null,
      '0/' + benignN + ' is not a rate: with ' + benignN + ' innocents, the data only licenses ' +
      '“under ' + (100 * ub).toFixed(1) + '%” (Wilson 95% upper bound). ' +
      'Hunt’s own 0/14 carries the same asterisk.'));
  }
  root.appendChild(sBase);

  /* --- the clock (SPEC-2 §8: live shifts only — a shift with no clock has
     no hours to audit, and the tab-open record below covers what was read) --- */
  if (rep.live) {
    var sClock = el('section');
    sClock.id = 'sec-clock';
    sClock.appendChild(el('h2', null, 'The clock'));
    var bt = el('table');
    var bhr = el('tr');
    ['tab', 'opens', 'hours'].forEach(function (h) { bhr.appendChild(el('th', null, h)); });
    bt.appendChild(bhr);
    TABS.forEach(function (tb) {
      if (tb.hours === 0) { return; }
      var tr = el('tr');
      tr.appendChild(el('td', null, tb.label));
      tr.appendChild(el('td', 'mono', String(state.audit[tb.key].opens)));
      tr.appendChild(el('td', 'mono', state.audit[tb.key].hours + 'h'));
      bt.appendChild(tr);
    });
    Object.keys(state.audit).forEach(function (k) {
      /* hours attributed by modes (e.g. waiting) show up too */
      var known = TABS.some(function (tb) { return tb.key === k; });
      if (known || !state.audit[k].hours) { return; }
      var tr = el('tr');
      tr.appendChild(el('td', null, k));
      tr.appendChild(el('td', 'mono', String(state.audit[k].opens)));
      tr.appendChild(el('td', 'mono', state.audit[k].hours + 'h'));
      bt.appendChild(tr);
    });
    var trTot = el('tr');
    trTot.appendChild(el('th', null, 'total'));
    trTot.appendChild(el('th', null, ''));
    trTot.appendChild(el('th', 'mono', rep.elapsed + 'h of ' + rep.length + 'h'));
    bt.appendChild(trTot);
    sClock.appendChild(bt);
    sClock.appendChild(el('p', 'small dim',
      'The clock decides what had arrived by the time you decided. It is not part of the ' +
      'score, and nothing here was ever refused for lack of hours.'));
    root.appendChild(sClock);
  }

  /* --- the most expensive mistake. Measured in tabs opened, not hours:
     the question is what the verdict rested on, and shift 1 has no clock. --- */
  var sMis = el('section');
  sMis.id = 'sec-mistake';
  sMis.appendChild(el('h2', null, 'Your most expensive mistake'));
  if (rep.bannedBenign.length) {
    var unread = rep.bannedBenign.filter(function (id) { return paidTabsOpened(id) === 0; });
    var pick, story;
    if (unread.length) {
      pick = unread[0];
      story = 'banned on the free view alone — not one evidence tab opened. Content was the ' +
        'whole accusation, which is the exact failure this queue was built to punish.';
    } else {
      pick = rep.bannedBenign.reduce(function (best, id) {
        return paidTabsOpened(id) > paidTabsOpened(best) ? id : best;
      }, rep.bannedBenign[0]);
      story = plural(paidTabsOpened(pick), 'evidence tab') + ' open, banned anyway. ' +
        'The evidence was there; the verdict ignored it.';
    }
    var box = el('div', 'mistake-box');
    var pm = el('p');
    pm.appendChild(el('span', 'mono', pick + ' '));
    pm.appendChild(document.createTextNode('— ' + story + ' (' + fmtPts(POINTS.banBenign) + ')'));
    box.appendChild(pm);
    sMis.appendChild(box);
  } else {
    sMis.appendChild(el('p', 'dim', 'No banned innocents. The record has nothing to hold against you.'));
  }
  root.appendChild(sMis);

  /* --- the designed pair — the thesis, personalized. Truth flows only
     through the report token; the pair object lives reveal-side and was
     composed from the emitted rows at build time, so these columns cannot
     disagree with the tabs the player saw. --- */
  (function () {
    var all;
    try { all = revealAllFor(rep); } catch (e) { return; }
    var pair = null;
    rep.verdicts.forEach(function (row) {
      var rv = all[row.id];
      if (rv && rv.twin && rv.twin.a === row.id) { pair = rv.twin; }
    });
    if (!pair) { return; }
    var vBy = {};
    rep.verdicts.forEach(function (row) { vBy[row.id] = row.verdict; });
    var vA = vBy[pair.a], vB = vBy[pair.b];
    if (!vA || !vB) { return; }
    var sTwin = el('section');
    sTwin.id = 'sec-twins';
    sTwin.appendChild(el('h2', null, 'The designed pair'));
    sTwin.appendChild(el('p', null, pair.shared));
    var tt = el('table');
    var hr2 = el('tr');
    [['', ''], [pair.a, pair.sessions.a], [pair.b, pair.sessions.b]].forEach(function (h, i) {
      var th = el('th', i ? 'mono' : null, h[0]);
      hr2.appendChild(th);
    });
    tt.appendChild(hr2);
    var trS = el('tr');
    trS.appendChild(el('td', 'small dim', 'sessions'));
    trS.appendChild(el('td', 'mono small', String(pair.sessions.a)));
    trS.appendChild(el('td', 'mono small', String(pair.sessions.b)));
    tt.appendChild(trS);
    pair.rows.forEach(function (row) {
      var tr = el('tr');
      tr.appendChild(el('td', 'small dim', row.tab));
      tr.appendChild(el('td', 'small', row.a));
      tr.appendChild(el('td', 'small', row.b));
      tt.appendChild(tr);
    });
    var trV = el('tr');
    trV.appendChild(el('td', 'small dim', 'your verdict'));
    trV.appendChild(el('td', 'mono small', verdictLabel(vA)));
    trV.appendChild(el('td', 'mono small', verdictLabel(vB)));
    tt.appendChild(trV);
    var trT = el('tr');
    trT.appendChild(el('td', 'small dim', 'the truth'));
    trT.appendChild(el('td', 'mono small', 'threat actor'));
    trT.appendChild(el('td', 'mono small', 'benign'));
    tt.appendChild(trT);
    sTwin.appendChild(tt);
    /* Column a is the actor, column b the innocent (asserted at build time),
       so severity order is the honest grading: harsher on a = told apart. */
    var sev = { ban: 2, monitor: 1, clear: 0 };
    var verdictLine;
    if (vA !== 'clear' && vB === 'clear') {
      verdictLine = 'Split. The difference was real and you found it.';
    } else if (sev[vA] > sev[vB]) {
      verdictLine = 'You ranked them the right way around — and the innocent ' +
        'still paid the hedge.';
    } else {
      var tabList = pair.rows.map(function (row) { return row.tab; }).join(', ');
      var unopened = [];
      [pair.a, pair.b].forEach(function (id) {
        var owned = state.unlocked.get(id) || new Set();
        pair.rows.forEach(function (row) {
          if (row.tab !== 'content' && !owned.has(row.tab)
              && unopened.indexOf(row.tab + ' on ' + id) < 0) {
            unopened.push(row.tab + ' on ' + id);
          }
        });
      });
      var clause = unopened.length
        ? ' — and you never opened ' + unopened[0] + '.'
        : ' — every diverging tab was open; the verdict ignored them.';
      verdictLine = (sev[vA] === sev[vB]
        ? 'Same verdict, opposite truths.'
        : 'You split them the wrong way around.')
        + ' The difference lived in ' + tabList + clause;
    }
    sTwin.appendChild(el('p', null, verdictLine));
    root.appendChild(sTwin);
  })();

  /* --- you vs the advisor (finding #18) — only if the bait was taken. The
     counts in the closing line are computed from the judged clusters and the
     reveal, never typed. --- */
  if (rep.secondOpinions && rep.secondOpinions.length && META.judge) {
    var allJ = null;
    try { allJ = revealAllFor(rep); } catch (e) { allJ = null; }
    if (allJ) {
      var sAdv = el('section');
      sAdv.id = 'sec-advisor';
      sAdv.appendChild(el('h2', null, 'You vs the advisor'));
      var vByJ = {};
      rep.verdicts.forEach(function (row) { vByJ[row.id] = row.verdict; });
      var at = el('table');
      var ahr = el('tr');
      ['account', 'the advisor said', 'the assessment', 'your verdict', 'the truth']
        .forEach(function (h) { ahr.appendChild(el('th', null, h)); });
      at.appendChild(ahr);
      rep.secondOpinions.forEach(function (id) {
        var acct = byId.get(id) || {};
        var clJ = (acct.pipeline || {}).cluster || {};
        var soJ = clJ.second_opinion;
        if (!soJ) { return; }
        var tr = el('tr');
        tr.appendChild(el('td', 'mono small', id));
        tr.appendChild(el('td', 'small', soJ.overall +
          (soJ.failed && soJ.failed.length ? ' (failed: ' + soJ.failed.join(', ') + ')' : '')));
        tr.appendChild(el('td', 'small',
          (clJ.assessment || '—') + ' → ' + String(clJ.decision || '—').toUpperCase()));
        tr.appendChild(el('td', 'mono small', verdictLabel(vByJ[id] || '—')));
        tr.appendChild(el('td', 'mono small',
          (allJ[id] && allJ[id].truth === 'malicious') ? 'threat actor' : 'benign'));
        at.appendChild(tr);
      });
      sAdv.appendChild(at);
      var actorWeak = 0, actorTotal = 0, wrongSound = false;
      var seenCl = {};
      state.order.forEach(function (idJ) {
        var acctJ = byId.get(idJ);
        var cJ = acctJ && acctJ.pipeline ? acctJ.pipeline.cluster : null;
        if (!cJ || !cJ.second_opinion) { return; }
        var keyJ = (cJ.members || []).join(',');
        if (seenCl[keyJ]) { return; }
        seenCl[keyJ] = true;
        var isActor = (cJ.members || []).some(function (m) {
          return allJ[m] && allJ[m].truth === 'malicious';
        });
        if (isActor) {
          actorTotal += 1;
          if (cJ.second_opinion.overall === 'weak') { actorWeak += 1; }
        } else if (cJ.second_opinion.overall === 'sound') {
          wrongSound = true;
        }
      });
      var J = META.judge;
      sAdv.appendChild(el('p', 'small',
        'Measured (' + J.model + ', decorrelated, ' + plural(J.reps, 'rep') +
        '): the known-wrong assessment drew ' + Number(J.known_error_failures).toFixed(1) +
        ' failures; the true positives drew ' + Number(J.true_positive_failures).toFixed(2) +
        '. Margin ' + String(J.margin).replace('-', '−') + ' — ' + J.verdict +
        '. It found fault with ' + actorWeak + ' of the ' + actorTotal +
        ' actor assessments' + (wrongSound ? ' and rated the wrong one sound.' : '.')));
      sAdv.appendChild(el('p', 'small dim',
        'What protected the engineer was the corroboration floor, not a model checking a model.'));
      root.appendChild(sAdv);
    }
  }

  /* --- the policy, on the record (finding #20) — rendered only when used;
     an empty section would nag, and the flag is an offer, not a duty --- */
  if (rep.policyFlags && rep.policyFlags.length) {
    var sFlag = el('section');
    sFlag.id = 'sec-flags';
    sFlag.appendChild(el('h2', null, 'The policy, on the record'));
    var pf = el('p');
    pf.appendChild(document.createTextNode(
      'You flagged ' + plural(rep.policyFlags.length, 'account') +
      ' as a policy gap rather than pretending a verdict resolved it: '));
    rep.policyFlags.forEach(function (id) {
      pf.appendChild(el('span', 'mono', id));
      pf.appendChild(document.createTextNode(' '));
    });
    sFlag.appendChild(pf);
    sFlag.appendChild(el('p', 'small dim',
      'The research did the same. Its second topic definition, its better-scoring ' +
      'thresholds and its escalation-arc variant were measured, published, and ' +
      'deliberately not adopted.'));
    root.appendChild(sFlag);
  }

  /* --- play again --- */
  var sEnd = el('section');
  sEnd.appendChild(el('h2', null, 'Again'));
  /* The shift travels with the seed (SPEC-2 §4): a replay stays on the
     shift it replays. Without career.js the shift param is inert. */
  var againBtn = el('button', 'btn-clear', 'Play again (new seed)');
  againBtn.addEventListener('click', function () {
    var s = Math.floor(Math.random() * 2147483647);
    location.search = '?shift=' + SHIFT.id + '&seed=' + s;
  });
  var replayBtn = el('button', null, 'Replay this seed');
  replayBtn.style.marginLeft = '8px';
  replayBtn.addEventListener('click', function () {
    location.search = '?shift=' + SHIFT.id + '&seed=' + SEED;
  });
  var pAgain = el('p');
  pAgain.appendChild(againBtn);
  pAgain.appendChild(replayBtn);
  sEnd.appendChild(pAgain);
  var pRepo = el('p', 'small dim');
  pRepo.appendChild(document.createTextNode('Every account here is a real fixture from the instrument this game is built on: '));
  var link = el('a', null, (META.source_repo || 'github.com/abognar-git/model-abuse-hunt'));
  link.href = 'https://' + (META.source_repo || 'github.com/abognar-git/model-abuse-hunt');
  pRepo.appendChild(link);
  if (META.source_commit && META.source_commit !== 'PLACEHOLDER') {
    pRepo.appendChild(document.createTextNode(' @ ' + String(META.source_commit).slice(0, 12)));
  }
  sEnd.appendChild(pRepo);
  root.appendChild(sEnd);
}

/* =========================================================================
   end-shift confirmation
========================================================================= */
function askEndShift() {
  if (state.phase !== 'play') { return; }
  var undecided = 0, unarrived = 0;
  state.order.forEach(function (id) {
    if (verdicts.has(id) || !inShiftScope(id)) { return; }
    undecided += 1;
    if (!arrived.has(id)) { unarrived += 1; }
  });
  if (undecided === 0) { finishShift(false); return; }
  state.phase = 'confirm-end';
  $('end-msg').textContent = plural(undecided, 'account') +
    ' still undecided. They will be recorded as cleared — no action taken, which also means any actor among them is missed.' +
    (unarrived > 0
      ? ' ' + unarrived + ' of them ' + (unarrived === 1 ? 'has' : 'have') +
        ' not arrived yet; ending now forfeits them the same way.'
      : '');
  $('overlay-end').hidden = false;
  setModalOpen(true);
  $('btn-end-cancel').focus();
}
function cancelEndShift() {
  if (state.phase !== 'confirm-end') { return; }
  $('overlay-end').hidden = true;
  setModalOpen(false);
  state.phase = 'play';
}
$('btn-endshift').addEventListener('click', askEndShift);
$('btn-end-cancel').addEventListener('click', cancelEndShift);
$('btn-end-confirm').addEventListener('click', function () {
  if (state.phase !== 'confirm-end') { return; }
  $('overlay-end').hidden = true;
  setModalOpen(false);
  finishShift(true);
});
$('btn-continue').addEventListener('click', continueFromInterstitial);

/* =========================================================================
   start
========================================================================= */
function startShift() {
  if (state.phase !== 'intro') { return; }
  /* the visible briefing is the only start surface — when a mode has its
     own landing screen up (career's shift select), Enter starts nothing */
  if ($('screen-intro').hidden) { return; }
  state.phase = 'play';
  $('screen-intro').hidden = true;
  $('screen-play').hidden = false;
  $('hud').hidden = false;
  $('btn-endshift').hidden = false;
  renderHud();
  emit('shiftStart', { shift: { id: SHIFT.id, title: SHIFT.title || '',
    length: state.length, flags: SHIFT.flags || {} } });
  emitNewArrivals();
  var first = null;
  for (var i = 0; i < state.order.length; i++) {
    if (arrived.has(state.order[i])) { first = state.order[i]; break; }
  }
  if (first !== null) {
    openAccount(first);
  } else {
    /* a live shift can open on an empty queue */
    renderQueue();
    renderDossier();
    setNotice('Nothing in the queue yet. Wait (W) advances the clock.');
  }
}
$('btn-start').addEventListener('click', startShift);
/* The briefing keeps a start control at each end: the top one for a
   visitor who arrived to play, the foot one for a reader who got here
   through the rules. Same handler, and startShift guards its own phase. */
var startFoot = $('btn-start-foot');
if (startFoot) { startFoot.addEventListener('click', startShift); }

/* =========================================================================
   keyboard — B ban, M monitor, C clear, 1-5 tabs, Enter continue,
   arrows queue; band picker: number keys pick a band, Esc cancels
========================================================================= */
document.addEventListener('keydown', function (e) {
  if (e.metaKey || e.ctrlKey || e.altKey) { return; }
  var k = e.key;
  if (state.phase === 'intro') {
    if (k === 'Enter') { e.preventDefault(); startShift(); }
    return;
  }
  if (state.phase === 'interstitial') {
    if (k === 'Enter') { e.preventDefault(); continueFromInterstitial(); }
    return;
  }
  if (state.phase === 'confirm-end') {
    if (k === 'Escape') { e.preventDefault(); cancelEndShift(); }
    return;
  }
  if (state.phase !== 'play') { return; }
  if (state.pendingBanId !== null && state.pendingBanId === state.currentId) {
    if (k === 'Escape') { e.preventDefault(); closeBandPicker(); setNotice(''); return; }
    if (k >= '1' && k <= '9') {
      var bi = Number(k) - 1;
      if (bi < BAND_LIST.length) {
        e.preventDefault();
        chooseBand(state.pendingBanId, BAND_LIST[bi].name);
        return;
      }
    }
  }
  var kl = k.toLowerCase();
  if (kl === 'b') {
    if (state.currentId && decidable(state.currentId)) {
      e.preventDefault();
      requestBan(state.currentId);
    }
    return;
  }
  if (kl === 'm' || kl === 'c') {
    if (state.currentId && decidable(state.currentId)) {
      e.preventDefault();
      closeBandPicker();
      commitVerdict(state.currentId, kl === 'm' ? 'monitor' : 'clear');
    }
    return;
  }
  if (kl === 'g') {
    /* finding #20 — annotation, so no decidable() gate: the record is open
       even on an account whose verdict already stands */
    if (state.currentId) { e.preventDefault(); togglePolicyFlag(state.currentId); }
    return;
  }
  if (k >= '1' && k <= '5') {
    e.preventDefault();
    openTab(TABS[Number(k) - 1].key);
    return;
  }
  if (k === 'ArrowDown' || k === 'ArrowRight' || k === 'ArrowUp' || k === 'ArrowLeft') {
    e.preventDefault();
    var dir = (k === 'ArrowDown' || k === 'ArrowRight') ? 1 : -1;
    var order = state.order.filter(function (id) { return arrived.has(id); });
    if (!order.length) { return; }
    var idx = order.indexOf(state.currentId);
    if (idx < 0) { idx = 0; }
    var next = order[(idx + dir + order.length) % order.length];
    openAccount(next);
  }
});

/* boot */
UI = {
  $: $, el: el, frag: frag,
  /* single sources for mode parts — the scoring table, the rank ladder,
     and the Wilson bound live here (and in the data's meta), nowhere else */
  points: POINTS, ranks: RANKS, wilson: wilsonUpperZero,
  notice: setNotice,
  renderQueue: renderQueue,
  renderHud: renderHud,
  renderDossier: renderDossier,
  renderIntro: renderIntro,
  openAccount: openAccount,
  openTab: openTab
};
initShift(SHIFTS[0]);
renderIntro();

})();
