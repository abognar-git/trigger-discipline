/* =========================================================================
   trigger-discipline — parts/career.js
   SPEC-2 §4: career mode. The landing screen is the shift select: five
   shifts in the order the job gets harder, a four-sentence framing, and a
   per-shift best. A shift unlocks when the previous one has been completed
   once, at any score. Progress lives in localStorage['trigger-discipline-career']
   (try/catch everywhere; losable without harm). Briefing screens come from
   the data — core renders them; this part adds the way back. ?seed=N
   reorders within the selected shift and ?shift=sN deep-links straight to
   a shift's briefing (core's play-again buttons emit both, so a replay
   stays on the shift it replays).

   After shift 5's shiftEnd this part runs the appeals round BEFORE the
   player sees the report: every banned account files a card — one
   nominated fact, plus what independent verification returned — and the
   player upholds or reverses each ban. A reversed ban on a benign account
   scores the reduced penalty; a reversed ban on an actor forfeits the
   credit; upheld cards stand as signed (adjustment values read from
   meta.scoring). The one unresolvable card is the coordination appeal:
   no document exists either way, and the card says so.

   The career dashboard opens from the shift select once two shifts are
   done: cumulative precision, recall, Brier, hours per correct ban, a
   per-shift table, and the finding-#16 base-rate section computed over the
   cumulative numbers.

   Vault rule (SPEC v1 §7.4, SPEC-2 §0): this part reads truth ONLY through
   Game.revealAllFor(report), only after shiftEnd. The appeals round screen
   renders nothing but the card fields (claim, verification, resolvable) —
   the truth stays off-screen until the report, or the round would grade
   itself.
========================================================================= */
(function () {
'use strict';
if (!window.Game) { return; }

var STORE_KEY = 'trigger-discipline-career';

var ui = null, st = null, meta = null, shifts = [], shift = null;
var career = null;   /* {v:1, shifts:{<id>:{completed,plays,best,bestStats}}} */
var appeal = null;   /* active appeals round: {report, truths, cards} */

function fmtScore(n) { return (n < 0 ? '−' : '') + Math.abs(n); }
function fmtPts(n) { return (n >= 0 ? '+' : '−') + Math.abs(n); }
/* points cells: a forfeited credit is 0, not +0 */
function fmtCell(n) { return n === 0 ? '0' : fmtPts(n); }
function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }

/* Scoring values come from the data (meta.scoring) and from core's own
   table (ui.points) — nothing here restates the shift table. The two
   appeal adjustments fall back to SPEC-2 §4's own values, which this part
   owns, for the hand-written placeholder sample only. */
function points() { return (ui && ui.points) || {}; }
function reversedPts(isActor) {
  var s = (meta && meta.scoring) || {};
  if (isActor) {
    return typeof s.appeal_reversed_actor_ban === 'number' ? s.appeal_reversed_actor_ban : 0;
  }
  return typeof s.appeal_reversed_benign_ban === 'number' ? s.appeal_reversed_benign_ban : -5;
}
function maxFor(counts) {
  var p = points();
  return (counts.actors || 0) * (p.banActor || 0) + (counts.benign || 0) * (p.clearBenign || 0);
}
function rankFor(score) {
  var ranks = (meta && meta.ranks && meta.ranks.length) ? meta.ranks : (ui.ranks || []);
  for (var i = 0; i < ranks.length; i++) {
    var t = ranks[i][0];
    if (t === null || t === undefined) { t = -Infinity; }
    if (score >= t) { return ranks[i][1]; }
  }
  return '';
}

/* ------------------------------------------------------------- storage */
function loadCareer() {
  var obj = null;
  try { obj = JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); }
  catch (e) { obj = null; }
  if (!obj || typeof obj !== 'object' || typeof obj.shifts !== 'object' || !obj.shifts) {
    obj = { v: 1, shifts: {} };
  }
  return obj;
}
function saveCareer() {
  try { localStorage.setItem(STORE_KEY, JSON.stringify(career)); }
  catch (e) { /* file:// storage may be unavailable; progress is losable without harm */ }
}
function recOf(id) { return (career && career.shifts[id]) || null; }
function completedCount() {
  var n = 0;
  shifts.forEach(function (sh) {
    var r = recOf(sh.id);
    if (r && r.completed) { n += 1; }
  });
  return n;
}
function unlocked(i) {
  if (i <= 0) { return true; }
  var prev = recOf(shifts[i - 1].id);
  return !!(prev && prev.completed);
}

/* ------------------------------------------------------- screen plumbing */
function hideCareerScreens() {
  var a = ui.$('screen-career');
  if (a) { a.hidden = true; }
  var b = ui.$('screen-appeals');
  if (b) { b.hidden = true; }
}
function showLanding() {
  ['overlay', 'overlay-end', 'screen-play', 'screen-report', 'screen-intro',
   'hud', 'btn-endshift', 'screen-appeals'].forEach(function (id) {
    var n = ui.$(id);
    if (n) { n.hidden = true; }
  });
  renderLanding();
  var root = ui.$('screen-career');
  if (root) { root.hidden = false; }
  if (window.scrollTo) { window.scrollTo(0, 0); }
}
function selectShift(id) {
  var idx = -1;
  shifts.forEach(function (sh, i) { if (sh.id === id) { idx = i; } });
  if (idx < 0 || !unlocked(idx)) { return false; }
  hideCareerScreens();
  window.Game.loadShift(id);
  ensureBackButton();
  if (window.scrollTo) { window.scrollTo(0, 0); }
  return true;
}
function ensureBackButton() {
  var sec = ui.$('screen-intro');
  if (!sec || ui.$('btn-career-back')) { return; }
  var b = ui.el('button', null, 'All shifts');
  b.id = 'btn-career-back';
  b.addEventListener('click', showLanding);
  sec.insertBefore(b, sec.firstChild);
}

/* -------------------------------------------------------------- landing */
function renderLanding() {
  var root = ui.$('screen-career');
  if (!root) { return; }
  root.textContent = '';
  root.appendChild(ui.el('h1', null, 'trigger-discipline'));
  /* §4: the landing is the shift select with a four-sentence framing. The
     copy ships in meta.framing; the fallback below covers the hand-written
     placeholder sample only. */
  var framing = (meta && meta.framing && meta.framing.length) ? meta.framing : [
    'Six shifts at an AI platform\'s enforcement desk, in the order the job gets harder.',
    'The pipeline flags; you decide, and every ban has to cite something that is not content.',
    'The queue starts obvious, then starts moving, then starts arriving as it actually arrives — mostly innocent.',
    'The actor you miss comes back tomorrow. The innocent you ban has no easy way back.'
  ];
  root.appendChild(ui.el('p', 'career-framing', framing.join(' ')));

  var list = ui.el('div', 'shift-list');
  shifts.forEach(function (sh, i) {
    var open = unlocked(i);
    var r = recOf(sh.id);
    var card = ui.el(open ? 'button' : 'div', 'shift-card' + (open ? '' : ' locked'));
    card.setAttribute('data-shift', sh.id);
    if (!open) { card.setAttribute('aria-disabled', 'true'); }
    card.appendChild(ui.el('div', 'sc-title', 'Shift ' + (i + 1) + ' — ' + (sh.title || sh.id)));
    if (sh.subtitle) { card.appendChild(ui.el('div', 'sc-sub small dim', sh.subtitle)); }
    var c = sh.counts || {};
    var nAcc = c.scheduled != null ? c.scheduled : (sh.accounts || []).length;
    /* SPEC-2 §8: the shift length is a fact about a clock, so it belongs
       only on a card that has one. Without this gate shift 1 advertises
       "no clock" in its subtitle and "32h" on the line under it. */
    var bits = [plural(nAcc, 'account')];
    var fl = sh.flags || {};
    if (fl.live) { bits.push((Number(sh.budget) || 0) + 'h', 'live queue'); }
    if (fl.cases) { bits.push('cases'); }
    if (fl.appeals) { bits.push('appeals'); }
    card.appendChild(ui.el('div', 'sc-meta mono small', bits.join(' · ')));
    var status;
    if (!open) { status = 'Locked — complete shift ' + i + ' first.'; }
    else if (r && r.completed) { status = 'Best ' + fmtScore(r.best) + ' · ' + plural(r.plays, 'run'); }
    else { status = 'Not yet played.'; }
    card.appendChild(ui.el('div', 'sc-status small' + (r && r.completed ? '' : ' dim'), status));
    if (open) { card.addEventListener('click', function () { selectShift(sh.id); }); }
    list.appendChild(card);
  });
  root.appendChild(list);

  if (completedCount() >= 2) {
    var dbtn = ui.el('button', null, 'Career dashboard');
    dbtn.id = 'btn-dashboard';
    var dash = ui.el('div');
    dash.id = 'career-dash';
    dash.hidden = true;
    dbtn.addEventListener('click', function () {
      if (dash.hidden) { renderDashboard(dash); dash.hidden = false; }
      else { dash.hidden = true; }
    });
    var pd = ui.el('p');
    pd.appendChild(dbtn);
    root.appendChild(pd);
    root.appendChild(dash);
  }

  root.appendChild(ui.el('p', 'small dim',
    'Add ?seed=N to the URL to reorder a shift\'s queue; ?shift=sN opens that shift\'s briefing directly.'));
}

/* ------------------------------------------------------------ dashboard */
function renderDashboard(box) {
  box.textContent = '';
  box.appendChild(ui.el('h2', null, 'Career dashboard'));
  var agg = { tp: 0, fp: 0, actors: 0, benign: 0, brierN: 0, brierSum: 0, hours: 0 };
  var rows = [];
  shifts.forEach(function (sh, i) {
    var r = recOf(sh.id);
    var s = (r && r.completed && r.bestStats) ? r.bestStats : null;
    if (s) {
      ['tp', 'fp', 'actors', 'benign', 'brierN', 'brierSum', 'hours'].forEach(function (k) {
        agg[k] += Number(s[k]) || 0;
      });
    }
    rows.push({ sh: sh, i: i, stats: s });
  });
  var bans = agg.tp + agg.fp;
  box.appendChild(ui.el('p', 'small dim',
    'Cumulative over each completed shift\'s best run. The bans are counted as signed at end of shift; appeals adjust the score, not the record.'));

  var facts = ui.el('table');
  function factRow(k, v, note) {
    var tr = ui.el('tr');
    tr.appendChild(ui.el('th', null, k));
    tr.appendChild(ui.el('td', 'mono', v));
    tr.appendChild(ui.el('td', 'small dim', note));
    facts.appendChild(tr);
  }
  factRow('precision',
    bans ? (agg.tp / bans).toFixed(2) : 'no bans yet',
    bans ? agg.tp + '/' + bans + ' bans landed on actors' : 'a precision needs a ban');
  factRow('recall',
    agg.actors ? (agg.tp / agg.actors).toFixed(2) : 'no actors seen yet',
    agg.actors ? agg.tp + '/' + agg.actors + ' actors banned' : '');
  factRow('Brier',
    agg.brierN ? (agg.brierSum / agg.brierN).toFixed(3) : 'no claims to score',
    agg.brierN ? 'across ' + plural(agg.brierN, 'banded ban') : 'a band only means something once an outcome checks it');
  factRow('hours per correct ban',
    agg.tp ? (agg.hours / agg.tp).toFixed(1) + 'h' : '—',
    agg.tp ? agg.hours + 'h of clock over ' + plural(agg.tp, 'actor ban') +
      ' — the first shift has no clock and contributes none'
      : 'no correct bans yet');
  box.appendChild(facts);

  var t = ui.el('table');
  var hr = ui.el('tr');
  ['shift', 'best', 'of max', '', 'false bans', 'hours', 'Brier'].forEach(function (h) {
    hr.appendChild(ui.el('th', null, h));
  });
  t.appendChild(hr);
  rows.forEach(function (row) {
    var tr = ui.el('tr');
    tr.appendChild(ui.el('td', null, (row.i + 1) + ' — ' + (row.sh.title || row.sh.id)));
    var s = row.stats;
    if (!s) {
      ['—', '', '', '', '', ''].forEach(function (x) { tr.appendChild(ui.el('td', 'dim small', x)); });
      t.appendChild(tr);
      return;
    }
    tr.appendChild(ui.el('td', 'mono', fmtScore(s.score)));
    tr.appendChild(ui.el('td', 'mono dim', String(s.max)));
    var sparkTd = ui.el('td');
    var sp = ui.el('span', 'spark');
    var fill = ui.el('i');
    var pct = s.max > 0 ? Math.max(0, Math.min(100, 100 * s.score / s.max)) : 0;
    fill.style.width = pct.toFixed(0) + '%';
    sp.appendChild(fill);
    sparkTd.appendChild(sp);
    tr.appendChild(sparkTd);
    tr.appendChild(ui.el('td', 'mono', s.fp + '/' + s.benign));
    /* SPEC-2 §8: a shift with no clock has no hours to report */
    tr.appendChild(s.live === false
      ? ui.el('td', 'small dim', 'no clock')
      : ui.el('td', 'mono', s.hours + 'h'));
    tr.appendChild(ui.el('td', 'mono', s.brierN ? (s.brierSum / s.brierN).toFixed(3) : '—'));
    t.appendChild(tr);
  });
  box.appendChild(t);

  /* §4: the dashboard closes with the #16 base-rate section over the
     cumulative numbers — it replaces the per-shift version here. */
  box.appendChild(ui.el('h3', null, 'The base-rate kicker, career-wide'));
  if (!bans) {
    box.appendChild(ui.el('p', 'small dim', 'No bans yet, so no rates to hold against you.'));
  } else if (agg.fp > 0) {
    var p = 0.001;
    var fpr = agg.fp / agg.benign;
    var tpr = agg.actors > 0 ? agg.tp / agg.actors : 0;
    var denom = fpr * (1 - p) + tpr * p;
    var innocentShare = denom > 0 ? (fpr * (1 - p)) / denom : 1;
    box.appendChild(ui.el('p', null,
      'Across your career the false-ban rate is ' + agg.fp + '/' + agg.benign +
      '. At a realistic 0.1% abuse prevalence, a queue with your rates would be ~' +
      (100 * innocentShare).toFixed(1) + '% innocent.'));
    box.appendChild(ui.el('p', 'small dim',
      'Computed from your cumulative confusion matrix: FPR·(1−p) / (FPR·(1−p) + TPR·p) ' +
      'with p = 0.001, FPR = ' + agg.fp + '/' + agg.benign + ', TPR = ' + agg.tp + '/' + agg.actors + '.'));
  } else {
    var ub = ui.wilson ? ui.wilson(agg.benign) : 0;
    box.appendChild(ui.el('p', null,
      '0/' + agg.benign + ' is not a rate: with ' + agg.benign +
      ' innocents across your career, the data only licenses “under ' +
      (100 * ub).toFixed(1) + '%” (Wilson 95% upper bound). ' +
      'Hunt\'s own 0/14 carries the same asterisk.'));
  }
}

/* ------------------------------------------------- report lead + career */
function insertReportLead(sh) {
  if (!sh || !sh.report_lead) { return; }
  var root = ui.$('screen-report');
  if (!root) { return; }
  /* §4: the shift-4 report leads with this line — right after the h1 */
  root.insertBefore(ui.el('p', 'report-lead', sh.report_lead), root.children[1] || null);
}

function finalize(report) {
  var id = report.shiftId;
  var m = report.matrix;
  var stats = {
    score: report.score,
    max: maxFor(report.counts),
    tp: m.banActor, fp: m.banBenign,
    monActor: m.monActor, monBenign: m.monBenign,
    clearActor: m.clearActor, clearBenign: m.clearBenign,
    actors: report.counts.actors, benign: report.counts.benign,
    brierN: report.brier.n,
    brierSum: report.brier.n ? report.brier.score * report.brier.n : 0,
    /* SPEC-2 §8: hours are how far the clock ran, and a shift without one
       contributes none. `live` says which kind of shift produced the row. */
    live: !!report.live,
    hours: report.elapsed,
    tabsOpened: report.tabsOpened,
    seed: report.seed,
    appealsDelta: report.appeals ? report.appeals.delta : 0
  };
  var r = career.shifts[id];
  if (!r) {
    r = { completed: false, plays: 0, best: null, bestStats: null };
    career.shifts[id] = r;
  }
  var firstCompletion = !r.completed;
  r.completed = true;
  r.plays += 1;
  var newBest = (r.best === null || stats.score > r.best);
  if (newBest) { r.best = stats.score; r.bestStats = stats; }
  saveCareer();

  var idx = -1;
  shifts.forEach(function (sh, i) { if (sh.id === id) { idx = i; } });
  var root = ui.$('screen-report');
  var sec = ui.el('section');
  sec.appendChild(ui.el('h2', null, 'Career'));
  sec.appendChild(ui.el('p', null,
    'Best for this shift: ' + fmtScore(r.best) + '.' +
    (newBest && r.plays > 1 ? ' This run set it.' : '')));
  if (firstCompletion && idx >= 0 && idx + 1 < shifts.length) {
    sec.appendChild(ui.el('p', null,
      'Shift ' + (idx + 2) + ' — “' + (shifts[idx + 1].title || shifts[idx + 1].id) +
      '” is now unlocked.'));
  }
  if (completedCount() === shifts.length && shifts.length > 1) {
    sec.appendChild(ui.el('p', null,
      'All ' + shifts.length + ' shifts complete. The shift select has the career dashboard.'));
  }
  var back = ui.el('button', null, 'Shift select');
  back.id = 'btn-career-select';
  back.addEventListener('click', showLanding);
  var pb = ui.el('p');
  pb.appendChild(back);
  sec.appendChild(pb);
  root.appendChild(sec);
}

/* -------------------------------------------------------- appeals round */
function beginAppeals(report) {
  var truths = window.Game.revealAllFor(report);
  var cards = [];
  report.verdicts.forEach(function (v) {
    if (v.verdict !== 'ban') { return; }
    var t = truths[v.id] || {};
    if (!t || !t.appeal) { return; }   /* no card authored: no appeal filed */
    cards.push({ id: v.id, band: v.band, appeal: t.appeal, decision: null });
  });
  if (!cards.length) {
    var root = ui.$('screen-report');
    if (root) {
      var sec = ui.el('section');
      sec.appendChild(ui.el('h2', null, 'Appeals'));
      sec.appendChild(ui.el('p', 'dim',
        'No bans, so no appeals. An appeal needs an enforcement to appeal.'));
      root.appendChild(sec);
    }
    finalize(report);
    return;
  }
  appeal = { report: report, truths: truths, cards: cards };
  var rep = ui.$('screen-report');
  if (rep) { rep.hidden = true; }   /* the round comes before the report */
  renderAppeals();
  var scr = ui.$('screen-appeals');
  if (scr) { scr.hidden = false; }
  if (window.scrollTo) { window.scrollTo(0, 0); }
}

/* Renders ONLY the card fields. No truth, no tells, no points — the round
   is decided blind, the way the desk would decide it. */
function renderAppeals() {
  var root = ui.$('screen-appeals');
  if (!root || !appeal) { return; }
  root.textContent = '';
  root.appendChild(ui.el('h1', null, 'Appeals'));
  root.appendChild(ui.el('p', null,
    'The shift is over. Every ban you signed has filed an appeal: each card nominates ' +
    'one fact, and independent verification has already returned. Uphold the ban or ' +
    'reverse it. The report follows the round.'));
  var p = points();
  root.appendChild(ui.el('p', 'small dim',
    'A reversed ban on a benign account scores ' + fmtScore(reversedPts(false)) +
    ' instead of ' + fmtScore(p.banBenign) + '. A reversed ban on an actor scores ' +
    fmtScore(reversedPts(true)) + ' instead of ' + fmtPts(p.banActor) +
    '. Upheld bans stand as signed.'));
  var done = 0;
  appeal.cards.forEach(function (c) { if (c.decision) { done += 1; } });
  var prog = ui.el('p', 'small dim mono', done + ' of ' + appeal.cards.length + ' decided');
  prog.id = 'appeals-progress';
  root.appendChild(prog);

  appeal.cards.forEach(function (card) {
    var box = ui.el('div', 'appeal-card');
    var head = ui.el('p', 'ap-head');
    head.appendChild(ui.el('span', 'mono', card.id + ' '));
    head.appendChild(ui.el('span', 'small dim',
      'banned at “' + String(card.band || '').replace(/_/g, ' ') + '”'));
    if (card.appeal.resolvable === false) {
      head.appendChild(document.createTextNode(' '));
      head.appendChild(ui.el('span', 'ap-chip', 'unresolvable'));
    }
    box.appendChild(head);
    box.appendChild(ui.el('p', null, 'Nominated fact: “' + (card.appeal.claim || '') + '”'));
    box.appendChild(ui.el('p', 'ap-verif', 'Verification: ' + (card.appeal.verification || '')));
    if (card.decision) {
      box.appendChild(ui.el('p',
        'ap-decided ' + (card.decision === 'reverse' ? 'ap-rev' : 'ap-up'),
        card.decision === 'reverse' ? 'REVERSED — the ban is lifted.' : 'UPHELD — the ban stands.'));
    } else {
      var row = ui.el('p');
      var up = ui.el('button', 'btn-ban', 'UPHOLD');
      up.setAttribute('data-appeal', card.id);
      up.setAttribute('data-act', 'uphold');
      up.addEventListener('click', function () { decide(card, 'uphold'); });
      var rv = ui.el('button', 'btn-clear', 'REVERSE');
      rv.setAttribute('data-appeal', card.id);
      rv.setAttribute('data-act', 'reverse');
      rv.addEventListener('click', function () { decide(card, 'reverse'); });
      row.appendChild(up);
      row.appendChild(document.createTextNode(' '));
      row.appendChild(rv);
      box.appendChild(row);
    }
    root.appendChild(box);
  });

  if (done === appeal.cards.length) {
    var close = ui.el('button', 'btn-clear', 'Close the round');
    close.id = 'btn-appeals-close';
    close.addEventListener('click', closeAppeals);
    var pc = ui.el('p');
    pc.appendChild(close);
    root.appendChild(pc);
  }
  /* §4: the round's footer, verbatim */
  root.appendChild(ui.el('p', 'appeals-foot',
    'The evidence that makes this pipeline hard to evade is the same evidence that ' +
    'makes a mistake hard to undo.'));
}
function decide(card, d) {
  if (!appeal || card.decision) { return; }   /* a decision is a decision */
  card.decision = d;
  renderAppeals();
}

function closeAppeals() {
  if (!appeal) { return; }
  var report = appeal.report;
  var truths = appeal.truths;
  var p = points();
  var delta = 0, upheld = 0, reversed = 0, hadUnresolvable = false;
  var rows = [];
  appeal.cards.forEach(function (card) {
    var t = truths[card.id] || {};
    var isActor = t.truth === 'malicious';
    var before = isActor ? p.banActor : p.banBenign;
    var after = before;
    if (card.decision === 'reverse') { reversed += 1; after = reversedPts(isActor); }
    else { upheld += 1; }
    if (card.appeal.resolvable === false) { hadUnresolvable = true; }
    delta += after - before;
    rows.push({ id: card.id, decision: card.decision, isActor: isActor,
                before: before, after: after,
                unresolvable: card.appeal.resolvable === false });
  });
  report.score += delta;
  st.score = report.score;
  report.appeals = {
    n: appeal.cards.length, upheld: upheld, reversed: reversed, delta: delta,
    decisions: rows.map(function (r) { return { id: r.id, decision: r.decision }; })
  };

  var root = ui.$('screen-report');
  var scoreLine = root.querySelector('.score-line');
  if (scoreLine) { scoreLine.textContent = fmtScore(report.score) + ' of ' + maxFor(report.counts); }
  var rankLine = root.querySelector('.rank-line');
  if (rankLine) { rankLine.textContent = 'Rank: ' + rankFor(report.score); }

  var sec = ui.el('section');
  sec.appendChild(ui.el('h2', null, 'Appeals'));
  sec.appendChild(ui.el('p', null,
    plural(report.appeals.n, 'appeal') + ': ' + upheld + ' upheld, ' + reversed +
    ' reversed. Net adjustment ' + fmtPts(delta) + '.'));
  var t = ui.el('table');
  var hr = ui.el('tr');
  ['account', 'decision', 'truth', 'points'].forEach(function (h) {
    hr.appendChild(ui.el('th', null, h));
  });
  t.appendChild(hr);
  rows.forEach(function (r) {
    var tr = ui.el('tr');
    tr.appendChild(ui.el('td', 'mono', r.id));
    tr.appendChild(ui.el('td', null, r.decision === 'reverse' ? 'reversed' : 'upheld'));
    tr.appendChild(ui.el('td', null,
      (r.isActor ? 'threat actor' : 'benign') + (r.unresolvable ? ' · unresolvable card' : '')));
    tr.appendChild(ui.el('td', 'mono',
      r.after === r.before ? fmtCell(r.before) : fmtCell(r.before) + ' → ' + fmtCell(r.after)));
    t.appendChild(tr);
  });
  sec.appendChild(t);
  if (hadUnresolvable) {
    sec.appendChild(ui.el('p', 'small dim',
      'One card was unresolvable by design: the finding it appealed was coordination, ' +
      'and no document exists either way. Whatever you decided there was a judgment, ' +
      'not a verification.'));
  }
  sec.appendChild(ui.el('p', 'small dim', 'The score above includes these adjustments.'));
  root.appendChild(sec);

  var scr = ui.$('screen-appeals');
  if (scr) { scr.hidden = true; }
  appeal = null;
  root.hidden = false;
  if (window.scrollTo) { window.scrollTo(0, 0); }
  finalize(report);
}

/* ------------------------------------------------------------- registry */
window.Game.registerMode('career', {
  init: function (ctx) {
    ui = ctx.ui;
    st = ctx.state;
    meta = ctx.data.meta;
    shifts = ctx.data.shifts || [];
    shift = ctx.shift;
    career = loadCareer();
    /* the shift select replaces the global intro as the landing screen */
    var intro = ui.$('screen-intro');
    if (intro) { intro.hidden = true; }
    renderLanding();
    var root = ui.$('screen-career');
    if (root) { root.hidden = false; }
    /* ?shift=sN deep-links to a shift's briefing; locked or unknown ids
       leave the landing standing */
    var want = null;
    try { want = new URLSearchParams(location.search).get('shift'); }
    catch (e) { want = null; }
    if (want) { selectShift(want); }
  },
  onEvent: function (ev, ctx) {
    ui = ctx.ui;
    st = ctx.state;
    meta = ctx.data.meta;
    shifts = ctx.data.shifts || [];
    shift = ctx.shift;
    if (ev.type === 'shiftStart') {
      appeal = null;
      hideCareerScreens();
      return;
    }
    if (ev.type === 'shiftEnd') {
      insertReportLead(shift);
      if (shift && shift.flags && shift.flags.appeals) { beginAppeals(ev.report); }
      else { finalize(ev.report); }
    }
  }
});

})();
