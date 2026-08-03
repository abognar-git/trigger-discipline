/* =========================================================================
   trigger-discipline — parts/live.js
   SPEC-2 §2, amended by §8 (A1): the live shift. One clock, forward only.
   Opening evidence takes time and advances it, and so does Wait 1h (W);
   nothing is ever refused for lack of hours. Accounts enter the queue when
   their first session lands; later sessions flag an open account UPDATED,
   or reopen a decided one — once, free — and open tabs refresh free. The
   shift ends when the clock reaches the shift's length, or by ending it
   early. Core owns arrival gating, session visibility, the reopen grant,
   and deferred scoring; this part owns the Wait control, the queue flags,
   §8's display-only "What ran while you read" section, and the
   end-of-shift reveal. It never reads `reveal` — the vault rule (SPEC v1
   §7.4, SPEC-2 §0) applies in full; post-shift truths come from
   Game.revealAllFor(report) only. Inert on shifts whose flags.live is off.
========================================================================= */
(function () {
'use strict';
if (!window.Game) { return; }

var live = false;             /* is the current shift live? set at shiftStart */
var ui = null, clock = null, st = null;
var accounts = [];            /* this shift's sealed account objects */
var updatedCounts = {};       /* id -> unseen-session count behind the badge */
var bannedAt = {};            /* id -> elapsed hour of a standing ban; a banned
                                 account's telemetry is frozen there, so its
                                 later session hours are not events */

function fmtPts(n) { return (n >= 0 ? '+' : '−') + Math.abs(n); }
function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }
function verdictCls(v) {
  return v === 'ban' ? 'v-ban' : v === 'monitor' ? 'v-monitor' : 'v-clear';
}
function verdictWord(v) {
  return v === 'ban' ? 'BANNED' : v === 'monitor' ? 'MONITORED' : 'CLEARED';
}

function setFlag(id, label, cls, sticky) {
  st.queueFlags.set(id, { label: label, cls: cls, sticky: !!sticky });
}

function doWait() {
  if (!live || !st || st.phase !== 'play') { return; }
  clock.spend(1, 'wait');
  clock.endIfOver();
}

/* The next hour at which anything happens, computed from the same
   player-visible data the arrival engine runs on: static arrivals and
   session hours for scheduled accounts, and the dynamic-arrival map for
   respawns (whose session hours are relative to their arrival). Returns
   null when nothing is left. No reveal access anywhere. */
function nextEventHour() {
  var h = st.elapsed;
  var best = null;
  accounts.forEach(function (a) {
    var dyn = st.dynamicArrivals.get(a.id);
    var arr = (dyn !== undefined) ? dyn : a.appears_at;
    if (arr === null || arr === undefined) { return; }   /* respawn never scheduled */
    if (arr > h && (best === null || arr < best)) { best = arr; }
    /* a standing ban freezes the account's telemetry at the ban hour: its
       later session hours land nowhere the player can observe, so the jump
       must not stop there */
    var frozen = Object.prototype.hasOwnProperty.call(bannedAt, a.id)
      ? bannedAt[a.id] : null;
    (a.sessions || []).forEach(function (s) {
      var sh = a.respawn ? arr + s.appears_at : s.appears_at;
      if (frozen !== null && sh > frozen) { return; }
      if (sh > h && (best === null || sh < best)) { best = sh; }
    });
  });
  return best;
}

/* SPEC-3 §11 — the pacing control. Jump the clock to the next event, or to
   the end of the shift when nothing is left. The hours cost exactly what
   pressing W that many times would cost; the control removes keypresses,
   never information. */
function doWaitNext() {
  if (!live || !st || st.phase !== 'play') { return; }
  var target = nextEventHour();
  var stop = (target === null) ? st.length : Math.min(target, st.length);
  var delta = stop - st.elapsed;
  if (delta < 1) { delta = 1; }
  clock.spend(delta, 'wait');
  clock.endIfOver();
}

function ensureWaitButton() {
  var btn = ui.$('btn-wait');
  if (!btn) {
    btn = ui.el('button', null, 'Wait 1h ');
    btn.id = 'btn-wait';
    btn.title = 'Advance the clock one hour; arrivals land as their telemetry does';
    btn.appendChild(ui.el('kbd', null, 'W'));
    btn.addEventListener('click', doWait);
    ui.$('hud').appendChild(btn);
  }
  btn.hidden = !live;
  var jump = ui.$('btn-waitnext');
  if (!jump) {
    jump = ui.el('button', null, 'Next event ');
    jump.id = 'btn-waitnext';
    jump.title = 'Run the clock forward to the next arrival or new session — ' +
      'or to the end of the shift if nothing is left. Costs exactly the hours it skips.';
    jump.appendChild(ui.el('kbd', null, '⇧W'));
    jump.addEventListener('click', doWaitNext);
    ui.$('hud').appendChild(jump);
  }
  jump.hidden = !live;
}

function onArrival(ev) {
  if (st.phase !== 'play') { return; }
  if (ev.id !== st.currentId) { setFlag(ev.id, 'NEW', 'qf-new', false); }
  ui.renderQueue();
  if (st.currentId === null || st.currentId === undefined) {
    /* nothing open — surface the arrival */
    ui.openAccount(ev.id);
  }
}

function onNewSessions(ev) {
  if (ev.reopened) {
    delete updatedCounts[ev.id];
    setFlag(ev.id, 'REOPENED', 'qf-reopened', true);
    ui.renderQueue();
    if (ev.id === st.currentId) { ui.renderDossier(); }
    return;
  }
  if (ev.id === st.currentId) {
    /* the open dossier refreshes in place; open tabs refresh free */
    ui.renderDossier();
    ui.notice(ev.count + (ev.count === 1 ? ' new session' : ' new sessions') +
      ' landed on this account. Open tabs refresh free.');
    return;
  }
  if (ev.decided) { return; }   /* verdict stands; the report will grade it */
  if (!st.queueFlags.has(ev.id)) { updatedCounts[ev.id] = 0; }
  updatedCounts[ev.id] = (updatedCounts[ev.id] || 0) + ev.count;
  setFlag(ev.id, 'UPDATED (' + updatedCounts[ev.id] + ' new)', 'qf-updated', false);
  ui.renderQueue();
}

function onVerdict(ev) {
  delete updatedCounts[ev.id];
  /* track standing bans for the next-event jump; a re-verdict away from ban
     unfreezes the account again */
  if (ev.verdict === 'ban') { bannedAt[ev.id] = st.elapsed; }
  else { delete bannedAt[ev.id]; }
  if (st.queueFlags.has(ev.id)) {
    st.queueFlags.delete(ev.id);
    ui.renderQueue();
  }
}

/* SPEC-2 §8 — "What ran while you read". Display only: no score effect, no
   input, no branch anywhere else reads it. Per actor: the malicious
   sessions that landed between the account's arrival and the ban that froze
   its telemetry (or the end of the shift if it was never banned), and the
   sessions the ban stopped — the ones scheduled after it, inside the shift.
   The clock facts come from the report's own verdict rows; the truth comes
   from revealAllFor and nowhere else. Inserted straight after the confusion
   matrix, before the reveal below. */
function ranWhileYouRead(report) {
  var truths = window.Game.revealAllFor(report);
  var matrix = ui.$('sec-matrix');
  var root = ui.$('screen-report');
  var sec = ui.el('section');
  sec.id = 'sec-ran';
  sec.appendChild(ui.el('h2', null, 'What ran while you read'));
  sec.appendChild(ui.el('p', 'small dim',
    'The malicious sessions that landed while the account sat in your queue, and the ones ' +
    'that never landed because you had already banned it. Display only; none of it scores.'));

  var rows = [];
  var ranTotal = 0, stoppedTotal = 0;
  report.verdicts.forEach(function (v) {
    var t = truths[v.id] || {};
    if (t.truth !== 'malicious') { return; }
    var banned = v.verdict === 'ban' && v.banAt !== null && v.banAt !== undefined;
    var cut = banned ? v.banAt : report.length;
    var ran = 0, stopped = 0;
    (v.sessionHours || []).forEach(function (h) {
      if (h <= cut) { ran += 1; }
      else if (h <= report.length) { stopped += 1; }
    });
    ranTotal += ran;
    stoppedTotal += stopped;
    rows.push({ id: v.id, arrived: v.arrivedAt, banned: banned, cut: cut,
                ran: ran, stopped: stopped });
  });

  if (!rows.length) {
    sec.appendChild(ui.el('p', null,
      'Nothing ran. There was no actor in this queue, so every hour you spent reading ' +
      'cost the platform exactly nothing.'));
  } else {
    var t = ui.el('table');
    var hr = ui.el('tr');
    ['account', 'in your queue', 'sessions that ran', 'sessions your ban stopped']
      .forEach(function (h) { hr.appendChild(ui.el('th', null, h)); });
    t.appendChild(hr);
    rows.forEach(function (r) {
      var tr = ui.el('tr');
      tr.appendChild(ui.el('td', 'mono', r.id));
      tr.appendChild(ui.el('td', 'small',
        'hour ' + (r.arrived === null ? '?' : r.arrived) + ' to ' +
        (r.banned ? 'your ban at hour ' + r.cut : 'end of shift, unbanned')));
      tr.appendChild(ui.el('td', 'mono', String(r.ran)));
      tr.appendChild(ui.el('td', 'mono', String(r.stopped)));
      t.appendChild(tr);
    });
    var tot = ui.el('tr');
    tot.appendChild(ui.el('th', null, 'total'));
    tot.appendChild(ui.el('th', 'small', plural(rows.length, 'actor')));
    tot.appendChild(ui.el('th', 'mono', String(ranTotal)));
    tot.appendChild(ui.el('th', 'mono', String(stoppedTotal)));
    t.appendChild(tot);
    sec.appendChild(t);
    sec.appendChild(ui.el('p', 'small dim',
      ranTotal + ' malicious ' + (ranTotal === 1 ? 'session' : 'sessions') +
      ' completed on the platform during this shift. ' +
      (stoppedTotal
        ? stoppedTotal + ' scheduled ' + (stoppedTotal === 1 ? 'session' : 'sessions') +
          ' never ran, because the account was gone by then.'
        : 'No ban landed early enough to stop one.')));
  }

  if (matrix && matrix.parentNode === root) {
    root.insertBefore(sec, matrix.nextSibling);
  } else {
    root.appendChild(sec);
  }
}

/* Live shifts defer every reveal to the report: one row per account, the
   truth, the points, and the tell that interstitials would have carried. */
function appendReveal(report) {
  var truths = window.Game.revealAllFor(report);
  var root = ui.$('screen-report');
  var sec = ui.el('section');
  sec.appendChild(ui.el('h2', null, 'The reveal'));
  sec.appendChild(ui.el('p', 'small dim',
    'A live queue does not pause to grade a verdict, so the grading all lands here. ' +
    'Queue order, one row per account.'));
  report.verdicts.forEach(function (v) {
    var t = truths[v.id] || {};
    var isActor = t.truth === 'malicious';
    var row = ui.el('div', 'rev-row');
    var line = ui.el('p');
    line.appendChild(ui.el('span', 'mono', v.id + ' '));
    line.appendChild(ui.el('span', 'verdict-chip ' + verdictCls(v.verdict),
      verdictWord(v.verdict)));
    var bits = [];
    if (v.band) { bits.push('at “' + String(v.band).replace(/_/g, ' ') + '”'); }
    if (v.reverdict) { bits.push('revised on new evidence'); }
    if (v.auto) { bits.push('undecided at end of shift'); }
    bits.push(isActor
      ? 'threat actor: ' + (t.actor || 'unknown')
      : 'benign' + (t.persona ? ' — ' + t.persona : ''));
    bits.push(fmtPts(v.points));
    line.appendChild(ui.el('span', 'small dim', ' ' + bits.join(' · ')));
    row.appendChild(line);
    if (t.tell) { row.appendChild(ui.el('p', 'small', t.tell)); }
    sec.appendChild(row);
  });
  root.appendChild(sec);
}

window.Game.registerMode('live', {
  init: function (ctx) {
    ui = ctx.ui;
    clock = ctx.clock;
    st = ctx.state;
    document.addEventListener('keydown', function (e) {
      if (e.metaKey || e.ctrlKey || e.altKey) { return; }
      if ((e.key === 'w' || e.key === 'W') && live && st.phase === 'play') {
        e.preventDefault();
        if (e.shiftKey) { doWaitNext(); } else { doWait(); }
      }
    });
  },
  onEvent: function (ev, ctx) {
    ui = ctx.ui;
    clock = ctx.clock;
    st = ctx.state;
    if (ev.type === 'shiftStart') {
      live = !!(ev.shift && ev.shift.flags && ev.shift.flags.live);
      /* the shiftStart event carries no account list; look the shift up in
         ctx.data the same way the case board does */
      accounts = [];
      ((ctx.data && ctx.data.shifts) || []).forEach(function (sh) {
        if (ev.shift && sh.id === ev.shift.id) { accounts = sh.accounts || []; }
      });
      updatedCounts = {};
      bannedAt = {};
      ensureWaitButton();
      return;
    }
    if (!live) { return; }
    if (ev.type === 'arrival') { onArrival(ev); return; }
    if (ev.type === 'newSessions') { onNewSessions(ev); return; }
    if (ev.type === 'verdict') { onVerdict(ev); return; }
    if (ev.type === 'shiftEnd') { ranWhileYouRead(ev.report); appendReveal(ev.report); }
  }
});

})();
