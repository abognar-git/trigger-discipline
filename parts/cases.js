/* =========================================================================
   trigger-discipline — parts/cases.js
   SPEC-2 §3: cases. Attribution is the unit of enforcement: accounts that
   belong to one operator are one case, and a case with >=2 members is
   banned once — one citation of a LINK REASON plus one band, applied to
   every member. Link reasons are computed, never typed: the picker lists
   only the overlaps that actually hold among the selected members
   (shared_asn / shared_ip / shared_target / shared_cadence, taken as
   undirected edges from the accounts' own network lists; a reason holds
   when it connects every member). A case ban whose only link reason is
   shared infrastructure is refused in the policy's own words. The
   mechanical commit path and the respawn trigger live in core
   (Game.banCase — the trigger consults the vault, which this part
   cannot). This part owns the board panel, the dossier add/remove action
   (A), the reason picker, the band row, and the refusal UX. It never
   reads `reveal` — the vault rule (SPEC v1 §7.4, SPEC-2 §0) applies in
   full. Inert on shifts whose flags.cases is off.
========================================================================= */
(function () {
'use strict';
if (!window.Game) { return; }

/* §3 — the infra-only refusal, verbatim; and the shared floor refusal. */
var REFUSE_CASE_LINK = 'Refused: an overlap is an observation, not a link. ' +
  'A link needs a reason — shared infrastructure is how the VPN user died.';
var REFUSE_FLOOR = 'Refused: below the confidence floor.';
/* Finding #17 — the style channel has no resolution on prompts this short:
   every pair in the queue scores alike, so the policy refuses it outright.
   Static skeleton here; the queue's own measured numbers are appended from
   the shift's style block when the refusal fires. */
var REFUSE_STYLE = 'Refused: writing style links every account here or none.';

var KINDS = [
  ['shared_asn', 'same ASN'],
  ['shared_ip', 'same IP'],
  ['shared_target', 'same target org'],
  ['shared_cadence', 'same automation cadence'],
  /* finding #17: hunt measured this channel and adopted it nowhere; the desk
     here accepts it, because letting the player merge on it is the only way
     to teach why the research did not */
  ['shared_hours', 'same active hours']
];

var casesOn = false;
var ui = null, st = null, meta = null;
var styleBlock = null;      /* the shift's pairwise style matrix (finding #17) */
var acctById = new Map();   /* sealed account objects for the current shift */
var cases = [];             /* {name, members:[ids], selected:{kind:bool}, banned:null|{...}, absorbed:[str]} */
var nextCaseNum = 1;        /* monotonic: a folded case's number is never reissued */
var activeIdx = -1;
var verdictOf = new Map();  /* id -> verdict, tracked from events only */
var pendingBand = false;    /* band row open for the active case */
var noticeText = '';

function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }
function minMembers() {
  return Number(meta && meta.policy && meta.policy.case_min_members) || 2;
}
function sufficientKinds() {
  return (meta && meta.policy && meta.policy.sufficient_link_reasons) ||
    ['shared_target', 'shared_cadence'];
}
function bandsAsc() {
  var bands = (meta && meta.bands) || {};
  return Object.keys(bands).map(function (name) {
    return { name: name, label: name.replace(/_/g, ' '), p: Number(bands[name]) };
  }).sort(function (a, b) { return a.p - b.p; });
}
function floorBand() { return (meta && meta.policy && meta.policy.floor_band) || ''; }
function floorP() {
  return Number(((meta && meta.bands) || {})[floorBand()]);
}
function activeCase() { return activeIdx >= 0 ? cases[activeIdx] : null; }

/* Finding #17 — pairwise style scores among the case members, read from the
   shift's emitted matrix (hunt src/linkage.py computed it; nothing here
   restates a feature). Returns null when the matrix cannot answer. */
function stylePairRange(members) {
  if (!styleBlock || members.length < 2) { return null; }
  var order = styleBlock.order || [];
  var n = order.length;
  var idx = {};
  order.forEach(function (id, i) { idx[id] = i; });
  var lo = null, hi = null;
  for (var i = 0; i < members.length; i++) {
    for (var j = i + 1; j < members.length; j++) {
      var a = idx[members[i]], b = idx[members[j]];
      if (a === undefined || b === undefined) { return null; }
      var r = Math.min(a, b), c = Math.max(a, b);
      var v = styleBlock.pairs[r * n - r * (r + 1) / 2 + (c - r - 1)];
      if (lo === null || v < lo) { lo = v; }
      if (hi === null || v > hi) { hi = v; }
    }
  }
  return { min: lo, max: hi };
}

function styleRefusal() {
  var msg = REFUSE_STYLE;
  if (styleBlock) {
    msg += ' Every pair in this queue scores between ' +
      styleBlock.min.toFixed(3) + ' and ' + styleBlock.max.toFixed(3) +
      '; the median account holds ' + styleBlock.median_words +
      ' words against an authorship floor of ' + styleBlock.word_floor + '.';
  }
  return msg;
}

/* A link reason holds when its overlap edges connect every member.
   Edges are undirected: a respawn lists its parents, but the parents'
   files predate it and do not list it back. */
function reasonHolds(kind, members) {
  if (members.length < 2) { return false; }
  var inCase = {};
  members.forEach(function (id) { inCase[id] = true; });
  var adj = {};
  members.forEach(function (id) { adj[id] = []; });
  members.forEach(function (id) {
    var a = acctById.get(id);
    (((a && a.network) || {})[kind] || []).forEach(function (other) {
      if (inCase[other]) { adj[id].push(other); adj[other].push(id); }
    });
  });
  var seen = {};
  var stack = [members[0]];
  seen[members[0]] = true;
  var n = 1;
  while (stack.length) {
    adj[stack.pop()].forEach(function (o) {
      if (!seen[o]) { seen[o] = true; n += 1; stack.push(o); }
    });
  }
  return n === members.length;
}
function holdingReasons(members) {
  return KINDS.filter(function (k) { return reasonHolds(k[0], members); });
}

function setCaseNotice(msg) {
  noticeText = msg || '';
  var n = ui.$('case-notice');
  if (n) { n.textContent = noticeText; }
}

function newCase() {
  cases.push({ name: 'Case ' + nextCaseNum, members: [], selected: {},
               banned: null, absorbed: [] });
  nextCaseNum += 1;
  activeIdx = cases.length - 1;
  pendingBand = false;
  noticeText = '';
}

function kindLabel(kind) {
  var label = kind;
  KINDS.forEach(function (kk) { if (kk[0] === kind) { label = kk[1]; } });
  return label;
}

/* -------------------------------------------------------------- between cases
   Exception-tier readout over the existing computed reasons, at the picker's
   exact disclosure level (player-visible network lists; no reveal, no
   scoring, no policy change). A real desk consolidates clusters by reading
   which members of one touch which members of the other, on what channel -
   so the line leads with the cross-edges, names the account every edge runs
   through when there is one (single-point linkage is the weakest attribution
   a desk accepts, and it is the entire s6 frame), and ends with what a merge
   would actually leave on the picker. */
function crossEdges(aMembers, bMembers) {
  var aSet = {}, bSet = {};
  aMembers.forEach(function (id) { aSet[id] = true; });
  bMembers.forEach(function (id) { bSet[id] = true; });
  var out = {};
  KINDS.forEach(function (k) {
    var seen = {};
    var edges = [];
    function scan(fromIds, toSet, flip) {
      fromIds.forEach(function (id) {
        var acct = acctById.get(id);
        ((((acct || {}).network) || {})[k[0]] || []).forEach(function (o) {
          if (!toSet[o]) { return; }
          var a = flip ? o : id, b = flip ? id : o;
          if (seen[a + '|' + b]) { return; }
          seen[a + '|' + b] = true;
          edges.push([a, b]);
        });
      });
    }
    /* both directions: a respawn's edges are one-directional in the data */
    scan(aMembers, bSet, false);
    scan(bMembers, aSet, true);
    if (edges.length) { out[k[0]] = edges; }
  });
  return out;
}

function foldCase(j) {
  if (!casesOn || !st || st.phase !== 'play') { return; }
  var c = activeCase();
  var o = cases[j];
  if (!c || c.banned || !c.members.length) { return; }
  if (!o || o === c || o.banned || !o.members.length) { return; }
  var moved = 0;
  o.members.forEach(function (id) {
    if (c.members.indexOf(id) < 0) { c.members.push(id); moved += 1; }
  });
  c.absorbed.push('Absorbed ' + o.name + ' (' + plural(moved, 'member') +
    ') at hour ' + st.elapsed + '.');
  cases.splice(j, 1);
  if (j < activeIdx) { activeIdx -= 1; }
  /* prune selections against the union here, not in a render branch;
     shared_style stays exempt (finding #17: always offerable) */
  var holdNow = { shared_style: true };
  holdingReasons(c.members).forEach(function (k) { holdNow[k[0]] = true; });
  Object.keys(c.selected).forEach(function (k) {
    if (!holdNow[k]) { delete c.selected[k]; }
  });
  pendingBand = false;
  noticeText = o.name + ' folded into ' + c.name + ' — ' +
    plural(c.members.length, 'member') + ' now. Only what holds across all ' +
    'of them is offered.';
  renderBoard();
  ui.renderDossier();
}

function inAnotherCase(id) {
  for (var i = 0; i < cases.length; i++) {
    if (i !== activeIdx && !cases[i].banned && cases[i].members.indexOf(id) >= 0) { return true; }
  }
  return false;
}

/* Add/remove the open account in the active case (dossier button, key A).
   Adding an account that sits in another open case moves it — one account,
   one attribution. */
function toggleCurrent() {
  if (!casesOn || !st || st.phase !== 'play') { return; }
  var id = st.currentId;
  if (!id || !acctById.has(id)) { return; }
  var c = activeCase();
  if (!c || c.banned) { newCase(); c = activeCase(); }
  var i = c.members.indexOf(id);
  if (i >= 0) {
    c.members.splice(i, 1);
  } else {
    cases.forEach(function (o) {
      if (o === c || o.banned) { return; }
      var j = o.members.indexOf(id);
      if (j >= 0) { o.members.splice(j, 1); }
    });
    c.members.push(id);
  }
  pendingBand = false;
  noticeText = '';
  renderBoard();
  ui.renderDossier();   /* refresh the dossier button label */
}

function removeMember(c, id) {
  if (c.banned) { return; }
  var i = c.members.indexOf(id);
  if (i >= 0) { c.members.splice(i, 1); }
  pendingBand = false;
  noticeText = '';
  renderBoard();
  ui.renderDossier();
}

function chosenReasons(c) {
  var holding = holdingReasons(c.members).map(function (k) { return k[0]; });
  return holding.filter(function (k) { return c.selected[k]; });
}

function requestCaseBan() {
  var c = activeCase();
  if (!c || c.banned || !st || st.phase !== 'play') { return; }
  if (c.members.length < minMembers()) {
    setCaseNotice('A case needs at least ' + minMembers() + ' members.');
    return;
  }
  var holding = holdingReasons(c.members).map(function (k) { return k[0]; });
  var chosen = chosenReasons(c);
  var styleChosen = !!c.selected.shared_style;
  if (!chosen.length && !styleChosen) {
    setCaseNotice(holding.length
      ? 'Pick the link reason the ban stands on.'
      : 'No overlap holds across every member. There is no case to ban.');
    return;
  }
  var suff = sufficientKinds();
  if (!chosen.some(function (k) { return suff.indexOf(k) >= 0; })) {
    /* §3: shared_asn / shared_ip alone never carry a case ban — and style
       (finding #17) never carries anything: a channel with no resolution is
       refused with its own measured numbers, the more specific lesson */
    pendingBand = false;
    noticeText = styleChosen ? styleRefusal() : REFUSE_CASE_LINK;
    renderBoard();
    return;
  }
  pendingBand = true;
  noticeText = '';
  renderBoard();
}

function chooseCaseBand(name) {
  var c = activeCase();
  if (!c || c.banned || !pendingBand) { return; }
  if (Number(((meta && meta.bands) || {})[name]) < floorP()) {
    setCaseNotice(REFUSE_FLOOR);   /* the band row stays open */
    return;
  }
  var chosen = chosenReasons(c);
  var res = window.Game.banCase(c.members.slice(), name, chosen);
  if (!res || !res.ok) {
    setCaseNotice(res && res.refused === 'link' ? REFUSE_CASE_LINK
      : res && res.refused === 'floor' ? REFUSE_FLOOR
      : res && res.refused === 'decided'
        ? 'Every member already carries a verdict. A verdict only moves on new evidence.'
        : 'The policy did not accept this case ban' +
          (res && res.refused ? ' (' + res.refused + ')' : '') + '.');
    return;
  }
  c.banned = { band: name, reasons: chosen,
               banned: res.banned.slice(), skipped: res.skipped.slice() };
  pendingBand = false;
  noticeText = res.skipped.length
    ? plural(res.banned.length, 'account') + ' banned; ' +
      plural(res.skipped.length, 'standing verdict') +
      ' unchanged — a verdict only moves on new evidence.'
    : plural(res.banned.length, 'account') + ' banned as one case.';
  renderBoard();
}

/* ------------------------------------------------------------------ board */
function renderBoard() {
  var bar = ui.$('casebar');
  if (!bar || !casesOn) { return; }
  bar.textContent = '';
  bar.appendChild(ui.el('h2', null, 'Case board'));
  bar.appendChild(ui.el('p', 'small dim',
    'Accounts that belong to one operator are one case. A case with at least ' +
    minMembers() + ' members is banned once — one link reason, one band, every member.'));

  var tabs = ui.el('div', 'case-tabs');
  cases.forEach(function (c, i) {
    var b = ui.el('button', null, c.name + (c.banned ? ' — enforced' : ''));
    b.setAttribute('data-case', String(i));
    if (i === activeIdx) { b.setAttribute('aria-current', 'true'); }
    b.addEventListener('click', function () {
      activeIdx = i;
      pendingBand = false;
      noticeText = '';
      renderBoard();
      ui.renderDossier();
    });
    tabs.appendChild(b);
  });
  var nb = ui.el('button', null, 'New case');
  nb.id = 'btn-newcase';
  nb.addEventListener('click', function () {
    newCase();
    renderBoard();
    ui.renderDossier();
  });
  tabs.appendChild(nb);
  bar.appendChild(tabs);

  var c = activeCase();
  if (!c) {
    bar.appendChild(ui.el('p', 'dim small',
      'No cases yet. Open an account and press A, or use the dossier button.'));
  } else {
    if (!c.members.length) {
      bar.appendChild(ui.el('p', 'dim small', 'Empty. Add accounts from the dossier.'));
    }
    c.members.forEach(function (id) {
      var row = ui.el('div', 'case-member');
      var chip = ui.el('button', 'acct-link', id);
      chip.addEventListener('click', function () { ui.openAccount(id); });
      row.appendChild(chip);
      var v = verdictOf.get(id);
      if (v) {
        row.appendChild(ui.el('span',
          'case-verdict ' + (v === 'ban' ? 'v-ban' : v === 'monitor' ? 'v-monitor' : 'v-clear'),
          v === 'ban' ? 'BANNED' : v === 'monitor' ? 'MONITORED' : 'CLEARED'));
      }
      if (!c.banned) {
        var x = ui.el('button', 'case-x', '×');
        x.setAttribute('aria-label', 'Remove ' + id + ' from the case');
        x.addEventListener('click', function () { removeMember(c, id); });
        row.appendChild(x);
      }
      bar.appendChild(row);
    });
    /* fold provenance is a record, not a notice: a wrong merge must be
       reversible by hand without memory, and memory is what a notice is not */
    (c.absorbed || []).forEach(function (lineTxt) {
      bar.appendChild(ui.el('p', 'small dim', lineTxt));
    });

    if (c.banned) {
      var enf = ui.el('div', 'case-enforced');
      enf.appendChild(ui.el('p', null,
        'Enforced — ' + plural(c.banned.banned.length, 'account') + ' banned at “' +
        c.banned.band.replace(/_/g, ' ') + '” on ' +
        c.banned.reasons.map(function (r) {
          var k = null;
          KINDS.forEach(function (kk) { if (kk[0] === r) { k = kk[1]; } });
          return k || r;
        }).join(' + ') + '.' +
        (c.banned.skipped.length
          ? ' ' + plural(c.banned.skipped.length, 'standing verdict') + ' unchanged.'
          : '')));
      bar.appendChild(enf);
    } else if (c.members.length >= minMembers()) {
      bar.appendChild(ui.el('h3', null, 'Link reason'));
      var holding = holdingReasons(c.members);
      /* drop selections that no longer hold — membership changed under them.
         shared_style is exempt: it is always offerable, which is finding #17. */
      var holdSet = { shared_style: true };
      holding.forEach(function (k) { holdSet[k[0]] = true; });
      Object.keys(c.selected).forEach(function (k) {
        if (!holdSet[k]) { delete c.selected[k]; }
      });
      {
        bar.appendChild(ui.el('p', 'small dim', holding.length
          ? 'Computed from the members’ own overlaps; only what holds is offered.'
          : 'No overlap holds across every member.'));
        holding.forEach(function (k) {
          var row = ui.el('label', 'case-reason');
          var cb = ui.el('input');
          cb.type = 'checkbox';
          cb.setAttribute('data-kind', k[0]);
          cb.checked = !!c.selected[k[0]];
          cb.addEventListener('change', function () {
            c.selected[k[0]] = cb.checked;
            if (pendingBand) { pendingBand = false; renderBoard(); }
          });
          row.appendChild(cb);
          var body = ui.el('span', null, k[1] + ' ');
          body.appendChild(ui.el('span', 'kind', k[0]));
          row.appendChild(body);
          bar.appendChild(row);
        });
        /* finding #17 — the style row is offered for EVERY case, because on
           prompts this short the channel matches every pair; the number
           beside it is the point, and selecting it gets the refusal */
        var srow = ui.el('label', 'case-reason');
        var scb = ui.el('input');
        scb.type = 'checkbox';
        scb.setAttribute('data-kind', 'shared_style');
        scb.checked = !!c.selected.shared_style;
        scb.addEventListener('change', function () {
          c.selected.shared_style = scb.checked;
          if (pendingBand) { pendingBand = false; renderBoard(); }
        });
        srow.appendChild(scb);
        var sbody = ui.el('span', null, 'same writing style ');
        sbody.appendChild(ui.el('span', 'kind', 'shared_style'));
        var range = stylePairRange(c.members);
        if (range && styleBlock) {
          var caseTxt = range.min === range.max
            ? range.min.toFixed(3)
            : range.min.toFixed(3) + '–' + range.max.toFixed(3);
          sbody.appendChild(ui.el('span', 'dim small',
            ' — this case ' + caseTxt + ' · the whole queue ' +
            styleBlock.min.toFixed(3) + '–' + styleBlock.max.toFixed(3)));
        }
        srow.appendChild(sbody);
        bar.appendChild(srow);
        var banBtn = ui.el('button', 'btn-ban', 'BAN CASE — ' + plural(c.members.length, 'member'));
        banBtn.id = 'btn-bancase';
        banBtn.addEventListener('click', requestCaseBan);
        bar.appendChild(ui.el('div')).appendChild(banBtn);
        if (pendingBand) {
          var bandRow = ui.el('div', 'case-bands');
          bandRow.id = 'case-bands';
          bandsAsc().forEach(function (b) {
            var btn = ui.el('button', null, b.label + ' ');
            btn.setAttribute('data-band', b.name);
            btn.appendChild(ui.el('span', 'band-p', 'P ' + b.p.toFixed(2)));
            btn.addEventListener('click', function () { chooseCaseBand(b.name); });
            bandRow.appendChild(btn);
          });
          var cancel = ui.el('button', null, 'Cancel');
          cancel.addEventListener('click', function () {
            pendingBand = false;
            noticeText = '';
            renderBoard();
          });
          bandRow.appendChild(cancel);
          bar.appendChild(bandRow);
          bar.appendChild(ui.el('p', 'small dim', 'Policy floor: “' +
            floorBand().replace(/_/g, ' ') + '” (P ' + floorP().toFixed(2) +
            '). Below it, the ban is refused.'));
        }
      }
    } else {
      bar.appendChild(ui.el('p', 'small dim',
        'Add at least ' + (minMembers() - c.members.length) + ' more; a case needs ' +
        minMembers() + '.'));
    }

    /* -- between cases: observations, never advice. Rendered only when the
       ACTIVE case is open and non-empty, so every union has two sides. No
       checkboxes here - the picker owns citations; this block only reads. -- */
    var others = [];
    cases.forEach(function (o, j) {
      if (j === activeIdx || o.banned || !o.members.length) { return; }
      others.push([o, j]);
    });
    if (!c.banned && c.members.length && others.length) {
      var bt = ui.el('div', 'case-between');
      bt.appendChild(ui.el('h3', null, 'Between cases'));
      others.forEach(function (pair) {
        var o = pair[0], j = pair[1];
        var edges = crossEdges(c.members, o.members);
        var kindsTouching = KINDS.map(function (k) { return k[0]; })
          .filter(function (kk) { return edges[kk]; });
        var unionHolding = holdingReasons(c.members.concat(o.members))
          .map(function (k) { return k[1]; });
        var txt = o.name + ' (' + plural(o.members.length, 'member') + ') — ';
        if (!kindsTouching.length) {
          txt += 'no member touches this case.';
        } else {
          /* the bridge: an account every cross-edge runs through */
          var counts = {};
          var total = 0;
          kindsTouching.forEach(function (kk) {
            edges[kk].forEach(function (e) {
              total += 1;
              counts[e[0]] = (counts[e[0]] || 0) + 1;
              counts[e[1]] = (counts[e[1]] || 0) + 1;
            });
          });
          var bridges = Object.keys(counts).filter(function (id) {
            return counts[id] === total;
          });
          var channels = kindsTouching.map(kindLabel).join(', ');
          if (bridges.length === 1) {
            txt += 'touches this case only through ' + bridges[0] + ': ' +
              channels + '. ';
          } else if (bridges.length === 2 && total === 1) {
            txt += 'touches this case through ' + bridges.join(' · ') +
              ' only: ' + channels + '. ';
          } else {
            txt += 'touches this case: ' + channels + '. ';
          }
          txt += unionHolding.length
            ? 'Merged, ' + unionHolding.join(' + ') + ' would hold across every member.'
            : 'Merged, no reason would hold.';
        }
        var line = ui.el('p', 'small');
        line.appendChild(document.createTextNode(txt + ' '));
        var fb = ui.el('button', null, 'Fold ' + o.name.toLowerCase() + ' in');
        fb.setAttribute('data-merge', String(j));
        fb.addEventListener('click', function () { foldCase(j); });
        line.appendChild(fb);
        bt.appendChild(line);
      });
      bt.appendChild(ui.el('p', 'small dim',
        'The pipeline chains overlaps pair by pair; a case ban stands on one ' +
        'reason that holds across every member.'));
      bar.appendChild(bt);
    }
  }

  var notice = ui.el('p');
  notice.id = 'case-notice';
  notice.setAttribute('aria-live', 'polite');
  notice.textContent = noticeText;
  bar.appendChild(notice);

  var foot = ui.el('p', 'small dim');
  foot.appendChild(ui.el('kbd', null, 'A'));
  foot.appendChild(document.createTextNode(
    ' adds the open account to the active case, or removes it.'));
  bar.appendChild(foot);
}

/* The dossier action — injected on every dossier render. */
function injectDossierButton(id) {
  if (!casesOn || !id || !st || st.phase !== 'play') { return; }
  var bar = ui.$('verdict-bar');
  if (!bar) { return; }
  var c = activeCase();
  var label;
  if (!c || c.banned) { label = 'Start a case'; }
  else if (c.members.indexOf(id) >= 0) { label = 'Remove from ' + c.name.toLowerCase(); }
  else if (inAnotherCase(id)) { label = 'Move to ' + c.name.toLowerCase(); }
  else { label = 'Add to ' + c.name.toLowerCase(); }
  var btn = ui.el('button', null, label + ' ');
  btn.id = 'btn-case-toggle';
  btn.appendChild(ui.el('kbd', null, 'A'));
  btn.addEventListener('click', toggleCurrent);
  bar.appendChild(btn);
}

window.Game.registerMode('cases', {
  init: function (ctx) {
    ui = ctx.ui;
    st = ctx.state;
    meta = ctx.data.meta;
    document.addEventListener('keydown', function (e) {
      if (e.metaKey || e.ctrlKey || e.altKey) { return; }
      if ((e.key === 'a' || e.key === 'A') && casesOn && st && st.phase === 'play') {
        e.preventDefault();
        toggleCurrent();
      }
    });
  },
  onEvent: function (ev, ctx) {
    ui = ctx.ui;
    st = ctx.state;
    meta = ctx.data.meta;
    if (ev.type === 'shiftStart') {
      casesOn = !!(ev.shift && ev.shift.flags && ev.shift.flags.cases);
      cases = [];
      nextCaseNum = 1;
      activeIdx = -1;
      verdictOf = new Map();
      pendingBand = false;
      noticeText = '';
      acctById = new Map();
      styleBlock = null;
      (ctx.data.shifts || []).forEach(function (sh) {
        if (sh.id === ev.shift.id) {
          (sh.accounts || []).forEach(function (a) { acctById.set(a.id, a); });
          styleBlock = sh.style || null;
        }
      });
      var bar = ui.$('casebar');
      if (bar) { bar.hidden = !casesOn; }
      if (casesOn) { renderBoard(); }
      return;
    }
    if (!casesOn) { return; }
    if (ev.type === 'verdict') {
      verdictOf.set(ev.id, ev.verdict);
      renderBoard();
      return;
    }
    if (ev.type === 'dossierRendered') { injectDossierButton(ev.id); return; }
    if (ev.type === 'shiftEnd') { pendingBand = false; }
  }
});

})();
