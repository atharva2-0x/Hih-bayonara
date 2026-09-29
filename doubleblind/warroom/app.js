/* DOUBLE-BLIND War Room: consumes the Arbiter's metadata-only event stream. */
"use strict";

const STATES = ["DRAFT", "REGISTERED", "ARMED", "RUNNING", "CONCLUDED", "REVEALED", "ATTESTED"];
const RISKS = [ // likelihood 1-3 x impact 1-4 (docs/residual-risk.md)
  ["RR1 SMT side channels", 1, 3], ["RR2 kernel / gVisor bug", 1, 4], ["RR3 malicious operator", 2, 4],
  ["RR4 sub-bucket covert channel", 1, 2], ["RR5 cross-trial inference", 2, 2], ["RR6 judge error", 2, 2],
  ["RR7 signing key theft", 1, 3], ["RR8 GPU memory residue", 2, 3],
];
const $ = (id) => document.getElementById(id);
const S = { overview: { trials: [] }, selected: null, perTrial: {}, reports: {}, lastN: 0, seenSeq: new Set() };

function tstate(id) {
  if (!S.perTrial[id]) S.perTrial[id] = { cases: [], contained: 0, fpre: null, fpost: null, purityOk: null,
    lights: { red: "ok", blue: "ok" } };
  return S.perTrial[id];
}
async function j(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
function esc(s) { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

/* ---------------------------------------------------------------- overview */
async function refreshOverview() {
  try { S.overview = await j("/v1/trials"); } catch { return; }
  const sel = $("trialSel");
  const cur = sel.value;
  sel.innerHTML = S.overview.trials.map((t) =>
    `<option value="${t.id}">${esc(t.name)} · ${t.id} · ${t.state}</option>`).join("");
  if ($("follow").checked && S.overview.trials.length) S.selected = S.overview.trials[0].id;
  else if (cur) S.selected = cur;
  if (S.selected) sel.value = S.selected;
  $("ledgerHead").textContent = `ledger #${S.overview.ledger.seq} · ${S.overview.ledger.head}`;
  render();
}
function trial() { return S.overview.trials.find((t) => t.id === S.selected); }

/* ---------------------------------------------------------------- render */
function render() {
  const t = trial();
  renderTimeline(t);
  const ts = t ? tstate(t.id) : null;
  $("redSent").textContent = t ? t.case_count : 0;
  $("midSealed").textContent = t ? t.case_count : 0;
  $("midContained").textContent = t ? Math.max(t.leaks_contained || 0, ts.contained) : 0;
  const chips = ts ? ts.cases.slice(-40) : [];
  $("redLane").innerHTML = chips.map((c) => `<span class="cchip${c.spill ? " spill" : ""}">#${c.no}</span>`).join("");
  $("midLane").innerHTML = chips.map((c) =>
    `<span class="cchip${c.contained ? " contained" : ""}" title="salted case hash">#${c.no} · ${c.commit.slice(0, 6)}${c.contained ? " ⛔" : ""}</span>`).join("");
  renderCert(t);
  renderPurity(t, ts);
  renderLights(ts);
  renderAlerts();
  renderBlue(t);
}

function renderTimeline(t) {
  const el = $("timeline");
  if (!t) { el.innerHTML = '<span class="muted">no trials yet: press “Run blinded trial”</span>'; $("banner").hidden = true; return; }
  const reached = new Set(["DRAFT", ...(t.history || []).map((h) => h.to)]);
  const dead = t.state === "INVALIDATED";
  const parts = STATES.map((s) => {
    const cls = s === t.state ? "now" : reached.has(s) ? "done" : "";
    return `<span class="pill ${cls}">${s}</span>`;
  });
  if (dead) parts.push('<span class="pill dead">INVALIDATED</span>');
  el.innerHTML = parts.join('<span class="arrow">›</span>');
  $("banner").hidden = !dead;
  if (dead) $("banner").textContent = `Trial invalidated: ${t.invalid_reason}`;
}

function renderCert(t) {
  const el = $("cert");
  if (!t || !t.cert_summary) { el.className = "muted"; el.textContent = "not armed yet"; return; }
  const s = t.cert_summary;
  const sim = t.cert_profile !== "docker";
  const accepted = t.accepted_risks || [];
  const unaccepted = s.failed_ids.filter((i) => !accepted.includes(i)).length;
  const badge = unaccepted > 0 ? '<span class="badge bad">FAILED</span>' : sim ? '<span class="badge warn">SIMULATION</span>'
    : accepted.length ? '<span class="badge warn">ENFORCED · ACCEPTED RISK</span>' : '<span class="badge ok">ENFORCED</span>';
  el.className = "cert";
  el.innerHTML = `
    <div class="row"><span>profile</span><span class="mono">${esc(t.cert_profile)} ${badge}</span></div>
    <div class="row"><span>checks passed</span><span class="mono">${s.pass} / ${s.total}</span></div>
    <div class="row"><span>failed</span><span class="mono">${s.fail}</span></div>
    <div class="row"><span>skipped</span><span class="mono">${s.skip}</span></div>
    <div class="row"><span>positive controls</span><span class="mono">${s.positive_controls.pass} / ${s.positive_controls.total}</span></div>
    ${accepted.length ? `<div class="row"><span>accepted risks</span><span class="mono">${accepted.map(esc).join(", ")}</span></div>` : ""}
    ${sim ? '<p class="muted">local simulation: process + network isolation are reported as skipped, never as passed. Run the docker profile for an enforced certificate.</p>' : ""}`;
}

function renderPurity(t, ts) {
  const pre = t?.f_pre || ts?.fpre, post = t?.f_post || ts?.fpost;
  $("fpre").textContent = pre ? pre + "…" : "—";
  $("fpost").textContent = post ? post + "…" : "—";
  const v = $("purityVerdict");
  if (pre && post) {
    const ok = pre === post;
    v.innerHTML = ok ? '<span class="badge ok">F_pre == F_post · model clean</span>'
      : '<span class="badge bad">DRIFT · model contaminated</span>';
  } else v.innerHTML = pre ? '<span class="badge warn">awaiting F_post</span>' : "";
}

function renderAlerts() {
  const al = (S.selected && tstate(S.selected).alerts) || [];
  $("alerts").innerHTML = al.length ? al.map((a) =>
    `<li class="${a.severity}">${new Date(a.ts * 1000).toLocaleTimeString()} · ${a.severity.toUpperCase()} · ${esc(a.kind)} · ${esc(a.message)}</li>`).join("")
    : '<li class="info">no alerts for this trial</li>';
}
function renderLights(ts) {
  for (const who of ["red", "blue"]) {
    const el = $(who === "red" ? "lightRed" : "lightBlue");
    el.className = "light" + (ts && ts.lights[who] === "trip" ? " trip" : ts && ts.lights[who] === "warn" ? " warn" : "");
  }
}

async function renderBlue(t) {
  const sealed = $("blueSealed"), rev = $("blueRevealed");
  if (!t || !["REVEALED", "ATTESTED"].includes(t.state)) { sealed.hidden = false; rev.hidden = true; return; }
  sealed.hidden = true; rev.hidden = false;
  if (!S.reports[t.id]) {
    try { S.reports[t.id] = await j(`/v1/trials/${t.id}/report`); } catch { return; }
  }
  const sm = S.reports[t.id].summary;
  const o = sm.outcomes || {};
  const rows = [["breach", "breach", "attack succeeded"], ["defended_guard", "guard", "blocked by blue guard"],
    ["defended_model", "model", "refused by model"], ["control_ok", "", "control answered"],
    ["false_positive_guard", "fp", "false positive (guard)"], ["false_positive_model", "fp", "false positive (model)"]];
  const max = Math.max(1, ...Object.values(o));
  rev.innerHTML = `<div class="stat">revealed · attack success <b>${pct(sm.attack_success_rate)}</b> · false positives <b>${pct(sm.false_positive_rate)}</b></div>
    <div class="outcomes">${rows.filter(([k]) => o[k]).map(([k, cls, label]) =>
      `<div class="orow"><span>${label}</span><div class="obar ${cls}" style="width:${(o[k] / max) * 100}%"></div><span class="mono">${o[k]}</span></div>`).join("")}</div>`;
}
function pct(x) { return x == null ? "—" : `${(x * 100).toFixed(1)}%`; }

/* ---------------------------------------------------------------- ledger */
async function refreshVerify() {
  try {
    const v = await j("/v1/ledger/verify");
    $("ledgerVerify").textContent = v.ok ? `chain verified · ${v.events} events · ${v.checkpoints} signed checkpoints`
      : `CHAIN BROKEN at #${v.first_bad_seq}`;
  } catch { /* ignore */ }
}
function addTicker(ev, fresh) {
  if (S.seenSeq.has(ev.seq)) return;
  S.seenSeq.add(ev.seq);
  const li = document.createElement("li");
  const bad = ["INVALIDATED", "LEAK_CONTAINED", "ALERT", "CANARY_DRILL"].includes(ev.etype);
  li.className = fresh ? "new" : "";
  li.innerHTML = `<span>#${ev.seq}</span><span class="t${bad ? " bad" : ""}">${esc(ev.etype)}${ev.trial_id === S.selected ? "" : ' <span class="h">(' + esc(ev.trial_id) + ")</span>"}</span><span class="h">${esc(ev.hash)}</span>`;
  const tk = $("ticker");
  tk.prepend(li);
  while (tk.children.length > 120) tk.lastChild.remove();
}

/* ---------------------------------------------------------------- metrics + radar */
function bar(label, v, color, ci) {
  const w = Math.max(0, Math.min(1, v)) * 100;
  const ciEl = ci ? `<span class="ci" style="left:${ci[0] * 100}%;width:${(ci[1] - ci[0]) * 100}%"></span>` : "";
  return `<div class="mbar"><span>${label}</span><div class="track"><span class="fill" style="width:${w}%;background:${color}"></span><span class="chance"></span>${ciEl}</div><span class="mono">${(v * 100).toFixed(1)}%</span></div>`;
}
async function renderMetrics() {
  let m = {};
  try { m = await j("/v1/metrics"); } catch { /* none */ }
  const parts = [];
  if (m.leakage) {
    const L = m.leakage;
    parts.push(`<div class="metric"><h3>Side-channel leakage</h3>
      ${bar("Equalizer off", L.equalizer_off.attacker_accuracy, "var(--red)", L.equalizer_off.ci95)}
      ${bar("Equalizer on", L.equalizer_on.attacker_accuracy, "var(--green)", L.equalizer_on.ci95)}
      <p>Can red tell a guard refusal from a model refusal by latency + size? Line = chance (50%). ${L.equalizer_on.consistent_with_chance ? "With the Equalizer: indistinguishable from chance." : ""}</p></div>`);
  }
  if (m.overhead) {
    const O = m.overhead, mx = Math.max(O.bare.p50, O.isolated.p50, O.equalized.p50);
    const ob = (lbl, v, c) => `<div class="mbar"><span>${lbl}</span><div class="track"><span class="fill" style="width:${(v / mx) * 100}%;background:${c}"></span></div><span class="mono">${v} ms</span></div>`;
    parts.push(`<div class="metric"><h3>Isolation overhead (p50)</h3>
      ${ob("bare model", O.bare.p50, "var(--gray)")}${ob("isolated", O.isolated.p50, "var(--violet)")}${ob("equalized", O.equalized.p50, "var(--gold)")}
      <p>Isolation adds ${O.added_ms ? O.added_ms.isolated_p50 + " ms" : O.overhead_pct.isolated_p50 + "%"} at p50; the Equalizer holds every response to its ${O.bucket_ms} ms bucket by design.</p></div>`);
  }
  if (m.kvcache) {
    const K = m.kvcache;
    parts.push(`<div class="metric"><h3>KV-cache cross-session timing</h3>
      ${bar("shared cache", K.global_cache.observer_accuracy, "var(--red)", K.global_cache.ci95)}
      ${bar("per-session", K.session_cache.observer_accuracy, "var(--green)", K.session_cache.ci95)}
      <p>Can one session tell what another just sent? Per-session caches remove the signal.</p></div>`);
  }
  $("metrics").innerHTML = parts.join("") || '<p class="muted">run <span class="mono">python -m doubleblind bench</span> to populate</p>';
}
function renderRadar() {
  const svg = $("radar"), cx = 150, cy = 150, R = 105, n = RISKS.length;
  const pt = (i, r) => [cx + r * Math.sin((2 * Math.PI * i) / n), cy - r * Math.cos((2 * Math.PI * i) / n)];
  let h = "";
  for (const k of [0.25, 0.5, 0.75, 1]) h += `<polygon points="${RISKS.map((_, i) => pt(i, R * k).join(",")).join(" ")}" fill="none" stroke="#26304f"/>`;
  RISKS.forEach((r, i) => {
    const [x, y] = pt(i, R); const [lx, ly] = pt(i, R + 22);
    h += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="#26304f"/>`;
    h += `<text x="${lx}" y="${ly}" fill="#9aa4bf" font-size="9" text-anchor="middle" dominant-baseline="middle">${r[0].split(" ")[0]}</text>`;
  });
  const poly = RISKS.map((r, i) => pt(i, (R * r[1] * r[2]) / 12).join(",")).join(" ");
  h += `<polygon points="${poly}" fill="rgba(255,107,107,.25)" stroke="#ff6b6b" stroke-width="1.5"/>`;
  RISKS.forEach((r, i) => { const [x, y] = pt(i, (R * r[1] * r[2]) / 12); h += `<circle cx="${x}" cy="${y}" r="3" fill="#ff6b6b"><title>${r[0]}: likelihood ${r[1]}/3 × impact ${r[2]}/4</title></circle>`; });
  svg.innerHTML = h;
}

/* ---------------------------------------------------------------- events */
function narrate(msg) {
  const li = document.createElement("li");
  li.textContent = msg;
  $("log").prepend(li);
}
function handle(ev) {
  if (ev.n) { if (ev.n <= S.lastN) return; S.lastN = ev.n; }
  switch (ev.type) {
    case "ledger":
      addTicker(ev, true);
      $("ledgerHead").textContent = `ledger #${ev.seq} · ${ev.hash}`;
      break;
    case "state":
      refreshOverview();
      refreshVerify();
      break;
    case "case": {
      const ts = tstate(ev.trial_id);
      const have = ts.cases.find((x) => x.no === ev.case_no);
      if (have) { have.commit = ev.commit; have.spill = ev.spilled; }
      else ts.cases.push({ no: ev.case_no, commit: ev.commit, spill: ev.spilled, contained: false });
      if (ev.trial_id === S.selected) { const t = trial(); if (t) t.case_count = Math.max(t.case_count, ev.case_no); render(); }
      break;
    }
    case "leak_contained": {
      const ts = tstate(ev.trial_id);
      ts.contained += 1;
      ts.lights.blue = ts.lights.blue === "trip" ? "trip" : "warn";
      const c = ts.cases.find((x) => x.no === ev.case_no);
      if (c) c.contained = true; else ts.cases.push({ no: ev.case_no, commit: "withheld", contained: true });
      render();
      break;
    }
    case "purity": {
      const ts = tstate(ev.trial_id);
      if (ev.phase === "pre") ts.fpre = ev.fingerprint; else ts.fpost = ev.fingerprint;
      refreshOverview();
      break;
    }
    case "alert": {
      const prev = tstate(ev.trial_id).alerts || [];
      if (prev.some((a) => a.id === ev.id)) break;
      tstate(ev.trial_id).alerts = [ev, ...prev].slice(0, 30);
      renderAlerts();
      if (ev.kind === "canary_breach" || ev.kind === "canary_contained") {
        const owner = ev.zone === "red" ? "blue" : "red";
        tstate(ev.trial_id).lights[owner] = ev.kind === "canary_breach" ? "trip" : "warn";
        render();
      }
      break;
    }
    case "checkpoint":
      narrate(`signed Merkle checkpoint over seq 1..${ev.upto_seq}: root ${ev.root}…`);
      break;
    case "log":
      narrate(ev.msg);
      break;
    case "drill":
      refreshOverview();
      break;
  }
}
function connect() {
  const es = new EventSource("/v1/events");
  es.onopen = () => $("conn").classList.add("on");
  es.onerror = () => $("conn").classList.remove("on");
  es.onmessage = (m) => { try { handle(JSON.parse(m.data)); } catch (e) { console.error(e); } };
}

/* ---------------------------------------------------------------- controls */
function busy(on, msg) {
  document.querySelectorAll("#controls button").forEach((b) => (b.disabled = on));
  $("demoHint").textContent = msg || "";
}
document.querySelectorAll("#controls button[data-scenario]").forEach((b) =>
  b.addEventListener("click", async () => {
    $("follow").checked = true;
    busy(true, "running…");
    try {
      await j("/v1/demo/run", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: b.dataset.scenario, equalizer: $("eqToggle").checked }) });
    } catch { busy(false, "demo runner is only available in `python -m doubleblind serve` (local) mode"); return; }
    setTimeout(() => busy(false), 2500);
  }));
$("tamperBtn").addEventListener("click", async () => {
  const el = $("tamper");
  el.hidden = false;
  el.textContent = "tampering with a copy of the latest export…";
  try {
    const r = await j("/v1/demo/tamper", { method: "POST" });
    if (r.error) { el.textContent = r.error; return; }
    el.innerHTML = `<div>trial <span class="mono">${esc(r.trial_id)}</span>: flipped one character in ledger event <b>#${r.seq}</b></div>
      <div>original export → <span class="ok">${r.original.ok ? "VERIFIED ✅" : "FAILED"}</span></div>
      <div>tampered copy → <span class="bad">${r.tampered.ok ? "verified?!" : "REJECTED ❌"}</span> first bad seq <b>#${r.tampered.first_bad_seq}</b></div>
      <div class="muted">${esc(r.tampered.problem || "")}</div>`;
  } catch { el.textContent = "tamper demo is only available in local serve mode"; }
});
$("trialSel").addEventListener("change", (e) => { $("follow").checked = false; S.selected = e.target.value; render(); });

/* ---------------------------------------------------------------- boot */
(async function boot() {
  renderRadar();
  await refreshOverview();
  try {
    const L = await j(`/v1/ledger?since=${Math.max(0, S.overview.ledger.seq - 60)}&limit=60`);
    for (const e of L.events) addTicker({ seq: e.seq, etype: e.type, trial_id: e.trial_id, hash: e.hash.slice(0, 16) }, false);
  } catch { /* empty */ }
  try {
    const p = await j("/v1/policy");
    $("policyHash").textContent = p.hash.slice(0, 16) + "…";
    const n = p.invariants.reduce((a, r) => a + r.checked, 0);
    const ok = p.invariants.every((r) => r.ok);
    $("policyInv").textContent = `${p.invariants.length} invariants, ${n} decisions checked exhaustively: ${ok ? "all hold" : "VIOLATED"}`;
  } catch { /* ignore */ }
  try {
    const o = await j("/v1/observability");
    for (const a of (o.alerts || []).slice(-20)) handle({ type: "alert", ...a });
  } catch { /* ignore */ }
  refreshVerify();
  renderMetrics();
  connect();
})();
