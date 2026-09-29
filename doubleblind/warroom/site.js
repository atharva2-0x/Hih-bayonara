/* DOUBLE-BLIND site: live, interactive front door for the Trial Authority.
   Data: the operator listener's JSON APIs and metadata-only SSE stream.
   Never renders payload text; only IDs, hashes, counts and states. */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const PAGE_T0 = Date.now() / 1000;

/* ------------------------------------------------------------------ icons */
const ICONS = {
  shield: '<path d="M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.2"/>',
  radar: '<circle cx="12" cy="12" r="9"/><path d="M12 12l6-5M12 3v2M3 12h2M12 12a4 4 0 1 0 4 0"/>',
  cpu: '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3"/>',
  scale: '<path d="M12 3v18M6 21h12M5 7h14M5 7l-3 7a3 3 0 0 0 6 0zM19 7l-3 7a3 3 0 0 0 6 0z"/>',
  commit: '<circle cx="12" cy="12" r="3.5"/><path d="M2.5 12h6M15.5 12h6"/>',
  sliders: '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="15" cy="6" r="2" fill="currentColor"/><circle cx="8" cy="12" r="2" fill="currentColor"/><circle cx="17" cy="18" r="2" fill="currentColor"/>',
  bell: '<path d="M6 17h12l-1.6-2.2V11a4.4 4.4 0 0 0-8.8 0v3.8zM10 20a2 2 0 0 0 4 0"/>',
  flask: '<path d="M9 3h6M10 3v6L4.6 18.6A1.6 1.6 0 0 0 6 21h12a1.6 1.6 0 0 0 1.4-2.4L14 9V3M7.5 15h9"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  chevL: '<path d="M15 5l-7 7 7 7"/>', chevR: '<path d="M9 5l7 7-7 7"/>',
  activity: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14.5 8.5l2 2"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.6 2.6L16 9.6"/>',
  hash: '<path d="M5 9h14M5 15h14M10 4L8 20M16 4l-2 16"/>',
  database: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
};
const icon = (n) => `<svg class="ic" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n] || ""}</svg>`;
function hydrateIcons(root = document) {
  $$("[data-icon]", root).forEach((el) => { if (!el.dataset.ic) { el.innerHTML = icon(el.dataset.icon); el.dataset.ic = "1"; } });
}

/* ------------------------------------------------------------------ state + api */
const S = { overview: { trials: [], ledger: { seq: 0, head: "" } }, metrics: {}, policy: null, obs: null, verify: null,
  lastN: 0, caseTimes: [], myRun: null, statsSeen: false };
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) { const e = new Error(`HTTP ${r.status}`); e.status = r.status; throw e; }
  return r.json();
}
const latest = () => S.overview.trials[0];
const latestCert = () => S.overview.trials.find((t) => t.cert_summary);
const policyDecisions = () => (S.policy ? S.policy.invariants.reduce((a, r) => a + r.checked, 0) : null);
const short = (h, n = 10) => (h ? String(h).slice(0, n) + "…" : "—");

/* ------------------------------------------------------------------ content */
const ZONES = [
  { key: "authority", name: "Trial Authority", tag: "Control plane", color: "#ffc857", icon: "scale",
    blurb: "The Arbiter is the only broker between zones. It also holds the state machine, policy, keys, judge and ledger.",
    guarantees: ["Every cross-zone message is authorised against the trial state", "Every step is written to a hash-chained ledger", "Findings are attested by a signed Merkle checkpoint"],
    controls: ["One listener per network, each pinning one zone's CA", "ABAC policy: 9 invariants checked over every (role, action, state)", "Per-trial data keys wrapped by a KEK; trial-scoped tokens"],
    evidence: ["tests/test_e2e.py: role separation and state policy", "python -m doubleblind policy", "/v1/ledger/verify"],
    live: () => `ledger #${S.overview.ledger.seq} · head ${short(S.overview.ledger.head, 12)}\n${S.verify ? `${S.verify.checkpoints} signed checkpoints · chain ${S.verify.ok ? "verified" : "BROKEN"}` : ""}\npolicy ${short(S.overview.policy_hash, 12)}` },
  { key: "red", name: "Red Zone", tag: "Tenant A", color: "#ff5d73", icon: "target",
    blurb: "The adversarial harness, with its payload set sealed in a tenant-keyed vault. Red only ever sees equalized responses.",
    guarantees: ["Cannot reach blue, the enclave, the model or the internet", "Cannot tell which layer refused (Equalizer)", "Cannot add unregistered cases undetected (commit-reveal)"],
    controls: ["net-red only · pinned red mTLS · trial-scoped token", "Encrypted vault with a canary that must never leave the zone", "Case budget and probing-rate alerts"],
    evidence: ["drill: net.deny.* from inside the red zone", "test_cases_outside_committed_set_invalidate", "bench/leakage.py"],
    live: () => { const t = latest(); return t ? `latest trial ${t.id}: ${t.case_count} cases submitted · ${t.state}` : "no trial yet"; } },
  { key: "blue", name: "Blue Zone", tag: "Tenant B", color: "#4da3ff", icon: "shield",
    blurb: "Authors the defense bundle and commits to it. Stays blind to red's cases until the reveal ceremony.",
    guarantees: ["No route to red data while the trial is live", "Bundle can't be swapped: the commitment is checked against what the enclave loaded", "Sees results only after REVEAL"],
    controls: ["net-blue only · pinned blue mTLS", "Policy denies D01 / invariant I1 over all pre-reveal states", "Canary planted in the system prompt"],
    evidence: ["test_policy_invariants_hold_exhaustively", "verifier: commitment opens (blue)"],
    live: () => { const t = latest(); if (!t) return "no trial yet"; return ["REVEALED", "ATTESTED"].includes(t.state) ? `trial ${t.id}: revealed, report available` : `trial ${t.id}: sealed, blind until REVEAL`; } },
  { key: "enclave", name: "Sealed Enclave", tag: "gVisor · no egress", color: "#9b8cff", icon: "lock",
    blurb: "Runs blue's declarative guards around the model. Blue authors it but can't watch it, and nothing flows back to blue.",
    guarantees: ["Bundles are data, not code: nothing to exfiltrate with", "Fixed output schema, whitelisted reason codes", "Only the Arbiter may call it"],
    controls: ["Read-only rootfs · cap_drop ALL · seccomp · non-root", "Enclave cert refused by the model's admin port", "Regex ReDoS guard, bundle size and rule limits"],
    evidence: ["test_bundle_validation_rejects", "drill: mtls.deny.model-admin"],
    live: () => { const t = latest(); return t ? `guards ${t.state === "RUNNING" ? "ACTIVE" : "idle"} · ${t.leaks_contained} leak(s) contained in ${t.id}` : "idle"; } },
  { key: "model", name: "Model Clean Room", tag: "Ephemeral replica", color: "#2ee6a6", icon: "cpu",
    blurb: "Digest-pinned weights and a per-session KV cache. A purity fingerprint is taken before and after every trial.",
    guarantees: ["Cross-session cache timing is indistinguishable from chance", "State that survives a trial is detected (F_pre ≠ F_post)", "Every case can be replayed bit-for-bit"],
    controls: ["No egress, tools disabled, cache_prompt=false on llama.cpp", "Reset per trial; digest re-checked at ARM", "Admin and data ports with different trust"],
    evidence: ["bench/kvcache.py: 100% → 45%", "test_purity_drift_invalidates", "dbverify --replay"],
    live: () => { const t = S.overview.trials.find((x) => x.f_pre); return t ? `${t.id}\nF_pre  ${t.f_pre}…\nF_post ${t.f_post ? t.f_post + "…" : "(pending)"}${t.f_post ? (t.f_pre === t.f_post ? "  ✓ clean" : "  ✗ DRIFT") : ""}` : "no fingerprint yet"; } },
  { key: "obs", name: "Observability", tag: "Metadata only", color: "#3ad6ff", icon: "eye",
    blurb: "Canary watcher and anomaly detector. It can invalidate a trial, but it can never read plaintext.",
    guarantees: ["A foreign canary arriving from a tenant invalidates the trial", "A foreign canary heading to a tenant is withheld", "The telemetry schema rejects any free text"],
    controls: ["Closed schema: enums, bounded numbers, digests", "Push-only alerts to the Arbiter over mTLS", "Rate, probing and latency-drift detectors"],
    evidence: ["test_canary_breach_vs_contained", "test_telemetry_schema_rejects_plaintext", "canary drill"],
    live: () => { const o = S.obs; if (!o || !o.counters) return "no telemetry yet"; const c = o.counters; return `${(c.alerts_critical || 0)} critical · ${(c.alerts_warn || 0)} warn alerts\ncanaries registered: red ${o.registered_canaries?.red ?? 0} · blue ${o.registered_canaries?.blue ?? 0}`; } },
];
const STEPS = [
  { state: "REGISTERED", title: "Pre-register", icon: "commit", text: "Red and blue commit H(artifact ‖ nonce) before anything runs." },
  { state: "ARMED", title: "Arm", icon: "radar", text: "Breach drill in every zone, purity fingerprint F_pre, bundle sealed in the enclave." },
  { state: "RUNNING", title: "Blind run", icon: "activity", text: "Cases move as salted hashes. Responses are equalized. Blue stays sealed." },
  { state: "CONCLUDED", title: "Conclude", icon: "clock", text: "Tokens revoked. F_post must equal F_pre. Replica reset." },
  { state: "REVEALED", title: "Reveal", icon: "key", text: "Commitments open, the salt is published, every sealed record is checked." },
  { state: "ATTESTED", title: "Attest", icon: "check", text: "A signed Merkle checkpoint makes the result replayable by anyone." },
];
const QUOTES = [
  { q: "Red-team attack payloads must not be observable by the blue team before a test concludes.",
    how: "<b>Network isolation, sealed records, salted ledger.</b> Blue's listener has no route to red data, cases are encrypted with a per-trial key, and invariant I1 is checked over every state.",
    proof: () => `invariant I1 · ${policyDecisions() ?? 195} decisions checked` },
  { q: "Blue-team defensive logic must not be exposed or inferable by red-team tooling.",
    how: "<b>Sealed enclave, Equalizer, canary.</b> Every refusal red sees is byte-identical and time-bucketed. A canary in blue's system prompt stops prompt leaks at the boundary.",
    proof: () => { const L = S.metrics.leakage; return L ? `attacker accuracy ${(L.equalizer_off.attacker_accuracy * 100).toFixed(0)}% → ${(L.equalizer_on.attacker_accuracy * 100).toFixed(1)}%` : "attacker accuracy → chance"; } },
  { q: "The client LLM must remain clean and uncontaminated throughout the evaluation.",
    how: "<b>Clean room + purity fingerprint.</b> Weights are digest-pinned and the KV cache is per session. F_pre must equal F_post, or the trial is invalidated.",
    proof: () => "contamination scenario → INVALIDATED" },
  { q: "Safety findings must not be invalidated by environmental leakage or cross-tenant interference.",
    how: "<b>Breach drill + tamper-evident ledger.</b> Every forbidden path is tried from inside every zone before arming. Every step is hash-chained, signed and replayable offline.",
    proof: () => { const t = latestCert(); return t ? `${t.cert_summary.pass}/${t.cert_summary.total} drill checks · ${t.cert_profile}` : "drill + 34/34 bit-for-bit replay"; } },
];

/* ------------------------------------------------------------------ nav */
function initNav() {
  const nav = $("#nav"), burger = $("#burger"), links = $("#navLinks");
  const onScroll = () => nav.classList.toggle("scrolled", scrollY > 10);
  addEventListener("scroll", onScroll, { passive: true }); onScroll();
  burger.addEventListener("click", () => { const open = links.classList.toggle("open"); burger.setAttribute("aria-expanded", open); });
  $$("a", links).forEach((a) => a.addEventListener("click", () => { links.classList.remove("open"); burger.setAttribute("aria-expanded", false); }));
  const spy = new IntersectionObserver((ents) => ents.forEach((e) => {
    if (e.isIntersecting) $$("a", links).forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + e.target.id));
  }), { rootMargin: "-45% 0px -50% 0px" });
  ["platform", "protocol", "proof", "evidence"].forEach((id) => spy.observe($("#" + id)));
}
function initReveal() {
  const io = new IntersectionObserver((ents) => ents.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.12 });
  $$(".reveal").forEach((el) => io.observe(el));
}

/* ------------------------------------------------------------------ hero particles */
function initParticles() {
  const c = $("#particles"); if (!c || REDUCED) return;
  const ctx = c.getContext("2d"); let W = 0, H = 0, pts = [], mouse = { x: -1e4, y: -1e4 }, running = true;
  const resize = () => {
    const dpr = Math.min(devicePixelRatio || 1, 2); W = c.clientWidth; H = c.clientHeight;
    c.width = W * dpr; c.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const n = Math.min(110, Math.floor((W * H) / 14000));
    pts = Array.from({ length: n }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - 0.5) * 0.35, vy: (Math.random() - 0.5) * 0.35, r: Math.random() * 1.6 + 0.6 }));
  };
  resize(); addEventListener("resize", resize);
  c.parentElement.addEventListener("mousemove", (e) => { const b = c.getBoundingClientRect(); mouse = { x: e.clientX - b.left, y: e.clientY - b.top }; });
  c.parentElement.addEventListener("mouseleave", () => (mouse = { x: -1e4, y: -1e4 }));
  new IntersectionObserver(([e]) => (running = e.isIntersecting)).observe(c);
  (function frame() {
    requestAnimationFrame(frame); if (!running) return;
    ctx.clearRect(0, 0, W, H);
    for (const p of pts) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1; if (p.y < 0 || p.y > H) p.vy *= -1;
      const dx = mouse.x - p.x, dy = mouse.y - p.y, d = Math.hypot(dx, dy);
      if (d < 160) { p.x += dx * 0.006; p.y += dy * 0.006; }
    }
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
      const a = pts[i], b = pts[j], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (d < 130) { ctx.strokeStyle = `rgba(58,160,255,${(1 - d / 130) * 0.28})`; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
    }
    for (const p of pts) { ctx.fillStyle = "rgba(120,200,255,.85)"; ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 6.283); ctx.fill(); }
  })();
}

/* ------------------------------------------------------------------ topology */
class Topology {
  constructor(canvas) {
    this.c = canvas; this.ctx = canvas.getContext("2d");
    this.N = { red: [0.1, 0.28], blue: [0.1, 0.74], authority: [0.43, 0.5], enclave: [0.72, 0.22], model: [0.9, 0.56], obs: [0.63, 0.84] };
    this.color = Object.fromEntries(ZONES.map((z) => [z.key, z.color]));
    this.label = { red: "RED", blue: "BLUE", authority: "ARBITER", enclave: "ENCLAVE", model: "MODEL", obs: "OBSERVABILITY" };
    this.allowed = [["red", "authority"], ["blue", "authority"], ["authority", "enclave"], ["enclave", "model"], ["authority", "model"], ["authority", "obs"]];
    this.forbidden = [["red", "blue"], ["red", "enclave"], ["blue", "model"]];
    this.packets = []; this.flashes = []; this.edgeFx = []; this.state = "IDLE"; this.visible = true;
    new ResizeObserver(() => this.resize()).observe(canvas); this.resize();
    new IntersectionObserver(([e]) => (this.visible = e.isIntersecting)).observe(canvas);
    if (!REDUCED) setInterval(() => this.visible && this.spawn(["authority", "obs"], "rgba(58,214,255,.45)", 900, 2), 2600);
    const loop = (t) => { requestAnimationFrame(loop); if (this.visible) this.draw(t); };
    requestAnimationFrame(loop);
  }
  resize() {
    const dpr = Math.min(devicePixelRatio || 1, 2); this.W = this.c.clientWidth; this.H = this.c.clientHeight;
    this.c.width = this.W * dpr; this.c.height = this.H * dpr; this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  p(k) { const [x, y] = this.N[k]; return [24 + x * (this.W - 48), 18 + y * (this.H - 50)]; }
  spawn(path, color, segMs = 260, r = 4, end = null) {
    this.packets.push({ path, color, segMs, r, t0: performance.now(), end, trail: [] });
    if (this.packets.length > 60) this.packets.shift();
  }
  caseFlow(hash) { this.spawn(["red", "authority", "enclave", "model", "enclave", "authority", "red"], "#3ad6ff", 230, 4.5); this.lastHash = hash; }
  contained() { this.spawn(["model", "enclave", "authority"], "#ff5d73", 300, 5, { node: "authority", text: "WITHHELD", color: "#ff5d73" }); }
  flash(node, color, text = null) { this.flashes.push({ node, color, text, t0: performance.now(), dur: 1400 }); }
  breach() {
    this.forbidden.forEach((e, i) => this.edgeFx.push({ e, color: "#ff5d73", t0: performance.now() + i * 80, dur: 2200, mark: "!" }));
    this.flash("authority", "#ff5d73", "BREACH → INVALIDATED");
  }
  drill() {
    this.forbidden.forEach((e, i) => this.edgeFx.push({ e, color: "#2ee6a6", t0: performance.now() + i * 350, dur: 1300, mark: "✓" }));
    this.flash("authority", "#2ee6a6", "ISOLATION CERTIFIED");
  }
  draw(now) {
    const { ctx, W, H } = this; if (!W) return;
    ctx.clearRect(0, 0, W, H);
    const dash = (now / 40) % 20;
    for (const [a, b] of this.allowed) {
      const [x1, y1] = this.p(a), [x2, y2] = this.p(b);
      ctx.strokeStyle = "rgba(31,162,255,.35)"; ctx.lineWidth = 1.6; ctx.setLineDash([6, 8]); ctx.lineDashOffset = -dash;
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
    }
    for (const [a, b] of this.forbidden) {
      const [x1, y1] = this.p(a), [x2, y2] = this.p(b);
      ctx.strokeStyle = "rgba(255,93,115,.22)"; ctx.lineWidth = 1.2; ctx.setLineDash([3, 6]); ctx.lineDashOffset = 0;
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2; ctx.setLineDash([]);
      ctx.fillStyle = "#061233"; ctx.beginPath(); ctx.arc(mx, my, 7, 0, 6.283); ctx.fill();
      ctx.strokeStyle = "rgba(255,93,115,.6)"; ctx.stroke();
      ctx.fillStyle = "rgba(255,93,115,.9)"; ctx.font = "bold 9px ui-monospace, monospace"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText("✕", mx, my + 0.5);
    }
    ctx.setLineDash([]);
    this.edgeFx = this.edgeFx.filter((f) => now - f.t0 < f.dur);
    for (const f of this.edgeFx) {
      const k = (now - f.t0) / f.dur; if (k < 0) continue;
      const [x1, y1] = this.p(f.e[0]), [x2, y2] = this.p(f.e[1]); const a = Math.sin(k * Math.PI);
      ctx.strokeStyle = f.color; ctx.globalAlpha = a; ctx.lineWidth = 3; ctx.shadowColor = f.color; ctx.shadowBlur = 14;
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke(); ctx.shadowBlur = 0;
      ctx.fillStyle = f.color; ctx.font = "bold 13px ui-monospace, monospace"; ctx.fillText(f.mark, (x1 + x2) / 2, (y1 + y2) / 2 - 14);
      ctx.globalAlpha = 1;
    }
    this.packets = this.packets.filter((pk) => {
      const segs = pk.path.length - 1, el = Math.max(0, now - pk.t0), total = segs * pk.segMs;
      if (el >= total) { if (pk.end) this.flash(pk.end.node, pk.end.color, pk.end.text); return false; }
      const si = Math.floor(el / pk.segMs), k = (el % pk.segMs) / pk.segMs, e = k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2;
      const [x1, y1] = this.p(pk.path[si]), [x2, y2] = this.p(pk.path[si + 1]);
      const x = x1 + (x2 - x1) * e, y = y1 + (y2 - y1) * e;
      pk.trail.push([x, y]); if (pk.trail.length > 10) pk.trail.shift();
      pk.trail.forEach(([tx, ty], i) => { ctx.globalAlpha = (i / pk.trail.length) * 0.4; ctx.fillStyle = pk.color; ctx.beginPath(); ctx.arc(tx, ty, pk.r * 0.7, 0, 6.283); ctx.fill(); });
      ctx.globalAlpha = 1; ctx.fillStyle = pk.color; ctx.shadowColor = pk.color; ctx.shadowBlur = 16;
      ctx.beginPath(); ctx.arc(x, y, pk.r, 0, 6.283); ctx.fill(); ctx.shadowBlur = 0;
      return true;
    });
    this.flashes = this.flashes.filter((f) => now - f.t0 < f.dur);
    for (const k of Object.keys(this.N)) {
      const [x, y] = this.p(k), col = this.color[k], big = k === "authority", r = big ? 21 : 15;
      const fl = this.flashes.filter((f) => f.node === k).pop();
      const pulse = 0.5 + 0.5 * Math.sin(now / (big ? 420 : 700) + x);
      ctx.fillStyle = "#061233"; ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.shadowColor = fl ? fl.color : col; ctx.shadowBlur = fl ? 34 : 10 + pulse * 10;
      ctx.beginPath(); ctx.arc(x, y, r, 0, 6.283); ctx.fill(); ctx.stroke(); ctx.shadowBlur = 0;
      ctx.fillStyle = col; ctx.globalAlpha = 0.18 + pulse * 0.12; ctx.beginPath(); ctx.arc(x, y, r - 5, 0, 6.283); ctx.fill(); ctx.globalAlpha = 1;
      if (fl) { const kk = (now - fl.t0) / fl.dur; ctx.strokeStyle = fl.color; ctx.globalAlpha = 1 - kk; ctx.beginPath(); ctx.arc(x, y, r + kk * 26, 0, 6.283); ctx.stroke(); ctx.globalAlpha = 1;
        if (fl.text) { ctx.fillStyle = fl.color; ctx.font = "bold 10px ui-monospace, monospace"; ctx.textAlign = "center"; ctx.fillText(fl.text, x, y - r - 12); } }
      ctx.fillStyle = "rgba(233,240,255,.85)"; ctx.font = "600 9.5px Inter, system-ui, sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "top";
      ctx.fillText(this.label[k], x, y + r + 6); ctx.textBaseline = "middle";
    }
    const st = `TRIAL · ${this.state}`, col = this.state === "ATTESTED" ? "#2ee6a6" : this.state === "INVALIDATED" ? "#ff5d73" : this.state === "IDLE" ? "#93a6cc" : "#3ad6ff";
    ctx.font = "bold 9.5px ui-monospace, monospace"; const tw = ctx.measureText(st).width + 16;
    ctx.fillStyle = "rgba(6,18,51,.9)"; ctx.strokeStyle = col; ctx.lineWidth = 1; ctx.beginPath(); if (ctx.roundRect) ctx.roundRect(10, 8, tw, 18, 9); else ctx.rect(10, 8, tw, 18); ctx.fill(); ctx.stroke();
    ctx.fillStyle = col; ctx.textAlign = "left"; ctx.fillText(st, 18, 17.5);
  }
}

/* ------------------------------------------------------------------ sparkline + ticker */
function drawSpark() {
  const c = $("#spark"); if (!c) return; const ctx = c.getContext("2d");
  const dpr = Math.min(devicePixelRatio || 1, 2), W = c.clientWidth, H = c.clientHeight; c.width = W * dpr; c.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const now = Date.now(); S.caseTimes = S.caseTimes.filter((t) => now - t < 60000);
  const bins = Array(60).fill(0); S.caseTimes.forEach((t) => { bins[59 - Math.floor((now - t) / 1000)]++; });
  const max = Math.max(4, ...bins), step = W / 59;
  const g = ctx.createLinearGradient(0, 0, 0, H); g.addColorStop(0, "rgba(58,214,255,.45)"); g.addColorStop(1, "rgba(58,214,255,0)");
  ctx.beginPath(); ctx.moveTo(0, H);
  bins.forEach((v, i) => ctx.lineTo(i * step, H - 4 - (v / max) * (H - 10))); ctx.lineTo(W, H); ctx.closePath(); ctx.fillStyle = g; ctx.fill();
  ctx.beginPath(); bins.forEach((v, i) => (i ? ctx.lineTo : ctx.moveTo).call(ctx, i * step, H - 4 - (v / max) * (H - 10)));
  ctx.strokeStyle = "#3ad6ff"; ctx.lineWidth = 1.6; ctx.stroke();
  ctx.fillStyle = "rgba(147,166,204,.9)"; ctx.font = "10px ui-monospace, monospace"; ctx.textAlign = "right"; ctx.fillText(`${bins[59]}/s · peak ${Math.max(...bins)}`, W - 2, 10);
}
const seenSeq = new Set();
function tickerAdd(ev) {
  if (seenSeq.has(ev.seq)) return; seenSeq.add(ev.seq);
  const li = document.createElement("li");
  const bad = ["INVALIDATED", "ALERT", "LEAK_CONTAINED", "CANARY_DRILL"].includes(ev.etype);
  li.innerHTML = `<span>#${ev.seq} <b class="${bad ? "bad" : ""}">${esc(ev.etype)}</b></span><span>${esc(String(ev.hash).slice(0, 10))}</span>`;
  const tk = $("#heroTicker"); tk.prepend(li); while (tk.children.length > 5) tk.lastChild.remove();
}

/* ------------------------------------------------------------------ zone cards + modal */
function renderCards() {
  $("#zoneCards").innerHTML = ZONES.map((z, i) => `
    <button class="card reveal" style="--zc:${z.color};transition-delay:${i * 60}ms" data-zone="${z.key}" aria-haspopup="dialog">
      <div class="card-media"><span class="ring"></span><span class="ring r2"></span><span class="orb">${icon(z.icon)}</span></div>
      <div class="card-body"><span class="card-tag">${z.tag}</span><h3>${z.name}</h3><p>${z.blurb}</p>
        <div class="card-live" data-live="${z.key}"></div><span class="card-more">Learn more ${icon("arrow")}</span></div>
    </button>`).join("");
  $$(".card").forEach((c) => {
    c.addEventListener("mousemove", (e) => { const b = c.getBoundingClientRect(); c.style.setProperty("--mx", `${e.clientX - b.left}px`); c.style.setProperty("--my", `${e.clientY - b.top}px`); });
    c.addEventListener("click", () => openZone(c.dataset.zone));
  });
}
function updateCardLive() { ZONES.forEach((z) => { const el = $(`[data-live="${z.key}"]`); if (el) el.textContent = z.live().split("\n")[0]; }); }
let lastFocus = null, openKey = null;
function openZone(key) {
  const z = ZONES.find((x) => x.key === key); openKey = key; lastFocus = document.activeElement;
  $("#modalBody").innerHTML = `
    <span class="card-tag" style="--zc:${z.color};color:${z.color}">${z.tag}</span>
    <h3 id="modalTitle">${z.name}</h3><p class="muted">${z.blurb}</p>
    <h4>Guarantees</h4><ul>${z.guarantees.map((g) => `<li>${g}</li>`).join("")}</ul>
    <h4>Controls</h4><ul>${z.controls.map((g) => `<li>${g}</li>`).join("")}</ul>
    <h4>Evidence</h4><ul>${z.evidence.map((g) => `<li><code>${esc(g)}</code></li>`).join("")}</ul>
    <h4>Live from the Arbiter</h4><div class="modal-live" id="modalLive">${esc(z.live())}</div>`;
  $("#modal").hidden = false; document.body.style.overflow = "hidden"; $(".modal-x").focus();
}
function closeModal() { $("#modal").hidden = true; document.body.style.overflow = ""; openKey = null; lastFocus?.focus(); }
function initModal() {
  $$("[data-close]").forEach((el) => el.addEventListener("click", closeModal));
  addEventListener("keydown", (e) => {
    if ($("#modal").hidden) return;
    if (e.key === "Escape") closeModal();
    if (e.key === "Tab") { const f = $$("#modal button, #modal a"); const [a, b] = [f[0], f[f.length - 1]];
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); b.focus(); } else if (!e.shiftKey && document.activeElement === b) { e.preventDefault(); a.focus(); } }
  });
}

/* ------------------------------------------------------------------ protocol timeline */
function renderTimelineSkeleton() {
  $("#timeline").innerHTML = STEPS.map((s, i) => `<li class="step" data-state="${s.state}"><div class="node">${icon(s.icon)}</div>
    <div><h3><small>0${i + 1}</small>${s.title}</h3><p>${s.text}</p></div></li>`).join("");
  $("#miniSteps").innerHTML = STEPS.map((s) => `<li data-state="${s.state}">${s.title.toUpperCase()}</li>`).join("");
}
function stepClasses(t) {
  if (!t) return { cls: STEPS.map(() => ""), p: 0, dead: false };
  const reached = new Set((t.history || []).map((h) => h.to)); reached.add(t.state);
  const dead = t.state === "INVALIDATED";
  let last = -1; STEPS.forEach((s, i) => { if (reached.has(s.state)) last = i; });
  const cls = STEPS.map((s, i) => (dead && i === last + 1 ? "dead" : i < last ? "done" : i === last ? (dead ? "done" : "now") : ""));
  return { cls, p: Math.max(0, (dead ? last + 1 : last) / (STEPS.length - 1)), dead };
}
function renderTimeline() {
  const t = latest(), { cls, p, dead } = stepClasses(t), tl = $("#timeline");
  tl.style.setProperty("--p", Math.min(1, p)); tl.classList.toggle("dead", dead); tl.classList.toggle("ok", t?.state === "ATTESTED");
  $$(".step", tl).forEach((li, i) => (li.className = "step " + cls[i]));
  $("#protoTrial").textContent = t ? `${t.name} · ${t.id} · ${t.state}` : "no trial yet";
  const b = $("#protoInvalid"); b.hidden = !dead; if (dead) b.textContent = `Trial invalidated: ${t.invalid_reason}`;
  const cs = $("#consoleState"); const st = t ? t.state : "IDLE";
  cs.textContent = st; cs.className = "badge " + (st === "ATTESTED" ? "ok" : st === "INVALIDATED" ? "bad" : st === "IDLE" ? "" : "run");
  if (topo) topo.state = st;
}
function renderMyRun() {
  if (!S.myRun) return; const t = S.overview.trials.find((x) => x.id === S.myRun.id);
  if (!t) return; const { cls } = stepClasses(t);
  $$("#miniSteps li").forEach((li, i) => (li.className = cls[i]));
  $("#runTitle").textContent = `${t.name} · ${t.id} · ${t.state}`;
  const note = { ATTESTED: "Attested: every commitment opened, every sealed record matched, and the signed checkpoint is in the ledger.",
    INVALIDATED: `Invalidated, as designed: ${t.invalid_reason}`, RUNNING: `Blinded run in progress: ${t.case_count} cases so far.` }[t.state];
  if (note && !S.myRun.docker) $("#runNote").textContent = note;
}

/* ------------------------------------------------------------------ stats + bench */
const STATS = [
  { id: "ledger", icon: "hash", label: "ledger events sealed and hash-chained", live: true, get: () => S.overview.ledger.seq },
  { id: "attested", icon: "check", label: "trials attested with a signed checkpoint", live: true, get: () => S.overview.trials.filter((t) => t.state === "ATTESTED").length },
  { id: "drill", icon: "radar", label: "breach-drill checks passed (latest certificate)", live: true, get: () => latestCert()?.cert_summary.pass, suffix: () => { const t = latestCert(); return t ? `/${t.cert_summary.total}` : ""; } },
  { id: "leak", icon: "sliders", label: "attacker accuracy with the Equalizer (chance = 50%)", get: () => S.metrics.leakage && S.metrics.leakage.equalizer_on.attacker_accuracy * 100, dec: 1, suffix: () => "%" },
  { id: "policy", icon: "scale", label: "policy decisions proven, exhaustively", get: () => policyDecisions() },
  { id: "caught", icon: "bell", label: "leaks contained + trials invalidated on purpose", live: true, get: () => S.overview.trials.reduce((a, t) => a + (t.leaks_contained || 0) + (t.state === "INVALIDATED" ? 1 : 0), 0) },
];
function renderStatsSkeleton() {
  $("#stats").innerHTML = STATS.map((s, i) => `<div class="stat reveal" style="transition-delay:${i * 60}ms" id="st-${s.id}">
    <span class="src ${s.live ? "live" : ""}">${s.live ? "● LIVE" : "BENCH"}</span><div class="si">${icon(s.icon)}</div>
    <div class="num" data-v="0">—</div><div class="lbl">${s.label}</div></div>`).join("");
  const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { S.statsSeen = true; updateStats(); io.disconnect(); } }, { threshold: 0.3 });
  io.observe($("#stats"));
}
function countTo(el, to, dec, suffix) {
  const from = parseFloat(el.dataset.v) || 0; el.dataset.v = to;
  const fmt = (v) => (dec ? v.toFixed(dec) : Math.round(v).toLocaleString()) + suffix;
  if (REDUCED || from === to) { el.textContent = fmt(to); return; }
  const t0 = performance.now(), dur = 1300;
  (function step(now) { const k = Math.min(1, (now - t0) / dur), e = 1 - (1 - k) ** 3; el.textContent = fmt(from + (to - from) * e); if (k < 1) requestAnimationFrame(step); })(t0);
}
function updateStats() {
  if (!S.statsSeen) return;
  for (const s of STATS) {
    const box = $("#st-" + s.id), el = $(".num", box), v = s.get();
    if (v == null || Number.isNaN(v)) { el.textContent = "—"; continue; }
    const prev = parseFloat(el.dataset.v);
    countTo(el, v, s.dec || 0, s.suffix ? s.suffix() : "");
    if (s.id === "drill") { const c = latestCert(); $(".lbl", box).textContent = c ? `breach-drill checks passed · ${c.cert_profile}${c.cert_summary.skip ? ` · ${c.cert_summary.skip} skipped (not enforced)` : ""}` : s.label; }
    if (el.dataset.init && prev !== v) { box.classList.add("bump"); setTimeout(() => box.classList.remove("bump"), 900); }
    el.dataset.init = "1";
  }
}
function renderBench() {
  const L = S.metrics.leakage, K = S.metrics.kvcache, O = S.metrics.overhead, out = [];
  const bar = (label, v, cls, ci, chance = true, text = null) => `<div class="bar"><span>${label}</span><div class="track">
      <div class="fill ${cls}" data-w="${Math.max(0, Math.min(1, v)) * 100}"></div>${chance ? '<i class="chance"></i>' : ""}
      ${ci ? `<i class="ci" style="left:${ci[0] * 100}%;width:${(ci[1] - ci[0]) * 100}%"></i>` : ""}</div><b>${text ?? (v * 100).toFixed(1) + "%"}</b></div>`;
  if (L) out.push(`<div class="bcard"><h3>Side-channel leakage</h3>${bar("Equalizer off", L.equalizer_off.attacker_accuracy, "bad", L.equalizer_off.ci95)}${bar("Equalizer on", L.equalizer_on.attacker_accuracy, "good", L.equalizer_on.ci95)}
    <p>Can red tell a guard refusal from a model refusal by latency and size? ${L.equalizer_on.consistent_with_chance ? "With the Equalizer: no better than a coin flip." : ""}</p></div>`);
  if (K) out.push(`<div class="bcard"><h3>KV-cache cross-session timing</h3>${bar("shared cache", K.global_cache.observer_accuracy, "bad", K.global_cache.ci95)}${bar("per-session", K.session_cache.observer_accuracy, "good", K.session_cache.ci95)}
    <p>Can one session tell what another just sent? Per-session caches remove the signal.</p></div>`);
  if (O) { const mx = Math.max(O.bare.p50, O.isolated.p50, O.equalized.p50);
    out.push(`<div class="bcard"><h3>Isolation overhead · p50</h3>${bar("bare model", O.bare.p50 / mx, "neutral", null, false, O.bare.p50 + " ms")}${bar("isolated", O.isolated.p50 / mx, "neutral", null, false, O.isolated.p50 + " ms")}${bar("equalized", O.equalized.p50 / mx, "neutral", null, false, O.equalized.p50 + " ms")}
    <p>The isolated path adds ${O.added_ms ? O.added_ms.isolated_p50 + " ms" : O.overhead_pct.isolated_p50 + "%"}. The Equalizer holds every reply to its ${O.bucket_ms} ms bucket, by design.</p></div>`); }
  const b = $("#bench"); b.innerHTML = out.join("") || '<p class="muted">Run <code>make bench</code> to populate benchmark results.</p>';
  const grow = () => $$(".fill", b).forEach((f) => (f.style.width = f.dataset.w + "%"));
  if (b.classList.contains("in")) grow(); else new IntersectionObserver(([e], o) => { if (e.isIntersecting) { setTimeout(grow, 200); o.disconnect(); } }, { threshold: 0.3 }).observe(b);
}

/* ------------------------------------------------------------------ carousel */
let slide = 0, carTimer = null;
function renderCarousel() {
  $("#slides").innerHTML = QUOTES.map((q, i) => `<article class="slide${i === slide ? " on" : ""}" aria-roledescription="slide" aria-label="${i + 1} of ${QUOTES.length}">
    <blockquote>${q.q}</blockquote><cite>Bayora problem statement · Hack in Hills '26</cite>
    <div class="how">${q.how}<div><span class="proof-chip">${icon("check")} ${esc(q.proof())}</span></div></div></article>`).join("");
  $("#carDots").innerHTML = QUOTES.map((_, i) => `<button role="tab" aria-label="requirement ${i + 1}" aria-selected="${i === slide}" class="${i === slide ? "on" : ""}" data-i="${i}"></button>`).join("");
  $$("#carDots button").forEach((b) => b.addEventListener("click", () => go(+b.dataset.i)));
}
function go(i) {
  slide = (i + QUOTES.length) % QUOTES.length;
  $$("#slides .slide").forEach((el, k) => el.classList.toggle("on", k === slide));
  $$("#carDots button").forEach((b, k) => { b.classList.toggle("on", k === slide); b.setAttribute("aria-selected", k === slide); });
}
function initCarousel() {
  renderCarousel();
  $("#prevSlide").addEventListener("click", () => go(slide - 1)); $("#nextSlide").addEventListener("click", () => go(slide + 1));
  const car = $("#carousel"), start = () => { if (!REDUCED) carTimer = setInterval(() => go(slide + 1), 7000); }, stop = () => clearInterval(carTimer);
  car.addEventListener("mouseenter", stop); car.addEventListener("mouseleave", start); car.addEventListener("focusin", stop); car.addEventListener("focusout", start);
  car.addEventListener("keydown", (e) => { if (e.key === "ArrowLeft") go(slide - 1); if (e.key === "ArrowRight") go(slide + 1); });
  start();
}

/* ------------------------------------------------------------------ trial form */
function initForm() {
  const f = $("#trialForm");
  const sync = () => { $("#bucketVal").textContent = f.bucket_ms.value + " ms"; $("#casesVal").textContent = f.limit.value; };
  f.bucket_ms.addEventListener("input", sync); f.limit.addEventListener("input", sync); sync();
  $$("[data-quickrun]").forEach((a) => a.addEventListener("click", () => setTimeout(() => $("#launchBtn").focus({ preventScroll: true }), 600)));
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const opts = { name: (f.name.value || "judge-demo").trim().slice(0, 60), scenario: f.scenario.value, equalizer: f.equalizer.checked,
      bucket_ms: +f.bucket_ms.value, limit: +f.limit.value };
    const btn = $("#launchBtn"); btn.disabled = true; btn.firstChild.textContent = "Launching… ";
    $("#runStatus").hidden = false; $("#runTitle").textContent = `${opts.name} · launching`; $("#runNote").textContent = "Waiting for the Arbiter…";
    $$("#miniSteps li").forEach((li) => (li.className = ""));
    S.myRun = { name: opts.name, since: Date.now() / 1000 - 2, id: null };
    try {
      await api("/v1/demo/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(opts) });
      toast("info", "Trial launched", `${opts.scenario} · equalizer ${opts.equalizer ? "on" : "off"} · ${opts.bucket_ms} ms buckets`);
    } catch (err) {
      if (err.status === 404) {
        try {
          const t = await api("/v1/trials", { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: opts.name, config: { equalizer: { enabled: opts.equalizer, bucket_ms: opts.bucket_ms } } }) });
          S.myRun.id = t.id; S.myRun.docker = true;
          $("#runNote").innerHTML = `Trial <code>${esc(t.id)}</code> created (DRAFT). In the isolated deployment, red and blue act from their own zones: run <code>make docker-trial</code> or the tenant CLIs.`;
          await refresh();
        } catch (e2) { $("#runNote").textContent = `Could not create a trial: ${e2.message}`; }
      } else $("#runNote").textContent = `Could not launch: ${err.message}`;
    } finally { setTimeout(() => { btn.disabled = false; btn.firstChild.textContent = "Launch trial "; }, 2500); }
  });
}

/* ------------------------------------------------------------------ toasts */
function toast(kind, title, msg) {
  const el = document.createElement("div"); el.className = "toast " + kind;
  el.innerHTML = `<b>${esc(title)}</b>${esc(msg)}`; $("#toasts").prepend(el);
  setTimeout(() => { el.style.transition = "opacity .4s"; el.style.opacity = "0"; setTimeout(() => el.remove(), 400); }, 5200);
  while ($("#toasts").children.length > 4) $("#toasts").lastChild.remove();
}

/* ------------------------------------------------------------------ data refresh + live */
let refreshing = null;
async function refresh() {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    try { S.overview = await api("/v1/trials"); } catch { /* offline */ }
    try { S.verify = await api("/v1/ledger/verify"); } catch { /* ignore */ }
    try { S.obs = await api("/v1/observability"); } catch { /* ignore */ }
    if (S.myRun && !S.myRun.id) { const m = S.overview.trials.find((t) => t.name === S.myRun.name && t.created_at >= S.myRun.since); if (m) S.myRun.id = m.id; }
    updateLive();
  })();
  try { await refreshing; } finally { refreshing = null; }
}
let refreshTimer = null;
const refreshSoon = () => { clearTimeout(refreshTimer); refreshTimer = setTimeout(refresh, 250); };
function updateLive() {
  const L = S.overview.ledger, t = latest();
  $("#cLedger").textContent = "#" + L.seq; $("#cTrial").textContent = t ? t.id : "—";
  $("#cChain").textContent = S.verify ? (S.verify.ok ? "verified ✓" : "BROKEN ✗") : "—";
  $("#cChain").style.color = S.verify && !S.verify.ok ? "var(--red)" : "var(--green)";
  const n = policyDecisions(); $("#cPolicy").textContent = S.policy ? (S.policy.invariants.every((r) => r.ok) ? `${n} ✓` : "VIOLATED") : "—";
  $("#footLive").textContent = `ledger #${L.seq} · ${short(L.head, 16)}`;
  $("#footPolicy").textContent = `policy ${short(S.overview.policy_hash, 16)}`;
  renderTimeline(); renderMyRun(); updateStats(); updateCardLive();
  if (openKey) { const z = ZONES.find((x) => x.key === openKey); $("#modalLive").textContent = z.live(); }
}

let topo = null;
function onEvent(ev) {
  if (ev.n) { if (ev.n <= S.lastN) return; S.lastN = ev.n; }
  const fresh = !ev.ts || ev.ts >= PAGE_T0 - 1;
  switch (ev.type) {
    case "ledger":
      tickerAdd(ev);
      if (ev.seq > S.overview.ledger.seq) { S.overview.ledger.seq = ev.seq; S.overview.ledger.head = ev.hash; }
      $("#cLedger").textContent = "#" + S.overview.ledger.seq;
      break;
    case "state":
      refreshSoon();
      if (fresh) {
        if (ev.state === "ATTESTED") toast("ok", "Attested", `${ev.name} · signed checkpoint in the ledger`);
        if (ev.state === "INVALIDATED") toast("critical", "Invalidated", `${ev.name}: ${ev.reason || ""}`);
      }
      break;
    case "case":
      if (fresh) { S.caseTimes.push(Date.now()); topo?.caseFlow(ev.commit); }
      if (S.myRun && S.myRun.id === ev.trial_id) { const t = latest(); if (t && t.id === ev.trial_id) { t.case_count = Math.max(t.case_count, ev.case_no); renderMyRun(); } }
      break;
    case "leak_contained":
      if (fresh) { topo?.contained(); toast("warn", "Leak contained", `case #${ev.case_no}: a response carrying blue's canary was withheld from red`); }
      break;
    case "drill": if (fresh) topo?.drill(); refreshSoon(); break;
    case "purity": if (fresh) topo?.flash("model", ev.ok === false ? "#ff5d73" : "#2ee6a6", ev.ok === false ? "DRIFT" : `F_${ev.phase}`); refreshSoon(); break;
    case "alert":
      if (fresh && ev.severity === "critical") { topo?.breach(); toast("critical", ev.kind.replace("_", " "), ev.message); }
      refreshSoon(); break;
    case "checkpoint": if (fresh) topo?.flash("authority", "#ffc857", "CHECKPOINT SIGNED"); break;
  }
}
function connect() {
  const pill = $("#livePill"), label = $("span", pill);
  const es = new EventSource("/v1/events");
  es.onopen = () => { pill.classList.add("on"); label.textContent = "live"; };
  es.onerror = () => { pill.classList.remove("on"); label.textContent = "reconnecting"; };
  es.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch (e) { console.error(e); } };
}

/* ------------------------------------------------------------------ boot */
(async function boot() {
  hydrateIcons(); initNav(); renderCards(); renderTimelineSkeleton(); renderStatsSkeleton(); initModal(); initForm();
  initReveal(); initParticles(); topo = new Topology($("#topology"));
  setInterval(drawSpark, 1000); drawSpark();
  try { S.metrics = await api("/v1/metrics"); } catch { /* none */ }
  try { S.policy = await api("/v1/policy"); } catch { /* none */ }
  renderBench(); initCarousel();
  await refresh();
  try {
    const L = await api(`/v1/ledger?since=${Math.max(0, S.overview.ledger.seq - 5)}&limit=5`);
    L.events.forEach((e) => tickerAdd({ seq: e.seq, etype: e.type, hash: e.hash }));
  } catch { /* ignore */ }
  connect();
  initReveal();
})();
