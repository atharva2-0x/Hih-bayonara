"""Generate docs/architecture.svg for DOUBLE-BLIND (hand-laid, dark theme).

Usage: python3 docs/gen_architecture_svg.py docs/architecture.svg
"""
from html import escape

W, H = 1720, 1070
BG = "#0b1020"
NODE = "#121a33"
TXT = "#e6e9f2"
MUTED = "#9aa4bf"
C = {
    "red": "#ff6b6b", "blue": "#4da3ff", "gold": "#f5c542",
    "violet": "#a78bfa", "green": "#34d399", "gray": "#94a3b8",
}
SANS = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'JetBrains Mono', Menlo, Consolas, monospace"

out = []
a = out.append


def text(x, y, s, size=12, fill=TXT, weight="normal", anchor="start", mono=False, style="", ls=None):
    fam = MONO if mono else SANS
    extra = f' letter-spacing="{ls}"' if ls else ""
    st = f' font-style="{style}"' if style else ""
    a(f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" fill="{fill}" '
      f'font-weight="{weight}" text-anchor="{anchor}"{extra}{st}>{escape(s)}</text>')


def zone(x, y, w, h, color, title, sub):
    a(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{color}" fill-opacity="0.07" '
      f'stroke="{color}" stroke-width="1.6"/>')
    text(x + 18, y + 28, title, 14, color, "700", ls="1.2")
    text(x + 18, y + 46, sub, 11, MUTED, mono=True)


def node(x, y, w, h, color, lines, dashed=False):
    d = ' stroke-dasharray="6 5"' if dashed else ""
    a(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{NODE}" stroke="{color}" stroke-width="1.4"{d}/>')
    n = len(lines)
    top = y + h / 2 - (n - 1) * 9 + 4
    for i, s in enumerate(lines):
        if i == 0:
            text(x + w / 2, top, s, 14, TXT, "700", "middle")
        else:
            text(x + w / 2, top + i * 18, s, 11, MUTED, anchor="middle")


def cylinder(cx, top, w, h, color, lines, ry=12):
    rx = w / 2
    bot = top + h
    a(f'<path d="M{cx-rx},{top} L{cx-rx},{bot} A{rx},{ry} 0 0 0 {cx+rx},{bot} L{cx+rx},{top}" '
      f'fill="{NODE}" stroke="{color}" stroke-width="1.4"/>')
    a(f'<ellipse cx="{cx}" cy="{top}" rx="{rx}" ry="{ry}" fill="{NODE}" stroke="{color}" stroke-width="1.4"/>')
    for i, s in enumerate(lines):
        if i == 0:
            text(cx, top + 34, s, 14, TXT, "700", "middle")
        else:
            text(cx, top + 34 + i * 18, s, 11, MUTED, anchor="middle")


def pill(x, y, s, color, fill_op=0.15, size=10.5, h=22, pad=10):
    w = len(s) * size * 0.62 + pad * 2
    a(f'<rect x="{x}" y="{y}" width="{w:.1f}" height="{h}" rx="{h/2}" fill="{color}" fill-opacity="{fill_op}" '
      f'stroke="{color}" stroke-opacity="0.7"/>')
    text(x + w / 2, y + h / 2 + size * 0.36, s, size, color, "600", "middle", mono=True)
    return w


def path(d, color=TXT, width=1.6, dashed=False, marker="w"):
    ds = ' stroke-dasharray="6 5"' if dashed else ""
    m = f' marker-end="url(#arr-{marker})"' if marker else ""
    a(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"{ds}{m}/>')


def badge(x, y, n, color=TXT):
    a(f'<circle cx="{x}" cy="{y}" r="10" fill="{BG}" stroke="{color}" stroke-width="1.5"/>')
    text(x, y + 4, str(n), 11, color, "700", "middle")


# ---------- canvas ----------
a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
a('<title>DOUBLE-BLIND architecture</title>')
a('<defs>')
for key, col in [("w", TXT), ("g", C["gold"]), ("r", C["red"]), ("m", MUTED), ("b", C["blue"])]:
    a(f'<marker id="arr-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
      f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{col}"/></marker>')
a('<pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse">'
  '<path d="M32 0 L0 0 0 32" fill="none" stroke="#ffffff" stroke-opacity="0.035" stroke-width="1"/></pattern>')
a('</defs>')
a(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
a(f'<rect width="{W}" height="{H}" fill="url(#grid)"/>')

# ---------- title ----------
text(30, 52, "DOUBLE-BLIND", 30, TXT, "800", ls="2")
text(30, 80, "Isolation for Bayora's red-team / blue-team AI safety testing, built to clinical-trial standards  ·  "
             "Hack in Hills '26 · Track 04", 14, MUTED)
steps = ["PRE-REGISTER", "ARM", "BLIND RUN", "CONCLUDE", "REVEAL", "ATTEST"]
x = 1690 - (sum(len(t) * 10.5 * 0.62 + 16 for t in steps) + 14 * (len(steps) - 1))
for i, s in enumerate(steps):
    w = pill(x, 42, s, C["gold"], 0.12, 10.5, 24, 8)
    x += w
    if i < len(steps) - 1:
        text(x + 7, 58, "›", 16, C["gold"], "700", "middle")
        x += 14

# ---------- RED ZONE ----------
zone(30, 110, 320, 300, C["red"], "RED ZONE · TENANT A", "net-red · gVisor · cores 2-3")
node(55, 175, 270, 70, C["red"], ["Red Runner", "attack harness · adaptive mode"])
cylinder(190, 280, 260, 70, C["red"], ["Red Vault", "benchmark sets · sealed with K_red"])
path("M190,278 L190,249", MUTED, 1.2, True, "m")
text(200, 263, "trial token", 10.5, MUTED, mono=True)
pill(48, 376, "◆ canary R-7f3a", C["red"], 0.12, 10)

# forbidden path red <-> blue
a(f'<line x1="190" y1="413" x2="190" y2="447" stroke="{C["red"]}" stroke-width="1.6" stroke-dasharray="4 4"/>')
a(f'<circle cx="190" cy="430" r="10" fill="{BG}" stroke="{C["red"]}" stroke-width="1.6"/>')
text(190, 434.5, "✕", 12, C["red"], "700", "middle")
text(208, 434, "no path, ever", 11, C["red"], "600", mono=True)

# ---------- BLUE ZONE ----------
zone(30, 450, 320, 280, C["blue"], "BLUE ZONE · TENANT B", "net-blue · cores 4-5")
node(55, 512, 270, 70, C["blue"], ["Blue Workbench", "author + package defense bundles"])
cylinder(190, 610, 260, 70, C["blue"], ["Blue Vault", "bundles + classifier weights · K_blue"])
pill(48, 700, "◆ canary B-21c9", C["blue"], 0.12, 10)

# ---------- TRIAL AUTHORITY ----------
zone(410, 110, 600, 620, C["gold"], "TRIAL AUTHORITY · CONTROL PLANE",
     "net-ctrl · only multi-homed service · cores 0-1")
hexpts = "560,240 590,188 830,188 860,240 830,292 590,292"
a(f'<polygon points="{hexpts}" fill="{NODE}" stroke="{C["gold"]}" stroke-width="2.2"/>')
text(710, 230, "ARBITER", 19, C["gold"], "800", "middle", ls="2")
text(710, 253, "trial state machine + sole message broker", 12, TXT, anchor="middle")
text(710, 272, "every cross-zone byte passes through here", 11, MUTED, anchor="middle", style="italic")

svc = [
    (428, "Equalizer", "time + size buckets", "canonical refusals"),
    (572, "Policy Engine", "OPA / Cedar ABAC", "role × state × time"),
    (716, "Key Broker", "per-tenant keys", "trial-scoped tokens"),
    (860, "Judge", "independent scoring", "red never self-grades"),
]
for sx, t1, t2, t3 in svc:
    node(sx, 330, 132, 78, C["gold"], [t1, t2, t3])

node(428, 428, 276, 70, C["gold"], ["Commit-Reveal Registry", "C = H(artifact ‖ nonce) · opened at REVEAL"])
node(716, 428, 276, 70, C["gold"], ["Breach Drill", "tests every forbidden path → Isolation Cert"])

# state strip
states = ["REGISTERED", "ARMED", "RUNNING", "CONCLUDED", "REVEALED", "ATTESTED"]
pw, gap = 86, 9.6
for i, s in enumerate(states):
    px = 428 + i * (pw + gap)
    a(f'<rect x="{px:.1f}" y="514" width="{pw}" height="24" rx="12" fill="{C["gold"]}" fill-opacity="0.12" '
      f'stroke="{C["gold"]}" stroke-opacity="0.6"/>')
    text(px + pw / 2, 530, s, 9.5, C["gold"], "700", "middle", mono=True)
text(724, 560, "↯ canary hit · policy violation ·", 11, C["red"], "600", mono=True)
text(724, 576, "  drift · mismatch → INVALIDATED", 11, C["red"], "600", mono=True)
text(698, 568, "append every event", 11, C["gold"], "600", "end", mono=True)

# ledger
cylinder(710, 604, 564, 84, C["gold"], [], ry=13)
text(710, 632, "TRIAL LEDGER", 15, C["gold"], "800", "middle", ls="1.5")
text(710, 650, "SHA-256 hash chain · Merkle checkpoints · Ed25519 signatures", 11, MUTED, anchor="middle")
blocks = ["#1041 9f3a", "#1042 c07e", "#1043 51bd", "#1044 e2a9", "#1045 7d10"]
bx = 499
for i, s in enumerate(blocks):
    a(f'<rect x="{bx}" y="662" width="70" height="20" rx="4" fill="{BG}" stroke="{C["gold"]}" stroke-opacity="0.6"/>')
    text(bx + 35, 676, s, 9.5, TXT, anchor="middle", mono=True)
    if i < len(blocks) - 1:
        path(f"M{bx+71},672 L{bx+86},672", C["gold"], 1.2, False, "g")
    bx += 88

# gold append line from Arbiter to Ledger
path("M710,293 L710,598", C["gold"], 3.2, False, "g")

# arbiter <-> policy / key broker (control)
path("M672,293 C672,312 638,310 638,327", MUTED, 1.2, True, "m")
path("M748,293 C748,312 782,310 782,327", MUTED, 1.2, True, "m")

# ---------- SEALED DEFENSE ENCLAVE ----------
zone(1070, 110, 280, 400, C["violet"], "SEALED DEFENSE ENCLAVE", "gVisor · RO bundle · no egress")
node(1095, 180, 230, 70, C["violet"], ["Input Guard", "blue's bundle, runs sealed"])
node(1095, 330, 230, 70, C["violet"], ["Output Guard", "verdict-only output schema"])
text(1210, 436, "blue authors it,", 12, TXT, anchor="middle", style="italic")
text(1210, 454, "blue can't watch it", 12, TXT, anchor="middle", style="italic")
text(1210, 480, "bundle mounted read-only at ARM", 10.5, MUTED, anchor="middle", mono=True)
text(1210, 496, "logs → Authority only", 10.5, MUTED, anchor="middle", mono=True)

# ---------- MODEL CLEAN ROOM ----------
zone(1400, 110, 290, 400, C["green"], "MODEL CLEAN ROOM", "ephemeral per trial · cores 6-7")
node(1425, 175, 240, 130, C["green"],
     ["Client LLM", "digest-pinned, read-only weights", "per-session KV cache, flushed",
      "no egress · tools disabled", "temp 0 · fixed seed (replayable)"])
node(1425, 330, 240, 84, C["green"], ["Purity Fingerprint", "golden probes → H(outputs)", "F_pre must equal F_post"])
pill(1440, 436, "sha256 7c1e…b04d ✓", C["green"], 0.12, 10)
text(1545, 492, "fresh replica every trial", 12, TXT, anchor="middle", style="italic")

# ---------- OBSERVABILITY ----------
zone(1070, 550, 620, 180, C["gray"], "OBSERVABILITY · METADATA ONLY · PUSH-ONLY",
     "sees hashes, sizes, timings, verdict codes · never plaintext")
node(1090, 612, 180, 76, C["gray"], ["Runtime Sensors", "Falco / Tetragon eBPF", "exec · connect · file"])
node(1290, 612, 180, 76, C["gray"], ["Canary Watcher", "+ boundary DLP", "hit → INVALIDATE < 1 s"])
node(1490, 612, 180, 76, C["gray"], ["Anomaly Detector", "rate + latency drift", "probing patterns"])
text(1090, 716, "alerts → Arbiter → trial INVALIDATED", 11, C["red"], "600", mono=True)
path("M1068,705 L1014,705", C["red"], 1.8, False, "r")

# ---------- DATA PATH ①-⑧ ----------
path("M326,202 C450,202 470,236 556,238")                 # 1 red -> arbiter
badge(440, 210, 1)
text(420, 182, "sealed case · mTLS", 10.5, MUTED, mono=True)
path("M862,238 C960,238 990,212 1091,212")                # 2 arbiter -> input guard
badge(972, 226, 2)
path("M1327,212 L1421,212")                               # 3 input guard -> LLM
badge(1375, 212, 3)
path("M1423,282 C1378,282 1372,362 1329,362")             # 4 LLM -> output guard
badge(1382, 322, 4)
path("M1093,360 C1010,360 960,250 852,258")               # 5 output guard -> arbiter
badge(985, 306, 5)
text(1210, 296, "verdict + output stay sealed", 10.5, MUTED, anchor="middle", mono=True)
path("M806,293 C806,312 926,306 926,326")                 # 6 arbiter -> judge
badge(880, 309, 6)
path("M614,293 C614,312 494,306 494,326")                 # 7 arbiter -> equalizer
badge(540, 309, 7)
path("M426,372 C384,372 372,232 329,232")                 # 8 equalizer -> red
badge(384, 312, 8)

# commitments
path("M322,318 C385,318 380,452 424,452", C["red"], 1.3, True, "r")
text(357, 372, "C_red", 10.5, C["red"], "600", mono=True)
path("M327,548 C385,548 380,478 424,478", C["blue"], 1.3, True, "b")
text(356, 530, "C_blue", 10.5, C["blue"], "600", mono=True)

# ---------- bottom row ----------
node(30, 772, 320, 78, C["gray"], ["War Room", "live three-lane dashboard", "shows IDs and hashes only, never payloads"])
node(410, 772, 290, 78, C["gold"], ["Verifier CLI · dbverify", "offline: chain · signatures", "commitments · deterministic replay"])
node(720, 772, 290, 78, C["gold"], ["Public Anchor (optional)", "checkpoint root → Sigstore Rekor"], dashed=True)
path("M560,702 L560,768", C["gold"], 1.6, False, "g")
path("M450,702 C450,756 190,744 190,768", C["gold"], 1.4, False, "g")
path("M865,702 L865,768", C["gold"], 1.4, True, "g")

# legend
a(f'<rect x="1070" y="772" width="620" height="78" rx="10" fill="{NODE}" stroke="{MUTED}" stroke-opacity="0.5"/>')
text(1088, 796, "LEGEND", 11, MUTED, "700", ls="1.5")
path("M1090,818 L1140,818", TXT, 1.6)
text(1148, 822, "data path 1-8", 11, TXT)
path("M1260,818 L1310,818", C["gold"], 3.2, False, "g")
text(1318, 822, "ledger append", 11, TXT)
path("M1430,818 L1480,818", MUTED, 1.2, True, "m")
text(1488, 822, "control / commitment", 11, TXT)
a(f'<circle cx="1102" cy="838" r="7" fill="{BG}" stroke="{C["red"]}" stroke-width="1.4"/>')
text(1102, 841.5, "✕", 9, C["red"], "700", "middle")
text(1116, 842, "forbidden path (breach drill proves it's denied)", 11, TXT)
pill(1460, 829, "◆ canary", C["gray"], 0.12, 9.5, 18, 8)
text(1540, 842, "honeytoken", 11, TXT)

# ---------- host band ----------
a(f'<rect x="30" y="880" width="1660" height="118" rx="14" fill="#ffffff" fill-opacity="0.03" '
  f'stroke="{MUTED}" stroke-opacity="0.45" stroke-dasharray="3 5"/>')
text(48, 906, "HOST · ANY STANDARD CLOUD VM · NO SPECIAL HARDWARE · docker compose up", 13, TXT, "700", ls="1.2")
chips = ["rootless Docker / Podman", "gVisor runsc", "seccomp allowlists", "cap_drop ALL", "no-new-privileges",
         "read-only rootfs", "user namespaces", "cgroups v2 cpusets", "memory · pids · io limits",
         "per-zone internal networks", "nftables default-deny", "cloud metadata IP blocked",
         "mTLS workload identity", "per-tenant envelope encryption"]
cx, cy = 48, 920
for s in chips:
    w = len(s) * 10.5 * 0.62 + 20
    if cx + w > 1675:
        cx, cy = 48, cy + 32
    pill(cx, cy, s, C["gray"], 0.10, 10.5, 24)
    cx += w + 10

# ---------- footer ----------
text(30, 1030, "Flow: Red → Arbiter → Input Guard → Model → Output Guard → Arbiter → Judge + Ledger → "
               "Equalizer → Red. Red only ever sees equalized responses; blue only sees results after REVEAL.",
     12, MUTED)
text(30, 1050, "Details: ARCHITECTURE.md · Plan: plan.md", 11, MUTED, mono=True)

a('</svg>')
import sys
open(sys.argv[1], "w").write("\n".join(out))
print("ok")
