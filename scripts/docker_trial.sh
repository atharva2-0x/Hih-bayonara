#!/usr/bin/env bash
# Full blinded trial through the isolated Docker zones.
# Prereqs: make env certs build up   (see Makefile)
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PY:-.venv/bin/python}
DC="docker compose --profile tenants --profile drill"
OP="$PY -m doubleblind operator"
set -a; [ -f .env ] && . ./.env; set +a
RISKS=${DB_ACCEPTED_RISKS:-}
BUCKET_MS=${BUCKET_MS:-250}

say() { printf '\n\033[1;33m▸ %s\033[0m\n' "$*"; }

say "breach drill: running an agent inside every zone"
for z in red blue enclave model observability; do
  $DC run --rm "drill-$z" >/dev/null 2>&1 || true
done
$DC run --rm --entrypoint python drill-red -c "import json,glob
for f in sorted(glob.glob('/drill-out/*.json')):
    r=json.load(open(f)); res=r['results']
    fails=[x['id'] for x in res if x['status']=='fail']
    print(f\"  {r['zone']:<14} {len(res)-len(fails):>2}/{len(res)} passed\", ('  failed: '+', '.join(fails)) if fails else '')"

say "red: sealing the payload set into the red vault (inside the red zone)"
$DC run --rm red-runner red init-vault

risks_json=$(python3 -c "import json,sys; print(json.dumps([r for r in sys.argv[1].split(',') if r]))" "$RISKS")
say "operator: creating trial (accepted risks on this host: ${risks_json})"
TID=$($OP create --quiet --name docker-trial --config "{\"equalizer\":{\"bucket_ms\":${BUCKET_MS}},\"accepted_risks\":${risks_json}}")
echo "  trial $TID"

say "pre-registration: red and blue commit from their own zones"
$DC run --rm red-runner red commit --trial "$TID" >/dev/null
$DC run --rm blue-workbench blue commit --trial "$TID" | grep -E '"state"'
$DC run --rm blue-workbench blue upload --trial "$TID" >/dev/null

say "arming: isolation certificate + purity fingerprint + sealed bundle"
$OP arm --trial "$TID" | grep -E '"(state|f_pre|pass|fail|skip)"' || { $OP status --trial "$TID"; exit 1; }
$OP start --trial "$TID" >/dev/null

say "blinded run: red submits from net-red over pinned mTLS"
$DC run --rm red-runner red run --trial "$TID"

say "conclude + reveal ceremony"
$OP conclude --trial "$TID" | grep '"state"'
$DC run --rm red-runner red reveal --trial "$TID" | grep -E '"(state|membership_ok)"'
$DC run --rm blue-workbench blue reveal --trial "$TID" | grep -E '"state"'

say "export + offline verification (with deterministic replay)"
mkdir -p exports
$OP export --trial "$TID" --out "exports/$TID.json"
$PY -m doubleblind verify "exports/$TID.json" --replay stub

say "canary drill on a second trial: a foreign canary arriving from red must invalidate it"
TID2=$($OP create --quiet --name docker-canary-drill --config "{\"equalizer\":{\"bucket_ms\":${BUCKET_MS}},\"accepted_risks\":${risks_json}}")
$DC run --rm red-runner red commit --trial "$TID2" >/dev/null
$DC run --rm blue-workbench blue commit --trial "$TID2" >/dev/null
$DC run --rm blue-workbench blue upload --trial "$TID2" >/dev/null
$OP arm --trial "$TID2" >/dev/null && $OP start --trial "$TID2" >/dev/null
$OP canary --trial "$TID2"
$OP status --trial "$TID2" | grep -E '"(state|invalid_reason)"'
