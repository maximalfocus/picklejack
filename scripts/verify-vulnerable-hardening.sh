#!/usr/bin/env bash
# Bring up the vulnerable stack and prove the container hardening required by the
# read-only / non-destructive guarantee: non-root, all capabilities dropped,
# no-new-privileges, a read-only root filesystem, an internal (no-egress) network,
# and no host port on the vulnerable container itself.
#
# Usage: ALLOW_VULNERABLE_DEMO=true bash scripts/verify-vulnerable-hardening.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ "${ALLOW_VULNERABLE_DEMO:-}" != "true" ]; then
  echo "Set ALLOW_VULNERABLE_DEMO=true to run this check." >&2
  exit 2
fi

cleanup() { docker compose --profile vulnerable down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "Starting the vulnerable stack..."
docker compose --profile vulnerable up -d --build vulnerable vuln-proxy >/dev/null

cid="$(docker compose ps -q vulnerable)"
fail=0
check() { # label expected actual
  if [ "$2" = "$3" ]; then echo "  ok    $1 = $3"; else echo "  FAIL  $1 = $3 (want $2)"; fail=1; fi
}

echo "Inspecting container hardening:"
check "ReadonlyRootfs" "true" "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$cid")"
check "CapDrop"        "[ALL]" "$(docker inspect --format '{{.HostConfig.CapDrop}}' "$cid")"
check "SecurityOpt"    "[no-new-privileges:true]" "$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$cid")"
check "User"           "10001:10001" "$(docker inspect --format '{{.Config.User}}' "$cid")"

networks="$(docker inspect --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$cid" | tr -s ' ')"
if echo "$networks" | grep -q edge; then
  echo "  FAIL  vulnerable container is attached to the edge network"; fail=1
else
  echo "  ok    networks = ${networks}(internal only)"
fi

echo "Proving no network egress from the vulnerable container:"
if docker compose exec -T vulnerable python -c "import socket;s=socket.socket();s.settimeout(4);s.connect(('1.1.1.1',53))" >/dev/null 2>&1; then
  echo "  FAIL  egress succeeded"; fail=1
else
  echo "  ok    egress blocked"
fi

echo "Confirming the code-execution proof runs as a non-root user:"
body="$(python3 - <<'PY'
import json
expr = "__import__('os').popen('id').read()"
print(json.dumps({"format": "yaml", "data": '!!python/object/apply:eval ["' + expr + '"]'}))
PY
)"
id_line="$(curl -s -X POST http://127.0.0.1:8001/workspace/import \
  -H 'Authorization: Bearer demo-token-globex-mallory' -H 'Content-Type: application/json' \
  --data "$body" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["reconstructed"].strip())')"
echo "  id → ${id_line}"
case "$id_line" in
  uid=10001*) echo "  ok    RCE runs as non-root (uid=10001)";;
  *) echo "  FAIL  unexpected id output"; fail=1;;
esac

if [ "$fail" -ne 0 ]; then echo "HARDENING: FAIL"; exit 1; fi
echo "HARDENING: PASS"
