#!/usr/bin/env bash
# The README's local setup, run for real: .env from .env.example, make core-up's stack, the replay,
# the analyst login, and a restart that must not lose the case. CI runs this on every pull request.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAILED: $*" >&2; exit 1; }

analyst_token=compose-check-analyst
analyst_hash=$(printf '%s' "$analyst_token" | sha256sum | cut -d' ' -f1)
sed -e "s/^CLOUDSHIELD_ANALYST_TOKEN=.*/CLOUDSHIELD_ANALYST_TOKEN=$analyst_token/" \
    -e "s/replace-me/compose-check/" \
    -e "s/sha256-of-your-token/$analyst_hash/" .env.example > .env

docker compose up -d --build --wait core
set -a; . ./.env; set +a
make demo-incident

api=http://localhost:8080
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
login=(-H "authorization: Bearer $CLOUDSHIELD_ANALYST_TOKEN")
cases() { curl -sf "${login[@]}" "$api/v1/cases"; }
field() { python3 -c "import json, sys; print(json.load(sys.stdin)[0]['$1'])"; }

[ "$(status "$api/v1/cases")" = 401 ] || fail "cases readable with no login"
[ "$(status -H 'authorization: Bearer wrong' "$api/v1/cases")" = 401 ] || fail "cases readable with a wrong token"
[ "$(status "${login[@]}" "$api/v1/cases")" = 200 ] || fail "the analyst from .env can't log in"

case_id=$(cases | field case_id)
[ "$(cases | field event_count)" = 2 ] || fail "S1's two alerts did not land in one case"
[ -n "$(docker compose exec -T core sh -c 'ls -A /evidence')" ] || fail "no raw evidence was archived"

docker compose restart core
for _ in $(seq 1 30); do
  [ "$(status "$api/healthz")" = 200 ] && break
  sleep 2
done
[ "$(cases | field case_id)" = "$case_id" ] || fail "the case did not survive a restart"

echo "compose check passed: login enforced, one case with 2 events, evidence archived, case $case_id survived a restart"
