#!/usr/bin/env bash
# DNS cutover: point the avln A records (proxied) at the Contabo
# origin. This is the LAST step of the host migration — run it only
# after push.sh succeeded and the direct-origin smoke test passed:
# once this flips, implants start landing on the new host.
#
# Usage: deploy/contabo/dns-cutover.sh [--check] [--rollback]
#   (default) flip both records to the Contabo origin
#   --check     show current records only
#   --rollback  point both records back at the Azure origin
set -euo pipefail

ZONE=02a6a5029a9c504e60876fed0f1b8500
CF_KEYS="C:/Users/antho/Desktop/Workstation/keys/cloudflare"
NEW_IP=13.140.191.31
OLD_IP=20.9.60.148
# avln + avln2 are separate A records, both proxied.
RECORDS="avln.nora.systems:fe8ecfa36d7794d31ed1f7e1ed5a226e avln2.nora.systems:60189a2d46e7b9d2bbadb0274b847856"

TOKEN=$(cat "$CF_KEYS/write-all.txt")

MODE=flip
case "${1:-}" in
  --check) MODE=check ;;
  --rollback) MODE=rollback ;;
  "") ;;
  *) echo "usage: dns-cutover.sh [--check] [--rollback]" >&2; exit 1 ;;
esac

say() { printf '\n==> %s\n' "$*"; }

for pair in $RECORDS; do
  name=${pair%%:*}; rid=${pair##*:}
  if [ "$MODE" = check ]; then
    say "current: $name"
    curl -s -H "Authorization: Bearer $TOKEN" \
      "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records/$rid" \
      | python -c "import json,sys; r=json.load(sys.stdin)['result']; print(r['type'], r['name'], '->', r['content'], '| proxied:', r['proxied'])"
    continue
  fi
  ip=$NEW_IP
  [ "$MODE" = rollback ] && ip=$OLD_IP
  say "pointing $name at $ip"
  curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data "{\"content\":\"$ip\"}" \
    "https://api.cloudflare.com/client/v4/zones/$ZONE/dns_records/$rid" \
    | python -c "
import json, sys
d = json.load(sys.stdin)
r = d.get('result', {})
ok = d.get('success') and r.get('content') == '$ip'
print('OK' if ok else 'FAILED: ' + json.dumps(d.get('errors')))
sys.exit(0 if ok else 1)
"
done

[ "$MODE" = check ] && exit 0
say "records flipped — implants will reach the Contabo origin via the edge"
