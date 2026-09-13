#!/usr/bin/env bash
# One-command redeploy of the avln teamserver (Azure VM, no SSH):
#   1. build the operational implant (embedded config) and stage it
#   2. sync the workspace source and build the server ON the VM
#   3. restart the service and health-check (mgmt + public stage hash)
#
# Usage: deploy/avln/push.sh [--skip-source] [--skip-stage]
#   --skip-source  only redeploy the stage (no server rebuild)
#   --skip-stage   only rebuild the server (stage stays as-is)
set -euo pipefail
cd "$(dirname "$0")/../.."

RG=rg-avln
VM=vm-avln
REMOTE=/opt/avln
RUN_DIR=/opt/avln/run
AZ_PY="C:/Program Files/Microsoft SDKs/Azure/CLI2/python.exe"
DOMAIN=avln.nora.systems

SKIP_SOURCE=0
SKIP_STAGE=0
for arg in "$@"; do
  case "$arg" in
    --skip-source) SKIP_SOURCE=1 ;;
    --skip-stage) SKIP_STAGE=1 ;;
    *) echo "usage: push.sh [--skip-source] [--skip-stage]" >&2; exit 1 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'push.sh: %s\n' "$*" >&2; exit 1; }

SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
# Native path form (C:/...) so the Azure CLI python accepts @file args.
WSCRATCH=$(cygpath -m "$SCRATCH")

# run_vm <name> — script text on stdin; prints the script's stdout and
# fails the deploy when the run-command itself fails.
run_vm() {
  local name=$1 out
  cat > "$WSCRATCH/$name.sh"
  out=$("$AZ_PY" -m azure.cli vm run-command invoke -g "$RG" -n "$VM" \
    --command-id RunShellScript --scripts "@$WSCRATCH/$name.sh" \
    --query "value[0].message" -o tsv 2> "$SCRATCH/$name.err") \
    || { cat "$SCRATCH/$name.err" >&2; die "run-command $name failed"; }
  printf '%s\n' "$out"
}

if [ "$SKIP_SOURCE" = 0 ] || [ "$SKIP_STAGE" = 0 ]; then
  say "building implant (embedded config, release)"
  # Absolute path: implant/build.rs resolves ABRAHAM_EMBED from the
  # package directory, not the workspace root.
  ABRAHAM_EMBED="$PWD/deploy/avln/embed.json" cargo build --release -p abraham-implant
  mkdir -p deploy/avln/.build
  cp target/release/abraham-implant.exe deploy/avln/.build/stage.bin
  echo "stage sha256: $(sha256sum deploy/avln/.build/stage.bin | cut -d' ' -f1)"
fi

if [ "$SKIP_SOURCE" = 0 ]; then
  say "syncing workspace source"
  tar czf "$SCRATCH/src.tar.gz" \
    --exclude=target --exclude=.git --exclude=loot --exclude=docs \
    --exclude=deploy --exclude='*.pcapng' --exclude='*.evtx' \
    Cargo.toml Cargo.lock common implant server tui tools 2>/dev/null \
    || tar czf "$SCRATCH/src.tar.gz" --exclude=target --exclude=.git \
       Cargo.toml Cargo.lock common server
  # MSYS_NO_PATHCONV: stop Git Bash from rewriting the REMOTE POSIX path
  # into a Windows one; the LOCAL temp path is converted explicitly.
  MSYS_NO_PATHCONV=1 "$AZ_PY" deploy/avln/upload_chunked.py \
    "$(cygpath -m "$SCRATCH/src.tar.gz")" "$REMOTE/src.tar.gz"

  say "building server on the VM (this is the slow step)"
  # RunShellScript runs via a bare dash without ~/.cargo/bin on PATH.
  out=$(run_vm build <<'EOS'
CARGO=$(command -v cargo || ls "$HOME"/.cargo/bin/cargo /root/.cargo/bin/cargo /home/*/.cargo/bin/cargo 2>/dev/null | head -1)
[ -n "$CARGO" ] || { echo "BUILD-STATUS:99 (cargo not found)"; exit 1; }
cd /opt/avln && tar xzf src.tar.gz && rm -f src.tar.gz
"$CARGO" build --release -p abraham-server > /tmp/avln-build.log 2>&1
echo "BUILD-STATUS:$?"
tail -5 /tmp/avln-build.log
EOS
) || exit 1
  echo "$out" | tail -7
  echo "$out" | grep -q "BUILD-STATUS:0" || die "server build failed on the VM"
fi

if [ "$SKIP_STAGE" = 0 ]; then
  say "staging the implant"
  MSYS_NO_PATHCONV=1 "$AZ_PY" deploy/avln/upload_chunked.py \
    deploy/avln/.build/stage.bin "$RUN_DIR/stage.bin"
fi

say "restarting avln-server"
out=$(run_vm restart <<'EOS'
# Mgmt token: generate once, keep stable across deploys. systemd does
# not expand $(...) in ExecStart — the token rides via EnvironmentFile.
if [ ! -s /opt/avln/mgmt.token ]; then
  head -c 32 /dev/urandom | base64 | tr -d '=+/' > /opt/avln/mgmt.token
fi
chmod 600 /opt/avln/mgmt.token
printf 'MGMT_TOKEN=%s\n' "$(cat /opt/avln/mgmt.token)" > /opt/avln/mgmt.env
chmod 600 /opt/avln/mgmt.env
cat > /etc/systemd/system/avln-server.service <<UNIT
[Unit]
Description=Abraham teamserver (avln)
After=network-online.target

[Service]
WorkingDirectory=/opt/avln/run
EnvironmentFile=/opt/avln/mgmt.env
ExecStart=/opt/avln/target/release/abraham-server --listen 0.0.0.0:443 --mgmt 127.0.0.1:9200 --mgmt-token \${MGMT_TOKEN} --tls-cert /etc/letsencrypt/live/avln.nora.systems/fullchain.pem --tls-key /etc/letsencrypt/live/avln.nora.systems/privkey.pem --profile /opt/avln/profiles/default.yaml --stage-file /opt/avln/run/stage.bin
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl restart avln-server && sleep 2 && systemctl is-active avln-server
journalctl -u avln-server -n 6 --no-pager
EOS
) || exit 1
  echo "$out"
  echo "$out" | grep -q "^active$" || die "avln-server did not come back active"

say "health: sessions via mgmt"
"$AZ_PY" deploy/avln/mgmt.py '{"cmd":"sessions"}'

if [ "$SKIP_STAGE" = 0 ]; then
  say "health: public stage hash"
  # Query string busts any edge cache; GETs on any URI serve the stage.
  remote=$(curl -s "https://$DOMAIN/cdn/update?nocache=$RANDOM" | sha256sum | cut -d' ' -f1)
  local_hash=$(sha256sum deploy/avln/.build/stage.bin | cut -d' ' -f1)
  echo "served: $remote"
  echo "local : $local_hash"
  [ "$remote" = "$local_hash" ] || die "served stage hash mismatch"
  echo "stage live and identical"
fi

say "deploy complete: https://$DOMAIN"
