#!/usr/bin/env bash
# One-command deploy of the avln teamserver (Contabo VPS, plain SSH).
#   1. build the operational implant (embedded config) and stage it
#   2. scp the workspace source and build the server ON the VM
#   3. install the migration bundle (identity key, live state, LE certs)
#      once — never overwriting an identity that already exists there
#   4. restart the service and health-check (mgmt + public stage hash)
#
# Port layout: the box's shared host Caddy owns 443 (other services),
# so the teamserver binds 127.0.0.1:8443 with its own TLS and Caddy
# fronts avln/avln2 as one more site block (tls internal — the CF
# ssl=full rule accepts it — reverse_proxy to the loopback). CF
# headers pass through, so T037 netblock rules keep resolving.
#
# First run on a fresh VM additionally installs the Rust toolchain.
#
# Usage: deploy/contabo/push.sh [--skip-source] [--skip-stage] [--no-bundle]
#   --skip-source  only redeploy the stage (no server rebuild)
#   --skip-stage   only rebuild the server (stage stays as-is)
#   --no-bundle    do not upload the migration bundle (identity/state
#                  already in place on the VM)
#
# Identity continuity: run/server.key is the Ed25519 identity every
# deployed implant embeds. The bundle installs it only when absent —
# a redeploy must never roll a new identity or implants will reject
# the server.
set -euo pipefail
cd "$(dirname "$0")/../.."

SSH_DEST=lilithops@13.140.191.31
SSH_KEY="$HOME/.ssh/id_rsa"
REMOTE=/opt/avln
RUN_DIR=/opt/avln/run
DOMAIN=avln.nora.systems
# Migration bundle pulled from the previous host (see keys/avln-migration).
BUNDLE_DIR="${ABLN_BUNDLE:-C:/Users/antho/Desktop/Workstation/keys/avln-migration/bundle}"

# The operator network blocks outbound 22, so SSH/scp ride an ETL
# SOCKS5 proxy (remote DNS, `connect` ships with Git for Windows).
# ABLN_SOCKS="" falls back to a direct connection.
SOCKS="${ABLN_SOCKS-127.0.0.1:1080}"
PROXY_OPTS=()
[ -n "$SOCKS" ] && PROXY_OPTS=(-o "ProxyCommand=connect -S $SOCKS %h %p")

SSH=(ssh "${PROXY_OPTS[@]}" -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=15 "$SSH_DEST")
SCP=(env MSYS_NO_PATHCONV=1 scp "${PROXY_OPTS[@]}" -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=15)

SKIP_SOURCE=0
SKIP_STAGE=0
NO_BUNDLE=0
for arg in "$@"; do
  case "$arg" in
    --skip-source) SKIP_SOURCE=1 ;;
    --skip-stage) SKIP_STAGE=1 ;;
    --no-bundle) NO_BUNDLE=1 ;;
    *) echo "usage: push.sh [--skip-source] [--skip-stage] [--no-bundle]" >&2; exit 1 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'push.sh: %s\n' "$*" >&2; exit 1; }

SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

if [ "$SKIP_SOURCE" = 0 ] || [ "$SKIP_STAGE" = 0 ]; then
  say "building implant (embedded config, release)"
  # Absolute path: implant/build.rs resolves ABRAHAM_EMBED from the
  # package directory, not the workspace root.
  ABRAHAM_EMBED="$PWD/deploy/avln/embed.json" cargo build --release -p abraham-implant
  mkdir -p deploy/contabo/.build
  cp target/release/abraham-implant.exe deploy/contabo/.build/stage.bin
  echo "stage sha256: $(sha256sum deploy/contabo/.build/stage.bin | cut -d' ' -f1)"
fi

if [ "$NO_BUNDLE" = 0 ] && [ -d "$BUNDLE_DIR" ]; then
  say "uploading migration bundle (identity, state, certs)"
  tar czf "$SCRATCH/bundle.tgz" -C "$BUNDLE_DIR" \
    run mgmt.token profiles etc
  "${SCP[@]}" "$SCRATCH/bundle.tgz" "$SSH_DEST:/tmp/abraham-bundle.tgz"
fi

if [ "$SKIP_SOURCE" = 0 ]; then
  say "syncing workspace source"
  # First-run bootstrap: the deploy user scps into /opt/avln directly,
  # so the directory must exist and be lilithops-writable before the
  # privileged install step locks it down.
  "${SSH[@]}" 'sudo -n mkdir -p /opt/avln && sudo -n chown lilithops:lilithops /opt/avln'
  tar czf "$SCRATCH/src.tar.gz" \
    --exclude=target --exclude=.git --exclude=loot --exclude=docs \
    --exclude=deploy --exclude='*.pcapng' --exclude='*.evtx' \
    Cargo.toml Cargo.lock common implant server tui tools 2>/dev/null \
    || tar czf "$SCRATCH/src.tar.gz" --exclude=target --exclude=.git \
       Cargo.toml Cargo.lock common server
  "${SCP[@]}" "$SCRATCH/src.tar.gz" "$SSH_DEST:$REMOTE/src.tar.gz"

  say "building server on the VM (this is the slow step)"
  # Non-root deploy user: everything privileged goes through sudo -n.
  "${SSH[@]}" 'sudo -n bash -s' <<'EOS'
set -e
CARGO=$(command -v cargo || ls /root/.cargo/bin/cargo /home/*/.cargo/bin/cargo 2>/dev/null | head -1)
if [ -z "$CARGO" ]; then
  echo "installing rust toolchain (first run)"
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal > /tmp/rustup.log 2>&1
  CARGO=/root/.cargo/bin/cargo
fi
# Minimal cloud images ship without a C linker; ring and friends need one.
if ! command -v cc >/dev/null 2>&1; then
  echo "installing build-essential (first run)"
  apt-get update -q > /tmp/apt.log 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential pkg-config >> /tmp/apt.log 2>&1
fi
mkdir -p /opt/avln && cd /opt/avln
tar xzf src.tar.gz && rm -f src.tar.gz
if "$CARGO" build --release -p abraham-server > /tmp/avln-build.log 2>&1; then
  echo "BUILD-STATUS:0"
else
  echo "BUILD-STATUS:$?"
fi
tail -5 /tmp/avln-build.log
EOS
fi

if [ "$SKIP_STAGE" = 0 ]; then
  say "staging the implant"
  "${SCP[@]}" deploy/contabo/.build/stage.bin "$SSH_DEST:/tmp/abraham-stage.bin"
fi

say "installing bundle + stage, restarting avln-server"
"${SSH[@]}" 'sudo -n bash -s' <<'EOS'
set -e
mkdir -p /opt/avln/run/state /opt/avln/profiles /etc/letsencrypt

# --- migration bundle: install ONCE. An existing identity/state on
# this host always wins over the bundle — that is what keeps implant
# continuity across redeploys.
if [ -s /tmp/abraham-bundle.tgz ]; then
  TMPD=$(mktemp -d)
  tar xzf /tmp/abraham-bundle.tgz -C "$TMPD"
  if [ ! -s /opt/avln/run/server.key ]; then
    echo "bundle: installing identity (server.key was absent)"
    cp "$TMPD"/run/server.key "$TMPD"/run/server.pub /opt/avln/run/
    [ -s "$TMPD"/run/state/sessions.json ] && \
      cp -r "$TMPD"/run/state/. /opt/avln/run/state/
  else
    echo "bundle: server.key already present — identity kept"
  fi
  [ -s "$TMPD"/mgmt.token ] && cp "$TMPD"/mgmt.token /opt/avln/mgmt.token
  cp "$TMPD"/profiles/default.yaml /opt/avln/profiles/default.yaml
  # LE certs: archive files + renewal conf, then the live/ symlinks
  # certbot expects.
  if [ -d "$TMPD"/etc/letsencrypt ]; then
    mkdir -p /etc/letsencrypt
    cp -r "$TMPD"/etc/letsencrypt/. /etc/letsencrypt/
    LIVE=/etc/letsencrypt/live/avln.nora.systems
    mkdir -p "$LIVE"
    for f in cert chain fullchain privkey; do
      ln -sf "../../archive/avln.nora.systems/${f}1.pem" "$LIVE/${f}.pem"
    done
  fi
  rm -rf "$TMPD" /tmp/abraham-bundle.tgz
fi

[ -s /tmp/abraham-stage.bin ] && mv /tmp/abraham-stage.bin /opt/avln/run/stage.bin

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
Description=Abraham teamserver (avln, Contabo)
After=network-online.target

[Service]
WorkingDirectory=/opt/avln/run
EnvironmentFile=/opt/avln/mgmt.env
ExecStart=/opt/avln/target/release/abraham-server --listen 127.0.0.1:8443 --mgmt 127.0.0.1:9200 --mgmt-token \${MGMT_TOKEN} --tls-cert /etc/letsencrypt/live/avln.nora.systems/fullchain.pem --tls-key /etc/letsencrypt/live/avln.nora.systems/privkey.pem --profile /opt/avln/profiles/default.yaml --stage-file /opt/avln/run/stage.bin
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

# --- shared Caddy owns 443: front avln as one more site block. The
# marker comments make the block idempotent and easy to lift out.
CADDY=/etc/caddy/Caddyfile
if ! grep -q "abraham-avln" "$CADDY"; then
  cp "$CADDY" "$CADDY.bak-abraham"
  cat >> "$CADDY" <<'SITE'
# abraham-avln begin
# Zone SSL mode is Full (strict): the origin must present a CA-trusted
# cert, hence the migrated LE pair (Caddy reloads post-renewal via the
# certbot deploy hook /etc/letsencrypt/renewal-hooks/deploy/).
avln.nora.systems, avln2.nora.systems {
	tls /etc/letsencrypt/live/avln.nora.systems/fullchain.pem /etc/letsencrypt/live/avln.nora.systems/privkey.pem
	reverse_proxy https://127.0.0.1:8443 {
		transport http {
			tls_insecure_skip_verify
		}
	}
}
# abraham-avln end
SITE
  if caddy validate --config "$CADDY" > /tmp/caddy-validate.log 2>&1; then
    systemctl reload caddy && echo "caddy: avln site added and reloaded"
  else
    cp "$CADDY.bak-abraham" "$CADDY"
    echo "caddy: config invalid, rolled back" >&2
    exit 1
  fi
else
  echo "caddy: avln site already present"
fi

systemctl daemon-reload
systemctl restart avln-server && sleep 2 && systemctl is-active avln-server
journalctl -u avln-server -n 6 --no-pager
EOS

say "health: sessions via mgmt"
python deploy/contabo/mgmt.py '{"cmd":"sessions"}' || die "mgmt health check failed"

if [ "$SKIP_STAGE" = 0 ]; then
  say "health: teamserver TLS strict on loopback (LE cert)"
  loop=$( "${SSH[@]}" \
    "curl -s --resolve avln.nora.systems:8443:127.0.0.1 \
       https://avln.nora.systems:8443/cdn/update?nocache=\$RANDOM | sha256sum | cut -d' ' -f1" )
  local_hash=$(sha256sum deploy/contabo/.build/stage.bin | cut -d' ' -f1)
  echo "loopback: $loop"
  echo "local   : $local_hash"
  [ "$loop" = "$local_hash" ] || die "loopback stage hash mismatch"

  say "health: full Caddy chain, direct to the new origin"
  # Caddy presents its internal-CA cert here, so -k is expected on a
  # direct-origin hit; real clients validate CF's edge cert and CF
  # accepts any origin cert under ssl=full. What this proves is the
  # vhost routing + proxy to the teamserver.
  remote=$(curl -sk --resolve "$DOMAIN:443:13.140.191.31" \
    "https://$DOMAIN/cdn/update?nocache=$RANDOM" | sha256sum | cut -d' ' -f1)
  echo "via caddy: $remote"
  [ "$remote" = "$local_hash" ] || die "caddy-chain stage hash mismatch"
  echo "stage live and identical on the new origin"
fi

say "deploy complete on the Contabo origin (DNS not yet switched)"
