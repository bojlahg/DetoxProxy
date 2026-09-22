#!/usr/bin/env bash
# Builds a committed revision for Linux in Docker and deploys it to the VPS with automatic rollback.
#   tools/deploy.sh [rev] [ssh-host]       (defaults: HEAD, detoxproxy)
# Service: systemd unit detox-proxy, user detox, /opt/detox-proxy, port 8080 (from config.yaml).
# Migrates the old pii-guard unit on first run. Refuses to run in the first/last 10 minutes of an hour
# (organizer checks start at :00); FORCE=1 overrides.
set -euo pipefail
rev="$(git rev-parse --short "${1:-HEAD}")"
host="${2:-detoxproxy}"
min=$((10#$(date +%M)))
if [ "${FORCE:-0}" != "1" ] && { [ "$min" -lt 10 ] || [ "$min" -ge 50 ]; }; then
  echo "refusing to deploy at :$(date +%M) (checks run at :00); FORCE=1 to override"; exit 2
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git archive "$rev" | tar -x -C "$work/"
bin_name="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$work/Cargo.toml" | head -1)"
mkdir -p /d/Hackaton/linux-build-cache
MSYS_NO_PATHCONV=1 docker run --rm -v "$(cygpath -w "$work"):/src" -v "D:/Hackaton/linux-build-cache:/cache" \
  -w /src -e CARGO_HOME=/cache/cargo rust:1-bookworm \
  sh -c "cargo build --release --target-dir /cache/target 2>&1 | tail -1 && cp /cache/target/release/$bin_name /src/app-linux"
mkdir -p "$work/pkg"
cp "$work/app-linux" "$work/pkg/detox-proxy"
cp "$work/config.yaml" "$work/pkg/"
cp -r "$work/data" "$work/pkg/"
rm -rf "$work/pkg/data/dict/raw"
echo "$rev" > "$work/pkg/REVISION"
tar -C "$work/pkg" -czf "$work/deploy.tgz" .
scp -q "$work/deploy.tgz" "$host:/root/deploy.tgz"
ssh "$host" 'bash -s' <<'EOF'
set -euo pipefail
dir=/opt/detox-proxy
id detox >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin detox
mkdir -p "$dir/logs"
if [ ! -f /etc/systemd/system/detox-proxy.service ]; then
  cat > /etc/systemd/system/detox-proxy.service <<'UNIT'
[Unit]
Description=DetoxProxy PII masking proxy
After=network-online.target
Wants=network-online.target
[Service]
User=detox
Group=detox
WorkingDirectory=/opt/detox-proxy
ExecStart=/opt/detox-proxy/detox-proxy --config /opt/detox-proxy/config.yaml
Restart=always
RestartSec=2
LimitNOFILE=65536
Environment=RUST_LOG=info
StandardOutput=append:/opt/detox-proxy/logs/service.log
StandardError=append:/opt/detox-proxy/logs/service.log
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/detox-proxy/logs
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable detox-proxy >/dev/null 2>&1
fi
rm -rf /root/prev && mkdir /root/prev
[ -f "$dir/detox-proxy" ] && cp -a "$dir/detox-proxy" "$dir/config.yaml" "$dir/data" /root/prev/ && cp -a "$dir/REVISION" /root/prev/ 2>/dev/null || true
tar -xzf /root/deploy.tgz -C "$dir" --no-same-permissions --no-same-owner
chown -R detox:detox "$dir"
chmod 755 "$dir" "$dir/detox-proxy"
find "$dir/data" -type d -exec chmod 755 {} + ; find "$dir/data" -type f -exec chmod 644 {} +
chmod 644 "$dir/config.yaml" "$dir/REVISION"
healthy() { for _ in $(seq 1 50); do curl -sf -o /dev/null http://127.0.0.1:8080/healthz && return 0; sleep 0.1; done; return 1; }
# one-time migration from the old unit: free port 8080 right before starting the new one
if systemctl list-unit-files pii-guard.service >/dev/null 2>&1 && systemctl is-enabled pii-guard >/dev/null 2>&1; then
  systemctl disable --now pii-guard >/dev/null 2>&1 || true
  migrated=1
fi
systemctl reset-failed detox-proxy 2>/dev/null || true
systemctl restart detox-proxy
if healthy; then
  echo "deployed $(cat $dir/REVISION), $(systemctl is-active detox-proxy)"
  if [ "${migrated:-0}" = 1 ]; then
    rm -f /etc/systemd/system/pii-guard.service && systemctl daemon-reload
    rm -rf /opt/pii-guard && userdel piiguard 2>/dev/null || true
    if [ -f /etc/nginx/sites-available/pii-guard ]; then
      mv /etc/nginx/sites-available/pii-guard /etc/nginx/sites-available/detox-proxy
      rm -f /etc/nginx/sites-enabled/pii-guard
      ln -sf /etc/nginx/sites-available/detox-proxy /etc/nginx/sites-enabled/detox-proxy
      nginx -t -q && systemctl reload nginx
    fi
    rm -f /root/setup.sh
    echo "old pii-guard unit removed"
  fi
else
  echo "HEALTH CHECK FAILED, rolling back"; journalctl -u detox-proxy -n 5 --no-pager | tail -5
  if [ "${migrated:-0}" = 1 ]; then
    systemctl stop detox-proxy; systemctl enable --now pii-guard; healthy && echo "old pii-guard restored"; exit 1
  fi
  cp -a /root/prev/. "$dir/" && chown -R detox:detox "$dir" && chmod 755 "$dir/detox-proxy"
  systemctl reset-failed detox-proxy 2>/dev/null || true; systemctl restart detox-proxy
  healthy && echo "rolled back to $(cat $dir/REVISION 2>/dev/null || echo previous)"; exit 1
fi
EOF
