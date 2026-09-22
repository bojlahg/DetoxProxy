#!/usr/bin/env bash
# Builds a committed revision for Linux in Docker and deploys it to the VPS with automatic rollback.
#   tools/deploy.sh [rev] [ssh-host]       (defaults: HEAD, detoxproxy)
# Refuses to run in the first/last 10 minutes of an hour (organizer checks start at :00).
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
mkdir -p /d/Hackaton/linux-build-cache
MSYS_NO_PATHCONV=1 docker run --rm -v "$(cygpath -w "$work"):/src" -v "D:/Hackaton/linux-build-cache:/cache" \
  -w /src -e CARGO_HOME=/cache/cargo rust:1-bookworm \
  sh -c 'cargo build --release --target-dir /cache/target 2>&1 | tail -1 && cp /cache/target/release/pii-guard /src/pii-guard-linux'
mkdir -p "$work/pkg"
cp "$work/pii-guard-linux" "$work/pkg/pii-guard"
cp "$work/config.yaml" "$work/pkg/"
cp -r "$work/data" "$work/pkg/"
rm -rf "$work/pkg/data/dict/raw"
echo "$rev" > "$work/pkg/REVISION"
tar -C "$work/pkg" -czf "$work/deploy.tgz" .
scp -q "$work/deploy.tgz" "$host:/root/deploy.tgz"
ssh "$host" 'bash -s' <<'EOF'
set -euo pipefail
cd /opt/pii-guard
rm -rf /root/prev && mkdir /root/prev
cp -a pii-guard config.yaml data /root/prev/ && cp -a REVISION /root/prev/ 2>/dev/null || true
tar -xzf /root/deploy.tgz -C /opt/pii-guard --no-same-permissions --no-same-owner
chown -R piiguard:piiguard /opt/pii-guard
chmod 755 /opt/pii-guard /opt/pii-guard/pii-guard
find /opt/pii-guard/data -type d -exec chmod 755 {} + ; find /opt/pii-guard/data -type f -exec chmod 644 {} +
chmod 644 /opt/pii-guard/config.yaml /opt/pii-guard/REVISION
healthy() { for _ in $(seq 1 50); do curl -sf -o /dev/null http://127.0.0.1:8080/healthz && return 0; sleep 0.1; done; return 1; }
systemctl reset-failed pii-guard 2>/dev/null || true
systemctl restart pii-guard
if healthy; then
  echo "deployed $(cat REVISION), $(systemctl is-active pii-guard)"
else
  echo "HEALTH CHECK FAILED, rolling back"; journalctl -u pii-guard -n 5 --no-pager | tail -5
  cp -a /root/prev/. /opt/pii-guard/ && chown -R piiguard:piiguard /opt/pii-guard && chmod 755 /opt/pii-guard/pii-guard
  systemctl reset-failed pii-guard 2>/dev/null || true; systemctl restart pii-guard
  healthy && echo "rolled back to $(cat REVISION 2>/dev/null || echo previous)"; exit 1
fi
EOF
