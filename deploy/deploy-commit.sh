#!/usr/bin/env bash
# Restricted SSH forced command: deploy only the exact main-branch commit
# that completed CI successfully. The caller supplies only its SHA as the
# SSH command; never evaluate SSH_ORIGINAL_COMMAND as shell code.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROLE="${1:-}"
SHA="${SSH_ORIGINAL_COMMAND:-}"

case "$ROLE" in
  standalone|hub|agent) ;;
  *) echo "Unsupported deploy role." >&2; exit 2 ;;
esac
if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Expected the 40-character tested commit SHA." >&2
  exit 2
fi

cd "$APP_DIR"
if [[ "$(git branch --show-current)" != "main" ]]; then
  echo "Deployment checkout must be on main." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Deployment checkout has local changes; refusing to overwrite them." >&2
  exit 1
fi

git fetch --quiet origin main
if [[ "$(git rev-parse origin/main)" != "$SHA" ]]; then
  echo "Tested SHA is no longer the current origin/main; waiting for its CI run." >&2
  exit 1
fi
git merge --ff-only "$SHA"

install_helpers() {
  local helper
  for helper in ccd log routes client-script; do
    sudo -n install -m 0750 -o root -g root \
      "$APP_DIR/deploy/pivpn-webui-${helper}-helper.sh" \
      "/usr/local/sbin/pivpn-webui-${helper}-helper.sh"
  done
}

case "$ROLE" in
  standalone)
    install_helpers
    sudo -n systemctl restart pivpn-webui
    ;;
  hub)
    sudo -n systemctl restart pivpn-webui-overview-stream
    sudo -n systemctl restart pivpn-webui
    ;;
  agent)
    install_helpers
    sudo -n systemctl restart pivpn-webui-agent
    ;;
esac

echo "Deployed $SHA ($ROLE)."
