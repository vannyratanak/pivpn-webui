#!/usr/bin/env bash
# Installs the CD Deploy workflow's forced-command SSH key on this server.
# Run this once per server, in addition to ./setup.sh, as the same user
# that installed PiVPN — not root. Idempotent: safe to re-run.
#
# The forced command is what actually runs when the shared deploy key
# connects, regardless of what command it sends: pull latest, reinstall
# the 4 helper scripts (setup.sh's own sudoers grants are what make the
# `sudo -n install ...` calls below work without a password), restart the
# service. See deploy/sudoers-pivpn-webui.template for the matching grants.
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Run this as your normal user (the one PiVPN was installed as), not root/sudo." >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

read -rp "Deploy public key (shared across servers — copy from an existing server's authorized_keys, or from the GitHub secret's public half): " DEPLOY_PUBKEY
[[ -n "$DEPLOY_PUBKEY" ]] || { echo "No key given, aborting." >&2; exit 1; }

FORCED_CMD="cd ${APP_DIR} && git pull"
for helper in ccd log routes client-script; do
  # Must be the absolute source path, matching deploy/sudoers-pivpn-webui.template's
  # __APP_DIR__ substitution exactly — sudoers does literal argv matching, not
  # path resolution, so a relative path here would silently fall back to
  # asking for a password no matter how correct the sudoers grant is.
  FORCED_CMD+=" && sudo -n install -m 0750 -o root -g root ${APP_DIR}/deploy/pivpn-webui-${helper}-helper.sh /usr/local/sbin/pivpn-webui-${helper}-helper.sh"
done
FORCED_CMD+=" && sudo -n systemctl restart pivpn-webui"

LINE="command=\"${FORCED_CMD}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${DEPLOY_PUBKEY}"

mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

if grep -qF "$DEPLOY_PUBKEY" ~/.ssh/authorized_keys 2>/dev/null; then
  echo "This key is already installed in authorized_keys — skipping."
  echo "Remove the old line first if the forced command itself needs to change."
else
  printf '%s\n' "$LINE" >> ~/.ssh/authorized_keys
  echo "Deploy key installed."
fi

echo
echo "Last manual step: add a 'Deploy to $(hostname -I 2>/dev/null | awk '{print $1}')'"
echo "step to .github/workflows/deploy.yml, copying the existing steps' pattern."
