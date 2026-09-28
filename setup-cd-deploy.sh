#!/usr/bin/env bash
# Install or update the restricted CD Deploy SSH key on this server.
# Run as the app user, not root. Choose standalone, hub, or agent to install
# only the sudo permissions required by that host's deploy service.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLE="${1:-standalone}"
DEPLOY_PUBKEY=""

require_non_root() {
  if [[ $EUID -eq 0 ]]; then
    echo "Run this as your normal application user, not root/sudo." >&2
    exit 1
  fi
}

install_role_sudoers() {
  local sudoers_tmp user
  user="$(whoami)"
  case "$ROLE" in
    standalone)
      # setup.sh already grants the exact helper installs and web UI restart.
      ;;
    hub)
      sudoers_tmp="$(mktemp)"
      {
        printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl restart pivpn-webui\n' "$user"
        printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl restart pivpn-webui-overview-stream\n' "$user"
      } > "$sudoers_tmp"
      sudo visudo -cf "$sudoers_tmp"
      sudo install -m 0440 -o root -g root "$sudoers_tmp" /etc/sudoers.d/pivpn-webui-cd-deploy
      rm -f "$sudoers_tmp"
      ;;
    agent)
      sudoers_tmp="$(mktemp)"
      {
        for helper in ccd log routes client-script; do
          printf '%s ALL=(root) NOPASSWD: /usr/bin/install -m 0750 -o root -g root %s/deploy/pivpn-webui-%s-helper.sh /usr/local/sbin/pivpn-webui-%s-helper.sh\n' \
            "$user" "$APP_DIR" "$helper" "$helper"
        done
        printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl restart pivpn-webui-agent\n' "$user"
      } > "$sudoers_tmp"
      sudo visudo -cf "$sudoers_tmp"
      sudo install -m 0440 -o root -g root "$sudoers_tmp" /etc/sudoers.d/pivpn-webui-agent-deploy
      rm -f "$sudoers_tmp"
      ;;
    *)
      echo "Usage: $0 [standalone|hub|agent]" >&2
      exit 2
      ;;
  esac
}

install_authorized_keys_entry() {
  local forced_cmd line authorized_keys_tmp
  forced_cmd="cd ${APP_DIR} && ${APP_DIR}/deploy/deploy-commit.sh ${ROLE}"
  line="command=\"${forced_cmd}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${DEPLOY_PUBKEY}"
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  touch ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
  if grep -qF "$DEPLOY_PUBKEY" ~/.ssh/authorized_keys; then
    # Replace this key's old forced command so deployments are SHA-pinned.
    authorized_keys_tmp="$(mktemp)"
    grep -Fv -- "$DEPLOY_PUBKEY" ~/.ssh/authorized_keys > "$authorized_keys_tmp" || true
    mv "$authorized_keys_tmp" ~/.ssh/authorized_keys
  fi
  printf '%s\n' "$line" >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
}

main() {
  require_non_root
  case "$ROLE" in standalone|hub|agent) ;; *) echo "Usage: $0 [standalone|hub|agent]" >&2; exit 2 ;; esac
  read -rp "Deploy public key (the public half of GitHub's DEPLOY_SSH_KEY secret): " DEPLOY_PUBKEY
  [[ -n "$DEPLOY_PUBKEY" ]] || { echo "No key given, aborting." >&2; exit 1; }
  if [[ ! "$DEPLOY_PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[^[:space:]]+)[[:space:]][A-Za-z0-9+/=]+([[:space:]][^\",[:cntrl:]]*)?$ ]]; then
    echo "Expected one valid SSH public key line." >&2
    exit 1
  fi
  install_role_sudoers
  install_authorized_keys_entry
  echo "Restricted deploy key installed/updated for role: $ROLE."
  echo "Configure DEPLOY_TARGET_1 for the hub/standalone, and DEPLOY_TARGET_2 for an agent."
}

main "$@"
