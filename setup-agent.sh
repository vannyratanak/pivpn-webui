#!/usr/bin/env bash
# One-time setup for an AGENT box (the actual PiVPN server) in a hub/agent
# deployment. Run this ONCE on each real PiVPN box you want a hub to
# manage remotely, after cloning this repo there and confirming PiVPN
# itself is already installed and working. This box only ever needs
# agent.py + the app package's local-execution code paths — NOT
# Postgres, NOT nginx, NOT the Flask app itself.
#
# Also turns on deploy/setup-traffic-log.sh's per-destination VPN traffic
# logging (Logs page's Traffic tab) if PiVPN is already installed —
# previously a separate, easy-to-forget manual step with the Traffic tab
# just silently staying empty forever otherwise.
#
# Before running this: register the box on the HUB first
#   python3 manage_servers.py register <name>
# (or answer "yes" to setup-hub.sh's own step 6) — you'll need the
# printed AGENT_SERVER_ID/AGENT_TOKEN (and cert paths, if the hub has
# mutual TLS set up) to answer this script's prompts below.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_USER=""

require_non_root() {
  if [[ $EUID -eq 0 ]]; then
    echo "Run this as your normal user (the one PiVPN was installed as), not root/sudo." >&2
    exit 1
  fi
}

print_intro() {
  echo "======================================================"
  echo " PiVPN Web UI — one-time AGENT setup"
  echo "======================================================"
  echo
  echo "This box dials OUT to the hub over an encrypted WebSocket — nothing"
  echo "inbound needs opening here. No Postgres/nginx/Flask runs on this"
  echo "machine; just the small always-on connector."
  echo
}

warn_if_pivpn_missing() {
  if ! command -v pivpn >/dev/null 2>&1; then
    echo "Warning: 'pivpn' not found on PATH. This box can't actually manage" >&2
    echo "clients/firewall until it is." >&2
  fi
}

stop_stray_agent_process() {
  # Courtesy check for an already-running ad-hoc agent.py (e.g. one started
  # by hand with nohup for testing, before this script existed) — two
  # processes both holding the same AGENT_TOKEN would just fight the hub
  # for the same connection slot instead of cleanly replacing each other.
  if pgrep -f "python3.*agent\.py" >/dev/null 2>&1; then
    echo
    echo "A python agent.py process is already running outside systemd:"
    pgrep -af "python3.*agent\.py" || true
    local stop_old
    read -rp "Stop it now, before installing the real service? [Y/n] " stop_old
    if [[ "${stop_old:-Y}" =~ ^[Yy]?$ ]]; then
      pkill -f "python3.*agent\.py" || true
      sleep 1
      echo "Stopped."
    fi
  fi
}

setup_venv() {
  echo
  echo "== Step 1/7: venv + dependencies =="
  # Debian/Ubuntu split ensurepip out of the base Python package. Install the
  # matching venv package automatically on a fresh PiVPN agent.
  if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    if ! command -v apt-get >/dev/null 2>&1; then
      echo "Python venv support is missing and apt-get is unavailable. Install the matching python3-venv package, then rerun this script." >&2
      exit 1
    fi
    local python_minor
    python_minor="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    echo "Installing Python venv support (python${python_minor}-venv)..."
    sudo apt-get update -y
    if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "python${python_minor}-venv"; then
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv
    fi
  fi

  python3 -m venv venv
  # shellcheck disable=SC1091
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt   # full list — `from app import pivpn_ctl` runs app/__init__.py first
}

write_env_config() {
  echo
  echo "== Step 2/7: connection config (.env) =="
  if [[ -f .env ]]; then
    echo ".env already exists — leaving it as-is."
    echo "(Delete it first if you want to re-enter these values.)"
    return
  fi

  local hub_url agent_server_id agent_token
  read -rp "Hub's HUB_URL (e.g. wss://hub.example.com:8765, or ws://... with no TLS): " hub_url
  read -rp "AGENT_SERVER_ID (from 'manage_servers.py register' on the hub): " agent_server_id
  read -rsp "AGENT_TOKEN (shown once at registration time — paste it now): " agent_token
  echo
  # `read` never expands `~` the way a shell parsing a command argument
  # does — a typed `~/foo` is stored as the literal 2 characters `~/foo`,
  # and neither .env nor Python's ssl module (which reads these paths
  # verbatim, see agent.py's _build_tls_context) expand it either. Hit
  # live: HUB_TLS_CERT=~/pivpn-webui/instance/hub-gateway.crt landed in
  # .env exactly like that, and agent.py failed with "[Errno 2] No such
  # file or directory" trying to open a literal `~` directory that never
  # existed. Expanding any leading `~` to $HOME right after each read
  # fixes this regardless of what the user types, instead of relying on
  # everyone remembering to type an absolute path.
  #
  # manage_servers.py's own printed instructions already tell whoever's
  # copying these files to drop them straight into this box's
  # instance/ — the one and only place they're ever told to go — so
  # check there first and offer it as the default instead of demanding
  # a full path be retyped every time. Still overridable, for anyone who
  # put them somewhere else.
  # "blank to skip" only means "skip" when there's no default filled in
  # — once a found file IS shown in [brackets], blank instead means
  # "use that file", which is the opposite thing and confusing to read
  # the same way. So once a default exists, blank accepts it and typing
  # the literal word "skip" is the only way to opt out instead.
  local default_hub_crt hub_tls_cert
  default_hub_crt="$APP_DIR/instance/hub-gateway.crt"
  if [[ -f "$default_hub_crt" ]]; then
    read -rp "Path to the hub's copied hub-gateway.crt — Enter to use this, or type 'skip' if HUB_URL is ws:// [$default_hub_crt]: " hub_tls_cert
    if [[ "$hub_tls_cert" == "skip" ]]; then
      hub_tls_cert=""
    else
      hub_tls_cert="${hub_tls_cert:-$default_hub_crt}"
    fi
  else
    read -rp "Path to the hub's copied hub-gateway.crt, if HUB_URL is wss:// (blank if ws://): " hub_tls_cert
  fi
  hub_tls_cert="${hub_tls_cert/#\~/$HOME}"

  # The agent's own cert is named after whatever <name> was used at
  # `manage_servers.py register <name>` — this box has no way to know
  # that string, but it can still look in instance/ for whichever .crt
  # actually landed there (excluding the hub's own hub-gateway.crt/
  # hub-ca.crt, which live in that same folder for unrelated reasons)
  # and offer that as the default.
  local agent_crt_guess agent_tls_cert agent_tls_key
  agent_crt_guess="$(find "$APP_DIR/instance" -maxdepth 1 -name '*.crt' \
    ! -name 'hub-gateway.crt' ! -name 'hub-ca.crt' 2>/dev/null | head -1)"
  if [[ -n "$agent_crt_guess" ]]; then
    read -rp "Path to this agent's own .crt — Enter to use this, or type 'skip' for no mutual TLS [$agent_crt_guess]: " agent_tls_cert
    if [[ "$agent_tls_cert" == "skip" ]]; then
      agent_tls_cert=""
    else
      agent_tls_cert="${agent_tls_cert:-$agent_crt_guess}"
    fi
  else
    read -rp "Path to this agent's own .crt, if the hub uses mutual TLS (blank to skip): " agent_tls_cert
  fi
  agent_tls_cert="${agent_tls_cert/#\~/$HOME}"
  agent_tls_key=""
  if [[ -n "$agent_tls_cert" ]]; then
    local agent_key_guess
    agent_key_guess="${agent_tls_cert%.crt}.key"
    if [[ -f "$agent_key_guess" ]]; then
      read -rp "Path to this agent's own .key [$agent_key_guess]: " agent_tls_key
      agent_tls_key="${agent_tls_key:-$agent_key_guess}"
    else
      read -rp "Path to this agent's own .key: " agent_tls_key
    fi
    agent_tls_key="${agent_tls_key/#\~/$HOME}"
  fi
  local ovpn_dir subnet_base
  read -rp "Path PiVPN writes .ovpn files to [$HOME/ovpns]: " ovpn_dir
  ovpn_dir="${ovpn_dir:-$HOME/ovpns}"
  ovpn_dir="${ovpn_dir/#\~/$HOME}"
  read -rp "OpenVPN subnet, first 3 octets [10.8.0]: " subnet_base
  subnet_base="${subnet_base:-10.8.0}"

  {
    echo "HUB_URL=${hub_url}"
    echo "AGENT_SERVER_ID=${agent_server_id}"
    echo "AGENT_TOKEN=${agent_token}"
    [[ -n "$hub_tls_cert" ]] && echo "HUB_TLS_CERT=${hub_tls_cert}"
    [[ -n "$agent_tls_cert" ]] && echo "AGENT_TLS_CERT=${agent_tls_cert}"
    [[ -n "$agent_tls_key" ]] && echo "AGENT_TLS_KEY=${agent_tls_key}"
    echo "PIVPN_OVPN_DIR=${ovpn_dir}"
    echo "OPENVPN_CCD_DIR=/etc/openvpn/ccd"
    echo "OPENVPN_SUBNET_BASE=${subnet_base}"
    echo "CCD_HELPER=/usr/local/sbin/pivpn-webui-ccd-helper.sh"
    echo "LOG_HELPER=/usr/local/sbin/pivpn-webui-log-helper.sh"
  } > .env
  chmod 600 .env
  unset agent_token
  echo "Wrote .env"
}

install_privileged_helpers() {
  echo
  echo "== Step 3/7: installing privileged helper scripts (requires sudo) =="
  # These run ON THIS BOX — the hub only ever relays a "run this helper"
  # request over the WebSocket; the actual pivpn/iptables calls happen
  # here, same as a standalone install.
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-ccd-helper.sh /usr/local/sbin/pivpn-webui-ccd-helper.sh
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-log-helper.sh /usr/local/sbin/pivpn-webui-log-helper.sh
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-routes-helper.sh /usr/local/sbin/pivpn-webui-routes-helper.sh
  sudo install -m 0750 -o root -g root deploy/pivpn-webui-client-script-helper.sh /usr/local/sbin/pivpn-webui-client-script-helper.sh
}

install_sudoers_grant() {
  echo
  echo "== Step 4/7: sudoers grant (narrower than the standalone/hub one — no Flask/CD on this box) =="
  CURRENT_USER="$(whoami)"
  local sudoers_tmp
  sudoers_tmp="$(mktemp)"
  sed -e "s/__USER__/${CURRENT_USER}/g" deploy/sudoers-pivpn-webui-agent.template > "$sudoers_tmp"
  sudo visudo -cf "$sudoers_tmp"
  sudo install -m 0440 -o root -g root "$sudoers_tmp" /etc/sudoers.d/pivpn-webui-agent
  rm -f "$sudoers_tmp"
}

install_crl_watcher() {
  echo
  echo "== Step 5/7: installing CRL permission watcher =="
  # PiVPN's own removeOVPN.sh does `cp -a .../pki/crl.pem /etc/openvpn/crl.pem`
  # on every revoke (which Renew also triggers, via revoke+reissue) — `-a`
  # preserves Easy-RSA's restrictive 0600 root:root source permissions, which
  # the unprivileged `openvpn` daemon can't read, silently breaking every
  # client's TLS handshake (`VERIFY ERROR: CRL not loaded`) until something
  # re-chmods it. This box is where that file actually lives (the hub never
  # has a local /etc/openvpn/crl.pem at all — see setup.sh's HUB_ONLY_INSTALL
  # handling), so — unlike the standalone/hub setup this was first added
  # to — this belongs here, not there. Missing here meant every hub/agent
  # split deployment had zero protection against this, the same live bug
  # that hit .12 on 2026-08-20 (see the .service file's own comment).
  sudo install -m 0644 deploy/fix-crl-perms.service /etc/systemd/system/fix-crl-perms.service
  sudo install -m 0644 deploy/fix-crl-perms.path /etc/systemd/system/fix-crl-perms.path
  sudo systemctl daemon-reload
  sudo systemctl enable --now fix-crl-perms.path
}

setup_traffic_logging() {
  echo
  echo "== Step 6/7: per-destination traffic logging (Logs page's Traffic tab) =="
  # deploy/setup-traffic-log.sh is written to be run standalone, by hand,
  # any time — real gap this closes: it's easy to forget entirely since
  # nothing else in setup ever mentions it, and the Traffic tab just stays
  # silently empty forever with no error pointing at why. It has its own
  # `set -euo pipefail` and hard-exits if /etc/openvpn/server.conf isn't
  # readable ("is PiVPN installed?") — checked here first instead of just
  # calling it, so a box where PiVPN genuinely isn't installed yet (this
  # script only warns about that, doesn't require it) gets a friendly skip
  # instead of aborting the rest of this setup over it.
  if [[ -r /etc/openvpn/server.conf ]]; then
    sudo ./deploy/setup-traffic-log.sh
    sudo ./deploy/tune-openvpn-liveness.sh
  else
    echo "No /etc/openvpn/server.conf found — skipping (PiVPN doesn't appear to be"
    echo "installed on this box yet). Run 'sudo ./deploy/setup-traffic-log.sh' by hand"
    echo "later once it is, if you want Traffic tab data."
  fi
}

install_agent_service() {
  echo
  echo "== Step 7/7: installing + starting the agent systemd service =="
  local service_tmp
  service_tmp="$(mktemp)"
  sed -e "s/__USER__/${CURRENT_USER}/g" -e "s#__APP_DIR__#${APP_DIR}#g" \
    deploy/pivpn-webui-agent.service.template > "$service_tmp"
  sudo install -m 0644 "$service_tmp" /etc/systemd/system/pivpn-webui-agent.service
  rm -f "$service_tmp"
  sudo systemctl daemon-reload
  sudo systemctl enable --now pivpn-webui-agent
}

print_completion_banner() {
  echo
  echo "======================================================"
  echo " Agent setup complete."
  echo "======================================================"
  echo
  echo "Verify it actually connected:"
  echo "  sudo journalctl -u pivpn-webui-agent -n 20 --no-pager"
  echo "Should show: connected to hub as server #<id>"
  echo
  echo "On the hub, confirm the other side too:"
  echo "  sudo journalctl -u pivpn-webui-hub-gateway -n 20 --no-pager"
  echo "Should show: agent for server #<id> connected"
  echo
  echo "Then log into the hub's web UI and check Clients — it should show"
  echo "this box's real clients within a few seconds."
}

main() {
  require_non_root
  cd "$APP_DIR"

  print_intro
  warn_if_pivpn_missing
  stop_stray_agent_process
  setup_venv
  write_env_config
  install_privileged_helpers
  install_sudoers_grant
  install_crl_watcher
  setup_traffic_logging
  install_agent_service
  print_completion_banner
}

main "$@"
