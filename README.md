# PiVPN Web UI

A small Flask admin panel for a PiVPN (OpenVPN mode) install: create/renew/
remove VPN clients, download their `.ovpn` files, and manage iptables
FORWARD accept/drop rules, DNAT port-forwards, and per-client block/unblock.

## What this actually does

- **Clients** page wraps the `pivpn` CLI:
  - *Add* → `pivpn add nopass -n <name> -d <days>`, or with `-p <pass>`
    instead of `nopass` for a password-protected cert. `-d`/`--days` is
    required for this to be non-interactive — without it, `makeOVPN.sh`
    falls back to a readline prompt for cert lifetime that just hangs under
    a non-interactive process. Defaults to PiVPN's own default (1080 days),
    overridable via `PIVPN_CERT_DAYS`.
  - *Download* → serves the `.ovpn` PiVPN wrote to `PIVPN_OVPN_DIR`.
  - *Renew* → **there is no native OpenVPN "renew" in PiVPN.** This does the
    standard workaround: revoke + reissue under the same name. The old
    `.ovpn` stops working the instant this runs; the client device needs the
    new file.
  - *Remove* → `pivpn revoke -y <name>` (non-interactive; PiVPN's newer
    subcommand is `revoke`, not `remove` — older docs/forks may differ).
  - *Block/Unblock* → inserts/removes a `DROP` rule in the `FORWARD` chain
    matching that client's VPN IP. PiVPN's own `add`/`revoke` scripts already
    pin and clean up a static per-client IP via client-config-dir (ccd) —
    this app only ever *reads* that (`get_client_ip`), it doesn't allocate
    IPs itself. A client only shows as blockable once it has a ccd entry,
    which PiVPN assigns at creation time.

- **Firewall** page manages two independent things, both stored in a local
  SQLite DB so they survive reapplication after reboot or an `iptables -F`:
  - General `FORWARD`-chain rules (protocol/source/dest/port → ACCEPT or DROP).
  - DNAT port-forwards (external port → a VPN client's internal IP:port).
  - "Reapply all" reconciles iptables against the DB (idempotent — safe to
    click repeatedly). "Save for reboot" calls `netfilter-persistent save`,
    which requires `iptables-persistent` to be installed.

- **Logs** page has three tabs:
  - *VPN Sessions* — client connect/disconnect events, best-effort parsed
    from the OpenVPN service journal (`app/vpnlog.py`).
  - *System* — raw tail of the `pivpn-webui` and system journals, for when
    you don't have SSH handy.
  - *User Auth* — login/logout history for the admin account, from the
    same local audit trail as the old single Activity Log (`app/db.py`).
  Sessions and System both read via `pivpn-webui-log-helper.sh`, a second
  narrowly-scoped root helper (see below) — three fixed `journalctl`
  invocations, no caller-supplied arguments.

## ⚠️ Verified against one real install — other PiVPN versions may differ

The `pivpn_ctl.py` invocations (`add`/`revoke`/`list` flags, `pivpn list`'s
Status/Name/Expiration column order, the fact it always emits ANSI color
codes even when stdout isn't a tty, and that its first data row is always
the server's own cert) are confirmed against a real PiVPN OpenVPN install
(Ubuntu 22.04, PiVPN installed 2026-08-17 from github.com/pivpn/pivpn). If
your install is a different fork/vintage and something here doesn't match,
`pivpn -h` / `pivpn add -h` on the box shows the current syntax — only
`app/pivpn_ctl.py` needs to change, everything else (routes, templates,
firewall logic) is independent of it.

## Architecture

- Plain Flask app (`app/`), single hardcoded admin account (`Flask-Login`),
  CSRF protection on all forms (`Flask-WTF`).
- Runs as your normal user (the one that installed PiVPN), **not root** —
  `pivpn` itself refuses to run as root. It does, however, need passwordless
  sudo for its own internal privileged steps, same as it would if you were
  typing commands at an interactive prompt as the default Raspberry Pi OS
  `pi` user (which has NOPASSWD sudo out of the box — that's why PiVPN
  "just works" there and why a generic Debian/Ubuntu install needs an
  explicit grant; see `deploy/sudoers-pivpn-webui.template`). The handful of
  *other* operations that need root (iptables, reading ccd/status files,
  `journalctl`) go through this app's own `sudo -n` calls against the same
  explicit allowlist — see `app/privileged.py`. Nothing is ever
  shell-interpolated; all commands are built as argument lists.
- Firewall/port-forward rules live in `instance/pivpn_webui.db` (SQLite) —
  the DB is the source of truth, iptables is just where it gets applied.

## Setup

On the Pi (or any Debian/Ubuntu box PiVPN is on), as the user that installed
PiVPN. Debian/Ubuntu's base Python doesn't always ship the `venv` module —
if `./setup.sh` fails with "ensurepip is not available", run
`sudo apt install python3-venv` first, then retry:

```bash
cd pivpn-webui
./setup.sh
```

This creates a venv, installs dependencies, generates your admin password
hash and a secret key into `.env`, installs the ccd and log root-helper
scripts to `/usr/local/sbin/`, installs a scoped `/etc/sudoers.d/pivpn-webui`
entry, and installs (but doesn't yet start) a systemd unit.

The log helper (`deploy/pivpn-webui-log-helper.sh`) hardcodes the OpenVPN
systemd unit name (`openvpn@server`) for the Sessions tab — verify it with
`systemctl list-units | grep openvpn` and update+reinstall the script if
your install uses a different unit name.

```bash
sudo systemctl enable --now pivpn-webui
```

By default it binds to `127.0.0.1:8443` only.

## Accessing it remotely

It's bound to localhost on purpose — this panel can revoke certs and edit
your firewall, so it shouldn't be reachable from the internet without more
thought than a weekend project gets. Options, easiest first:

- **SSH tunnel**: `ssh -L 8443:127.0.0.1:8443 pi@yourpi`, then browse to
  `https://127.0.0.1:8443` from your laptop. Simplest, no extra exposure.
- **LAN-only**: set `BIND_HOST=0.0.0.0` in `.env`, restart the service, and
  add a host-firewall rule scoping port `BIND_PORT` to your LAN subnet
  specifically — don't just open the bind address and rely on there being
  no route from further out. Plain traffic, no auth beyond the app's login,
  so only do this on a network you trust:
  ```bash
  sudo iptables -A INPUT -p tcp --dport 8443 -s 192.168.1.0/24 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 8443 -j DROP
  sudo netfilter-persistent save   # survive reboot
  ```
- **Reverse proxy with TLS** in front of it — the real move if this needs to
  be reachable beyond a LAN you already trust. `./deploy/setup-nginx-tls.sh`
  installs nginx if needed, generates a self-signed cert (or leaves an
  existing one at `/etc/nginx/ssl/pivpn-webui.{crt,key}` alone if you
  supplied a real one first), and installs the reverse-proxy vhost. Add its
  own auth layer in front too if you want defense in depth. Caddy is a fine
  alternative if you prefer it, just not what this script automates.
- This app never serves HTTPS itself — anything beyond the SSH-tunnel option
  is sending the login password in plaintext unless you put TLS in front.

## Known limitations / things to check

- Single static admin user — fine for one operator, not built for a team.
- `renew_client` fully revokes before reissuing; if `add_client` then fails
  (e.g. a Pi resource hiccup), the client is left removed with no new cert.
  The UI will show an error — check `pivpn list` to confirm state.
- Per-client block needs a ccd-assigned IP, which PiVPN only writes once a
  client has been through `add`. Clients created before this tool (or before
  PiVPN itself added ccd pinning, if you're on an old version) may show no
  IP and thus no block/unblock option until renewed.
- `add_portforward_rule` opens the DNAT target as ACCEPT in FORWARD for that
  IP:port — it does not also open your router's WAN port; if the Pi isn't
  your edge device, you still need a port-forward on whatever actually faces
  the internet.
- VPN Sessions tab parsing is best-effort: it depends on OpenVPN's log line
  format, which isn't strictly standardized. Unrecognized lines still show
  up (event "other", raw text in Detail) rather than being silently dropped.
- If you installed this app before the Logs page existed, rerun the two
  `sudo install ...pivpn-webui-log-helper.sh...` / sudoers steps from
  `setup.sh` manually, or just rerun `./setup.sh` — it's safe to re-run.
