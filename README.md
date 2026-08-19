# PiVPN Web UI

A small Flask admin panel for a PiVPN (OpenVPN mode) install: create/renew/
remove VPN clients, download their `.ovpn` files, per-client block/unblock,
manage iptables FORWARD rules and DNAT port-forwards, control what
destinations get routed into the tunnel, and view VPN/system/auth logs.
Ships with a manual-trigger CD pipeline (`git push` → `Deploy` button →
live on the server) for keeping a running install in sync with this repo.

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

- **VPN Routes** page manages `push "route ..."` lines in `server.conf` —
  what destinations get routed into the tunnel at all for every client
  (separate from the Firewall page's NAT/SNAT rules, which handle the
  return path once traffic arrives). Only ever adds/removes lines it
  tagged itself (`# pivpn-webui-route` marker) via
  `pivpn-webui-routes-helper.sh`; a route already in `server.conf` before
  the app touched it (e.g. added by hand) shows up read-only, tagged
  "unmanaged" — the page reflects `server.conf`'s real state either way,
  it just can't remove what it can't prove it created. Adding a route
  restarts the OpenVPN service to push it to clients.

- **Logs** page has four tabs:
  - *VPN Sessions* — raw client connect/disconnect events, best-effort
    parsed from the OpenVPN service journal (`app/vpnlog.py`).
  - *Client Sessions* — the same connect/disconnect events paired into
    per-client session records (when, how long, how many) instead of a raw
    event stream. A session still in progress shows "ongoing" with no end
    time yet.
  - *System* — raw tail of the `pivpn-webui` and system journals, for when
    you don't have SSH handy.
  - *User Auth* — login/logout history for the admin account, from the
    same local audit trail as the old single Activity Log (`app/db.py`).
  Sessions and System both read via `pivpn-webui-log-helper.sh`, a second
  narrowly-scoped root helper (see below) — three fixed `journalctl`
  invocations, no caller-supplied arguments.

- **CRL permission watcher** (`fix-crl-perms.path`/`.service`, installed by
  `setup.sh`, running independently of the webui itself) — works around a
  real bug in PiVPN's own `removeOVPN.sh`: it regenerates
  `/etc/openvpn/crl.pem` via `cp -a`, which preserves Easy-RSA's restrictive
  `0600 root:root` source permissions. The unprivileged `openvpn` daemon
  can't read that, so every `pivpn revoke` (which *Renew* also triggers,
  via revoke+reissue) silently breaks **every** client's TLS handshake
  (`VERIFY ERROR: CRL not loaded`) until something re-`chmod`s the file. A
  `systemd` path unit watches `/etc/openvpn/crl.pem` and fixes it within
  about a second of any change, regardless of what triggered it (this app,
  raw CLI, cron) — see [Known limitations](#known-limitations--things-to-check)
  for the one thing to verify before trusting it on a different install.

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

## Complete setup, start to finish

The two sudo password prompts noted below are once per script run (sudo
caches your password for its default ~15 minutes), not once per command.
Zero iptables rules get added until you deliberately visit the Firewall
page in step 6 — everything before that is new files and process startup
only. See [Setup](#setup), [Accessing it remotely](#accessing-it-remotely),
and [First login](#first-login) below for the full detail behind each step.

```
┌────────────────────────────────────────────────────────────────┐
│  On the box, as your normal sudo user (not root)                │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        git clone https://github.com/vannyratanak/pivpn-webui.git
        cd pivpn-webui
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 1 — ./setup.sh                        [sudo password: 1x]  │
├────────────────────────────────────────────────────────────────┤
│ • creates venv/, installs Python deps                          │
│ • prompts: admin username, admin password ×2, ovpn dir,        │
│   OpenVPN subnet base                                          │
│ • writes .env (chmod 600) — secrets, paths, helper locations   │
│ • sudo installs 4 helper scripts → /usr/local/sbin/             │
│ • sudo installs sudoers rule (visudo -cf validated first)      │
│ • sudo installs systemd unit + daemon-reload                   │
│ • sudo installs + starts a CRL permission watcher (see below)  │
│ • creates empty instance/ dir                                  │
│                                                                  │
│ Touches nothing PiVPN owns, no iptables, no VPN impact — except │
│ the CRL watcher, which starts running immediately (protects     │
│ against a real PiVPN bug even before the webui itself starts).  │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 2 — sudo systemctl enable --now pivpn-webui                │
├────────────────────────────────────────────────────────────────┤
│ • gunicorn starts, binds 127.0.0.1:8443 only                   │
│ • creates instance/pivpn_webui.db (empty tables)                │
│ • sync_all() runs → loops over DB rules → DB is empty →         │
│   does nothing                                                 │
│                                                                  │
│ Still zero iptables rules — nothing in the DB yet to sync.      │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 3 — ./setup-nginx.sh                  [sudo password: 1x]  │
├────────────────────────────────────────────────────────────────┤
│ • installs nginx via apt if missing                             │
│ • prompts for server name (auto-detects your IP as default)    │
│ • generates a self-signed cert (or leaves a real one alone)    │
│ • installs the reverse-proxy vhost → nginx -t → reload          │
│                                                                  │
│ Separate port (443, admin panel) from OpenVPN's tunnel port —  │
│ zero effect on connected VPN clients.                          │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                  https://<server-name>/
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 4 — Log in with the credentials from Step 1                │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 5 — Visit Clients page first                                │
├────────────────────────────────────────────────────────────────┤
│ Read-only — runs `pivpn list` + reads CCD files. Confirms the  │
│ app sees your real clients correctly. Nothing is written.      │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 6 — Visit Firewall page (pick a quiet moment)               │
├────────────────────────────────────────────────────────────────┤
│ discover_cli_rules() adopts every untagged rule it finds        │
│ (e.g. PiVPN's own MASQUERADE/FORWARD rules from original        │
│ install): delete → re-add same rule, now tagged.                │
│ Sub-millisecond per rule. OpenVPN daemon never touched —        │
│ tunnel sessions unaffected.                                     │
│                                                                  │
│ Table now shows everything found, marked "Unsaved."             │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 7 — Review the table, then click "Save Rules"               │
├────────────────────────────────────────────────────────────────┤
│ Locks the tagged version in as what survives a reboot           │
│ (needs iptables-persistent installed for this to work).         │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                     ✅  Fully installed
```

Optional, separate from the above: if you want the `git push` → auto-deploy
CD pipeline too (not required for the app to work), see
[CD: deploying code changes to a running server](#cd-deploying-code-changes-to-a-running-server).

## Setup

On the server PiVPN is installed on (Raspberry Pi, Ubuntu, or any other
Debian-based system), as the user that installed PiVPN — not root.
Debian/Ubuntu's base Python doesn't always ship the `venv` module — if
`./setup.sh` fails with "ensurepip is not available", run
`sudo apt install python3-venv` first, then retry:

```bash
git clone https://github.com/vannyratanak/pivpn-webui.git
cd pivpn-webui
./setup.sh
```

`setup.sh` will prompt you for an admin username/password and a couple of
paths (defaults are usually fine), then it creates a venv, installs
dependencies, generates your admin password hash and a secret key into
`.env`, installs all four root-helper scripts to `/usr/local/sbin/`,
installs a scoped `/etc/sudoers.d/pivpn-webui` entry, and installs (but
doesn't yet start) a systemd unit.

The log helper (`deploy/pivpn-webui-log-helper.sh`) hardcodes the OpenVPN
systemd unit name (`openvpn@server`) for the Sessions tab — verify it with
`systemctl list-units | grep openvpn` and update+reinstall the script if
your install uses a different unit name. Same caution applies to the
`pivpn` CLI flags `app/pivpn_ctl.py` assumes — run `pivpn -h && pivpn add -h`
and compare before relying on client add/remove/renew.

```bash
sudo systemctl enable --now pivpn-webui
```

By default it binds to `127.0.0.1:8443` only — see
[Accessing it remotely](#accessing-it-remotely) below (`./setup-nginx.sh`
is the quickest path to real browser access with TLS).

## Accessing it remotely

It's bound to localhost on purpose — this panel can revoke certs and edit
your firewall, so it shouldn't be reachable from the internet without more
thought than a weekend project gets. Options, easiest first:

- **SSH tunnel**: `ssh -L 8443:127.0.0.1:8443 youruser@yourserver`, then
  browse to `https://127.0.0.1:8443` from your laptop. Simplest, no extra
  exposure.
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
  be reachable beyond a LAN you already trust. `./setup-nginx.sh`
  installs nginx if needed, generates a self-signed cert (or leaves an
  existing one at `/etc/nginx/ssl/pivpn-webui.{crt,key}` alone if you
  supplied a real one first), and installs the reverse-proxy vhost. Add its
  own auth layer in front too if you want defense in depth. Caddy is a fine
  alternative if you prefer it, just not what this script automates.
- This app never serves HTTPS itself — anything beyond the SSH-tunnel option
  is sending the login password in plaintext unless you put TLS in front.

## CD: deploying code changes to a running server

`.github/workflows/deploy.yml` is a **manual-trigger only** workflow
(`workflow_dispatch` — nothing runs automatically on push, only `CI`/tests
do). Running it from GitHub Actions SSHes into each configured server with
a dedicated deploy key; each server's `authorized_keys` entry has a
**forced command** on that key, so whatever the workflow actually sends is
ignored — the server always runs exactly this, regardless:

```
cd <app dir> && git pull \
  && sudo -n install -m 0750 -o root -g root deploy/pivpn-webui-ccd-helper.sh /usr/local/sbin/pivpn-webui-ccd-helper.sh \
  && sudo -n install -m 0750 -o root -g root deploy/pivpn-webui-log-helper.sh /usr/local/sbin/pivpn-webui-log-helper.sh \
  && sudo -n install -m 0750 -o root -g root deploy/pivpn-webui-routes-helper.sh /usr/local/sbin/pivpn-webui-routes-helper.sh \
  && sudo -n install -m 0750 -o root -g root deploy/pivpn-webui-client-script-helper.sh /usr/local/sbin/pivpn-webui-client-script-helper.sh \
  && sudo -n systemctl restart pivpn-webui
```

**Why the reinstall steps matter**: `git pull` alone only updates files
inside the repo checkout. It does **not** touch `/usr/local/sbin/` —
only `setup.sh` (or this forced command) does that. A change to any of the
4 privileged helper scripts would silently never take effect through
Deploy without this — the workflow would report success while the live
server kept running the old script. Hit this for real once; it's why the
reinstall steps exist.

### Adding a new server to this pipeline

1. `./setup.sh` on the server as usual — the sudoers grants for the
   `sudo -n install ...` calls above are included automatically (they
   need `__APP_DIR__` substituted to that server's real checkout path,
   which `setup.sh` now does).
2. `./setup-cd-deploy.sh` — installs the forced-command deploy key.
   Prompts for the public key; use the same one already on other servers
   (`grep -oP 'ssh-ed25519 \S+ github-actions-deploy@pivpn-webui'
   ~/.ssh/authorized_keys` on an existing server) so one GitHub secret
   covers every server. **Not idempotent for updates** — if a server
   already has this key installed, the script detects the exact key
   string and skips, even if the forced command itself should change
   (e.g. after a future edit to the reinstall-steps list above). Remove
   the old `authorized_keys` line by hand first if the command itself
   needs to change on an already-configured server.
3. Add a matching `- name: Deploy to <ip>` step to `.github/workflows/deploy.yml`,
   copying an existing step's pattern (same deploy key, different host).
4. Before trusting the button: manually run the exact forced-command
   sequence over SSH once (steps 1-2 above, pasted directly) — this is
   the one thing worth verifying by hand rather than assuming, since a
   path mismatch between the sudoers grant and the forced command fails
   silently as "needs a password" rather than a clear error.

## First login

1. Log in with the admin username/password you set during `./setup.sh`.
2. **Visit Clients first.** It's read-only — just `pivpn list` plus a CCD
   read — a safe first check that the app can see your real clients before
   you touch anything that writes.
3. **Visit Firewall next, at a quiet moment rather than peak VPN usage.**
   The first time this page loads, it scans your live iptables (`FORWARD`,
   `INPUT`, and the `nat` table's `PREROUTING`/`POSTROUTING` chains) for any
   rule that isn't already tagged `pivpn-webui:<id>` — on a box that's never
   run this app before, that includes whatever PiVPN's own installer set up
   (its `MASQUERADE`/`FORWARD` rules) plus anything added by hand over the
   years. Each one gets adopted: recorded into the app's database, then
   deleted and immediately re-added with the same match and action, just
   now tagged. It's a live iptables write, but a same-rule swap, not a
   behavior change — the OpenVPN daemon itself is never touched or
   restarted, so connected clients' tunnels aren't affected. A rule shape
   the parser doesn't recognize (`REJECT`, `LOG`, an unusual multi-match
   rule) is left alone entirely — it keeps working, it just never shows up
   in this app's table.
4. **Review the Active Rules table against what you expect to be there,
   then click "Save Rules."** Everything just discovered shows as
   "Unsaved" until you do — that button persists the newly-tagged version
   into the reboot-survival snapshot (`netfilter-persistent save`, so
   `iptables-persistent` needs to be installed). Skip this and a reboot
   brings back the original untagged rules, which just get rediscovered
   (and re-tagged with fresh IDs) the next time you visit.

## Known limitations / things to check

- Single static admin user — fine for one operator, not built for a team.
- `renew_client` fully revokes before reissuing; if `add_client` then fails
  (e.g. a server resource hiccup), the client is left removed with no new
  cert.
  The UI will show an error — check `pivpn list` to confirm state.
- Per-client block needs a ccd-assigned IP, which PiVPN only writes once a
  client has been through `add`. Clients created before this tool (or before
  PiVPN itself added ccd pinning, if you're on an old version) may show no
  IP and thus no block/unblock option until renewed.
- `add_portforward_rule` opens the DNAT target as ACCEPT in FORWARD for that
  IP:port — it does not also open your router's WAN port; if this server
  isn't your edge device, you still need a port-forward on whatever
  actually faces the internet.
- VPN Sessions tab parsing is best-effort: it depends on OpenVPN's log line
  format, which isn't strictly standardized. Unrecognized lines still show
  up (event "other", raw text in Detail) rather than being silently dropped.
  Client Sessions pairs the same parsed events, so it inherits the same
  fragility — a missed connect/disconnect line there shows as a session
  with no matching end (or start) rather than a wrong duration.
- If you installed this app before the Logs page existed, rerun the two
  `sudo install ...pivpn-webui-log-helper.sh...` / sudoers steps from
  `setup.sh` manually, or just rerun `./setup.sh` — it's safe to re-run.
- The CRL permission watcher assumes PiVPN's default `crl-verify` path,
  `/etc/openvpn/crl.pem` — check `crl-verify` in `/etc/openvpn/server.conf`
  matches on your install; if it doesn't, update `PathModified` in
  `deploy/fix-crl-perms.path` and reinstall
  (`sudo install -m 0644 deploy/fix-crl-perms.path
  /etc/systemd/system/fix-crl-perms.path && sudo systemctl daemon-reload
  && sudo systemctl restart fix-crl-perms.path`).
