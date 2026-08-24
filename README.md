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
  - *Block/Unblock* → inserts/removes a `DROP` rule matching that client's
    VPN IP in **both** `FORWARD` (stops it reaching anything past this
    server — LAN, internet) **and** `INPUT` (stops it reaching this server
    itself). Blocking is refused if the client's IP is the same address
    the request is coming from, to avoid cutting off your own access.
    PiVPN's own `add`/`revoke` scripts already pin and clean up a static
    per-client IP via client-config-dir (ccd) — this app only ever *reads*
    that (`get_client_ip`), it doesn't allocate IPs itself. A client only
    shows as blockable once it has a ccd entry, which PiVPN assigns at
    creation time.

- **Firewall** page manages two independent things, both stored in a local
  SQLite DB so they survive reapplication after reboot or an `iptables -F`:
  - General `FORWARD`-chain rules (protocol/source/dest/port → ACCEPT or DROP).
  - DNAT port-forwards (external port → a VPN client's internal IP:port).
  - "Reapply all" reconciles iptables against the DB (idempotent — safe to
    click repeatedly). "Save for reboot" calls `netfilter-persistent save`,
    which requires `iptables-persistent` to be installed.
  - SNAT rules' "Outgoing interface" is a dropdown of the server's real
    network interfaces (`ip -o link show`, loopback excluded), not free
    text — populated live on each page load, so it always reflects
    whatever NICs actually exist on that box.
  - "Import Rules" detects one common mistake: a file in the *Clients*
    page's import format (`name=foo passphrase=bar` per line) uploaded
    here by accident, since both pages phrase their dialog the same way
    ("Import ... from file"). Instead of a generic "Unknown rule kind"
    error per line, it says so directly and points at the Clients page's
    Import Client dialog instead.

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
  The fix service also has `StartLimitIntervalSec=0`: a *bulk* remove (many
  clients in quick succession) re-triggers the watcher once per revoke, and
  without this, systemd's default rate limit (5 starts/10s) would put the
  watcher itself into a permanent `failed` state after ~5 rapid triggers —
  silently leaving the CRL unreadable, breaking every VPN connection
  attempt, until someone runs `systemctl reset-failed` by hand. Hit this
  for real on a 6-client bulk remove; every trigger is just a harmless,
  idempotent `chmod`, so there's no real runaway-restart risk in disabling
  the limit entirely.

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

Run this on the server PiVPN is installed on (Raspberry Pi, Ubuntu, or any
other Debian-based system), **as the user that installed PiVPN — not
root**. Debian/Ubuntu's base Python doesn't always ship the `venv` module —
if `./setup.sh` fails with "ensurepip is not available", run
`sudo apt install python3-venv` first, then retry.

The two sudo password prompts noted below are once per script run (sudo
caches your password for its default ~15 minutes), not once per command.
Zero iptables rules get added until you deliberately visit the Firewall
page in step 7 — everything before that is new files and process startup
only. See [Accessing it remotely](#accessing-it-remotely) and
[First login](#first-login) below for the full detail behind those steps.

**Step 1 — clone the repo** (on the box, as your normal sudo user, not root)

```bash
git clone https://github.com/vannyratanak/pivpn-webui.git
cd pivpn-webui
```

**Step 2 — run setup.sh** `[sudo password: 1x]`

```bash
./setup.sh
```

Creates `venv/`, installs Python deps, prompts for admin username/password
×2/ovpn dir/OpenVPN subnet base, writes `.env` (chmod 600), sudo-installs
the 4 helper scripts + sudoers rule + systemd unit, and installs+starts
the CRL permission watcher (see below) — which starts running immediately,
protecting against a real PiVPN bug even before the webui itself starts.
Touches nothing PiVPN owns otherwise, no iptables, no VPN impact.

Before trusting the Sessions/System log tabs, verify the OpenVPN systemd
unit name matches what's hardcoded in the log helper:

```bash
systemctl list-units | grep openvpn
```

Compare against `OPENVPN_UNIT` in `deploy/pivpn-webui-log-helper.sh`.
Mismatch? Update that one file and reinstall:

```bash
sudo install -m 0750 -o root -g root deploy/pivpn-webui-log-helper.sh /usr/local/sbin/pivpn-webui-log-helper.sh
```

(Client add/remove/renew has the same kind of version caveat — see
"Verified against one real install" above, before this step.)

**Step 3 — start the service**

```bash
sudo systemctl enable --now pivpn-webui
```

gunicorn starts, binds `127.0.0.1:8443` only; creates
`instance/pivpn_webui.db` (empty tables); `sync_all()` runs but the DB is
empty so it does nothing. Still zero iptables rules at this point.

**Step 4 — put nginx + TLS in front of it** `[sudo password: 1x]`

```bash
./setup-nginx.sh
```

Installs nginx via apt if missing, prompts for a server name
(auto-detects your IP as the default), generates a self-signed cert (or
leaves a real one alone), installs the reverse-proxy vhost. Separate port
(443, admin panel) from OpenVPN's own tunnel port — zero effect on
connected VPN clients. Browse to `https://<server-name>/` once it's done.

**Step 5 — log in** with the admin username/password from Step 2.

**Step 6 — visit the Clients page first.** Read-only — runs `pivpn list` +
reads CCD files. Confirms the app sees your real clients correctly;
nothing is written.

**Step 7 — visit the Firewall page, at a quiet moment.**
`discover_cli_rules()` adopts every untagged rule it finds (e.g. PiVPN's
own MASQUERADE/FORWARD rules from the original install): delete → re-add
the same rule, now tagged. Sub-millisecond per rule, OpenVPN daemon never
touched. The table now shows everything found, marked "Unsaved."

**Step 8 — review the table, then click "Save Rules."** Locks the tagged
version in as what survives a reboot (needs `iptables-persistent`
installed).

✅ Fully installed.

Optional, separate from the above: if you want the `git push` → auto-deploy
CD pipeline too (not required for the app to work), see
[CD: deploying code changes to a running server](#cd-deploying-code-changes-to-a-running-server).

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

## Real client IPs behind a relay (optional)

Only relevant if this server's real OpenVPN traffic is relayed through
another box — e.g. because this server can only reach the internet on
TCP/443 and dials out through a public relay that forwards/MASQUERADEs
real VPN clients in. In that setup, every connection this server's own
OpenVPN log sees is stamped with the *relay's* tunnel-facing address
(e.g. `10.66.66.1:<port>`), not the client's real internet address — the
MASQUERADE rule that lets return traffic route back through the tunnel
necessarily relabels it that way. **If you're not relaying traffic through
another box, skip this whole section** — `RELAY_HOST`/`RELAY_TUNNEL_IP`
default to unset, and `resolve_real_address()` in `app/vpnlog.py` returns
`None` immediately without ever touching `ssh`, so Client Sessions behaves
exactly as it always has.

### How it works

The relay's own connection-tracking table (`conntrack`) still remembers
the real `(client IP, client port)` behind each masqueraded connection,
for as long as that connection stays open. This server asks for that
mapping over SSH, using a key that's restricted to running exactly one
lookup script and nothing else — the relay may be a shared box hosting
other, unrelated services, so this is deliberately not full root/shell
access from here.

### One-time setup on the relay

1. Install `conntrack-tools` (`apt install conntrack-tools`) and the
   lookup script at `/usr/local/sbin/vpn-real-ip.sh` (`chmod 755`):

   ```bash
   #!/bin/bash
   set -euo pipefail
   PORT="${1:?usage: $0 <port-from-openvpn-log>}"

   conntrack -L -p udp --dport 1194 2>/dev/null | awk -v want="dport=$PORT" '
     {
       seen = 0
       for (i = 1; i <= NF; i++) {
         if ($i ~ /^dport=/) {
           seen++
           if (seen == 2 && $i == want) {
             gsub(/src=/, "", $4)
             gsub(/sport=/, "", $6)
             print $4":"$6
             found = 1
           }
         }
       }
     }
     END { if (!found) exit 1 }
   '
   ```

   Adjust `--dport 1194` if the relay forwards a different UDP port.

2. Install a forced-command wrapper at
   `/usr/local/sbin/vpn-real-ip-wrapper.sh` (`chmod 755`) — this is the
   actual security boundary the restricted key below relies on, not the
   key itself, so it validates the incoming command tightly rather than
   trusting `authorized_keys` option-globbing:

   ```bash
   #!/bin/bash
   set -euo pipefail
   if [[ "${SSH_ORIGINAL_COMMAND:-}" =~ ^/usr/local/sbin/vpn-real-ip\.sh\ ([0-9]{1,5})$ ]]; then
     exec /usr/local/sbin/vpn-real-ip.sh "${BASH_REMATCH[1]}"
   fi
   echo "rejected: only vpn-real-ip.sh <port> is permitted" >&2
   exit 1
   ```

### One-time setup on this server (the OpenVPN box)

1. Generate a dedicated key — don't reuse the CD deploy key from the
   section below, this one needs different, narrower permissions:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/relay_lookup_key -N '' -C 'thisserver-to-relay-real-ip'
   ```
2. On the relay, add the **public** half to `root`'s `authorized_keys`
   with a forced command pointing at the wrapper above. **The quotes
   around the `command=` value are required** — an unquoted value is
   silently rejected by `sshd` with nothing useful in the log at default
   verbosity (cost real debugging time to track down once already):
   ```
   command="/usr/local/sbin/vpn-real-ip-wrapper.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... thisserver-to-relay-real-ip
   ```
3. `resolve_real_address()` calls plain `ssh user@host script port` with
   no `-i` flag, so point it at the right key via `~/.ssh/config`, set up
   as the same user the `pivpn-webui` service runs as (check `User=` in
   `/etc/systemd/system/pivpn-webui.service`):
   ```
   Host <relay's public IP>
     User root
     IdentityFile ~/.ssh/relay_lookup_key
     IdentitiesOnly yes
     StrictHostKeyChecking accept-new
   ```
4. Add to `.env` and restart the service:
   ```
   RELAY_HOST=<relay's public IP>
   RELAY_TUNNEL_IP=<relay's tunnel-facing IP, e.g. 10.66.66.1>
   RELAY_SSH_USER=root
   ```
   (`RELAY_LOOKUP_SCRIPT` only needs setting if the script isn't at the
   default `/usr/local/sbin/vpn-real-ip.sh`.)
5. Verify: with a client actually connected, note its port from
   `sudo cat /var/log/openvpn-status.log`, then from this server run:
   ```bash
   ssh root@<relay's public IP> /usr/local/sbin/vpn-real-ip.sh <port>
   ```
   It should print `real.ip.address:port`. If it does, the Client
   Sessions tab will show it too — but only for sessions still ongoing;
   `conntrack` forgets the mapping the moment a client disconnects, so an
   already-ended session always falls back to showing the relayed
   address, same as before this feature existed.

## CD: deploying code changes to a running server

This repo is public and its `Deploy` workflow runs on a **self-hosted**
runner (has to — the deploy targets are private-network addresses no
GitHub-hosted runner can reach). That combination is normally the classic
"fork a public repo, open a PR, get code execution on someone's runner"
risk — it doesn't apply here because `deploy.yml`'s only trigger is
`workflow_dispatch`, which requires the invoker to already have write
access to the repo; a stranger's fork PR can't make it run. Fork PR
workflows are also disabled repo-wide as a second, independent layer
(Settings → Actions → General → "Run workflows from fork pull requests"),
so even a future workflow added with a `pull_request` trigger by mistake
wouldn't run from a fork without that box being checked first. Deploy
targets and the SSH username live in GitHub secrets
(`DEPLOY_TARGET_1`/`_2`/...), not hardcoded in the workflow file, so
nothing about the network layout is visible to a public reader either.

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
3. Add a new GitHub Actions secret for this server (`gh secret set
   DEPLOY_TARGET_3 --body "vpn@<its IP>"` — same `user@host` format as
   the existing `DEPLOY_TARGET_1`/`_2`, keeps real IPs and usernames out
   of the workflow file itself, so `deploy.yml` stays safe to read in a
   public repo). Then add a matching `- name: Deploy to target 3` step to
   `.github/workflows/deploy.yml`, copying an existing step's pattern
   (same deploy key, `${{ secrets.DEPLOY_TARGET_3 }}` for the host).
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
- Login is rate-limited (5 failed attempts / 5 minutes, per source IP —
  see `app/db.py`'s `login_failures` table) and sessions expire after
  `SESSION_LIFETIME_HOURS` (default 8) of inactivity — a sliding window,
  renewed on every request, not a fixed timer from login time. Both exist
  because a relay setup (see below) can put the login page on the public
  internet; tune `SESSION_LIFETIME_HOURS` in `.env` if 8 hours doesn't
  match how this install is actually used.
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
