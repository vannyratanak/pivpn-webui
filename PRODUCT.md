# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary user: a PiVPN (OpenVPN) operator who already has PiVPN installed
via SSH/CLI on their own server and wants a web UI for the routine,
repeated work — adding/revoking clients, adjusting firewall rules,
checking who's connected — without a fresh SSH session every time.

Built for adoption beyond the original author's own servers: the public
repo, the generic "adding a new server to this pipeline" instructions,
and the explicit PiVPN-version-compatibility caveat in the README all
reflect real intent for other PiVPN admins to deploy this themselves, not
just documentation of one person's private setup.

## Product Purpose

A self-hosted web admin panel that wraps the real `pivpn` CLI and the
server's actual live `iptables` state directly — not a reimplementation
or a separate managed abstraction — giving one place to manage VPN
clients, firewall/NAT rules, pushed routes, and logs. Success means an
operator can do a day's routine PiVPN admin entirely through the browser,
falling back to SSH only for genuinely unusual situations.

## Positioning

Stays truthful to whatever is actually running on the box, including
rules a human wrote by hand with `iptables` before this tool ever existed
— it discovers and adopts those into its own tracked state instead of
requiring a clean-slate install or ignoring them. Ships a safety guard
most simple iptables-wrapper UIs don't have: firewall changes are
simulated against the live rule set before being applied, and any change
that would lock the admin's own connection out is refused outright,
before it happens. No separate database server or background agent
process — SQLite plus a handful of narrowly-scoped, sudoers-gated root
helper scripts, installable on the exact box PiVPN already runs on.

## Operating Context

Runs directly on the same Debian/Raspbian box PiVPN is installed on
(gunicorn app + nginx reverse proxy, both systemd services). Bound to
localhost by default — reaching it remotely (SSH tunnel, a LAN-scoped
firewall rule, or a reverse proxy with real TLS) is a deliberate choice
the operator makes, never a default. A single operator per install, not
a multi-user team tool. An optional CD pipeline (GitHub Actions,
manual-trigger only) can push code updates to already-deployed servers
via a forced-command-restricted SSH key.

## Capabilities and Constraints

- **Clients**: add (optional passphrase), download `.ovpn`, "renew"
  (revoke + reissue under the same name — PiVPN has no native renew),
  remove, and per-client block (both directions: stop it reaching past
  the server, and stop it reaching the server itself).
- **Firewall**: general FORWARD/INPUT accept-or-drop rules, DNAT
  port-forwards, SNAT/MASQUERADE, all tracked in a local DB with explicit
  position ordering so the live `iptables` order always matches intent;
  auto-discovers and adopts any matching rule already live on the box.
- **VPN Routes**: view, push, and remove routes pushed to clients,
  including ones a previous admin added by hand.
- **Logs**: VPN session history, the web UI's own service log, the
  system journal, and a login audit log.
- **Constraint (explicit)**: verified against one real PiVPN install —
  other PiVPN versions or OpenVPN configs may name services/scripts
  differently; the app prints reminders to verify assumptions like the
  OpenVPN systemd unit name on a new box rather than assuming they hold.
- **Constraint**: single static admin user, not built for a team.
- **Constraint**: never terminates TLS itself — a reverse proxy or SSH
  tunnel must sit in front of it for any real remote access.

## Brand Commitments

Name is "PiVPN Web UI" — plain and functional, no separate visual brand
or logo. Dark theme is the default; a light theme is available via a
persisted toggle.

## Evidence on Hand

Deployed against and exercised on real, active PiVPN installs — real
client add/revoke/renew cycles, real firewall-rule adoption from
pre-existing hand-written `iptables` rules, and a working CD pipeline
pushing to already-deployed servers. Specific server addresses and
network topology are operational detail, intentionally not recorded
here.

## Product Principles

1. Stay truthful to the live box, never a separate abstraction — read
   and write the real `pivpn` CLI and real `iptables` state directly, and
   adopt whatever's already there rather than requiring a clean slate.
2. Guard against irreversible mistakes before they happen, not after —
   simulate a firewall change's effect and refuse one that would lock the
   admin out, rather than relying on the admin catching it themselves.
3. No default expansion of attack surface — localhost by default, a
   single static admin, and every privileged operation goes through a
   narrowly-scoped, sudoers-gated helper script rather than a broad root
   shell.
4. Assume the reader already knows OpenVPN/iptables — show the real
   commands and real values (actual IPs, actual `iptables` flags) rather
   than paraphrasing them away.

## Accessibility & Inclusion

WCAG AA is a maintained target for the web UI: both themes are
contrast-checked, interactive elements are keyboard-operable (including
giving a keyboard equivalent to drag-and-drop-style features, not just a
mouse path), and `prefers-reduced-motion` is respected.
