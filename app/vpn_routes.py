"""Manages `push "route ..."` lines in the production OpenVPN server config
(server.conf), via pivpn-webui-routes-helper.sh — see that script for the
actual privileged file edit + service restart.

Deliberately not stored in sqlite like firewall.py's rules: server.conf
itself is already the single source of truth for what's pushed to clients,
so there's nothing to keep in sync — list_routes() just reads it live.
"""
import ipaddress

import config
from app.privileged import PrivilegedCommandError, run_root


class VpnRouteError(RuntimeError):
    pass


def _valid_network(network, netmask):
    try:
        ipaddress.ip_address(network)
        ipaddress.ip_address(netmask)
        ipaddress.IPv4Network(f"{network}/{netmask}")
    except ValueError as exc:
        raise VpnRouteError(f"Invalid network/netmask: {network}/{netmask}") from exc


def list_routes() -> list[dict]:
    try:
        out = run_root([config.ROUTES_HELPER, "list"])
    except PrivilegedCommandError as exc:
        raise VpnRouteError(str(exc)) from exc
    routes = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        network, _, netmask = line.partition(" ")
        routes.append({"network": network, "netmask": netmask})
    return routes


def add_route(network: str, netmask: str):
    _valid_network(network, netmask)
    try:
        run_root([config.ROUTES_HELPER, "add", network, netmask])
    except PrivilegedCommandError as exc:
        raise VpnRouteError(str(exc)) from exc


def remove_route(network: str, netmask: str):
    _valid_network(network, netmask)
    try:
        run_root([config.ROUTES_HELPER, "remove", network, netmask])
    except PrivilegedCommandError as exc:
        raise VpnRouteError(str(exc)) from exc
