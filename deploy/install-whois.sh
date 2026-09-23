#!/usr/bin/env bash
# Organization lookups run in the WebUI process. Install WHOIS on the
# application host (standalone server or hub); remote agents only provide
# flow logs and do not need the client.
set -euo pipefail

if command -v whois >/dev/null 2>&1; then
  echo "WHOIS is already installed."
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "Cannot install WHOIS automatically: apt-get is unavailable." >&2
  exit 1
fi

echo "Installing whois for Traffic organization lookups..."
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y whois
