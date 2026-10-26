#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y bubblewrap socat apparmor ripgrep

# Ubuntu 24.04 restricts user namespaces. Grant them only to bubblewrap, as in
# https://code.claude.com/docs/en/sandboxing#setup-linux-and-wsl2.
sudo tee /etc/apparmor.d/bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
PROFILE
sudo apparmor_parser -r /etc/apparmor.d/bwrap

npm install --global @anthropic-ai/claude-code@2.1.310
