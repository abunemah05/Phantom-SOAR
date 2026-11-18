#!/bin/sh
# Install the Phantom SOAR active-response scripts on a Linux Wazuh agent. Run as root from this directory.
set -eu
BIN=/var/ossec/active-response/bin
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -d "$BIN" ] || { echo "$BIN not found: is the Wazuh agent installed?" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v nft >/dev/null || { echo "nftables (nft) is required" >&2; exit 1; }
for name in isolate-host unisolate-host block-ip unblock-ip rate-limit kill-process quarantine-file; do
  install -o root -g wazuh -m 0750 "$(dirname "$0")/phantom-ar" "$BIN/phantom-$name"
done
install -o root -g wazuh -m 0750 "$(dirname "$0")/phantom-ar" "$BIN/phantom-ar"
if [ ! -e /var/ossec/etc/phantom-allowlist.txt ]; then
  install -o root -g wazuh -m 0640 "$(dirname "$0")/../phantom-allowlist.example.txt" /var/ossec/etc/phantom-allowlist.txt
  echo "Created /var/ossec/etc/phantom-allowlist.txt from the example: EDIT IT before enabling live response."
fi
echo "Installed. Test with: wazuh/README.md section 'Safe first test'."
