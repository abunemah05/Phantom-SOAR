# Phantom SOAR response scripts for Wazuh

Phantom SOAR carries out response actions by calling the Wazuh manager API
(`PUT /active-response`). Wazuh only ships `firewall-drop` and a few other stock scripts, so the
actions below need the scripts in this folder on every agent you want to respond on.

| Phantom action | Wazuh command (script) | Reversible by | Linux | Windows |
|---|---|---|---|---|
| isolate_endpoint | `phantom-isolate-host` | `phantom-unisolate-host` | nftables | Windows Firewall |
| unisolate_endpoint | `phantom-unisolate-host` | | yes | yes |
| block_ip | `phantom-block-ip` IP HOURS DIRECTION | `phantom-unblock-ip`, or expires after HOURS | nftables set with per-element timeout | firewall rules + one-shot scheduled task |
| unblock_ip | `phantom-unblock-ip` IP | | yes | yes |
| apply_rate_limit | `phantom-rate-limit` IP RATE HOURS | `phantom-unblock-ip`, or expires | nftables `limit rate` rule | **not supported** (logged, refused) |
| terminate_process | `phantom-kill-process` NAME [PID] | not reversible | yes | yes |
| quarantine_file | `phantom-quarantine-file` PATH [HASH] | `phantom-ar restore ID` (Linux), manual move (Windows) | yes | yes |

Requirements: Wazuh manager and agents **4.2.0 or newer** (older agents get a legacy text message, not JSON);
Linux agents need `python3` and `nft`; Windows agents need PowerShell 5.1.

## Safety rules built into the scripts

* Input comes only from the `extra_args` of the Wazuh message, is validated strictly (IP parsing, whitelisted
  characters, length limits) and is never passed to a shell. Alert contents are ignored.
* `block-ip`, `rate-limit` and `isolate-host` refuse to touch: the Wazuh manager (read from the agent's
  `ossec.conf`), loopback, link-local, multicast, the host's own addresses and anything in the allow-list file.
  `isolate-host` refuses to run if it cannot find the manager address (it would cut the agent off) and always
  keeps the manager and the allow-list reachable.
* `kill-process` refuses protected processes (init/systemd, sshd, the Wazuh agent, lsass...), verifies that a PID
  still belongs to the named process, and refuses to kill more than 10 matches.
* `quarantine-file` refuses system paths and symlinks, verifies an optional hash first and keeps the file
  (mode 000, root-only directory) with metadata so it can be restored.
* Every decision is logged to the agent's `active-responses.log`
  (Linux `/var/ossec/logs/active-responses.log`, Windows `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`).
* The Phantom connector never sends a request without `agents_list` (an empty list would target every agent) and
  refuses agent `000` (the manager).

## Install

### 1. Allow-list (do this first)
Copy `phantom-allowlist.example.txt` to `/var/ossec/etc/phantom-allowlist.txt` (Windows:
`C:\Program Files (x86)\ossec-agent\phantom-allowlist.txt`) and list everything that must never be cut off: your
admin jump host/VPN, DNS, domain controllers, gateways, the SOAR server. The installers create it from the example.

### 2. Linux agents (as root)
```
cd wazuh/linux && sudo ./install-linux.sh
```
This installs `phantom-ar` as `/var/ossec/active-response/bin/phantom-<action>` (root:wazuh, mode 750).
No restart is needed: Wazuh starts the script for each request.

### 3. Windows agents (elevated PowerShell)
```
cd wazuh\windows ; .\install-windows.ps1
```
Installs `phantom-ar.ps1` plus a `phantom-<action>.cmd` launcher per action. Windows launchers must carry
the `.cmd` extension in the request, so add each Windows agent id to the Phantom setting
`wazuh_windows_agent_ids` (comma separated, e.g. `007,012`); Phantom then sends `!phantom-block-ip.cmd` to them.

### 4. Manager
Nothing is required with the default `wazuh_ar_script_prefix=true`: Phantom sends `!phantom-<action>`, which
the manager forwards to the named script. Only if you disable the prefix, add
`ossec-manager-snippets.xml` to the manager's `ossec.conf` (details inside the file).
Create a Wazuh API user for Phantom with the `active-response:command` action on `agent:id:*` (RBAC), and set in
Phantom: `siem_manager_url` (`https://manager:55000`), `siem_user`, `siem_password`.
For TLS use `wazuh_ca_bundle` (path to the PEM CA that signed the manager's API certificate) rather than
turning `siem_verify_tls` off.

## Safe first test (nothing production-facing)

1. Use a lab VM agent, with simulation still ON in Phantom and `hotl_enabled` true.
2. On the agent, dry-run the script (logs the commands, changes nothing):
   ```
   echo '{"command":"add","parameters":{"extra_args":["198.51.100.7","1","inbound"]}}' \
     | sudo PHANTOM_AR_DRY_RUN=1 /var/ossec/active-response/bin/phantom-block-ip; echo "exit $?"
   sudo tail -n 3 /var/ossec/logs/active-responses.log
   ```
3. Real block of a documentation address, then check and remove it:
   ```
   echo '{"command":"add","parameters":{"extra_args":["198.51.100.7","1","inbound"]}}' | sudo /var/ossec/active-response/bin/phantom-block-ip
   sudo nft list set inet phantom block4_in      # shows the IP with 'expires 59m...'
   echo '{"command":"add","parameters":{"extra_args":["198.51.100.7"]}}' | sudo /var/ossec/active-response/bin/phantom-unblock-ip
   ```
4. Prove the protections: blocking `127.0.0.1`, an allow-listed IP or your manager's IP must log `refused`.
5. Through the manager, with curl (replace TOKEN; get it with `POST /security/user/authenticate`):
   ```
   curl -sk -X PUT "https://MANAGER:55000/active-response?agents_list=AGENT_ID" \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"command":"!phantom-block-ip","arguments":["198.51.100.7","1","inbound"],"alert":{"data":{"srcip":"198.51.100.7"}}}'
   ```
   Expect `affected_items: ["AGENT_ID"]` and the log line on the agent.
6. Only then, in Phantom, configure the Wazuh settings, keep `simulation_mode` as is, and run one playbook
   action manually against the lab agent. Do isolation last, and only after the allow-list holds your own access.

### Testing a script without a manager
Use `PHANTOM_AR_DRY_RUN=1` plus the path overrides, all on an ordinary user account:
```
export PHANTOM_AR_DRY_RUN=1 PHANTOM_AR_LOG=/tmp/ar.log PHANTOM_AR_STATE_DIR=/tmp/ar-state \
       PHANTOM_AR_OSSEC_DIR=/tmp/ossec PHANTOM_AR_MANAGER_IPS=203.0.113.9
cp wazuh/linux/phantom-ar /tmp/phantom-block-ip
echo '{"command":"add","parameters":{"extra_args":["203.0.113.9"]}}' | python3 /tmp/phantom-block-ip   # refused: manager
```
Windows: `$env:PHANTOM_AR_DRY_RUN='1'; '{"command":"add","parameters":{"extra_args":["198.51.100.7"]}}' | .\phantom-ar.cmd`
(rename a copy to `phantom-block-ip.cmd` first). The automated tests are in `backend/tests/test_ws3_*.py`.

## Notes and limits
* Timed blocks use nftables element timeouts on Linux (removed by the kernel). nftables rules are not persistent
  across a reboot, so blocks and isolation end when the host restarts; rate limits use a state file plus a
  detached expirer and a sweep on every later request.
* Windows blocks expire through a one-shot SYSTEM scheduled task named `phantom-expire-<ip>`.
* Wazuh's stock `firewall-drop` ignores arguments, and commands sent with `!` get no Wazuh timeout, so Phantom
  uses `phantom-block-ip`. If you set `wazuh_ar_block_command=firewall-drop` the duration/direction are not honoured and the
  action result says so.
* The Windows script could not be executed in the development environment (no PowerShell); run the dry-run test
  above on a lab Windows agent before relying on it.
