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

Requirements: Wazuh manager and agents **4.2.0 or newer** (older agents get a legacy text message, not JSON; checked
against the 4.2 to 4.14 sources, nothing here was run against 5.x); Linux agents need `python3` and `nft`; Windows
agents need PowerShell 5.1. Active response must be enabled on the agent (it is by default; if the agent's
`ossec.conf` has `<active-response><disabled>yes</disabled>` the API answers error 1750) and the agent must be
`active` (error 1707).

## The request Phantom sends

```
POST /security/user/authenticate            (HTTP Basic; the JWT in {"data":{"token":...}} is cached until ~60 s before it expires)
PUT  /active-response?agents_list=004       (Authorization: Bearer <jwt>, Content-Type: application/json)
{"command": "!phantom-block-ip", "arguments": ["198.51.100.7", "24", "inbound"], "alert": {"data": {"srcip": "198.51.100.7"}}}
```

* `agents_list` is a comma-separated list of agent ids (`004,007`). Leaving it out targets **all** agents, so Phantom
  never omits it and never sends `000` (the manager).
* `command` starting with `!` means "script name in the agent's `active-response/bin`" (official API reference,
  <https://documentation.wazuh.com/current/user-manual/api/reference.html>, Active-response > Run command). Without
  `!` the manager only accepts names listed in its `ar.conf` (`<command name><timeout>`, e.g. `firewall-drop600`).
* There is **no `"custom": true`** field. Managers 4.2 to 4.7 had it, but it only mattered for agents older than 4.2.0;
  from 4.8.0 it was removed ("Removed `custom` parameter from `PUT /active-response` endpoint", Wazuh 4.8.0
  changelog) and the API rejects unknown body fields with HTTP 400, so sending it would break current managers.
* The script receives `arguments` as `parameters.extra_args` and `alert` as `parameters.alert` on stdin (see
  <https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html>).
* The request/response shape is covered by `backend/tests/test_ws3_wazuh.py`; the authoritative source is the
  `ActiveResponseBody` schema in the Wazuh repository (`api/api/spec/spec.yaml`).

## Safety rules built into the scripts

* Input comes only from the `extra_args` of the Wazuh message, is validated strictly (IP parsing, whitelisted
  characters, length limits) and is never passed to a shell. Alert contents are ignored.
* `block-ip`, `rate-limit` and `isolate-host` refuse to touch: the Wazuh manager (read from the agent's
  `ossec.conf`), loopback, link-local, multicast, the host's own addresses and anything in the allow-list file.
  `isolate-host` refuses to run if it cannot find the manager address (it would cut the agent off) and always
  keeps the manager and the allow-list reachable.
* IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) and IPv4 shorthand such as `127.1` are rejected as input.
* `kill-process` refuses protected processes (init/systemd, sshd and its sshd-session helpers, the Wazuh agent, lsass...), verifies that a PID
  still belongs to the named process, and refuses to kill more than 10 matches.
* `quarantine-file` refuses system paths (also when a symlinked or junction directory in the path would hide one) and symlinks, verifies an optional hash first and keeps the file
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
turning `siem_verify_tls` off (the Wazuh docs use `curl -k` only because the default API certificate is self-signed).
The **Test** button in Phantom is a read-only connection check: it sends no response action, with simulation on or off.

## Safe first test (nothing production-facing)

Phantom's switches for this test (see `LIVE_CHECKLIST.md` sections 8 and 9 and its "Going live for one item"):
**simulation mode ON** while you do steps 1 to 5 (in this version simulation is a hard stop: with it on, Phantom sends
nothing to Wazuh, even with credentials saved) and **HOTL OFF**, AI auto-triage off, agent autonomy `recommend_only`, so
that nothing runs unless a human approves it. Do not enable HOTL for this test.

1. Use a lab VM agent and documentation addresses only. Steps 1 to 5 involve the agent and the manager, not Phantom's
   actions.
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
5. Through the manager, with curl (replace TOKEN; get it with
   `curl -u USER:PASS --cacert ca.pem -X POST "https://MANAGER:55000/security/user/authenticate?raw=true"`, which
   prints the bare JWT):
   ```
   curl --cacert ca.pem -X PUT "https://MANAGER:55000/active-response?agents_list=AGENT_ID" \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"command":"!phantom-block-ip","arguments":["198.51.100.7","1","inbound"],"alert":{"data":{"srcip":"198.51.100.7"}}}'
   ```
   Expect `affected_items: ["AGENT_ID"]` and the log line on the agent. Remove the block again with
   `phantom-unblock-ip` the same way. (Use `-k` instead of `--cacert` only for a throwaway lab manager with the default
   self-signed certificate.)
6. Phantom with simulation still **ON**: save the Wazuh settings (`siem_manager_url`, `siem_user`, `siem_password`,
   and `wazuh_ca_bundle`), press **Test** (read-only, no response action is sent), then post a lab alert from the lab
   agent and approve a `block_ip` for `198.51.100.7`. *Expect:* result `Simulated`, and **no change on the agent** (no
   log line, no nft element). That proves the hard stop.
7. Phantom with simulation **OFF for this one test only**, HOTL still off, Wazuh as the only response integration with
   credentials: follow "Going live for one item" in `LIVE_CHECKLIST.md`. Turn simulation mode off, post a new lab
   alert from the lab agent (automation only acts through the agent that raised the alert), approve the one
   `block_ip` as a human, check the action is recorded `live` and the block is on the agent, and then **turn simulation
   mode back on at once**. Remove the block with `unblock_ip` the same way (simulation off, approve, back on) or with
   the script by hand. Do isolation last, and only after the allow-list holds your own access path and you have console
   access to the VM.

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
