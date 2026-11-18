"""Builds Phantom_SOAR_Educational_Guide.pdf and Phantom_SOAR_Educational_Guide.html from one set of blocks.

    python build_educational_pdf.py [output_directory]     (needs: pip install reportlab)

The guide teaches SOAR concepts using this repository as the worked example. Every statement about the platform describes
what the code does; anything that is only a design intention or untested against real vendors is labelled as such.
Edit BLOCKS and rebuild; do not edit the generated files.
"""
import os
import sys

from guide_render import build_html, build_pdf

COVER = {
    "title": "Phantom SOAR: Educational Guide",
    "subtitle": "Learning security orchestration, automation and response by reading and running a real implementation",
    "lines": [
        "This guide explains the concepts behind a SOAR platform and shows where each one lives in the Phantom SOAR source. It is "
        "a teaching document, not a product brochure: the limitations are stated next to the features. The automated tests mock "
        "all vendor systems, and the platform has not been exercised against live Wazuh, Okta, Jira, Slack or threat-intelligence "
        "services.",
    ],
    "meta": [
        ("Author", "Omar Abunemah"),
        ("Institution", "Balqa Applied University, Faculty of Artificial Intelligence and Cybersecurity"),
        ("Subject", "Security automation, incident response, secure software engineering"),
        ("Code base", "Phantom SOAR 2.0 (branch real-soar): Python, FastAPI, Celery, Next.js"),
        ("Companion documents", "README.md, docs/ARCHITECTURE.md, docs/DEPLOYMENT.md, SECURITY.md, LIVE_CHECKLIST.md"),
    ],
}

PICERL = """
 Preparation -> Identification -> Containment -> Eradication -> Recovery -> Lessons learned
  (setup,        (alert in,        (isolate,      (remove       (restore     (reports,
   guardrails)    enrichment)       block, lock)   malware)      service)     audit log)

 Phantom automates parts of Identification and Containment. It does not do Eradication or Recovery:
 those are manual work, tracked through ticketing and the case status.
"""

LIFECYCLE = """
 sender --POST--> /api/webhooks/{wazuh|edr|xdr}         authenticate (ingest token), validate, normalise
                       |
                       v
                  alert row (New) --> queue (Redis) --> worker
                       |                                  |
                       |             extract indicators --> enrich (VirusTotal, AbuseIPDB, OTX, ThreatFox)
                       |                                  |
                       |                       score, verdict, severity bump --> match playbook
                       |                                  |
                       |            HOTL conditions met?  +-- no --> Triaged  (analyst decides)
                       |                                  +-- yes -> run steps -> Contained / Simulated
                       v
                 console: dashboard, alert detail, approvals, AI proposals, PDF report, audit log
"""

BLOCKS = [
    ("h1", "1. What SOAR is, and what it is not"),
    ("p", "A security operations centre (SOC) receives far more alerts than people can read. A **SOAR** (security orchestration, automation and response) platform sits between detection tools and response tools. It collects alerts, enriches them with context, decides what should happen and calls other systems to do it, while keeping a record of every step."),
    ("ul", [
        "**Orchestration** connects tools: a SIEM or EDR sends alerts in; threat-intelligence services, identity providers, firewalls and ticketing systems are called out to.",
        "**Automation** removes repetitive manual steps: looking up an IP address, opening a ticket, blocking an address.",
        "**Response** is the set of actions that limit damage: isolate a host, disable an account, block an address.",
    ]),
    ("p", "A SOAR platform is not a detector. If the sensor sends nothing, SOAR sees nothing. It is also only as trustworthy as its guardrails, because it holds credentials that can disrupt your own business. Most of the engineering in Phantom SOAR goes into limiting what automation may do, not into making it do more."),

    ("h1", "2. The incident-response lifecycle"),
    ("p", "The NIST incident-handling lifecycle (often remembered as PICERL) has six phases. The table shows what the platform does for each, honestly."),
    ("code", PICERL),
    ("table", ["Phase", "What Phantom SOAR provides", "What it does not"], [
        ["Preparation", "Protected hosts/users/IPs, HOTL master switch, role-based access, playbooks, safe defaults (simulation on, HOTL off)", "It cannot decide your protected assets for you"],
        ["Identification", "Webhook ingest, indicator extraction, threat-intel enrichment, MITRE mapping, severity adjustment, optional AI triage", "No detection rules of its own"],
        ["Containment", "Policy-checked actions through Wazuh active response, Okta, Jira, Slack; HITL approval or conditional HOTL", "Only as good as your connector configuration and agent scripts"],
        ["Eradication", "Ticket creation and notification to hand the work over", "No malware removal or forensic collection"],
        ["Recovery", "Un-isolate and un-block actions, case status changes", "No automated restore or verification"],
        ["Lessons learned", "Per-alert PDF report, audit log, system log, mean time to respond from real timestamps", "No post-incident review workflow"],
    ], [0.15, 0.48, 0.37]),

    ("h1", "3. The architecture in one picture"),
    ("p", "The application consists of a Caddy reverse proxy, the Next.js console, the FastAPI backend and a Celery worker, with PostgreSQL and Redis behind them. Only the proxy is reachable from outside the Docker network; the database and broker are never published."),
    ("code", LIFECYCLE),
    ("p", "Read this diagram together with `docs/ARCHITECTURE.md`. The source files to open first are `backend/routers/webhooks.py` (entry), `backend/engine/ingest.py` (normalisation), `backend/celery_app.py` (worker tasks), `backend/engine/runner.py` (routing), `backend/engine/policy.py` (guardrails) and `backend/engine/actions.py` (execution)."),

    ("h1", "4. Alerts in: ingestion and trust"),
    ("p", "An alert is a JSON document posted to `/api/webhooks/wazuh`, `/edr` or `/xdr`. The first design question is trust: anyone who can reach the endpoint could invent incidents. Phantom therefore requires an `X-Phantom-Ingest-Token`. Tokens are created per sender in the console, shown once, stored only as hashes, and can be revoked or given an expiry."),
    ("ul", [
        "**Size limit**: bodies over 1 MiB are rejected with HTTP 413 before parsing.",
        "**Severity**: for Wazuh it is derived from `rule.level`; for EDR and XDR it is taken from the sender's `severity` field. Because the sender controls that value, severity alone is never enough to trigger autonomous action.",
        "**Indicator extraction**: regular expressions find IP addresses, hashes, URLs and domains, including defanged forms such as `hxxp://` and `1[.]2[.]3[.]4`. At most 25 indicators are kept per alert, so an attacker cannot make the platform spend its API quota on one huge alert.",
        "**Reliability**: if the queue is unavailable the alert is processed inside the request; the worker task claims an alert with an atomic update so running twice is harmless.",
    ]),
    ("note", "Lesson: authenticate machines separately from people, store only hashes of credentials, and cap everything an outsider can make you do."),

    ("h1", "5. Threat-intelligence enrichment"),
    ("p", "Enrichment answers the question \"what is known about this indicator?\" Phantom queries up to four public services and combines the answers."),
    ("table", ["Status", "Meaning", "Counts as evidence?"], [
        ["`live`", "A real answer from the provider", "Yes"],
        ["`not_found`", "The provider has never seen it", "No (unknown is not the same as clean)"],
        ["`not_configured`", "No API key is set", "No"],
        ["`error`", "Network failure or bad response", "No"],
        ["`rate_limited`", "The provider (or the local budget) refused; a retry time is recorded", "No"],
        ["`lab_fixture`", "Built-in demo data, only while simulation mode is on", "Yes, but labelled as lab data"],
        ["`skipped`", "Private or reserved address; never sent to a third party", "No"],
    ], [0.2, 0.55, 0.25]),
    ("p", "The consensus score is the highest score among providers that returned evidence. A score of 70 or more is **Malicious**, 30 or more **Suspicious**, otherwise **Clean**; with no evidence the verdict is **Unknown**. The thresholds are settings. A Malicious verdict raises the alert severity by one step, never beyond High, and never lowers it."),
    ("h2", "Why the scoring is conservative"),
    ("ul", [
        "VirusTotal needs a minimum number of weighted detections before it can say Malicious, so a single noisy engine does not condemn an address.",
        "AlienVault OTX alone can reach Suspicious but never Malicious, because pulse membership is weak evidence.",
        "A provider that is rate limited is never read as \"clean\". Treating silence as safety is a classic automation mistake.",
        "There is no offline heuristic or machine-learning score. With no API keys every indicator is simply Unknown.",
    ]),

    ("h1", "6. Playbooks and routing"),
    ("p", "A playbook is an ordered list of response steps for a type of incident. Phantom ships 13 templates: ransomware, SSH and RDP brute force, phishing, privilege escalation, web shell, data exfiltration, lateral movement, DDoS, credential dumping, SQL injection, supply chain tampering, insider threat and reconnaissance. Six are marked HOTL (autonomous when conditions allow) and seven HITL (always need a person). Analysts can edit them in the console."),
    ("p", "To choose a playbook the runner looks, in order, at the MITRE ATT&CK technique id supplied by the sender, then the sender's rule description and groups, and only then at keywords. Keyword matches in free-text log fields are treated as weak, because an attacker controls log text."),
    ("h2", "The twelve actions"),
    ("p", "A step names an action from a fixed catalogue: `isolate_endpoint`, `unisolate_endpoint`, `terminate_process`, `quarantine_file`, `block_ip`, `unblock_ip`, `apply_rate_limit`, `disable_account`, `revoke_user_sessions`, `force_password_reset`, `create_ticket` and `send_notification`. Nothing outside the catalogue can be executed, which also bounds what an AI agent can ask for."),

    ("h1", "7. HITL versus HOTL"),
    ("p", "Two supervision models appear throughout automation design."),
    ("table", ["Model", "Who acts first", "Phantom behaviour"], [
        ["HITL (human in the loop)", "A person approves before anything runs", "The default for every alert. Status `Triaged`, then the analyst approves in the console"],
        ["HOTL (human on the loop)", "The platform acts, a person reviews afterwards", "Allowed only when all three conditions below hold"],
    ], [0.25, 0.3, 0.45]),
    ("ul", [
        "The global HOTL switch is on. It is **off by default**, and it cannot be switched on until protected users and protected hosts or IPs are configured.",
        "The playbook is a HOTL playbook and was chosen by a strong signal (technique id, or the sender's own rule text), not by free-text keywords.",
        "A `Malicious` indicator backed by live provider data exists. Lab fixtures count only while simulation is on.",
    ]),
    ("p", "Notice what is missing: neither high severity nor a particular score alone starts containment. Requiring several independent signals is a deliberate way to reduce false-positive damage."),
    ("note", "Exercise for discussion: which of the three conditions would you relax for a pure-Linux web server fleet, and what could go wrong? Write the failure scenario before you decide."),

    ("h1", "8. The policy engine: guardrails"),
    ("p", "The most important file for safety is `backend/engine/policy.py`. Every action from every source (playbook, analyst, AI agent) goes through `evaluate_action` before any connector is called. The result is allowed, needs approval, or blocked, with a reason that is saved."),
    ("ul", [
        "**Protected assets**: lists of hosts, users and IPs that automation may never touch. The Wazuh manager, loopback, the server itself and its default gateway are protected automatically.",
        "**Never-block addresses**: loopback and reserved ranges cannot be blocked by anyone.",
        "**Actor rules**: automated actors (`playbook`, `agent`) are stricter than a human analyst. An AI agent additionally needs a confidence of at least 0.85 (setting `agent_min_confidence`) and the configured autonomy level.",
        "**Autonomy levels** for the agent: `recommend_only` (default; a person approves everything), `low_impact`, or `policy`.",
    ]),
    ("p", "This is the principle of **least agency**: give automation the narrowest authority that still helps, and put the limit in code that the automation cannot rewrite."),

    ("h1", "9. Simulation mode and honest outcomes"),
    ("p", "A new install runs in simulation mode, which is a hard stop: no response action reaches a real system, even if credentials are saved, until you turn the mode off. The important teaching point is how results are labelled. A step ends in one of: `live` (really done), `simulated` (pretend), `skipped` (no credentials configured and simulation off), `blocked` (policy refused) or `failed`."),
    ("ul", [
        "An alert whose actions were only simulated gets the status `Simulated`, never `Contained`.",
        "Dashboards and the containment rate count only live success. A tool that reports pretend containment as real is dangerous because people stop looking.",
        "In production mode the API refuses to start with simulation on while real credentials are present, unless an explicit confirmation variable is set.",
        "Autonomous response is checked again at run time: switching it on without listing protected assets has no effect.",
    ]),

    ("h1", "10. Response through Wazuh active response"),
    ("p", "Wazuh is an open-source detection platform whose manager can tell its agents to run a script (\"active response\"). Phantom does not log into endpoints. It calls the manager API and names the agent and the script command."),
    ("table", ["Phantom action", "Command sent to the agent"], [
        ["`isolate_endpoint` / `unisolate_endpoint`", "`phantom-isolate-host` / `phantom-unisolate-host`"],
        ["`terminate_process`", "`phantom-kill-process`"],
        ["`quarantine_file`", "`phantom-quarantine-file`"],
        ["`block_ip` / `unblock_ip`", "firewall scripts on the alert's agent or on configured gateway agents"],
        ["`apply_rate_limit`", "firewall script (Linux only)"],
    ], [0.4, 0.6]),
    ("p", "Only some of these commands exist in stock Wazuh, so the repository ships the missing scripts in `wazuh/` with installers, an allow-list and configuration snippets. The scripts validate their input, refuse to act on the manager or loopback, and log every decision. The request always includes an explicit agent list and never agent 000 (the manager itself)."),
    ("note", "Not verified: the Linux scripts were unit tested, the Windows scripts were not executed, and nothing was run against a live Wazuh manager. Follow LIVE_CHECKLIST.md in a lab before trusting any of it."),

    ("h1", "11. Optional AI triage"),
    ("p", "Large language models can summarise an alert and suggest next steps, but they can also be wrong, be manipulated by text inside the alert, and leak data to a third party. Phantom's design treats the model as an untrusted advisor."),
    ("ul", [
        "**Off by default**. Enable with `PHANTOM_AI_ENABLED=true` and an OpenRouter key stored encrypted in the configuration page.",
        "**Minimised input**: a redacted summary of the alert is sent, never secrets. The raw payload is sent only if `PHANTOM_AI_SEND_RAW_PAYLOAD=true`.",
        "**No tools**: the model returns text. It cannot call any API.",
        "**Strict output**: the reply must be JSON with a verdict, a confidence between 0 and 1 and at most five actions from the catalogue. Anything else becomes verdict `unknown` with no action.",
        "**Prompt-injection containment**: alert content is placed in randomly delimited data blocks, never in the instructions, and the worst the model can do is propose an action that policy then evaluates like any other.",
        "**Human gate**: with the default `recommend_only` autonomy every proposal waits for a person to approve or reject it.",
        "**Cost cap**: a local calls-per-minute limit and bounded output size. Also set a spending limit with the provider.",
    ]),
    ("p", "The `confidence` value is the model's own claim and is not calibrated. Treat it as a hint. Measure the proposals against analyst decisions for a while before enabling anything beyond `recommend_only`."),

    ("h1", "12. Securing the platform itself"),
    ("p", "A SOAR system is a high-value target: it holds keys to firewalls and identity systems. Study how the code defends itself."),
    ("table", ["Threat", "Mitigation in the code"], [
        ["Stolen password database", "Argon2id hashes; 15-character minimum (8 with MFA)"],
        ["Password guessing", "Failed-login blocking per username-and-address pair (one attacker cannot lock everyone out) and per-address rate limits; identical 401 for unknown, locked and wrong-password cases"],
        ["Session theft", "JWT with server-side revocation list; role re-read on every request; optional TOTP MFA, mandatory for admins when configured"],
        ["Stolen database dump", "Integration secrets and MFA seeds are Fernet-encrypted; the key is not in the database or backups"],
        ["Fake alerts", "Per-sender hashed ingest tokens"],
        ["Server-side request forgery", "Outbound test calls use a guard that connects only to public addresses"],
        ["Over-privileged viewers", "Roles: Admin, Security Engineer, SOC Analyst, SOC Auditor (read-only)"],
        ["Weak production config", "The API refuses to start with a short JWT secret or no encryption key"],
        ["Tampering with history", "Audit log of analyst actions with minimum retention; purge needs a one-time confirmation"],
        ["Container escape or lateral movement", "Non-root, read-only filesystems, dropped capabilities, internal data network, pinned images"],
    ], [0.3, 0.7]),
    ("p", "See `SECURITY.md` for known limits and key rotation."),

    ("h1", "13. Running it and exploring safely"),
    ("p", "These exercises use only simulation mode and a local machine. None of them contacts a real vendor if you leave all keys empty."),
    ("ul", [
        "**Start**: `python scripts/gen_env.py`, then `docker compose up -d --build --wait`, and open https://localhost. Log in with the bootstrap administrator (the generated password is written to a file inside the stack, see `docs/DEPLOYMENT.md`).",
        "**Send an alert**: create an ingest token in the console, then `curl` a small JSON body to `/api/webhooks/wazuh` (examples are in `docs/DEPLOYMENT.md`). Watch the status move from New to Triaged or Simulated.",
        "**Compare routing**: send the same alert with a MITRE technique that matches a HOTL playbook, then with plain keywords. Explain the difference using section 7.",
        "**Probe a guardrail**: try to isolate or block the address of the Wazuh manager, loopback or the server itself. These automatic protected entries are denied for every actor, analysts included. Then list an ordinary lab host as protected and compare how a playbook step and a manual analyst request are treated (automation is denied; an analyst is allowed, with a note). Read the policy reasons saved with each step.",
        "**Read the tests**: `pytest backend/tests/test_ws1_runner.py` and `test_policy_and_actions.py` show each rule as an executable example.",
        "**Enable AI in a lab**: set a small spending limit with the provider, keep `recommend_only`, trigger a triage and compare the proposal with your own judgement.",
    ]),
    ("p", "Developer workflow: `pip install -r backend/requirements-dev.txt`, then `pytest` from the repository root runs the backend suite on SQLite; CI also runs it on PostgreSQL 16. For the console, `npm ci` and `npm run build` inside `frontend/`."),

    ("h1", "14. Limitations you should be able to explain"),
    ("ul", [
        "No benchmark has been performed. There is no measured response time or throughput figure; the dashboard shows real elapsed time per alert.",
        "Single API process and a single worker with the scheduler: not highly available.",
        "No sender-side forwarder from Wazuh to the webhook is shipped; you must configure one.",
        "Vendor request shapes (Wazuh active-response API for your version, Okta lookups, ThreatFox queries) are implemented from documentation and tested only with mocks.",
        "Confidence from an AI model is self-reported and uncalibrated.",
        "Licence and security contact are placeholders for the owner to fill in.",
    ]),

    ("h1", "15. Glossary"),
    ("table", ["Term", "Meaning"], [
        ["Active response", "Wazuh feature that runs a script on an agent when the manager asks"],
        ["Alert", "A record that a sensor saw something suspicious"],
        ["Containment", "Limiting the spread or damage of an incident"],
        ["EDR / XDR", "Endpoint / extended detection and response tools"],
        ["Enrichment", "Adding context, such as threat reputation, to an alert"],
        ["Fernet", "Authenticated symmetric encryption from the `cryptography` library"],
        ["HITL / HOTL", "Human in the loop / human on the loop"],
        ["IOC", "Indicator of compromise: an IP, domain, URL or file hash"],
        ["MITRE ATT&CK", "Public catalogue of attacker techniques with ids such as T1110"],
        ["Playbook", "An ordered set of response steps for an incident type"],
        ["Policy engine", "Code that decides whether an action may run, for whom, on what"],
        ["Prompt injection", "Attacker text that tries to give instructions to a language model"],
        ["SIEM", "System that collects and correlates security logs"],
        ["SOC", "Security operations centre"],
        ["SSRF", "Server-side request forgery: making a server call an attacker-chosen address"],
        ["TIP", "Threat-intelligence platform or provider"],
        ["TOTP", "Time-based one-time passwords used for multi-factor login"],
    ], [0.25, 0.75]),
]

FOOTER = "Phantom SOAR Educational Guide. Balqa Applied University. Generated by build_educational_pdf.py from the repository source; verify claims against the code."

if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    pdf_path = os.path.join(out_dir, "Phantom_SOAR_Educational_Guide.pdf")
    html_path = os.path.join(out_dir, "Phantom_SOAR_Educational_Guide.html")
    build_pdf(pdf_path, COVER, BLOCKS,
              header_left="PHANTOM SOAR: EDUCATIONAL GUIDE",
              header_right="Balqa Applied University",
              footer_left="Phantom SOAR Educational Guide. Generated by build_educational_pdf.py")
    build_html(html_path, COVER, BLOCKS, FOOTER)
    print(f"Wrote {pdf_path}\nWrote {html_path}")
