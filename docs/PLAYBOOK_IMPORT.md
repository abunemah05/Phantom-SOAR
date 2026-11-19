# Importing playbooks

Phantom SOAR ships 13 built-in playbook templates. This page describes how an administrator can add more from a
JSON "playbook pack": an uploaded file, the small starter pack that ships with Phantom, or a file in a public
GitHub repository.

Imported playbooks are never trusted: each one is checked against Phantom's own schema, and every one is created
**inactive** and in **HITL** (analyst approval) mode. Importing is administrators only. Enabling an imported
playbook afterwards (the toggle, `PATCH /api/playbooks/{id}/toggle`) is allowed to **administrators and Security
Engineers**, exactly like any other playbook: that role can already create and edit playbooks, so enabling one grants
nothing new, and an enabled imported playbook still only runs in HITL (analyst approval) mode. It is not restricted
to administrators; if you want a four-eyes rule, have an administrator review the playbook before anyone enables it.

## Is there an API (with a key) that delivers ready-made playbooks?

No. There is no single official API, with or without a key, that delivers ready-to-run SANS PICERL playbooks into a
tool like this one. What exists is:

* Vendor playbook libraries in vendor-specific formats that call vendor integrations Phantom does not have
  (Splunk SOAR Python and JSON, Cortex XSOAR YAML, Microsoft Sentinel Logic Apps ARM templates, Shuffle, Tines and
  Swimlane exports). Several of them are only usable inside the vendor's own product or tenant.
* Human-readable frameworks and runbooks (NIST SP 800-61, CISA, CERT Societe Generale IRM) that are documents, not
  machine-readable playbooks.

So the import feature does not talk to a vendor service and needs no vendor key. It reads a pack in the format
below and maps everything to Phantom's own 12 response actions. Converting a vendor playbook is a manual,
reviewed task: Phantom cannot run a step that calls an integration it does not have.

The import feature itself uses only your Phantom administrator session. It sends no token or API key to GitHub:
the files it reads must be public. GitHub allows unauthenticated reads of public repository content, at 60 REST API
requests per hour per IP address; `raw.githubusercontent.com` is the lighter route for a single file.

## Using it

Playbooks page, **Import** (administrators only):

1. Choose a source: upload a `.json` pack, load the **starter pack**, or paste a URL.
2. Choose what to do when a name already exists: **skip** it, or **rename** it (`Name (imported)`).
3. **Preview**: every playbook is listed as importable, renamed, skipped (duplicate) or rejected, with the reasons.
   Nothing is written yet.
4. **Confirm**: the importable playbooks are created, inactive and in HITL mode.
5. Open each imported playbook, check its steps, and enable it with the toggle when you are satisfied (an
   administrator or a Security Engineer can do this).

### Allowed URLs

Only https URLs on these two hosts, with a `.json` path, are fetched:

* `https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>.json`
* `https://api.github.com/repos/<owner>/<repo>/contents/<path>.json` (optionally `?ref=<branch-or-tag>`)

Everything else is refused before any request is made: other hosts, `http`, ports, credentials in the URL, query
strings (other than `ref`), fragments, `..` in the path, and `github.com` page links. The connection goes through
the SSRF guard in `backend/netguard.py` (public addresses only, checked again at connect time), redirects are not
followed, the download is limited to 256 KiB and 10 seconds, and nothing is sent except a plain `GET`.

**Limitation: URL import does not work behind a mandatory egress proxy.** The guarded client does not read the
environment (`trust_env=False`: the standard proxy environment variables and custom CA bundle variables are ignored), so that a
proxy setting can never route the fetch around the address checks. If your network only allows outbound HTTPS through a
proxy, a URL import fails with "The request failed" or a timeout. Use **file upload** (download the pack yourself and
upload it) or the bundled **starter pack**; both need no outbound connection from Phantom and work normally.

**Logging.** The URL you paste is never logged as typed. Audit rows and the stored provenance carry only scheme, host and
path (for example `https://raw.githubusercontent.com/o/r/main/pack.json`): no credentials, no query string (so the
`?ref=` of an `api.github.com` URL is not recorded; the pack's SHA-256 identifies exactly what was imported), no
fragment, truncated to 200 characters.

### API

All three endpoints need an administrator token.

```
GET  /api/playbooks/import/info      limits and allowed hosts
POST /api/playbooks/import/preview   validate, report, write nothing
POST /api/playbooks/import           create the playbooks (needs the preview's sha256)
```

Request body (JSON, about 520 KB at most):

```json
{ "source": "file", "content": "<the text of the pack>", "filename": "my-pack.json",
  "on_duplicate": "skip" }
```

* `source` is `file` (send `content`), `url` (send `url`) or `starter` (send neither).
* `on_duplicate` is `skip` (default) or `rename`.
* To import, repeat the same request with `expected_sha256` set to the `sha256` the preview returned. If the pack
  changed in between (for example a file on GitHub was edited) the import answers 409 and nothing is created.

Example:

```
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"source":"starter"}' https://phantom.example/api/playbooks/import/preview
```

The preview answers with `ok`, `sha256`, `pack` (metadata), `pack_errors` (the pack as a whole is unusable when
this is not empty), `items` (one per playbook: `status`, `final_name`, `errors`, `warnings`, `steps`) and `counts`.

## Pack format (version 1)

A pack is one JSON object. The machine-readable description is [playbook-pack.schema.json](playbook-pack.schema.json);
the importer checks more than a schema can say (parameter ranges for each action, the connector of each action,
duplicate JSON keys), so treat the importer as the authority. A complete example is the starter pack,
`backend/playbook_packs/starter_pack.json`.

```json
{
  "format": "phantom-playbook-pack",
  "format_version": 1,
  "pack": {
    "name": "My pack",
    "version": "1.0.0",
    "author": "Jane Analyst",
    "license": "CC0-1.0",
    "source": "https://example.org/where-it-came-from",
    "description": "Optional text about the pack."
  },
  "playbooks": [
    {
      "name": "Example: stolen laptop",
      "target_threat": "Lost Device",
      "description": "Own summary of the response. Mention the framework it follows.",
      "source_framework": "NIST SP 800-61",
      "execution_mode": "HITL",
      "workflow_logic": {
        "mitre_id": "T1078",
        "mitre_tactic": "Initial Access",
        "picerl_phase": "Containment",
        "keywords": ["lost laptop", "stolen device"],
        "triggers": ["device_reported_lost"],
        "steps": [
          { "action": "await_analyst_approval", "role": "SOC Analyst L2" },
          { "action": "disable_account", "params": { "reason": "Device reported lost" } },
          { "action": "revoke_user_sessions" },
          { "action": "create_ticket", "params": { "priority": "High" } }
        ]
      }
    }
  ]
}
```

Rules:

* **Required**: `format`, `format_version` (1), `pack.name`, `pack.license`, `playbooks`; per playbook `name`
  (3 to 150 characters), `target_threat`, `description` (10 to 1000 characters) and `workflow_logic.steps`.
  `pack.license` is stored with every imported playbook and in the audit log, so say under what terms the pack may be
  used.
* **Unknown fields are rejected** at every level.
* **No control or invisible characters.** Names, descriptions, notes, keywords, pack metadata and string parameters
  that contain control characters or invisible Unicode formatting characters are rejected: bidirectional overrides and
  isolates (U+202A-202E, U+2066-2069), bidi marks (U+200E-200F, U+061C), zero-width characters (U+200B-200D,
  U+2060-2064, U+FEFF, U+180E), interlinear annotation marks and the Unicode tag block. They can make a name read
  differently on screen than it is stored (display spoofing). Ordinary non-ASCII text (accents, CJK, dashes) is fine.
* **Steps** run in list order. `action` must be one of Phantom's 12 response actions (`isolate_endpoint`,
  `unisolate_endpoint`, `terminate_process`, `quarantine_file`, `block_ip`, `unblock_ip`, `apply_rate_limit`,
  `disable_account`, `revoke_user_sessions`, `force_password_reset`, `create_ticket`, `send_notification`) or one of
  the runner's pseudo-steps (`await_analyst_approval`, `enrich_ioc`, `query_abuseipdb`, `query_virustotal`,
  `query_virustotal_url`, `query_otx`, `generate_report`, `generate_pdf_report`). Legacy aliases are not accepted.
  `GET /api/playbooks/actions` lists the parameters of each action; the importer rejects unknown parameters, wrong
  types and out-of-range values, and does not allow `agent_id`.
* **Limits**: 256 KiB per pack, 50 playbooks per pack, 30 steps per playbook, 20 keywords and 20 triggers.
* **Forced safety**: `execution_mode` `HOTL` and `is_active: true` are accepted but ignored, with a warning in the
  report: the playbook is stored in HITL mode and inactive. Changing a playbook to autonomous mode stays a separate,
  deliberate step in the playbook editor, and the global HOTL switch still applies.
* **Duplicates**: a name that already exists (case-insensitive), or that repeats inside the pack, is skipped or
  renamed, as chosen.

## What gets recorded

* Each imported playbook carries an `imported_from` block in its workflow: pack name and version, author, license
  text, the source (file name, URL or `starter pack`), the SHA-256 of the pack, who imported it and when.
* The audit log (source `PLAYBOOKS`) gets one entry per import with the same facts plus the list of created,
  skipped and rejected playbooks and which ones were forced to HITL. Refused URLs, hash mismatches and invalid packs
  are logged as warnings. Fetching a pack from a URL for a preview is logged too.

## The starter pack

`backend/playbook_packs/starter_pack.json` holds eight playbooks for incident types that are not among the 13
built-in templates: business email compromise, malware outbreak, cryptojacking, an actively exploited vulnerability
on a public service, a compromised service credential, website defacement, an unauthorised remote access tool and
malware from removable media. They were written for Phantom as short summaries of the response stages in public
frameworks (NIST SP 800-61, the CISA incident and vulnerability response playbooks, and the style of CERT Societe
Generale's IRM cheat sheets). No text was copied from those sources; each description names the framework it
follows. They are starting points: review the steps against your own procedures before enabling any of them.

## Writing packs from other sources

If you want to bring in playbooks from a framework or from another team, write them as a pack and keep the original
license. Notes on common sources (checked November 2026; check again before you rely on them):

* NIST SP 800-61 and the CISA playbooks are documents. The CISA PDF is marked TLP:CLEAR ("subject to standard
  copyright rules, may be distributed without restriction"). Summarise them in your own words.
* CERT Societe Generale's IRM is licensed CC BY 3.0: you may adapt it if you give credit to CERT Societe Generale
  and state the license in `pack.license`.
* Vendor repositories (Splunk SOAR community playbooks, Cortex XSOAR content, Microsoft Sentinel) have open-source
  licenses for the files, but the playbooks themselves depend on vendor integrations. Use them as ideas, then
  express the response with Phantom's actions.
