"""Playbook pack import: validation, forced safety (inactive + HITL), admin-only, URL allow-list / SSRF, audit."""
import copy
import json

import httpx
import pytest

from backend import netguard
from backend.engine import playbook_import as pi
from backend.engine.actions import ACTION_CATALOG, PSEUDO_STEPS
from backend.tests.ws6_helpers import _clean_state, admin_h, bearer, make_user  # noqa: F401

PUBLIC_IP = "140.82.112.3"  # a public address, so the offline tests do not depend on DNS


def make_pack(*playbooks, **meta):
    pack = {
        "format": "phantom-playbook-pack",
        "format_version": 1,
        "pack": {"name": "Unit test pack", "version": "1.0.0", "license": "CC0-1.0 test fixture", **meta},
        "playbooks": list(playbooks),
    }
    return pack


def make_playbook(name="Imp Test Playbook One", **overrides):
    entry = {
        "name": name,
        "target_threat": "Malware",
        "description": "A test playbook written for the unit tests of the import feature.",
        "workflow_logic": {
            "mitre_id": "T1204",
            "keywords": ["unit test"],
            "steps": [
                {"action": "isolate_endpoint", "connector": "edr"},
                {"action": "block_ip", "connector": "firewall", "params": {"duration_hours": 24}},
                {"action": "await_analyst_approval", "role": "SOC Analyst L2"},
                {"action": "create_ticket", "params": {"priority": "High"}},
            ],
        },
    }
    entry.update(overrides)
    return entry


def raw(pack) -> bytes:
    return json.dumps(pack).encode()


def body_for(pack, **extra):
    return {"source": "file", "content": json.dumps(pack), "filename": "pack.json", **extra}


def preview(client, headers, pack, **extra):
    return client.post("/api/playbooks/import/preview", json=body_for(pack, **extra), headers=headers)


def do_import(client, headers, pack, sha=None, **extra):
    sha = sha or pi.pack_sha256(json.dumps(pack).encode())
    return client.post("/api/playbooks/import", json=body_for(pack, expected_sha256=sha, **extra), headers=headers)


def import_logs(client, headers):
    res = client.get("/api/logs?source=PLAYBOOKS&limit=200", headers=headers)
    assert res.status_code == 200, res.text
    body = res.json()
    return body["logs"] if isinstance(body, dict) and "logs" in body else body


def delete_all_named(client, headers, prefix):
    for pb in client.get("/api/playbooks?limit=200", headers=headers).json():
        if pb["name"].startswith(prefix):
            client.delete(f"/api/playbooks/{pb['playbook_id']}", headers=headers)


@pytest.fixture(autouse=True)
def _cleanup(client, admin_h):
    yield
    delete_all_named(client, admin_h, "Imp ")
    delete_all_named(client, admin_h, "Phantom Imp")


# --- pure validation ------------------------------------------------------------------------
def test_valid_pack_is_importable_and_normalised():
    report = pi.build_report(raw(make_pack(make_playbook())), [])
    assert report["ok"] and report["counts"]["importable"] == 1
    item = report["items"][0]
    assert item["status"] == "importable" and not item["errors"]
    pb = item["playbook"]
    assert pb["is_active"] is False and pb["execution_mode"] == "HITL"
    assert [s["order"] for s in pb["workflow_logic"]["steps"]] == [1, 2, 3, 4]
    assert pb["workflow_logic"]["description"].startswith("A test playbook")


def test_unknown_action_and_alias_are_rejected():
    bad = make_playbook("Imp Bad Action")
    bad["workflow_logic"]["steps"].append({"action": "delete_all_the_things"})
    alias = make_playbook("Imp Alias")
    alias["workflow_logic"]["steps"] = [{"action": "notify"}]  # a legacy alias: packs must use canonical names
    report = pi.build_report(raw(make_pack(bad, alias, make_playbook("Imp Fine"))), [])
    statuses = {i["name"]: i["status"] for i in report["items"]}
    assert statuses == {"Imp Bad Action": "rejected", "Imp Alias": "rejected", "Imp Fine": "importable"}
    assert "unknown action 'delete_all_the_things'" in report["items"][0]["errors"][0]


@pytest.mark.parametrize("params,fragment", [
    ({"duration_hours": 100000}, "<= 720"),
    ({"direction": "sideways"}, "one of"),
    ({"surprise": 1}, "Unknown parameter"),
    ({"agent_id": "007"}, "agent_id"),
    ({"duration_hours": True}, "integer"),
    ("not-an-object", "params must be an object"),
])
def test_bad_params_are_rejected(params, fragment):
    entry = make_playbook("Imp Params")
    entry["workflow_logic"]["steps"] = [{"action": "block_ip", "params": params}]
    item = pi.build_report(raw(make_pack(entry)), [])["items"][0]
    assert item["status"] == "rejected"
    assert fragment in " ".join(item["errors"])


def test_connector_must_match_action_and_pseudo_steps_take_no_params():
    wrong_connector = make_playbook("Imp Connector")
    wrong_connector["workflow_logic"]["steps"] = [{"action": "block_ip", "connector": "edr"}]
    pseudo_params = make_playbook("Imp Pseudo")
    pseudo_params["workflow_logic"]["steps"] = [{"action": "generate_report", "params": {"x": 1}}]
    items = pi.build_report(raw(make_pack(wrong_connector, pseudo_params)), [])["items"]
    assert [i["status"] for i in items] == ["rejected", "rejected"]


def test_unknown_fields_missing_fields_and_structure_are_rejected():
    entries = [
        make_playbook("Imp Extra Field", surprise=True),
        {k: v for k, v in make_playbook("Imp No Description").items() if k != "description"},
        make_playbook("Imp Empty Steps", workflow_logic={"steps": []}),
        make_playbook("Imp Logic Key", workflow_logic={"steps": [{"action": "block_ip"}], "evil": 1}),
        make_playbook("Imp Mode", execution_mode="YOLO"),
        make_playbook("Imp Mitre", workflow_logic={"mitre_id": "banana", "steps": [{"action": "block_ip"}]}),
        make_playbook("Imp Control\x07Chars"),
        "not an object",
    ]
    items = pi.build_report(raw(make_pack(*entries)), [])["items"]
    assert [i["status"] for i in items] == ["rejected"] * len(entries)


def test_too_many_steps_and_playbooks_and_oversize_pack():
    many_steps = make_playbook("Imp Steps")
    many_steps["workflow_logic"]["steps"] = [{"action": "send_notification"}] * (pi.MAX_STEPS + 1)
    assert pi.build_report(raw(make_pack(many_steps)), [])["items"][0]["status"] == "rejected"

    too_many = make_pack(*[make_playbook(f"Imp Many {i}") for i in range(pi.MAX_PLAYBOOKS + 1)])
    report = pi.build_report(raw(too_many), [])
    assert not report["ok"] and "limit" in report["pack_errors"][0]

    big = make_pack(make_playbook(), description="x" * (pi.MAX_PACK_BYTES + 10))
    report = pi.build_report(raw(big), [])
    assert not report["ok"] and "limit" in report["pack_errors"][0]


@pytest.mark.parametrize("payload,fragment", [
    (b"", "empty"),
    (b"\xff\xfe\x00bad", "UTF-8"),
    (b"{not json", "not valid JSON"),
    (b"[1, 2]", "JSON object"),
    (b'{"format": "phantom-playbook-pack", "format": "x"}', "duplicate key"),
    (b"[" * 100000, "deeply"),
])
def test_unparseable_packs_give_a_pack_error(payload, fragment):
    report = pi.build_report(payload, [])
    assert not report["ok"] and fragment in report["pack_errors"][0]


def test_pack_level_checks():
    pack = make_pack(make_playbook())
    pack["format_version"] = 2
    del pack["pack"]["license"]
    pack["extra"] = 1
    errors = " ".join(pi.build_report(raw(pack), [])["pack_errors"])
    assert "format_version" in errors and "pack.license is required" in errors and "unknown field" in errors


def test_hotl_and_active_requests_are_downgraded_with_warnings():
    entry = make_playbook("Imp Hotl", execution_mode="hotl", is_active=True)
    item = pi.build_report(raw(make_pack(entry)), [])["items"][0]
    assert item["status"] == "importable"
    assert item["requested_mode"] == "HOTL"
    assert item["playbook"]["execution_mode"] == "HITL" and item["playbook"]["is_active"] is False
    assert any("HOTL" in w for w in item["warnings"]) and any("inactive" in w for w in item["warnings"])


def test_duplicate_names_skip_or_rename():
    pack = make_pack(make_playbook("Imp Dup"), make_playbook("imp dup"), make_playbook("Imp Existing"))
    skip = pi.build_report(raw(pack), ["IMP EXISTING"], "skip")
    assert [i["status"] for i in skip["items"]] == ["importable", "skipped_duplicate", "skipped_duplicate"]
    assert skip["counts"]["skipped_duplicate"] == 2

    rename = pi.build_report(raw(pack), ["IMP EXISTING"], "rename")
    assert [i["status"] for i in rename["items"]] == ["importable", "renamed", "renamed"]
    assert [i["final_name"] for i in rename["items"]] == ["Imp Dup", "imp dup (imported)", "Imp Existing (imported)"]
    with pytest.raises(pi.PackError):
        pi.build_report(raw(pack), [], "overwrite")


def test_rename_respects_the_name_length_limit():
    long_name = "L" * pi.MAX_NAME
    report = pi.build_report(raw(make_pack(make_playbook(long_name))), [long_name], "rename")
    assert len(report["items"][0]["final_name"]) <= pi.MAX_NAME


def test_starter_pack_is_valid_and_only_uses_our_actions():
    data = json.loads(pi.load_starter_pack())
    report = pi.build_report(pi.load_starter_pack(), [])
    assert report["ok"] and report["counts"]["rejected"] == 0 and report["counts"]["importable"] == len(data["playbooks"]) >= 8
    allowed = set(ACTION_CATALOG) | set(PSEUDO_STEPS)
    builtin = {p["name"].casefold() for p in __import__("backend.engine.playbooks_catalog", fromlist=["x"]).PRECONFIGURED_PLAYBOOKS}
    for entry in data["playbooks"]:
        assert entry["execution_mode"] == "HITL" and entry["is_active"] is False
        assert entry["source_framework"] and entry["name"].casefold() not in builtin
        assert {s["action"] for s in entry["workflow_logic"]["steps"]} <= allowed
        assert not any("params" in s for s in entry["workflow_logic"]["steps"] if s["action"] in PSEUDO_STEPS)


def test_shipped_json_schema_accepts_the_starter_pack_structure():
    from pathlib import Path
    schema = json.loads((Path(__file__).resolve().parents[2] / "docs" / "playbook-pack.schema.json").read_text())
    assert schema["properties"]["format"]["const"] == pi.PACK_FORMAT
    step_actions = set(schema["$defs"]["step"]["properties"]["action"]["enum"])
    assert step_actions == set(ACTION_CATALOG) | set(PSEUDO_STEPS)
    assert set(schema["$defs"]["playbook"]["properties"]) == pi.PLAYBOOK_KEYS
    assert set(schema["$defs"]["workflow_logic"]["properties"]) == pi.WORKFLOW_KEYS
    assert set(schema["$defs"]["step"]["properties"]) == pi.STEP_KEYS
    assert schema["properties"]["playbooks"]["maxItems"] == pi.MAX_PLAYBOOKS
    assert schema["$defs"]["workflow_logic"]["properties"]["steps"]["maxItems"] == pi.MAX_STEPS


# --- API: RBAC ---------------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["SOC Analyst", "Security Engineer", "SOC Auditor (Read-Only)"])
def test_non_admins_are_forbidden(client, admin_h, role):
    username = "imp_" + role.split()[0].lower() + "_" + str(len(role))
    make_user(client, admin_h, username, role)
    headers = bearer(username)
    pack = make_pack(make_playbook("Imp Forbidden"))
    assert preview(client, headers, pack).status_code == 403
    assert do_import(client, headers, pack).status_code == 403
    assert client.get("/api/playbooks/import/info", headers=headers).status_code == 403
    assert client.post("/api/playbooks/import/preview", json={"source": "starter"}).status_code == 401
    assert not any(p["name"] == "Imp Forbidden" for p in client.get("/api/playbooks?limit=200", headers=admin_h).json())


# --- API: preview and import --------------------------------------------------------------------
def test_preview_writes_nothing_and_reports_per_item(client, admin_h):
    pack = make_pack(make_playbook("Imp Preview Good"), make_playbook("Imp Preview Bad", workflow_logic={"steps": [{"action": "nope"}]}))
    res = preview(client, admin_h, pack)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] and body["sha256"] == pi.pack_sha256(json.dumps(pack).encode())
    assert [i["status"] for i in body["items"]] == ["importable", "rejected"]
    assert body["items"][0]["step_count"] == 4 and "playbook" not in body["items"][0]
    assert body["forced"] == {"inactive": True, "execution_mode": "HITL"}
    assert not any(p["name"].startswith("Imp Preview") for p in client.get("/api/playbooks?limit=200", headers=admin_h).json())


def test_import_creates_inactive_hitl_playbooks_with_provenance_and_audit(client, admin_h):
    hotl = make_playbook("Imp Wants Hotl", execution_mode="HOTL", is_active=True)
    bad = make_playbook("Imp Rejected One", workflow_logic={"steps": [{"action": "format_disk"}]})
    pack = make_pack(hotl, make_playbook("Imp Plain"), bad, license="MIT test license text")
    res = do_import(client, admin_h, pack)
    assert res.status_code == 200, res.text
    body = res.json()
    assert [c["name"] for c in body["created"]] == ["Imp Wants Hotl", "Imp Plain"]
    assert all(c["is_active"] is False and c["execution_mode"] == "HITL" for c in body["created"])

    stored = {p["name"]: p for p in client.get("/api/playbooks?limit=200", headers=admin_h).json()}
    for name in ("Imp Wants Hotl", "Imp Plain"):
        assert stored[name]["is_active"] is False and stored[name]["execution_mode"] == "HITL"
        origin = stored[name]["workflow_logic"]["imported_from"]
        assert origin["license"] == "MIT test license text"
        assert origin["sha256"] == pi.pack_sha256(json.dumps(pack).encode())
        assert origin["source"] == "pack.json" and origin["imported_by"]
    assert "Imp Rejected One" not in stored

    entry = next(l for l in import_logs(client, admin_h) if l["level"] == "ACTION" and l["target"] == "Unit test pack")
    details = entry["details"]
    assert details["sha256"] == body["report"]["sha256"] and details["license"] == "MIT test license text"
    assert [c["name"] for c in details["created"]] == ["Imp Wants Hotl", "Imp Plain"]
    assert details["forced_to_hitl"] == ["Imp Wants Hotl"]
    assert details["rejected"][0]["name"] == "Imp Rejected One" and details["by"]


def test_imported_playbooks_never_run_until_an_admin_enables_them(client, admin_h):
    from backend.database import SessionLocal
    from backend.engine import runner
    entry = make_playbook("Imp Never Auto", workflow_logic={
        "keywords": ["zzz-import-never-auto-keyword"], "steps": [{"action": "isolate_endpoint"}]})
    assert do_import(client, admin_h, make_pack(entry)).status_code == 200
    with SessionLocal() as db:
        names = {p.name for p in db.query(runner.Playbook).filter(runner.Playbook.is_active == True).all()}  # noqa: E712
    assert "Imp Never Auto" not in names
    pid = next(p["playbook_id"] for p in client.get("/api/playbooks?limit=200", headers=admin_h).json() if p["name"] == "Imp Never Auto")
    toggled = client.patch(f"/api/playbooks/{pid}/toggle", headers=admin_h)
    assert toggled.status_code == 200 and toggled.json()["is_active"] is True  # only an explicit admin action


def test_import_duplicate_handling_via_api(client, admin_h):
    pack = make_pack(make_playbook("Imp Api Dup"))
    assert do_import(client, admin_h, pack).json()["created"][0]["name"] == "Imp Api Dup"
    skipped = do_import(client, admin_h, pack).json()
    assert skipped["created"] == [] and skipped["report"]["items"][0]["status"] == "skipped_duplicate"
    renamed = do_import(client, admin_h, pack, on_duplicate="rename").json()
    assert renamed["created"][0]["name"] == "Imp Api Dup (imported)"
    # A refused import (nothing created) is audited as a WARNING.
    assert any(l["level"] == "WARNING" and "imported 0 of 1" in l["message"] for l in import_logs(client, admin_h))


def test_import_requires_the_previewed_hash(client, admin_h):
    pack = make_pack(make_playbook("Imp Hash"))
    missing = client.post("/api/playbooks/import", json=body_for(pack), headers=admin_h)
    assert missing.status_code == 422
    changed = do_import(client, admin_h, pack, sha="0" * 64)
    assert changed.status_code == 409
    assert any("changed after the preview" in l["message"] for l in import_logs(client, admin_h))
    assert not any(p["name"] == "Imp Hash" for p in client.get("/api/playbooks?limit=200", headers=admin_h).json())


def test_invalid_pack_is_422_and_audited(client, admin_h):
    pack = make_pack(make_playbook("Imp Invalid Pack"))
    pack["format"] = "something-else"
    res = do_import(client, admin_h, pack)
    assert res.status_code == 422
    assert res.json()["detail"]["report"]["pack_errors"]
    assert any("not valid" in l["message"] for l in import_logs(client, admin_h))


def test_request_shape_and_size_limits(client, admin_h):
    assert client.post("/api/playbooks/import/preview", json={"source": "file"}, headers=admin_h).status_code == 422
    assert client.post("/api/playbooks/import/preview", json={"source": "file", "content": "{}", "url": "https://x"},
                       headers=admin_h).status_code == 422
    assert client.post("/api/playbooks/import/preview", json={"source": "starter", "extra": 1}, headers=admin_h).status_code == 422
    assert client.post("/api/playbooks/import/preview", content=b"not json", headers=admin_h).status_code == 422
    huge = {"source": "file", "content": "x" * (pi.MAX_PACK_BYTES * 2 + 20000)}
    assert client.post("/api/playbooks/import/preview", json=huge, headers=admin_h).status_code == 413
    oversize = client.post("/api/playbooks/import/preview", json={"source": "file", "content": " " * (pi.MAX_PACK_BYTES + 5)},
                           headers=admin_h)
    assert oversize.status_code == 200 and not oversize.json()["ok"]  # fits the request, exceeds the pack limit


def test_starter_pack_via_api_and_info(client, admin_h):
    info = client.get("/api/playbooks/import/info", headers=admin_h).json()
    assert info["forced"] == {"is_active": False, "execution_mode": "HITL"} and "raw.githubusercontent.com" in info["allowed_url_hosts"]
    pv = client.post("/api/playbooks/import/preview", json={"source": "starter"}, headers=admin_h).json()
    assert pv["ok"] and pv["counts"]["rejected"] == 0 and pv["source"]["kind"] == "starter"
    created = []
    try:
        res = client.post("/api/playbooks/import", json={"source": "starter", "expected_sha256": pv["sha256"],
                                                         "on_duplicate": "rename"}, headers=admin_h)
        assert res.status_code == 200, res.text
        created = res.json()["created"]
        assert len(created) == pv["counts"]["importable"] + pv["counts"]["renamed"]
        assert all(not c["is_active"] and c["execution_mode"] == "HITL" for c in created)
    finally:
        for c in created:
            client.delete(f"/api/playbooks/{c['playbook_id']}", headers=admin_h)


# --- URL sources ---------------------------------------------------------------------------------
@pytest.fixture
def fake_github(monkeypatch):
    """Route URL fetches to a mock transport; resolve every host to a public address."""
    calls = []
    state = {"handler": None}

    def handler(request: httpx.Request):
        calls.append(request)
        return state["handler"](request)

    monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: [PUBLIC_IP])
    monkeypatch.setattr(pi, "make_http_client", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    state["calls"] = calls
    return state


RAW_URL = "https://raw.githubusercontent.com/example-org/example-repo/main/packs/pack.json"


def url_preview(client, headers, url):
    return client.post("/api/playbooks/import/preview", json={"source": "url", "url": url}, headers=headers)


def test_url_import_happy_path_sends_no_credentials(client, admin_h, fake_github):
    pack = make_pack(make_playbook("Imp From Url"))
    fake_github["handler"] = lambda req: httpx.Response(200, content=json.dumps(pack).encode())
    pv = url_preview(client, admin_h, RAW_URL)
    assert pv.status_code == 200 and pv.json()["ok"] and pv.json()["source"] == {"kind": "url", "url": RAW_URL}
    sent = fake_github["calls"][0]
    assert "authorization" not in sent.headers and "cookie" not in sent.headers

    res = client.post("/api/playbooks/import", json={"source": "url", "url": RAW_URL, "expected_sha256": pv.json()["sha256"]},
                      headers=admin_h)
    assert res.status_code == 200 and res.json()["created"][0]["name"] == "Imp From Url"
    stored = next(p for p in client.get("/api/playbooks?limit=200", headers=admin_h).json() if p["name"] == "Imp From Url")
    assert stored["workflow_logic"]["imported_from"]["source"] == RAW_URL
    entry = next(l for l in import_logs(client, admin_h) if l["level"] == "ACTION" and l["details"].get("source", {}).get("url") == RAW_URL)
    assert entry["details"]["sha256"] == pv.json()["sha256"]


def test_api_github_url_asks_for_raw_content(client, admin_h, fake_github):
    fake_github["handler"] = lambda req: httpx.Response(200, content=json.dumps(make_pack(make_playbook("Imp Api Host"))).encode())
    url = "https://api.github.com/repos/example-org/example-repo/contents/packs/pack.json?ref=main"
    assert url_preview(client, admin_h, url).status_code == 200
    assert fake_github["calls"][0].headers["accept"] == "application/vnd.github.raw+json"


@pytest.mark.parametrize("url", [
    "http://raw.githubusercontent.com/o/r/main/pack.json",                    # not https
    "https://github.com/o/r/blob/main/pack.json",                              # HTML page host
    "https://evil.example.com/o/r/main/pack.json",
    "https://raw.githubusercontent.com.evil.example.com/o/r/main/pack.json",   # look-alike host
    "https://evil.example.com@raw.githubusercontent.com/o/r/main/pack.json",   # credentials
    "https://raw.githubusercontent.com:8443/o/r/main/pack.json",               # port
    "https://127.0.0.1/o/r/main/pack.json",
    "https://169.254.169.254/latest/meta-data/",
    "https://[::1]/o/r/main/pack.json",
    "https://raw.githubusercontent.com/o/r/main/pack.json?token=abc",          # query on raw
    "https://raw.githubusercontent.com/o/r/main/pack.json#frag",
    "https://raw.githubusercontent.com/o/r/main/../../etc/passwd.json",        # traversal
    "https://raw.githubusercontent.com/o/r/main/%2e%2e/x.json",
    "https://raw.githubusercontent.com/o/r/main/pack.txt",                     # not json
    "https://api.github.com/user",
    "https://api.github.com/repos/o/r/contents/pack.json?access_token=x",
    "https://api.github.com/repos/o/r/contents/pack.json?ref=a&ref=b",
    "file:///etc/passwd",
    "ftp://raw.githubusercontent.com/o/r/main/pack.json",
    "",
])
def test_disallowed_urls_are_refused_before_any_request(client, admin_h, fake_github, url):
    fake_github["handler"] = lambda req: pytest.fail("no request may be made")
    res = url_preview(client, admin_h, url) if url else client.post(
        "/api/playbooks/import/preview", json={"source": "url", "url": url}, headers=admin_h)
    assert res.status_code in (422,), res.text
    assert fake_github["calls"] == []


def test_refused_url_is_audited(client, admin_h, fake_github):
    assert url_preview(client, admin_h, "https://evil.example.com/o/r/main/pack.json").status_code == 422
    assert any(l["level"] == "WARNING" and "refused" in l["message"] and
               l["details"].get("url") == "https://evil.example.com/o/r/main/pack.json" for l in import_logs(client, admin_h))


def test_redirects_are_not_followed(client, admin_h, fake_github):
    fake_github["handler"] = lambda req: httpx.Response(302, headers={"location": "https://evil.example.com/x.json"})
    res = url_preview(client, admin_h, RAW_URL)
    assert res.status_code == 422 and "redirect" in res.text
    assert len(fake_github["calls"]) == 1  # the Location target was never requested


def test_host_resolving_to_a_private_address_is_refused(client, admin_h, monkeypatch):
    monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: ["10.0.0.5"])
    monkeypatch.setattr(pi, "make_http_client", lambda: pytest.fail("must not connect"))
    res = url_preview(client, admin_h, RAW_URL)
    assert res.status_code == 422 and "non-public" in res.text


def test_real_guard_blocks_private_address_at_connect_time(monkeypatch):
    """No mock client: the real guarded transport must refuse a private address (DNS rebinding case)."""
    answers = iter([[PUBLIC_IP], ["127.0.0.1"]])  # first lookup (pre-check) is public, the connect-time lookup is not
    monkeypatch.setattr(netguard, "resolve_host", lambda host, port=443: next(answers))
    with pytest.raises(pi.SourceError) as err:
        pi.fetch_pack_from_url(RAW_URL)
    assert "SSRF guard" in str(err.value) or "non-public" in str(err.value)


@pytest.mark.parametrize("status_code,fragment", [(404, "not found"), (403, "refused"), (429, "refused"), (500, "HTTP 500")])
def test_http_errors_are_reported(client, admin_h, fake_github, status_code, fragment):
    fake_github["handler"] = lambda req: httpx.Response(status_code, content=b"nope")
    res = url_preview(client, admin_h, RAW_URL)
    assert res.status_code == 422 and fragment in res.text


def test_oversize_download_is_cut_off(client, admin_h, fake_github):
    fake_github["handler"] = lambda req: httpx.Response(200, content=b"{" + b" " * (pi.MAX_PACK_BYTES + 100) + b"}")
    res = url_preview(client, admin_h, RAW_URL)
    assert res.status_code == 422 and "larger" in res.text
    fake_github["handler"] = lambda req: httpx.Response(200, headers={"content-length": str(pi.MAX_PACK_BYTES + 1)}, content=b"{}")
    assert "larger" in url_preview(client, admin_h, RAW_URL).text


def test_timeout_is_reported(client, admin_h, fake_github):
    def slow(req):
        raise httpx.ReadTimeout("slow", request=req)
    fake_github["handler"] = slow
    res = url_preview(client, admin_h, RAW_URL)
    assert res.status_code == 422 and "timed out" in res.text


def test_url_validation_unit():
    assert pi.validate_source_url(RAW_URL) == RAW_URL
    assert pi.validate_source_url("https://api.github.com/repos/o/r/contents/a/b.json?ref=v1.0")
    with pytest.raises(pi.SourceError):
        pi.validate_source_url(None)
    with pytest.raises(pi.SourceError):
        pi.validate_source_url("https://raw.githubusercontent.com/" + "a" * 3000 + ".json")


# --- display spoofing: invisible / bidirectional characters ------------------------------------------------------
SPOOF_CHARS = ["‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩",
               "​", "‌", "‍", "‎", "‏", "﻿", "⁠", "؜", "\U000e0041"]


@pytest.mark.parametrize("char", SPOOF_CHARS)
def test_invisible_and_bidi_characters_are_rejected_in_names_descriptions_and_string_params(char):
    cases = {
        "name": make_playbook(f"Imp Evil{char}Name"),
        "description": make_playbook(description=f"A description that hides {char} something from the reader."),
        "target_threat": make_playbook(target_threat=f"Mal{char}ware"),
        "param": make_playbook(workflow_logic={"steps": [{"action": "create_ticket", "params": {"priority": f"High{char}"}}]}),
        "note": make_playbook(workflow_logic={"steps": [{"action": "isolate_endpoint", "note": f"do{char}it"}]}),
        "keyword": make_playbook(workflow_logic={"keywords": [f"a{char}b"], "steps": [{"action": "isolate_endpoint"}]}),
    }
    for label, entry in cases.items():
        report = pi.build_report(raw(make_pack(entry)), [])
        item = report["items"][0]
        assert item["status"] == "rejected" and item["playbook"] is None, label
        assert any("invisible" in e or "control" in e for e in item["errors"]), (label, item["errors"])
    # pack metadata is checked too
    bad_meta = pi.build_report(raw(make_pack(make_playbook(), author=f"Jane{char}Doe")), [])
    assert bad_meta["pack_errors"] and "invisible" in bad_meta["pack_errors"][0]


def test_nested_string_params_are_checked_and_the_rejected_name_is_shown_cleaned():
    entry = make_playbook("Imp Name‮gnp.exe", workflow_logic={"steps": [
        {"action": "create_ticket", "params": {"priority": "High", "extra": ["ok", {"k": "v‮"}]}}]})
    item = pi.build_report(raw(make_pack(entry)), [])["items"][0]
    assert item["status"] == "rejected"
    assert item["name"] == "Imp Namegnp.exe" and "‮" not in json.dumps(item["name"])  # never echoed back to the console
    assert "‮" not in " ".join(item["errors"])


def test_ordinary_non_ascii_text_is_still_accepted():
    entry = make_playbook("Imp Phishing – Zahlungsaufforderung überprüfen", description="Prüfen Sie den Absender — 日本語 is fine too.")
    item = pi.build_report(raw(make_pack(entry)), [])["items"][0]
    assert item["status"] == "importable", item["errors"]


def test_a_spoofed_name_is_refused_over_the_api(client, admin_h):
    pack = make_pack(make_playbook("Imp Spoof\u202e"), make_playbook("Imp Fine Name"))
    res = preview(client, admin_h, pack)
    assert res.status_code == 200
    body = res.json()
    assert [i["status"] for i in body["items"]] == ["rejected", "importable"]
    assert "\u202e" not in res.text and "\\u202e" not in res.text  # the spoofed name is not echoed back
    done = do_import(client, admin_h, pack)
    assert done.status_code == 200
    assert [c["name"] for c in done.json()["created"]] == ["Imp Fine Name"]  # only the clean playbook exists
    names = [p["name"] for p in client.get("/api/playbooks?limit=200", headers=admin_h).json()]
    assert not any("\u202e" in n for n in names)


# --- the URL is never logged raw ---------------------------------------------------------------------------------
def test_safe_url_for_log_keeps_only_scheme_host_and_path():
    assert pi.safe_url_for_log("https://user:p4ss@raw.githubusercontent.com/o/r/main/x.json?token=abc#frag") == \
        "https://raw.githubusercontent.com/o/r/main/x.json"
    assert pi.safe_url_for_log("https://api.github.com/repos/o/r/contents/x.json?ref=main") == \
        "https://api.github.com/repos/o/r/contents/x.json"
    assert pi.safe_url_for_log("https://evil.example:8443/a‮b") == "https://evil.example:8443/ab"
    long = pi.safe_url_for_log("https://evil.example/" + "a" * 5000)
    assert len(long) <= 200 and long.endswith("...")
    for garbage in ("https://[bad", "not a url", "", None, 12345, "https://:pw@/path"):
        assert pi.safe_url_for_log(garbage).startswith("(")
    assert "p4ss" not in pi.safe_url_for_log("https://user:p4ss@host.example/x")


SECRET_URLS = [
    "https://alice:S3cretPw@raw.githubusercontent.com/example-org/example-repo/main/packs/pack.json",
    "https://raw.githubusercontent.com/example-org/example-repo/main/packs/pack.json?token=S3cretPw",
    "https://evil.example.com/o/r/main/pack.json?api_key=S3cretPw#S3cretPw",
    "https://bob:S3cretPw@evil.example.com:8443/o/r/main/pack.json",
    "http://carol:S3cretPw@raw.githubusercontent.com/o/r/main/pack.json",
]


@pytest.mark.parametrize("url", SECRET_URLS)
def test_a_url_with_credentials_never_reaches_system_logs(client, admin_h, fake_github, url):
    fake_github["handler"] = lambda req: httpx.Response(200, content=json.dumps(make_pack(make_playbook("Imp Secret Url"))).encode())
    for path in ("/api/playbooks/import/preview", "/api/playbooks/import"):
        body = {"source": "url", "url": url}
        if path.endswith("/import"):
            body["expected_sha256"] = "0" * 64
        client.post(path, json=body, headers=admin_h)
    from backend.database import SessionLocal
    from backend.models import SystemLog
    db = SessionLocal()
    try:
        dump = " ".join(f"{r.message} {r.target} {json.dumps(r.details, default=str)}" for r in db.query(SystemLog).all())
    finally:
        db.close()
    assert "S3cretPw" not in dump and "alice:" not in dump and "bob:" not in dump and "carol:" not in dump


def test_an_accepted_url_is_logged_and_stored_without_its_query(client, admin_h, fake_github):
    pack = make_pack(make_playbook("Imp Query Url"))
    fake_github["handler"] = lambda req: httpx.Response(200, content=json.dumps(pack).encode())
    url = "https://api.github.com/repos/example-org/example-repo/contents/packs/pack.json?ref=release-1"
    pv = url_preview(client, admin_h, url)
    assert pv.status_code == 200 and pv.json()["source"]["url"] == "https://api.github.com/repos/example-org/example-repo/contents/packs/pack.json"
    res = client.post("/api/playbooks/import", json={"source": "url", "url": url, "expected_sha256": pv.json()["sha256"]}, headers=admin_h)
    assert res.status_code == 200, res.text
    stored = client.get("/api/playbooks?limit=200", headers=admin_h).json()
    row = next(p for p in stored if p["name"] == "Imp Query Url")
    logic = row["workflow_logic"] if isinstance(row["workflow_logic"], dict) else json.loads(row["workflow_logic"])
    assert "?" not in logic["imported_from"]["source"] and "release-1" not in json.dumps(logic["imported_from"])
