"""Threat-intel honesty, IOC extraction, webhook ingestion and the lab demo seeder."""
import base64
import json
import uuid

import httpx
import pytest

from backend.engine.ingest import MAX_IOCS_PER_ALERT, escalated_severity, extract_iocs
from backend.integrations.nvd import NationalVulnerabilityDatabase
from backend.integrations.tip import LAB_FIXTURES, ThreatIntelligencePlatform, TipSettings

NO_KEYS_SIM = TipSettings(simulation_mode=True)
NO_KEYS_LIVE = TipSettings(simulation_mode=False)
RANDOM_SHA256 = "9f2c1b7e4d3a5f6e8c0b1a2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5"


def _tip(handler) -> ThreatIntelligencePlatform:
    return ThreatIntelligencePlatform(transport=httpx.MockTransport(handler), cache_ttl=0)


def _wazuh(level=8, **data):
    return {
        "rule": {"id": f"t-{uuid.uuid4().hex[:8]}", "level": level, "description": "Unit test detection"},
        "agent": {"id": "099", "name": "test-host-01", "ip": "10.9.9.9"},
        "data": data,
    }


# -- enrichment: no fabricated scores ----------------------------------------------------

@pytest.mark.parametrize("ioc_type,value", [("IP", "8.8.8.8"), ("Domain", "google.com"), ("Hash", RANDOM_SHA256), ("Domain", "github.com")])
def test_unknown_indicators_without_keys_are_unknown_not_malicious(ioc_type, value):
    res = ThreatIntelligencePlatform().enrich_ioc(ioc_type, value, settings=NO_KEYS_SIM)
    assert res["verdict"] == "Unknown"
    assert res["threat_score"] == 0
    assert res["severity"] is None
    assert res["enrichment_status"] == "not_configured"
    assert res["simulated"] is False
    assert len(res["providers"]) == 3
    assert {p["status"] for p in res["providers"].values()} == {"not_configured"}
    assert all(p["threat_score"] is None for p in res["providers"].values())


def test_lab_fixture_only_in_simulation_mode():
    tip = ThreatIntelligencePlatform()
    res = tip.enrich_ioc("IP", "198.51.100.45", settings=NO_KEYS_SIM)
    assert res["verdict"] == "Malicious"
    assert res["threat_score"] == LAB_FIXTURES["198.51.100.45"]["threat_score"]
    assert res["simulated"] is True
    assert {p["status"] for p in res["providers"].values()} == {"lab_fixture"}
    assert "lab fixture" in res["consensus"]["reason"].lower()
    assert res["abuseipdb"]["provider"] == "AbuseIPDB" and res["threatfox"] is None

    eicar = tip.enrich_ioc("Hash", "44D88612FEA8A8F36DE82E1278ABB02F", settings=NO_KEYS_SIM)
    assert eicar["verdict"] == "Malicious" and eicar["artifact_type"] == "HASH"
    assert eicar["threatfox"]["status"] == "lab_fixture"

    # Outside simulation mode the same documentation-range IP is never looked up or scored.
    off = tip.enrich_ioc("IP", "198.51.100.45", settings=NO_KEYS_LIVE)
    assert off["verdict"] == "Unknown"
    assert {p["status"] for p in off["providers"].values()} == {"skipped"}


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.10", "172.20.1.1", "127.0.0.1", "169.254.10.1", "fd00::1", "100.64.3.2"])
def test_private_and_reserved_ips_are_skipped(ip):
    calls = []
    tip = _tip(lambda req: calls.append(req) or httpx.Response(500))
    res = tip.enrich_ioc("IP", ip, settings=TipSettings(virustotal_api_key="k", otx_api_key="k", abuseipdb_api_key="k"))
    assert {p["status"] for p in res["providers"].values()} == {"skipped"}
    assert res["verdict"] == "Unknown"
    assert calls == []


def test_public_ip_with_private_looking_octets_is_not_private():
    # The old substring check treated 8.8.10.1 as internal because it contains "10."
    res = ThreatIntelligencePlatform().enrich_ioc("IP", "8.8.10.1", settings=NO_KEYS_SIM)
    assert {p["status"] for p in res["providers"].values()} == {"not_configured"}


# -- providers (mocked HTTP) -------------------------------------------------------------

def test_virustotal_404_is_not_found_not_malicious():
    tip = _tip(lambda req: httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    res = tip.enrich_ioc("Hash", RANDOM_SHA256, settings=TipSettings(virustotal_api_key="vt-key"))
    vt = res["providers"]["virustotal"]
    assert vt["status"] == "not_found"
    assert vt["threat_score"] is None
    assert res["verdict"] == "Unknown"
    assert res["threat_score"] == 0
    assert res["enrichment_status"] == "partial"  # VT answered, OTX/ThreatFox not configured


def test_virustotal_scoring_and_url_id():
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        stats = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20}
        if "files" in req.url.path:
            stats = {"malicious": 12, "suspicious": 1, "harmless": 0, "undetected": 50}
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})

    tip = _tip(handler)
    keys = TipSettings(virustotal_api_key="vt-key")
    bad = tip.enrich_ioc("Hash", RANDOM_SHA256, settings=keys)
    assert bad["verdict"] == "Malicious" and bad["providers"]["virustotal"]["threat_score"] == 100
    assert bad["providers"]["virustotal"]["summary"]["malicious"] == 12

    url = "https://example.org/a?b=c"
    clean = tip.enrich_ioc("URL", url, settings=keys)
    assert clean["verdict"] == "Clean" and clean["threat_score"] == 0 and clean["severity"] == "Low"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert seen[-1].url.path == f"/api/v3/urls/{url_id}"
    assert seen[-1].headers["x-apikey"] == "vt-key"


@pytest.mark.parametrize("code,needle", [(401, "authentication failed"), (403, "authentication failed"), (429, "rate limited")])
def test_virustotal_errors_are_reported(code, needle):
    tip = _tip(lambda req: httpx.Response(code))
    res = tip.enrich_ioc("Domain", "example.org", settings=TipSettings(virustotal_api_key="secret-key"))
    vt = res["providers"]["virustotal"]
    assert vt["status"] == "error" and needle in vt["error"]
    assert "secret-key" not in json.dumps(res)
    assert res["verdict"] == "Unknown" and res["enrichment_status"] == "unavailable"


def test_timeouts_never_raise():
    def handler(req):
        raise httpx.ConnectTimeout("slow", request=req)

    res = _tip(handler).enrich_ioc("IP", "8.8.8.8", settings=TipSettings(virustotal_api_key="k", abuseipdb_api_key="k"))
    assert res["providers"]["virustotal"]["status"] == "error"
    assert res["providers"]["virustotal"]["error"] == "request timed out"
    assert res["verdict"] == "Unknown"


def test_threatfox_request_and_results():
    bodies = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        bodies.append((req.headers.get("Auth-Key"), body))
        if body["search_term"] == "c2.example.net":
            return httpx.Response(200, json={"query_status": "ok", "data": [
                {"confidence_level": 75, "malware_printable": "Cobalt Strike", "threat_type_desc": "botnet C2"},
                {"confidence_level": 100, "malware_printable": "Cobalt Strike"},
            ]})
        return httpx.Response(200, json={"query_status": "no_result"})

    tip = _tip(handler)
    keys = TipSettings(threatfox_api_key="tf-key")
    hit = tip.enrich_ioc("Domain", "c2.example.net", settings=keys)
    assert hit["providers"]["threatfox"]["status"] == "live"
    assert hit["threat_score"] == 100 and hit["verdict"] == "Malicious" and hit["severity"] == "Critical"
    assert hit["providers"]["threatfox"]["summary"]["malware_families"] == ["Cobalt Strike"]
    assert bodies[0] == ("tf-key", {"query": "search_ioc", "search_term": "c2.example.net"})

    miss = tip.enrich_ioc("Domain", "nothing.example.net", settings=keys)
    assert miss["providers"]["threatfox"]["status"] == "not_found" and miss["verdict"] == "Unknown"


def test_abuseipdb_semantics():
    answers = {
        "8.8.8.8": {"abuseConfidenceScore": 0, "totalReports": 3, "isWhitelisted": True},
        "1.2.3.4": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": False},
        "5.6.7.8": {"abuseConfidenceScore": 88, "totalReports": 140, "isWhitelisted": False},
    }

    def handler(req: httpx.Request):
        assert req.headers["Key"] == "ab-key" and req.url.params["maxAgeInDays"] == "90"
        return httpx.Response(200, json={"data": answers[req.url.params["ipAddress"]]})

    tip = _tip(handler)
    keys = TipSettings(abuseipdb_api_key="ab-key")
    assert tip.enrich_ioc("IP", "8.8.8.8", settings=keys)["verdict"] == "Clean"
    unknown = tip.enrich_ioc("IP", "1.2.3.4", settings=keys)
    assert unknown["providers"]["abuseipdb"]["status"] == "not_found" and unknown["verdict"] == "Unknown"
    bad = tip.enrich_ioc("IP", "5.6.7.8", settings=keys)
    assert bad["threat_score"] == 88 and bad["verdict"] == "Malicious"


def test_otx_semantics_and_endpoints():
    paths = []

    def handler(req: httpx.Request):
        paths.append(req.url.path)
        if "google.com" in req.url.path:
            return httpx.Response(200, json={"pulse_info": {"count": 50, "pulses": []}, "validation": [{"source": "alexa"}]})
        if "busy" in req.url.path:
            return httpx.Response(200, json={"pulse_info": {"count": 9, "pulses": [{"tags": ["c2"]}]}, "validation": []})
        return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}, "validation": []})

    tip = _tip(handler)
    keys = TipSettings(otx_api_key="otx-key")
    assert tip.enrich_ioc("Domain", "google.com", settings=keys)["verdict"] == "Clean"
    busy = tip.enrich_ioc("Domain", "busy.example.org", settings=keys)
    assert busy["threat_score"] == 60 and busy["verdict"] == "Suspicious"  # OTX alone never reaches Malicious
    none = tip.enrich_ioc("IP", "2606:4700:4700::1111", settings=keys)
    assert none["providers"]["alienvault_otx"]["status"] == "not_found"
    assert "/indicators/domain/google.com/general" in paths[0]
    assert "/indicators/hostname/busy.example.org/general" in paths[1]
    assert "/indicators/IPv6/" in paths[2]


def test_keys_saved_in_configuration_are_used(client):
    from backend.database import SessionLocal
    from backend.integrations.tip import load_tip_settings
    from backend.models import SystemConfig

    db = SessionLocal()
    row = db.query(SystemConfig).filter_by(category="TIP", key_name="virustotal_api_key").first()
    created = row is None
    if created:
        row = SystemConfig(category="TIP", key_name="virustotal_api_key", key_value="", is_secret=True)
        db.add(row)
    previous = row.key_value
    try:
        row.key_value = "saved-from-ui"
        db.commit()
        assert load_tip_settings().virustotal_api_key == "saved-from-ui"
    finally:
        if created:
            db.delete(row)
        else:
            row.key_value = previous
        db.commit()
        db.close()
    assert load_tip_settings().virustotal_api_key == ""


# -- IOC extraction ---------------------------------------------------------------------

def test_extract_iocs_types_dedupe_and_exclusions():
    payload = _wazuh(
        srcip="198.51.100.45",
        dstip="198.51.100.45",
        file_hash="44D88612FEA8A8F36DE82E1278ABB02F",
        sender="someone@mail.example.org",
        process="C:\\Windows\\Temp\\dropper.exe",
        nested={"remote": "conn from 2606:4700:4700::1111 port 443", "mac": "00:1a:2b:3c:4d:5e"},
        url="https://login.example.net/verify?id=1",
    )
    payload["severity"] = "Critical"
    payload["full_log"] = (
        "at 2024-01-01T10:22:33.123Z host 10.9.9.9 contacted 8.8.8.8 and c2.example.org; "
        "dropped shell.php and update.zip; sha1 3395856ce81f2b7382dee72602f798b642f14140; dc01.corp.local"
    )
    iocs, dropped = extract_iocs(payload)
    pairs = [(i["artifact_type"], i["value"]) for i in iocs]
    assert dropped == 0
    assert ("IP", "198.51.100.45") in pairs and pairs.count(("IP", "198.51.100.45")) == 1
    assert ("Hash", "44d88612fea8a8f36de82e1278abb02f") in pairs
    assert ("Hash", "3395856ce81f2b7382dee72602f798b642f14140") in pairs
    assert ("IP", "2606:4700:4700::1111") in pairs
    assert ("URL", "https://login.example.net/verify?id=1") in pairs
    assert ("Domain", "login.example.net") in pairs
    assert ("Domain", "c2.example.org") in pairs
    assert ("IP", "8.8.8.8") in pairs
    values = {v for _, v in pairs}
    assert "10.9.9.9" not in values  # the reporting agent's own IP
    assert not {"shell.php", "update.zip", "dropper.exe", "mail.example.org", "dc01.corp.local"} & values


def test_extract_iocs_cap_reports_dropped():
    payload = {"full_log": " ".join(f"8.8.{i // 200}.{i % 200 + 1}" for i in range(MAX_IOCS_PER_ALERT + 7))}
    iocs, dropped = extract_iocs(payload)
    assert len(iocs) == MAX_IOCS_PER_ALERT and dropped == 7


def test_escalation_is_bounded():
    assert escalated_severity("Low", ["Malicious"]) == "Medium"
    assert escalated_severity("Medium", ["Malicious", "Unknown"]) == "High"
    assert escalated_severity("High", ["Malicious"]) is None
    assert escalated_severity("Critical", ["Malicious"]) is None
    assert escalated_severity("Low", ["Unknown", "Suspicious", "Clean"]) is None


# -- webhooks ---------------------------------------------------------------------------

def test_webhooks_require_ingest_token(client):
    for path in ("/api/webhooks/wazuh", "/api/webhooks/edr", "/api/webhooks/xdr"):
        assert client.post(path, json=_wazuh()).status_code == 401
        assert client.post(path, json=_wazuh(), headers={"X-Phantom-Ingest-Token": "wrong"}).status_code == 401


def test_webhook_rejects_oversized_and_non_object_bodies(client, ingest_headers):
    big = json.dumps({"full_log": "A" * (1024 * 1024 + 10)})
    resp = client.post("/api/webhooks/wazuh", content=big, headers={**ingest_headers, "Content-Type": "application/json"})
    assert resp.status_code == 413
    assert client.post("/api/webhooks/wazuh", json=[1, 2], headers=ingest_headers).status_code == 422
    resp = client.post("/api/webhooks/wazuh", content=b"{not json", headers={**ingest_headers, "Content-Type": "application/json"})
    assert resp.status_code == 422


def test_wazuh_ingest_stores_tip_results(client, ingest_headers):
    from backend.database import SessionLocal
    from backend.models import IocArtifact

    resp = client.post("/api/webhooks/wazuh", json=_wazuh(level=8, srcip="198.51.100.45", dstip="8.8.8.8"), headers=ingest_headers)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["status"] == "Success" and data["ioc_count"] == 2 and data["iocs_dropped"] == 0
    assert data["processing"] in ("sync", "celery", "failed")
    by_value = {i["value"]: i for i in data["iocs"]}
    assert by_value["198.51.100.45"]["verdict"] == "Malicious"
    assert by_value["198.51.100.45"]["tip_results"]["virustotal"]["status"] == "lab_fixture"
    assert by_value["8.8.8.8"]["verdict"] == "Unknown"
    assert by_value["8.8.8.8"]["enrichment_status"] == "not_configured"
    assert by_value["8.8.8.8"]["threat_score"] == 0

    db = SessionLocal()
    try:
        stored = db.query(IocArtifact).filter(IocArtifact.alert_id == data["alert_id"]).all()
        assert {a.value for a in stored} == {"198.51.100.45", "8.8.8.8"}
        assert all(a.tip_results and set(a.tip_results) == {"virustotal", "alienvault_otx", "abuseipdb"} for a in stored)
    finally:
        db.close()


def test_wazuh_severity_override_is_ignored(client, ingest_headers):
    payload = _wazuh(level=3)
    payload["severity"] = "Critical"
    data = client.post("/api/webhooks/wazuh", json=payload, headers=ingest_headers).json()
    assert data["severity"] == "Low"
    assert data["severity_basis"] == "Wazuh rule.level 3"


def test_malicious_evidence_escalates_one_step_unknown_does_not(client, ingest_headers):
    low_bad = client.post("/api/webhooks/wazuh", json=_wazuh(level=3, srcip="198.51.100.45"), headers=ingest_headers).json()
    assert low_bad["severity"] == "Medium" and low_bad["escalated_from"] == "Low"

    high_bad = client.post("/api/webhooks/wazuh", json=_wazuh(level=10, srcip="198.51.100.45"), headers=ingest_headers).json()
    assert high_bad["severity"] == "High" and high_bad["escalated_from"] is None

    low_unknown = client.post("/api/webhooks/wazuh", json=_wazuh(level=3, srcip="8.8.8.8"), headers=ingest_headers).json()
    assert low_unknown["severity"] == "Low" and low_unknown["escalated_from"] is None


def test_edr_and_xdr_severity_is_validated(client, ingest_headers):
    edr = client.post("/api/webhooks/edr", json={
        "rule_id": "EDR-T1", "severity": "high",
        "agent": {"hostname": "wks-22"}, "process": {"name": "evil.exe", "pid": 4242},
    }, headers=ingest_headers).json()
    assert edr["severity"] == "High" and edr["target_host"] == "wks-22" and edr["target_process"] == "evil.exe"

    xdr = client.post("/api/webhooks/xdr", json={
        "incident_id": "XDR-T1", "severity": "apocalyptic", "correlated_layers": ["Endpoint", "Network"],
    }, headers=ingest_headers).json()
    assert xdr["severity"] == "Medium" and xdr["correlated_layers"] == ["Endpoint", "Network"]


def test_reenrich_updates_artifacts_without_changing_severity(client, ingest_headers):
    from backend.database import SessionLocal
    from backend.engine.ingest import reenrich_alert_iocs
    from backend.models import Alert

    data = client.post("/api/webhooks/wazuh", json=_wazuh(level=3, srcip="198.51.100.45"), headers=ingest_headers).json()
    db = SessionLocal()
    try:
        summary = reenrich_alert_iocs(db, data["alert_id"])
        assert summary["iocs_enriched"] == 1 and summary["verdicts"] == {"Malicious": 1}
        assert db.get(Alert, data["alert_id"]).severity == data["severity"]
    finally:
        db.close()


# -- demo seeder ------------------------------------------------------------------------

def _analyst_headers():
    from backend.database import SessionLocal
    from backend.models import User
    from backend.security import create_access_token, hash_password

    name = f"tip_analyst_{uuid.uuid4().hex[:6]}"
    db = SessionLocal()
    try:
        db.add(User(username=name, password_hash=hash_password("Analyst-Passphrase-2026!"), role="SOC Analyst"))
        db.commit()
    finally:
        db.close()
    return {"Authorization": f"Bearer {create_access_token({'sub': name})}"}


def test_demo_seed_requires_admin(client):
    assert client.post("/api/demo/seed").status_code == 401
    assert client.post("/api/demo/seed", headers=_analyst_headers()).status_code == 403


def test_demo_seed_runs_lab_payloads_through_pipeline(client, admin_headers):
    resp = client.post("/api/demo/seed", headers=admin_headers)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["simulation_mode"] is True and body["seeded_playbooks_count"] >= 12
    by_scenario = {a["scenario"]: a for a in body["seeded_alerts"]}
    assert set(by_scenario) == {"ransomware", "phishing", "webshell", "recon"}

    assert by_scenario["ransomware"]["severity"] == "Critical"
    assert set(by_scenario["ransomware"]["ioc_verdicts"].values()) == {"Malicious"}
    assert by_scenario["phishing"]["severity"] == "Medium"
    assert "Malicious" not in by_scenario["phishing"]["ioc_verdicts"].values()
    assert by_scenario["webshell"]["severity"] == "High"
    assert by_scenario["recon"]["severity"] == "Low"
    assert set(by_scenario["recon"]["ioc_verdicts"].values()) == {"Unknown"}
    assert by_scenario["recon"]["max_threat_score"] == 0


def test_demo_seed_refused_outside_simulation_mode(client, admin_headers):
    from backend.database import SessionLocal
    from backend.models import SystemConfig

    db = SessionLocal()
    row = db.query(SystemConfig).filter_by(category="ORCHESTRATION", key_name="simulation_mode").first()
    created = row is None
    if created:
        row = SystemConfig(category="ORCHESTRATION", key_name="simulation_mode", key_value="true", is_secret=False)
        db.add(row)
    previous = row.key_value
    try:
        row.key_value = "false"
        db.commit()
        assert client.post("/api/demo/seed", headers=admin_headers).status_code == 409
    finally:
        if created:
            db.delete(row)
        else:
            row.key_value = previous
        db.commit()
        db.close()


# -- NVD --------------------------------------------------------------------------------

def test_nvd_without_key_reports_not_configured_and_infers_nothing():
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert nvd.extract_cves_from_text("cve-2021-44228 then CVE-2024-3094 and CVE-2021-44228") == ["CVE-2021-44228", "CVE-2024-3094"]
    detail = nvd.get_vulnerability_details("CVE-2024-3094")
    assert detail["status"] == "not_configured" and detail["cvss_score"] is None and detail["hotl_action"] == "none"

    # Keywords such as "log4j" or a High severity never produce a CVE.
    analysis = nvd.analyze_alert_vulnerabilities({"rule_id": "x", "severity": "Critical", "raw_payload": {"full_log": "log4j jndi backdoor"}})
    assert analysis["cves_detected"] == [] and analysis["lookup_status"] == "no_cves"
    assert analysis["max_cvss_score"] is None and analysis["hotl_autonomous_policy"]["eligible_for_hotl"] is False


def test_nvd_live_lookup(monkeypatch):
    import backend.integrations.nvd as nvd_module

    def handler(req: httpx.Request):
        assert req.headers["apiKey"] == "nvd-key" and req.url.params["cveId"] == "CVE-2021-44228"
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Log4j JNDI RCE"}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "baseScore": 10.0, "baseSeverity": "CRITICAL", "attackVector": "NETWORK",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},
            "weaknesses": [{"description": [{"value": "CWE-502"}]}],
            "cisaExploitAdd": "2021-12-10", "cisaRequiredAction": "Apply updates per vendor instructions.",
        }}]})

    monkeypatch.setattr(nvd_module.integration_config, "get_setting", lambda key, *a, **k: "nvd-key" if key == "nvd_api_key" else "")
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(handler))
    analysis = nvd.analyze_alert_vulnerabilities({"rule_id": "r", "raw_payload": {"full_log": "exploit for CVE-2021-44228"}})
    detail = analysis["vulnerabilities"][0]
    assert detail["status"] == "live" and detail["cvss_score"] == 10.0 and detail["cwe"] == "CWE-502"
    assert detail["known_exploited"] is True
    assert analysis["lookup_status"] == "live" and analysis["max_cvss_score"] == 10.0
    assert analysis["hotl_autonomous_policy"]["eligible_for_hotl"] is True
