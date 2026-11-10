import pytest
from backend.integrations.edr import edr_client
from backend.integrations.tip import tip_client
from backend.integrations.firewall import firewall_client
from backend.integrations.iam import iam_client
from backend.integrations.itsm import itsm_client

def test_edr_isolate_and_terminate():
    iso_res = edr_client.isolate_endpoint("host-test-99", "dc-test")
    assert iso_res["status"] == "Success"
    assert "isolate_endpoint" == iso_res["action"]

    term_res = edr_client.terminate_process("host-test-99", pid=9999, process_name="evil.exe")
    assert term_res["status"] == "Success"
    assert "evil.exe" == term_res["process_name"]

def test_tip_enrichment():
    # Tests run in simulation mode with no API keys: only explicit lab fixtures carry a score.
    res = tip_client.enrich_ioc("IP", "198.51.100.45")
    assert res["artifact_type"] == "IP"
    assert res["threat_score"] > 50
    assert res["verdict"] == "Malicious"
    assert res["simulated"] is True
    assert res["providers"]["abuseipdb"]["status"] == "lab_fixture"

    hash_res = tip_client.enrich_ioc("Hash", "44d88612fea8a8f36de82e1278abb02f")  # EICAR test file
    assert hash_res["threat_score"] >= 80

    unknown = tip_client.enrich_ioc("Domain", "google.com")
    assert unknown["verdict"] == "Unknown"
    assert unknown["threat_score"] == 0

def test_firewall_block():
    fw_res = firewall_client.block_ip("198.51.100.45")
    assert fw_res["status"] == "Success"
    assert fw_res["ip_address"] == "198.51.100.45"
    assert "198.51.100.45" in firewall_client.blocked_ips

def test_iam_disable_and_revoke():
    iam_res = iam_client.disable_user_account("compromised_user@corp.local")
    assert iam_res["status"] == "Success"
    assert iam_res["account_status"] == "DISABLED"

    sess_res = iam_client.revoke_user_sessions("compromised_user@corp.local")
    assert sess_res["status"] == "Success"

def test_itsm_ticket():
    ticket = itsm_client.create_jira_ticket(alert_id=101, summary="Ransomware alert", description="Test", priority="Critical")
    assert ticket["status"] == "Success"
    assert "SEC-" in ticket["ticket_key"]
