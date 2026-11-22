"""WS4: threat-intel rate limiting, ThreatFox/OTX correctness, VirusTotal scoring, bounded caches, NVD."""
import json
import threading

import httpx
import pytest

import backend.integrations.nvd as nvd_module
from backend.integrations import tip as tip_module
from backend.integrations.nvd import NationalVulnerabilityDatabase
from backend.integrations.tip import (
    RateLimiter, ThreatIntelligencePlatform, TipSettings, otx_domain_section, parse_retry_after,
    registrable_domain,
)

SHA256 = "9f2c1b7e4d3a5f6e8c0b1a2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5"
MD5 = "9f2c1b7e4d3a5f6e8c0b1a2d3e4f5a6b"
SHA1 = "9f2c1b7e4d3a5f6e8c0b1a2d3e4f5a6b7c8d9e0f"


def _tip(handler, **kw) -> ThreatIntelligencePlatform:
    return ThreatIntelligencePlatform(transport=httpx.MockTransport(handler), **kw)


def _vt_body(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected}}}}


# -- rate limiter ----------------------------------------------------------------------------

def test_rate_limiter_window_and_bounded_wait():
    lim = RateLimiter(per_window=2, window_seconds=60)
    assert lim.acquire(0) == (True, 0.0)
    assert lim.acquire(0) == (True, 0.0)
    ok, retry = lim.acquire(max_wait=1.0)
    assert ok is False and 50 < retry <= 60  # never waits longer than max_wait


def test_rate_limiter_short_wait_is_granted_and_slot_reserved():
    lim = RateLimiter(per_window=1, window_seconds=0.2)
    assert lim.acquire(0) == (True, 0.0)
    ok, wait = lim.acquire(max_wait=1.0)
    assert ok is True and 0 < wait <= 0.2


def test_rate_limiter_daily_quota_resets_at_utc_midnight(monkeypatch):
    from datetime import datetime, timezone

    clock = {"now": datetime(2026, 1, 1, 23, 0, tzinfo=timezone.utc)}
    lim = RateLimiter(per_day=2)
    monkeypatch.setattr(lim, "_utcnow", lambda: clock["now"])
    assert lim.acquire(0)[0] and lim.acquire(0)[0]
    ok, retry = lim.acquire(0)
    assert ok is False and retry == 3600
    clock["now"] = datetime(2026, 1, 2, 0, 0, 1, tzinfo=timezone.utc)
    assert lim.acquire(0)[0] is True


def test_rate_limiter_is_thread_safe():
    lim = RateLimiter(per_window=10, window_seconds=60)
    granted = []

    def work():
        granted.append(lim.acquire(0)[0])

    threads = [threading.Thread(target=work) for _ in range(40)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert granted.count(True) == 10


def test_parse_retry_after_seconds_date_and_garbage():
    assert parse_retry_after("120") == 120
    assert parse_retry_after("0") == 1
    assert parse_retry_after("nonsense", default=45) == 45
    assert parse_retry_after(None) == 60
    assert parse_retry_after("999999999") == 24 * 3600
    assert 1 <= parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT") <= 24 * 3600


# -- provider budget / 429 --------------------------------------------------------------------

def test_virustotal_429_honours_retry_after_and_blocks_further_calls():
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(429, headers={"Retry-After": "120"}, json={"error": {"code": "QuotaExceededError"}})

    tip = _tip(handler)
    keys = TipSettings(virustotal_api_key="k")
    res = tip.enrich_ioc("Domain", "example.org", settings=keys)
    vt = res["providers"]["virustotal"]
    assert vt["status"] == "rate_limited" and vt["retry_after_seconds"] == 120
    assert vt["threat_score"] is None and vt["verdict"] is None
    assert res["verdict"] == "Unknown" and res["threat_score"] == 0 and res["severity"] is None
    assert res["incomplete"] is True and res["retry_after_seconds"] == 120
    assert res["consensus"]["incomplete"] is True and "not evidence" in res["consensus"]["reason"]

    again = tip.enrich_ioc("Domain", "example.org", settings=keys)
    assert again["providers"]["virustotal"]["status"] == "rate_limited"
    assert 100 <= again["providers"]["virustotal"]["retry_after_seconds"] <= 120
    assert len(calls) == 1  # provider is blocked locally until Retry-After has passed


def test_virustotal_per_minute_budget_returns_rate_limited_without_http():
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(200, json=_vt_body())

    tip = _tip(handler, cache_ttl=0)
    keys = TipSettings(virustotal_api_key="k", vt_requests_per_minute=2, max_wait_seconds=0.0)
    results = [tip.enrich_ioc("Domain", f"host{i}.example.org", settings=keys) for i in range(4)]
    statuses = [r["providers"]["virustotal"]["status"] for r in results]
    assert statuses == ["live", "live", "rate_limited", "rate_limited"]
    assert len(calls) == 2
    limited = results[2]
    assert limited["verdict"] == "Unknown" and limited["incomplete"] is True
    assert limited["providers"]["virustotal"]["retry_after_seconds"] >= 1


def test_daily_quota_for_abuseipdb():
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})

    tip = _tip(handler, cache_ttl=0)
    keys = TipSettings(abuseipdb_api_key="k", abuseipdb_daily_limit=1)
    first = tip.enrich_ioc("IP", "8.8.8.8", settings=keys)
    second = tip.enrich_ioc("IP", "8.8.4.4", settings=keys)
    assert first["providers"]["abuseipdb"]["status"] == "not_found"
    ab = second["providers"]["abuseipdb"]
    assert ab["status"] == "rate_limited" and ab["retry_after_seconds"] >= 1
    assert len(calls) == 1


def test_rate_limited_is_never_clean_even_with_other_answers():
    def handler(req):
        if "virustotal" in req.url.host:
            return httpx.Response(429)
        return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}, "validation": []})

    res = _tip(handler).enrich_ioc("Domain", "example.org", settings=TipSettings(virustotal_api_key="k", otx_api_key="k"))
    assert res["providers"]["virustotal"]["status"] == "rate_limited"
    assert res["providers"]["virustotal"]["retry_after_seconds"] == 60  # default when no header
    assert res["verdict"] == "Unknown" and res["incomplete"] is True
    assert res["enrichment_status"] == "partial"


def test_rate_limited_and_error_are_never_cached():
    state = {"n": 0}

    def handler(req):
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        if state["n"] == 2:
            return httpx.Response(500)
        return httpx.Response(200, json=_vt_body())

    tip = _tip(handler, cache_ttl=900)
    keys = TipSettings(virustotal_api_key="k", vt_requests_per_minute=0, vt_requests_per_day=0)
    assert tip.enrich_ioc("Domain", "example.org", settings=keys)["providers"]["virustotal"]["status"] == "rate_limited"
    tip.reset_rate_limits()
    assert tip.enrich_ioc("Domain", "example.org", settings=keys)["providers"]["virustotal"]["status"] == "error"
    assert tip.enrich_ioc("Domain", "example.org", settings=keys)["providers"]["virustotal"]["status"] == "live"
    assert len(tip._cache) == 1


def test_error_only_answers_are_incomplete_unknown():
    res = _tip(lambda req: httpx.Response(500)).enrich_ioc("Domain", "example.org", settings=TipSettings(virustotal_api_key="k"))
    assert res["verdict"] == "Unknown" and res["incomplete"] is True and res["retry_after_seconds"] is None


def test_complete_answers_are_not_flagged_incomplete():
    res = _tip(lambda req: httpx.Response(200, json=_vt_body())).enrich_ioc(
        "Domain", "example.org", settings=TipSettings(virustotal_api_key="k"))
    assert res["incomplete"] is False and res["verdict"] == "Clean"


# -- ThreatFox ---------------------------------------------------------------------------------

def _threatfox_tip(bodies, data):
    def handler(req):
        body = json.loads(req.content)
        bodies.append(body)
        return httpx.Response(200, json={"query_status": "ok", "data": data})

    return _tip(handler, cache_ttl=0)


KEYS_TF = TipSettings(threatfox_api_key="tf")


def test_threatfox_hash_uses_search_hash():
    bodies = []
    tip = _threatfox_tip(bodies, [{"confidence_level": 80, "ioc": "1.2.3.4:443"}])
    res = tip.enrich_ioc("Hash", SHA256, settings=KEYS_TF)
    assert bodies == [{"query": "search_hash", "hash": SHA256}]
    assert res["providers"]["threatfox"]["status"] == "live" and res["providers"]["threatfox"]["threat_score"] == 80
    tip.enrich_ioc("Hash", MD5.upper(), settings=KEYS_TF)
    assert bodies[-1] == {"query": "search_hash", "hash": MD5}


def test_threatfox_sha1_is_skipped_without_request():
    bodies = []
    res = _threatfox_tip(bodies, []).enrich_ioc("Hash", SHA1, settings=KEYS_TF)
    assert bodies == []
    assert res["providers"]["threatfox"]["status"] == "skipped"


def test_threatfox_ip_searches_bare_ip_and_matches_ip_port_only():
    bodies = []
    data = [
        {"ioc": "8.8.8.8:443", "confidence_level": 90, "malware_printable": "Cobalt Strike"},
        {"ioc": "8.8.8.80:80", "confidence_level": 100},  # wildcard noise, a different address
    ]
    res = _threatfox_tip(bodies, data).enrich_ioc("IP", "8.8.8.8", settings=TipSettings(threatfox_api_key="x"))
    # IPs only go to the third provider slot AbuseIPDB, so call the provider directly as well.
    tf = ThreatIntelligencePlatform(transport=httpx.MockTransport(lambda r: (
        bodies.append(json.loads(r.content)) or httpx.Response(200, json={"query_status": "ok", "data": data}))))
    out = tf.query_threatfox("IP", "8.8.8.8", "tf")
    assert bodies[-1] == {"query": "search_ioc", "search_term": "8.8.8.8", "exact_match": False}
    assert out["status"] == "live" and out["summary"]["matches"] == 1 and out["threat_score"] == 90
    assert res["artifact_type"] == "IP"


def test_threatfox_ip_wildcard_noise_alone_is_not_found():
    data = [{"ioc": "8.8.8.80:80", "confidence_level": 100}]
    tf = ThreatIntelligencePlatform(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"query_status": "ok", "data": data})))
    assert tf.query_threatfox("IP", "8.8.8.8", "tf")["status"] == "not_found"


def test_threatfox_domain_and_url_use_exact_search_ioc():
    bodies = []
    tip = _threatfox_tip(bodies, [{"confidence_level": 75}])
    tip.enrich_ioc("Domain", "c2.example.net", settings=KEYS_TF)
    tip.enrich_ioc("URL", "http://c2.example.net/x", settings=KEYS_TF)
    assert bodies[0] == {"query": "search_ioc", "search_term": "c2.example.net", "exact_match": True}
    assert bodies[1] == {"query": "search_ioc", "search_term": "http://c2.example.net/x", "exact_match": True}


@pytest.mark.parametrize("level,expected_verdict,expected_score", [
    (100, "Malicious", 100), (75, "Malicious", 75), (50, "Suspicious", 50), (10, "Suspicious", 30), (None, "Suspicious", 50),
])
def test_threatfox_score_follows_confidence_and_a_listing_is_never_clean(level, expected_verdict, expected_score):
    entry = {"ioc": "x"} if level is None else {"ioc": "x", "confidence_level": level}
    res = _threatfox_tip([], [entry]).enrich_ioc("Domain", "c2.example.net", settings=KEYS_TF)
    assert res["verdict"] == expected_verdict and res["threat_score"] == expected_score


def test_threatfox_429_is_rate_limited():
    tip = _tip(lambda r: httpx.Response(429, headers={"Retry-After": "30"}))
    res = tip.enrich_ioc("Domain", "c2.example.net", settings=KEYS_TF)
    assert res["providers"]["threatfox"]["status"] == "rate_limited"
    assert res["providers"]["threatfox"]["retry_after_seconds"] == 30


# -- OTX ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("host,apex", [
    ("example.com", "example.com"), ("www.example.com", "example.com"), ("a.b.example.org", "example.org"),
    ("example.co.uk", "example.co.uk"), ("www.example.co.uk", "example.co.uk"), ("evil.com.au", "evil.com.au"),
    ("x.evil.com.br", "evil.com.br"), ("user.github.io", "user.github.io"), ("a.user.github.io", "user.github.io"),
    ("shop.example.co.jp", "example.co.jp"),
])
def test_registrable_domain(host, apex):
    assert registrable_domain(host) == apex
    assert otx_domain_section(host) == ("domain" if host == apex else "hostname")


def test_otx_domain_vs_hostname_and_url_form():
    paths = []

    def handler(req):
        paths.append(req.url.raw_path.decode())
        return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}, "validation": []})

    tip = _tip(handler, cache_ttl=0)
    keys = TipSettings(otx_api_key="k")
    tip.enrich_ioc("Domain", "example.co.uk", settings=keys)
    tip.enrich_ioc("Domain", "www.example.co.uk", settings=keys)
    tip.enrich_ioc("URL", "http://evil.example.org/a/b.php?x=1&y=2#frag", settings=keys)
    assert paths[0] == "/api/v1/indicators/domain/example.co.uk/general"
    assert paths[1] == "/api/v1/indicators/hostname/www.example.co.uk/general"
    # scheme kept, fragment dropped, "?" and "&" encoded so they stay inside the path segment
    assert paths[2] == "/api/v1/indicators/url/http://evil.example.org/a/b.php%3Fx%3D1%26y%3D2/general"


def test_otx_429_is_rate_limited():
    res = _tip(lambda r: httpx.Response(429, headers={"Retry-After": "7"})).enrich_ioc(
        "Domain", "example.org", settings=TipSettings(otx_api_key="k"))
    assert res["providers"]["alienvault_otx"]["status"] == "rate_limited"
    assert res["providers"]["alienvault_otx"]["retry_after_seconds"] == 7


# -- VirusTotal scoring ------------------------------------------------------------------------

def _vt_verdict(settings, **stats):
    tip = _tip(lambda r: httpx.Response(200, json=_vt_body(**stats)), cache_ttl=0)
    res = tip.enrich_ioc("Domain", "example.org", settings=settings)
    return res["verdict"], res["threat_score"], res["providers"]["virustotal"]["summary"]


def test_five_engines_alone_is_not_malicious_by_default():
    verdict, score, summary = _vt_verdict(TipSettings(virustotal_api_key="k"), malicious=5, harmless=60, undetected=10)
    assert verdict == "Suspicious" and 30 <= score < 70
    assert summary["weighted_detections"] == 5.0 and summary["detection_ratio"] < 0.10


def test_vt_ratio_reaches_malicious():
    verdict, score, _ = _vt_verdict(TipSettings(virustotal_api_key="k"), malicious=10, harmless=60, undetected=5)
    assert verdict == "Malicious" and score >= 70
    verdict, score, _ = _vt_verdict(TipSettings(virustotal_api_key="k"), malicious=40, harmless=30, undetected=5)
    assert verdict == "Malicious" and score == 100


def test_vt_min_detections_blocks_small_engine_sets():
    # 3 of 10 engines is a 30 % ratio but only 3 detections: never Malicious with the default minimum of 5.
    verdict, score, _ = _vt_verdict(TipSettings(virustotal_api_key="k"), malicious=3, harmless=5, undetected=2)
    assert verdict == "Suspicious" and score == 69


def test_vt_one_or_two_engines_stay_clean_or_low():
    assert _vt_verdict(TipSettings(virustotal_api_key="k"), malicious=1)[0] == "Clean"


def test_vt_weights_and_thresholds_are_configurable():
    strict = TipSettings(virustotal_api_key="k", vt_malicious_weight=1.0, vt_malicious_threshold=0.05, vt_min_detections=3)
    assert _vt_verdict(strict, malicious=5, harmless=60, undetected=10)[0] == "Malicious"
    heavy_suspicious = TipSettings(virustotal_api_key="k", vt_suspicious_weight=1.0, vt_min_detections=1)
    verdict, _, summary = _vt_verdict(heavy_suspicious, suspicious=8, harmless=62, undetected=0)
    assert verdict == "Malicious" and summary["weighted_detections"] == 8.0
    light = TipSettings(virustotal_api_key="k", vt_suspicious_weight=0.0)
    assert _vt_verdict(light, suspicious=20, harmless=50, undetected=0)[2]["weighted_detections"] == 0.0


def test_consensus_thresholds_are_configurable():
    s = TipSettings(virustotal_api_key="k", malicious_threshold=90, suspicious_threshold=50, critical_threshold=95)
    verdict, score, _ = _vt_verdict(s, malicious=6, harmless=64, undetected=5)
    assert 70 <= score < 90 and verdict == "Suspicious"  # a score of 72 is Malicious with the default threshold of 70
    res = _tip(lambda r: httpx.Response(200, json=_vt_body(malicious=40, harmless=30, undetected=5))).enrich_ioc(
        "Domain", "example.org", settings=s)
    assert res["verdict"] == "Malicious" and res["severity"] == "Critical"
    assert res["consensus"]["thresholds"] == {"malicious": 90, "suspicious": 50, "critical_severity": 95}


def test_load_tip_settings_parses_and_validates(monkeypatch):
    values = {
        "vt_requests_per_minute": "10", "vt_requests_per_day": "abc", "abuseipdb_daily_limit": "-5",
        "vt_malicious_threshold": "0.2", "tip_malicious_threshold": "40", "tip_suspicious_threshold": "60",
    }
    monkeypatch.setattr(
        tip_module.integration_config, "get_setting",
        lambda key, db=None, default=None: values.get(key, default if default is not None else ""),
    )
    monkeypatch.setattr(tip_module.integration_config, "is_simulation_mode", lambda db=None: False)
    s = tip_module.load_tip_settings()
    assert s.vt_requests_per_minute == 10
    assert s.vt_requests_per_day == 500 and s.abuseipdb_daily_limit == 1000  # invalid values fall back
    assert s.vt_malicious_threshold == 0.2
    assert (s.malicious_threshold, s.suspicious_threshold) == (70, 30)  # inconsistent pair falls back


# -- caches ------------------------------------------------------------------------------------

def test_tip_cache_is_bounded_lru():
    tip = _tip(lambda r: httpx.Response(200, json=_vt_body()), cache_ttl=900, cache_max_entries=3)
    keys = TipSettings(virustotal_api_key="k", vt_requests_per_minute=0, vt_requests_per_day=0)
    for i in range(3):
        tip.enrich_ioc("Domain", f"h{i}.example.org", settings=keys)
    tip.enrich_ioc("Domain", "h0.example.org", settings=keys)  # touch h0 so h1 is the oldest
    tip.enrich_ioc("Domain", "h3.example.org", settings=keys)
    assert len(tip._cache) == 3
    cached_values = {k[2] for k in tip._cache}
    assert cached_values == {"h0.example.org", "h2.example.org", "h3.example.org"}


def test_tip_cache_ttl_expires(monkeypatch):
    calls = []
    tip = _tip(lambda r: calls.append(1) or httpx.Response(200, json=_vt_body()), cache_ttl=900)
    keys = TipSettings(virustotal_api_key="k", vt_requests_per_minute=0, vt_requests_per_day=0)
    tip.enrich_ioc("Domain", "example.org", settings=keys)
    assert tip.enrich_ioc("Domain", "example.org", settings=keys)["providers"]["virustotal"]["cached"] is True
    key = next(iter(tip._cache))
    stored, result = tip._cache[key]
    tip._cache[key] = (stored - 901, result)
    tip.enrich_ioc("Domain", "example.org", settings=keys)
    assert len(calls) == 2


def test_force_refresh_and_clear_cache():
    calls = []
    tip = _tip(lambda r: calls.append(1) or httpx.Response(200, json=_vt_body()), cache_ttl=900)
    keys = TipSettings(virustotal_api_key="k", vt_requests_per_minute=0, vt_requests_per_day=0)
    tip.enrich_ioc("Domain", "example.org", settings=keys)
    tip.enrich_ioc("Domain", "example.org", settings=keys)
    assert len(calls) == 1
    refreshed = tip.enrich_ioc("Domain", "example.org", settings=keys, force_refresh=True)
    assert len(calls) == 2 and "cached" not in refreshed["providers"]["virustotal"]
    tip.clear_cache()
    assert len(tip._cache) == 0
    tip.enrich_ioc("Domain", "example.org", settings=keys)
    assert len(calls) == 3


def test_module_level_clear_cache(monkeypatch):
    fresh = ThreatIntelligencePlatform()
    monkeypatch.setattr(tip_module, "tip_client", fresh)
    fresh._cache[("virustotal", "DOMAIN", "x")] = (0.0, {})
    tip_module.clear_cache()
    assert len(fresh._cache) == 0


def test_key_added_after_not_configured_takes_effect_immediately():
    tip = _tip(lambda r: httpx.Response(200, json=_vt_body(malicious=40, harmless=30, undetected=5)))
    assert tip.enrich_ioc("Domain", "example.org", settings=TipSettings())["verdict"] == "Unknown"
    assert tip.enrich_ioc("Domain", "example.org", settings=TipSettings(virustotal_api_key="k"))["verdict"] == "Malicious"


# -- NVD ---------------------------------------------------------------------------------------

CVE_LOG4J = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "descriptions": [{"lang": "en", "value": "Log4j JNDI RCE"}],
    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
        "baseScore": 10.0, "baseSeverity": "CRITICAL", "attackVector": "NETWORK"}}]},
}}]}
ALERT = {"rule_id": "r", "raw_payload": {"full_log": "exploit for CVE-2021-44228"}}


@pytest.fixture
def nvd_key(monkeypatch):
    def fake(key, db=None, default=None):
        return {"nvd_api_key": "nvd-key"}.get(key, default if default is not None else "")

    monkeypatch.setattr(nvd_module.integration_config, "get_setting", fake)


def test_nvd_allow_live_false_makes_no_http_call_and_reports_pending(nvd_key):
    calls = []
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json=CVE_LOG4J)))
    analysis = nvd.analyze_alert_vulnerabilities(ALERT, None, allow_live=False)
    assert calls == []
    assert analysis["lookup_status"] == "pending" and analysis["incomplete"] is True
    assert analysis["pending_cves"] == ["CVE-2021-44228"]
    assert analysis["vulnerabilities"][0]["status"] == "pending"
    assert analysis["hotl_autonomous_policy"]["eligible_for_hotl"] is False


def test_nvd_allow_live_false_serves_cache_and_live_fills_it(nvd_key):
    calls = []
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json=CVE_LOG4J)))
    nvd.analyze_alert_vulnerabilities(ALERT, None, allow_live=True)
    assert len(calls) == 1
    cached = nvd.analyze_alert_vulnerabilities(ALERT, None, allow_live=False)
    assert len(calls) == 1
    assert cached["lookup_status"] == "live" and cached["max_cvss_score"] == 10.0 and cached["incomplete"] is False
    assert cached["vulnerabilities"][0]["cached"] is True


def test_nvd_without_key_is_pending_when_not_live_and_never_invents_data(monkeypatch):
    monkeypatch.setattr(nvd_module.integration_config, "get_setting", lambda key, db=None, default=None: default or "")
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert nvd.analyze_alert_vulnerabilities(ALERT, None, allow_live=False)["lookup_status"] == "pending"


def test_nvd_works_without_a_key_and_sends_no_api_key_header(monkeypatch):
    """NVD allows keyless requests (5 per 30 s): a missing key must not stop lookups."""
    monkeypatch.setattr(nvd_module.integration_config, "get_setting", lambda key, db=None, default=None: default or "")
    seen = {}

    def handler(req: httpx.Request):
        seen["has_key_header"] = "apikey" in {k.lower() for k in req.headers.keys()}
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Log4j JNDI RCE"}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "baseScore": 10.0, "baseSeverity": "CRITICAL", "attackVector": "NETWORK",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},
        }}]})

    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(handler))
    record = nvd.get_vulnerability_details("CVE-2021-44228")
    assert record["status"] == "live" and record["cvss_score"] == 10.0 and record["auth"] == "keyless"
    assert seen["has_key_header"] is False


def test_nvd_keyless_403_is_reported_as_rate_limited(monkeypatch):
    monkeypatch.setattr(nvd_module.integration_config, "get_setting", lambda key, db=None, default=None: default or "")
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    record = nvd.get_vulnerability_details("CVE-2021-44229")
    assert record["status"] == "rate_limited" and record["cvss_score"] is None


def test_nvd_accepts_alert_objects_with_to_dict(nvd_key):
    class Obj:
        def to_dict(self):
            return ALERT

    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=CVE_LOG4J)))
    assert nvd.analyze_alert_vulnerabilities(Obj(), None)["lookup_status"] == "live"


def test_nvd_429_is_rate_limited_with_retry_after_and_blocks(nvd_key):
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(429, headers={"Retry-After": "25"})

    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(handler))
    first = nvd.get_vulnerability_details("CVE-2021-44228")
    assert first["status"] == "rate_limited" and first["retry_after_seconds"] == 25
    second = nvd.get_vulnerability_details("CVE-2021-44228")
    assert second["status"] == "rate_limited" and second["retry_after_seconds"] <= 25
    assert len(calls) == 1 and len(nvd._cache) == 0
    analysis = nvd.analyze_alert_vulnerabilities(ALERT, None)
    assert analysis["lookup_status"] == "rate_limited" and analysis["incomplete"] is True
    assert analysis["retry_after_seconds"] >= 1


def test_nvd_local_budget_returns_rate_limited_without_http(monkeypatch):
    def fake(key, db=None, default=None):
        return {"nvd_api_key": "k", "nvd_requests_per_30s": "1", "tip_max_wait_seconds": "0"}.get(key, default or "")

    monkeypatch.setattr(nvd_module.integration_config, "get_setting", fake)
    calls = []
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(
        lambda r: calls.append(r) or httpx.Response(404)), cache_ttl=0)
    assert nvd.get_vulnerability_details("CVE-2021-0001")["status"] == "not_found"
    limited = nvd.get_vulnerability_details("CVE-2021-0002")
    assert limited["status"] == "rate_limited" and limited["retry_after_seconds"] >= 1
    assert len(calls) == 1


def test_nvd_cache_is_bounded_and_clearable(nvd_key):
    nvd = NationalVulnerabilityDatabase(
        transport=httpx.MockTransport(lambda r: httpx.Response(404)), cache_max_entries=2)
    nvd._limiter.configure(0)
    for n in (1, 2, 3):
        nvd._cache_put(f"CVE-2021-000{n}", {"status": "not_found"})
    assert list(nvd._cache) == ["CVE-2021-0002", "CVE-2021-0003"]
    nvd_module.nvd_client._cache.clear()
    nvd.clear_cache()
    assert len(nvd._cache) == 0


def test_nvd_force_refresh_bypasses_cache(nvd_key):
    calls = []
    nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json=CVE_LOG4J)))
    nvd.get_vulnerability_details("CVE-2021-44228")
    nvd.get_vulnerability_details("CVE-2021-44228")
    assert len(calls) == 1
    nvd.get_vulnerability_details("CVE-2021-44228", force_refresh=True)
    assert len(calls) == 2


def test_refresh_alert_vulnerabilities_fills_cache_for_background_use(nvd_key):
    from backend.database import SessionLocal
    from backend.models import Alert

    db = SessionLocal()
    alert = Alert(rule_id="WS4-NVD", source="Wazuh", severity="High", status="New",
                  raw_payload={"full_log": "exploit for CVE-2021-44228"})
    db.add(alert)
    db.commit()
    alert_id = alert.alert_id
    alert_dict = alert.to_dict()
    db.close()
    try:
        calls = []
        nvd = NationalVulnerabilityDatabase(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json=CVE_LOG4J)))
        assert nvd.analyze_alert_vulnerabilities(alert_dict, None, allow_live=False)["lookup_status"] == "pending"
        assert calls == []
        analysis = nvd.refresh_alert_vulnerabilities(alert_id)
        assert analysis["lookup_status"] == "live" and len(calls) == 1
        after = nvd.analyze_alert_vulnerabilities(alert_dict, None, allow_live=False)
        assert after["lookup_status"] == "live" and len(calls) == 1
        assert nvd.refresh_alert_vulnerabilities(10 ** 9) is None
    finally:
        db = SessionLocal()
        db.delete(db.get(Alert, alert_id))
        db.commit()
        db.close()
