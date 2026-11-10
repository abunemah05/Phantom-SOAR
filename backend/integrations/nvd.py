import re
import logging
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from backend.config import settings

logger = logging.getLogger(__name__)

class NationalVulnerabilityDatabase:
    """
    NVD (National Vulnerability Database) Integration Connector:
    - Queries official NIST NVD API 2.0 (services.nvd.nist.gov/rest/json/cves/2.0)
    - Extracts CVE indicators from alert payload, rule descriptions, and logs
    - Evaluates CVSS v3.1 metrics for Human-in-the-Loop (HITL) remediation advice
    - Evaluates critical severity for Human-out-of-the-Loop (HOTL) automated containment
    """

    def __init__(self):
        self.api_key = settings.NVD_API_KEY
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Curated Offline/Lab Knowledgebase for resilient deterministic scoring
        self.cve_knowledgebase = {
            "CVE-2024-3094": {
                "cve_id": "CVE-2024-3094",
                "title": "XZ Utils Malicious Code Injection / SSH Backdoor",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "cwe": "CWE-506: Embedded Malicious Code",
                "description": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through complex obfuscations, the liblzma build process extracts a prebuilt test file, modifying functions in liblzma to intercept OpenSSH authentication.",
                "hitl_remediation": [
                    "Downgrade xz-utils / liblzma to version 5.4.x immediately.",
                    "Audit authorized_keys and all active SSH sessions.",
                    "Rotate all SSH host keys and administrator credentials."
                ],
                "hotl_action": "isolate_endpoint",
                "hotl_action_description": "Immediately isolate endpoint from network to prevent unauthorized remote root SSH takeover.",
                "patches": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094", "Debian Security Advisory DSA-5649-1"]
            },
            "CVE-2021-44228": {
                "cve_id": "CVE-2021-44228",
                "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "cwe": "CWE-502: Deserialization of Untrusted Data",
                "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints, allowing unauthenticated RCE.",
                "hitl_remediation": [
                    "Upgrade Log4j to >= 2.17.1 or apply log4j2.formatMsgNoLookups=true flag.",
                    "Block outbound LDAP (389), RMI (1099), and DNS egress to unauthorized external IP addresses.",
                    "Review application logs for ${jndi:ldap://} and ${jndi:rmi://} artifacts."
                ],
                "hotl_action": "block_ip",
                "hotl_action_description": "Block external LDAP/RMI adversary callback IP at boundary firewall.",
                "patches": ["https://logging.apache.org/log4j/2.x/security.html"]
            },
            "CVE-2023-34362": {
                "cve_id": "CVE-2023-34362",
                "title": "Progress MOVEit Transfer SQL Injection Vulnerability",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "cwe": "CWE-89: SQL Injection",
                "description": "SQL injection vulnerability in the MOVEit Transfer web application could allow an unauthenticated attacker to gain access to MOVEit Transfer's database and execute arbitrary SQL commands.",
                "hitl_remediation": [
                    "Apply the latest vendor cumulative service pack patch.",
                    "Disable all HTTP/HTTPS inbound traffic to MOVEit transfer until patched.",
                    "Delete human2.aspx webshell if present in wwwroot."
                ],
                "hotl_action": "isolate_endpoint",
                "hotl_action_description": "Sever host network connectivity to stop active database exfiltration.",
                "patches": ["https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31-May-2023"]
            },
            "CVE-2020-1472": {
                "cve_id": "CVE-2020-1472",
                "title": "Microsoft Netlogon Elevation of Privilege (Zerologon)",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "cwe": "CWE-287: Improper Authentication",
                "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller using the Netlogon Remote Protocol (MS-NRPC).",
                "hitl_remediation": [
                    "Deploy Microsoft security update KB4557222 to Domain Controllers.",
                    "Enforce secure RPC communication with Netlogon (Full Enforcement Mode).",
                    "Audit event ID 5829 on domain controllers."
                ],
                "hotl_action": "isolate_endpoint",
                "hotl_action_description": "Isolate compromised host to prevent domain controller password reset.",
                "patches": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"]
            }
        }

    def extract_cves_from_text(self, text: str) -> List[str]:
        """Extract all CVE identifiers matching standard regex CVE-YYYY-NNNN+."""
        if not text:
            return []
        matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        return list({m.upper() for m in matches})

    def query_nvd_api(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Query official NIST NVD API 2.0 for live CVE metrics and descriptions."""
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(f"{self.base_url}?cveId={cve_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        cve_item = vulnerabilities[0].get("cve", {})
                        metrics = cve_item.get("metrics", {})
                        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})

                        cvss_score = cvss_v31.get("baseScore", 7.5)
                        severity = cvss_v31.get("baseSeverity", "HIGH")
                        attack_vector = cvss_v31.get("attackVector", "NETWORK")

                        descriptions = cve_item.get("descriptions", [])
                        desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

                        return {
                            "cve_id": cve_id,
                            "title": f"NVD Entry {cve_id}",
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "attack_vector": attack_vector,
                            "description": desc_text,
                            "hitl_remediation": [
                                f"Apply vendor security update for {cve_id}.",
                                "Restrict ingress network access to vulnerable port.",
                                "Verify host integrity and review system event logs."
                            ],
                            "hotl_action": "isolate_endpoint" if cvss_score >= 9.0 else "none",
                            "hotl_action_description": "Automated host isolation recommended due to CVSS >= 9.0 Critical rating." if cvss_score >= 9.0 else "No autonomous containment required.",
                            "status": "Online (NIST NVD Live API)",
                            "queried_at": datetime.now(timezone.utc).isoformat()
                        }
        except Exception as e:
            logger.debug(f"NVD live query error for {cve_id}: {e}")

        return None

    def get_vulnerability_details(self, cve_id: str) -> Dict[str, Any]:
        """Fetch CVE information from live NVD API or fall back to curated database."""
        cve_id = cve_id.strip().upper()

        # Check offline curated database first for instant response
        if cve_id in self.cve_knowledgebase:
            res = self.cve_knowledgebase[cve_id].copy()
            res["status"] = "Knowledgebase Curated"
            res["queried_at"] = datetime.now(timezone.utc).isoformat()
            return res

        # Try live NVD API
        live_result = self.query_nvd_api(cve_id)
        if live_result:
            return live_result

        # Generic heuristic fallback
        return {
            "cve_id": cve_id,
            "title": f"Vulnerability {cve_id}",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "cwe": "CWE-Generic",
            "description": f"National Vulnerability Database indicator for {cve_id}.",
            "hitl_remediation": [
                f"Review patch release notes from vendor regarding {cve_id}.",
                "Monitor endpoint process activity and outbound network telemetry.",
                "Apply principle of least privilege on affected application."
            ],
            "hotl_action": "none",
            "hotl_action_description": "Severity threshold below autonomous containment trigger (< 9.0).",
            "status": "Heuristic Model",
            "queried_at": datetime.now(timezone.utc).isoformat()
        }

    def analyze_alert_vulnerabilities(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze an alert's raw payload, rule, and IoCs to identify linked CVEs,
        produce actionable HITL remediation advice, and determine HOTL autonomous actions.
        """
        raw = alert_dict.get("raw_payload") or {}
        rule = raw.get("rule", {})
        rule_desc = rule.get("description", "")
        rule_id = str(alert_dict.get("rule_id", ""))
        full_log = str(raw.get("full_log", ""))
        raw_text = f"{rule_desc} {full_log} {rule_id}"

        # Extract explicit CVE IDs
        found_cves = self.extract_cves_from_text(raw_text)

        # Context-based mapping if no explicit CVE found
        if not found_cves:
            lower_text = raw_text.lower()
            if "log4j" in lower_text or "jndi" in lower_text:
                found_cves.append("CVE-2021-44228")
            elif "xz" in lower_text or "liblzma" in lower_text or "backdoor" in lower_text:
                found_cves.append("CVE-2024-3094")
            elif "mimikatz" in lower_text or "lsass" in lower_text or "zerologon" in lower_text:
                found_cves.append("CVE-2020-1472")
            elif "moveit" in lower_text or "sqli" in lower_text:
                found_cves.append("CVE-2023-34362")
            else:
                # Default demonstration reference for Critical/High alerts
                if alert_dict.get("severity") in ["Critical", "High"]:
                    found_cves.append("CVE-2024-3094")

        cve_details = [self.get_vulnerability_details(cve) for cve in found_cves]

        # Determine highest CVSS score
        max_cvss = max([c["cvss_score"] for c in cve_details], default=0.0)

        # Evaluate HOTL (Human-Out-of-the-Loop) Automation Trigger
        # Threshold: CVSS >= 9.0 (Critical) + Network Attack Vector triggers autonomous containment
        should_hotl_contain = any(
            c["cvss_score"] >= 9.0 and c.get("attack_vector") == "NETWORK"
            for c in cve_details
        )

        hotl_recommendation = {
            "eligible_for_hotl": should_hotl_contain,
            "action_type": "isolate_endpoint" if should_hotl_contain else "none",
            "justification": (
                f"CVSS score {max_cvss} qualifies as CRITICAL with network exploitability. "
                "Autonomous host isolation policy triggered per HOTL rules."
                if should_hotl_contain else
                "Vulnerability does not meet autonomous HOTL isolation criteria. Requires standard HITL review."
            )
        }

        # Aggregate HITL (Human-in-the-Loop) Remediation steps
        all_remediations = []
        for c in cve_details:
            for rem in c.get("hitl_remediation", []):
                if rem not in all_remediations:
                    all_remediations.append(rem)

        return {
            "cves_detected": found_cves,
            "max_cvss_score": max_cvss,
            "vulnerabilities": cve_details,
            "hitl_remediation_steps": all_remediations,
            "hotl_autonomous_policy": hotl_recommendation
        }

nvd_client = NationalVulnerabilityDatabase()
