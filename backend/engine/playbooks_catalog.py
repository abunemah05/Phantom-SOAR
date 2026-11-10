"""Pre-configured SANS / MITRE ATT&CK response playbooks.

Each step's "action" is a name from backend.engine.actions.ACTION_CATALOG or a
pseudo-step (await_analyst_approval, enrich_ioc, query_abuseipdb, generate_report).
Step targets are not hardcoded: the runner resolves them from the alert's
entities (hosts, IPs, users, processes, files) at execution time.

"keywords" and "mitre_id" drive playbook matching; "mitre_tactic" and
"mitre_technique" are the ATT&CK names for mitre_id.
"""
from typing import List, Dict, Any

PRECONFIGURED_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "name": "Ransomware Outbreak Containment",
        "target_threat": "Ransomware",
        "execution_mode": "HOTL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1486",
            "mitre_tactic": "Impact",
            "mitre_technique": "Data Encrypted for Impact",
            "picerl_phase": "Containment",
            "keywords": ["ransomware", "shadow cop", "vssadmin", "bulk encryption", "lockbit", "ryuk", "conti"],
            "triggers": ["rule_ransomware_detected", "vss_shadow_copies_deleted", "bulk_file_rename"],
            "steps": [
                {"order": 1, "action": "isolate_endpoint", "connector": "edr"},
                {"order": 2, "action": "terminate_process", "connector": "edr"},
                {"order": 3, "action": "block_ip", "connector": "firewall", "params": {"direction": "both"}},
                {"order": 4, "action": "revoke_user_sessions", "connector": "iam"},
                {"order": 5, "action": "generate_report", "connector": "reporter"}
            ]
        }
    },
    {
        "name": "SSH & RDP Brute Force Mitigation",
        "target_threat": "Brute Force",
        "execution_mode": "HOTL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force",
            "picerl_phase": "Identification & Containment",
            "keywords": ["brute force", "brute-force", "authentication failures", "multiple failed", "password spray"],
            "triggers": ["failed_ssh_auth_burst", "wazuh_rule_5710", "rdp_login_failure_surge"],
            "steps": [
                {"order": 1, "action": "query_abuseipdb", "connector": "tip"},
                {"order": 2, "action": "block_ip", "connector": "firewall", "params": {"duration_hours": 48}},
                {"order": 3, "action": "apply_rate_limit", "connector": "firewall"},
                {"order": 4, "action": "create_ticket", "connector": "itsm", "params": {"priority": "Medium"}}
            ]
        }
    },
    {
        "name": "Spearphishing Email & Credential Harvesting",
        "target_threat": "Phishing",
        "execution_mode": "HITL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1566",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "Phishing",
            "picerl_phase": "Identification",
            "keywords": ["phishing", "spearphishing", "credential harvesting", "suspicious email", "malicious link"],
            "triggers": ["suspicious_email_gateway", "dmarc_spf_failure", "vt_url_malicious"],
            "steps": [
                {"order": 1, "action": "enrich_ioc", "connector": "tip"},
                {"order": 2, "action": "await_analyst_approval", "role": "SOC Analyst L2"},
                {"order": 3, "action": "revoke_user_sessions", "connector": "iam"},
                {"order": 4, "action": "block_ip", "connector": "firewall"}
            ]
        }
    },
    {
        "name": "Privilege Escalation via Token Impersonation",
        "target_threat": "Privilege Escalation",
        "execution_mode": "HITL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1068",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "Exploitation for Privilege Escalation",
            "picerl_phase": "Containment",
            "keywords": ["privilege escalation", "token impersonation", "unauthorized sudo", "token manipulation"],
            "triggers": ["unauthorized_sudo", "cve_kernel_privesc", "token_manipulation"],
            "steps": [
                {"order": 1, "action": "terminate_process", "connector": "edr"},
                {"order": 2, "action": "isolate_endpoint", "connector": "edr"},
                {"order": 3, "action": "await_analyst_approval", "role": "Incident Commander"},
                {"order": 4, "action": "force_password_reset", "connector": "iam"}
            ]
        }
    },
    {
        "name": "Web Shell Execution & Backdoor Isolation",
        "target_threat": "WebShell",
        "execution_mode": "HOTL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1505.003",
            "mitre_tactic": "Persistence",
            "mitre_technique": "Server Software Component: Web Shell",
            "picerl_phase": "Eradication",
            "keywords": ["webshell", "web shell", "china chopper", "reverse shell", "backdoor"],
            "triggers": ["chopper_eval_detected", "php_reverse_shell_socket", "unusual_cgi_process"],
            "steps": [
                {"order": 1, "action": "quarantine_file", "connector": "edr"},
                {"order": 2, "action": "block_ip", "connector": "firewall"},
                {"order": 3, "action": "isolate_endpoint", "connector": "edr"},
                {"order": 4, "action": "generate_report", "connector": "reporter"}
            ]
        }
    },
    {
        "name": "Data Exfiltration over Covert C2 Protocol",
        "target_threat": "Data Exfiltration",
        "execution_mode": "HOTL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1048",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "Exfiltration Over Alternative Protocol",
            "picerl_phase": "Containment",
            "keywords": ["exfiltration", "dns tunneling", "covert channel", "data transfer to"],
            "triggers": ["high_outbound_volume_s3", "dns_tunneling_queries", "tor_traffic_detected"],
            "steps": [
                {"order": 1, "action": "block_ip", "connector": "firewall"},
                {"order": 2, "action": "apply_rate_limit", "connector": "firewall"},
                {"order": 3, "action": "isolate_endpoint", "connector": "edr"},
                {"order": 4, "action": "create_ticket", "connector": "itsm", "params": {"priority": "Highest"}}
            ]
        }
    },
    {
        "name": "Lateral Movement via SMB & PsExec",
        "target_threat": "Lateral Movement",
        "execution_mode": "HITL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1550",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "Use Alternate Authentication Material",
            "picerl_phase": "Identification & Containment",
            "keywords": ["lateral movement", "psexec", "pass the hash", "pass-the-hash", "wmi remote"],
            "triggers": ["psexec_service_install", "wmi_remote_invocation", "pass_the_hash_event"],
            "steps": [
                {"order": 1, "action": "isolate_endpoint", "connector": "edr"},
                {"order": 2, "action": "await_analyst_approval", "role": "SOC Tier 2"},
                {"order": 3, "action": "revoke_user_sessions", "connector": "iam"},
                {"order": 4, "action": "generate_report", "connector": "reporter"}
            ]
        }
    },
    {
        "name": "DDoS Flood Perimeter Mitigation",
        "target_threat": "DDoS Mitigation",
        "execution_mode": "HOTL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1498",
            "mitre_tactic": "Impact",
            "mitre_technique": "Network Denial of Service",
            "picerl_phase": "Containment",
            "keywords": ["ddos", "denial of service", "syn flood", "udp flood", "http flood", "amplification"],
            "triggers": ["syn_flood_threshold_exceeded", "udp_amplification", "http_flood_edge"],
            "steps": [
                {"order": 1, "action": "apply_rate_limit", "connector": "firewall", "params": {"rate": "5/second"}},
                {"order": 2, "action": "block_ip", "connector": "firewall"},
                {"order": 3, "action": "send_notification", "connector": "itsm", "params": {"level": "CRITICAL"}}
            ]
        }
    },
    {
        "name": "Credential Dumping via LSASS Injection",
        "target_threat": "Credential Dumping",
        "execution_mode": "HOTL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1003",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "OS Credential Dumping",
            "picerl_phase": "Containment",
            "keywords": ["credential dumping", "lsass", "mimikatz", "sekurlsa", "nanodump"],
            "triggers": ["lsass_memory_read", "mimikatz_sekurlsa", "nanodump_detected"],
            "steps": [
                {"order": 1, "action": "terminate_process", "connector": "edr"},
                {"order": 2, "action": "isolate_endpoint", "connector": "edr"},
                {"order": 3, "action": "force_password_reset", "connector": "iam"},
                {"order": 4, "action": "generate_report", "connector": "reporter"}
            ]
        }
    },
    {
        "name": "Database SQL Injection & Unauthorized Export",
        "target_threat": "Data Tampering",
        "execution_mode": "HITL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1190",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "Exploit Public-Facing Application",
            "picerl_phase": "Identification",
            "keywords": ["sql injection", "sqli", "union select", "xp_cmdshell"],
            "triggers": ["union_select_query_injection", "sql_syntax_error_anomaly", "xp_cmdshell_attempt"],
            "steps": [
                {"order": 1, "action": "block_ip", "connector": "firewall"},
                {"order": 2, "action": "await_analyst_approval", "role": "DBA / SOC Lead"},
                {"order": 3, "action": "create_ticket", "connector": "itsm", "params": {"priority": "High"}}
            ]
        }
    },
    {
        "name": "Supply Chain Dependency Tampering",
        "target_threat": "Supply Chain Attack",
        "execution_mode": "HITL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1195",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "Supply Chain Compromise",
            "picerl_phase": "Identification & Eradication",
            "keywords": ["supply chain", "typosquat", "malicious package", "postinstall"],
            "triggers": ["typosquatting_package_load", "malicious_postinstall_hook", "unauthorized_npm_publish"],
            "steps": [
                {"order": 1, "action": "quarantine_file", "connector": "edr"},
                {"order": 2, "action": "await_analyst_approval", "role": "AppSec Engineer"},
                {"order": 3, "action": "generate_report", "connector": "reporter"}
            ]
        }
    },
    {
        "name": "Insider Threat Privilege Abuse & Data Hoard",
        "target_threat": "Insider Threat",
        "execution_mode": "HITL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1078",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "Valid Accounts",
            "picerl_phase": "Identification & Containment",
            "keywords": ["insider threat", "bulk download", "mass usb", "data hoard"],
            "triggers": ["off_hours_bulk_download", "mass_usb_storage_write", "sensitive_repo_clone"],
            "steps": [
                {"order": 1, "action": "revoke_user_sessions", "connector": "iam"},
                {"order": 2, "action": "await_analyst_approval", "role": "SOC Director & HR"},
                {"order": 3, "action": "disable_account", "connector": "iam"},
                {"order": 4, "action": "generate_report", "connector": "reporter"}
            ]
        }
    },
    {
        "name": "Reconnaissance & Port Scan Response",
        "target_threat": "Reconnaissance",
        "execution_mode": "HITL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1595",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "Active Scanning",
            "picerl_phase": "Identification",
            "keywords": ["port scan", "portscan", "network scan", "nmap", "masscan", "reconnaissance"],
            "triggers": ["port_scan_detected", "syn_scan", "service_enumeration"],
            "steps": [
                {"order": 1, "action": "enrich_ioc", "connector": "tip"},
                {"order": 2, "action": "await_analyst_approval", "role": "SOC Analyst L1"},
                {"order": 3, "action": "block_ip", "connector": "firewall", "params": {"duration_hours": 24}},
                {"order": 4, "action": "create_ticket", "connector": "itsm", "params": {"priority": "Low"}}
            ]
        }
    }
]

TEMPLATES_BY_NAME: Dict[str, Dict[str, Any]] = {pb["name"]: pb for pb in PRECONFIGURED_PLAYBOOKS}
