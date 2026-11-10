from typing import List, Dict, Any

PRECONFIGURED_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "name": "Ransomware Outbreak Containment",
        "target_threat": "Ransomware",
        "execution_mode": "HOTL",
        "is_active": True,
        "workflow_logic": {
            "mitre_id": "T1486",
            "picerl_phase": "Containment",
            "triggers": ["rule_ransomware_detected", "vss_shadow_copies_deleted", "bulk_file_rename"],
            "steps": [
                {"order": 1, "action": "isolate_endpoint", "connector": "edr", "timeout_sec": 5},
                {"order": 2, "action": "terminate_process", "connector": "edr", "params": {"target": "encryptor.exe"}},
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
            "picerl_phase": "Identification & Containment",
            "triggers": ["failed_ssh_auth_burst", "wazuh_rule_5710", "rdp_login_failure_surge"],
            "steps": [
                {"order": 1, "action": "query_abuseipdb", "connector": "tip"},
                {"order": 2, "action": "block_ip", "connector": "firewall", "params": {"duration_hours": 48}},
                {"order": 3, "action": "apply_rate_limit", "connector": "firewall"},
                {"order": 4, "action": "create_jira_ticket", "connector": "itsm", "priority": "Medium"}
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
            "picerl_phase": "Identification",
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
            "picerl_phase": "Containment",
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
            "picerl_phase": "Eradication",
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
            "picerl_phase": "Containment",
            "triggers": ["high_outbound_volume_s3", "dns_tunneling_queries", "tor_traffic_detected"],
            "steps": [
                {"order": 1, "action": "block_ip", "connector": "firewall"},
                {"order": 2, "action": "apply_rate_limit", "connector": "firewall"},
                {"order": 3, "action": "isolate_endpoint", "connector": "edr"},
                {"order": 4, "action": "create_jira_ticket", "connector": "itsm", "priority": "Critical"}
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
            "picerl_phase": "Identification & Containment",
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
            "picerl_phase": "Containment",
            "triggers": ["syn_flood_threshold_exceeded", "udp_amplification", "http_flood_edge"],
            "steps": [
                {"order": 1, "action": "apply_rate_limit", "connector": "firewall", "params": {"rate": "5/second"}},
                {"order": 2, "action": "block_ip", "connector": "firewall"},
                {"order": 3, "action": "send_notification", "connector": "itsm", "level": "CRITICAL"}
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
            "picerl_phase": "Containment",
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
            "picerl_phase": "Identification",
            "triggers": ["union_select_query_injection", "sql_syntax_error_anomaly", "xp_cmdshell_attempt"],
            "steps": [
                {"order": 1, "action": "block_ip", "connector": "firewall"},
                {"order": 2, "action": "await_analyst_approval", "role": "DBA / SOC Lead"},
                {"order": 3, "action": "create_jira_ticket", "connector": "itsm", "priority": "High"}
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
            "picerl_phase": "Identification & Eradication",
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
            "picerl_phase": "Identification & Containment",
            "triggers": ["off_hours_bulk_download", "mass_usb_storage_write", "sensitive_repo_clone"],
            "steps": [
                {"order": 1, "action": "revoke_user_sessions", "connector": "iam"},
                {"order": 2, "action": "await_analyst_approval", "role": "SOC Director & HR"},
                {"order": 3, "action": "disable_account", "connector": "iam"},
                {"order": 4, "action": "generate_report", "connector": "reporter"}
            ]
        }
    }
]
