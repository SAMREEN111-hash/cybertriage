"""
CyberTriage Engine
==================
Replicates the core logic of an MDR platform alert triage pipeline:
  Raw event → Enrichment → Risk Scoring → MITRE Mapping → Response Decision
"""

from dataclasses import dataclass
from typing import Tuple


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────

MITRE_MAP = {
    "brute_force":         ("T1110 – Brute Force",               "Credential Access",   85),
    "sql_injection":       ("T1190 – Exploit Public-Facing App",  "Initial Access",      90),
    "xss":                 ("T1059.007 – JavaScript Execution",   "Execution",           70),
    "privilege_escalation":("T1068 – Exploitation for Priv Esc",  "Privilege Escalation",88),
    "lateral_movement":    ("T1021 – Remote Services",            "Lateral Movement",    92),
    "data_exfiltration":   ("T1041 – Exfiltration Over C2",       "Exfiltration",        95),
    "malware":             ("T1204 – User Execution",             "Execution",           88),
    "phishing":            ("T1566 – Phishing",                   "Initial Access",      80),
    "dos":                 ("T1498 – Network DoS",                "Impact",              75),
    "ransomware":          ("T1486 – Data Encrypted for Impact",  "Impact",              98),
    "c2_beacon":           ("T1071 – App Layer Protocol",         "Command & Control",   93),
    "port_scan":           ("T1046 – Network Service Discovery",  "Discovery",           60),
    "unknown":             ("T1082 – System Information Discovery","Discovery",           40),
}

RESPONSE_MAP = {
    "critical": "🔴 IMMEDIATE: Isolate host, block IP at firewall, page on-call analyst, open P1 incident",
    "high":     "🟠 URGENT: Block source IP, quarantine endpoint, notify SOC lead, open P2 ticket",
    "medium":   "🟡 INVESTIGATE: Enrich IOC context, correlate with other events, assign to analyst queue",
    "low":      "🟢 MONITOR: Log and retain, increase monitoring frequency, review in 24h",
}


@dataclass
class TriageDecision:
    severity: str
    risk_score: float
    mitre_technique: str
    mitre_tactic: str
    recommended_action: str


def _score_from_keywords(log_message: str) -> int:
    """Boost risk score based on high-signal keywords in log message."""
    keywords = {
        "root": 15, "admin": 10, "sudo": 12, "system32": 10,
        "powershell": 15, "cmd.exe": 10, "wget": 8, "curl": 8,
        "base64": 12, "encode": 8, "bypass": 15, "disable": 10,
        "delete": 8, "drop table": 20, "union select": 20,
        "passwd": 15, "shadow": 15, "credentials": 12,
        "encrypted": 15, "ransom": 20, "bitcoin": 18,
    }
    msg_lower = log_message.lower()
    return min(sum(v for k, v in keywords.items() if k in msg_lower), 25)


def triage(event_type: str, log_message: str, ip_abuse_score: float = 0) -> TriageDecision:
    """
    Core triage function.
    
    Algorithm:
      1. Lookup base risk from MITRE event type mapping
      2. Boost by log message keyword analysis  
      3. Boost by external threat intel (AbuseIPDB score)
      4. Clamp to 0-100, derive severity tier
      5. Return structured triage decision
    """
    event_key = event_type.lower().replace(" ", "_").replace("-", "_")
    mitre_technique, mitre_tactic, base_score = MITRE_MAP.get(
        event_key, MITRE_MAP["unknown"]
    )

    keyword_boost = _score_from_keywords(log_message)
    ip_boost = min((ip_abuse_score / 100) * 15, 15)  # max 15 pts from IP intel

    risk_score = min(base_score + keyword_boost + ip_boost, 100)
    risk_score = round(risk_score, 1)

    if risk_score >= 90:
        severity = "critical"
    elif risk_score >= 70:
        severity = "high"
    elif risk_score >= 45:
        severity = "medium"
    else:
        severity = "low"

    return TriageDecision(
        severity=severity,
        risk_score=risk_score,
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        recommended_action=RESPONSE_MAP[severity],
    )
