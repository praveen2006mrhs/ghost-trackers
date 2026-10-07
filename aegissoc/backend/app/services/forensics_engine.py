import re
import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Any, Tuple
from app.models.schemas import TimelineEvent, ForensicsAnalysisResponse

# ==============================================================================
# 1. PARSER FOR APACHE / NGINX ACCESS LOGS
# ==============================================================================

# Combined Log Format: 127.0.0.1 - user [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "referer" "user-agent"
NGINX_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+[^\"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^\"]*)"\s+"(?P<ua>[^\"]*)")?'
)

SUSPICIOUS_UA_PATTERNS = [
    (r'(?i)sqlmap', "SQLMap Automated SQL Injection Tool"),
    (r'(?i)nikto', "Nikto Web Vulnerability Scanner"),
    (r'(?i)gobuster', "GoBuster Directory Brute-Forcer"),
    (r'(?i)dirbuster', "DirBuster Path Fuzzer"),
    (r'(?i)nmap', "Nmap Network Scanner"),
    (r'(?i)masscan', "Masscan High-Speed Scanner"),
    (r'(?i)hydra', "THC-Hydra Network Logon Cracker"),
    (r'(?i)burpcollaborator|burp\s*suite', "Burp Suite Automated Probe"),
    (r'(?i)python-requests|aiohttp|urllib', "Automated Scripting Agent")
]

SUSPICIOUS_PATH_PATTERNS = [
    (r'\.\./|\.\.\\', "Directory Traversal Attempt", "T1083"),
    (r'(?i)\.(env|git|aws|ssh|htaccess)', "Sensitive Credential File Probe", "T1552"),
    (r'(?i)(wp-login\.php|administrator|phpmyadmin)', "Administrative Panel Scan", "T1190"),
    (r'(?i)(union\s+select|select\s+.*\s+from|\%27|\'\s*or\s*\'1\'=\'1)', "SQL Injection Attack Vector", "T1190"),
    (r'(?i)(/bin/sh|/bin/bash|cmd\.exe|powershell)', "Remote Command Execution Payload", "T1059")
]

def parse_apache_nginx_logs(raw_content: str) -> Tuple[List[TimelineEvent], Dict[str, Any]]:
    events: List[TimelineEvent] = []
    ip_counter = Counter()
    ua_counter = Counter()
    detected_tactics = set()
    anomalies = 0

    lines = raw_content.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        match = NGINX_REGEX.match(line)
        if match:
            ip = match.group("ip")
            user = match.group("user")
            time_str = match.group("time")
            method = match.group("method")
            path = match.group("path")
            status = int(match.group("status"))
            ua = match.group("ua") or "Unknown"

            ip_counter[ip] += 1
            ua_counter[ua] += 1

            is_anomaly = False
            attack_tag = None
            mitre_tactic = None
            severity = "Informational"

            # Check Suspicious User-Agents
            for ua_re, desc in SUSPICIOUS_UA_PATTERNS:
                if re.search(ua_re, ua):
                    is_anomaly = True
                    attack_tag = desc
                    mitre_tactic = "T1595 Active Scanning"
                    severity = "Medium"
                    detected_tactics.add("Reconnaissance (T1595)")
                    break

            # Check Path Attacks
            for path_re, desc, tactic in SUSPICIOUS_PATH_PATTERNS:
                if re.search(path_re, path):
                    is_anomaly = True
                    attack_tag = desc
                    mitre_tactic = f"{tactic} Initial Access"
                    severity = "High" if status < 400 else "Medium"
                    detected_tactics.add("Initial Access (T1190)")
                    break

            if status >= 500:
                is_anomaly = True
                severity = "High"
                attack_tag = f"Server Error Spike (HTTP {status})"
                detected_tactics.add("Impact (T1499)")

            if is_anomaly:
                anomalies += 1

            details = f"{method} {path} [{status}]"
            if attack_tag:
                details += f" - ALERT: {attack_tag}"

            events.append(TimelineEvent(
                timestamp=time_str,
                source_ip=ip,
                user=user if user != "-" else None,
                event_type="HTTP Request",
                severity=severity,
                details=details,
                mitre_attack=mitre_tactic,
                is_anomaly=is_anomaly
            ))
        else:
            # Fallback for simpler log lines
            events.append(TimelineEvent(
                timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                event_type="Raw Web Log",
                severity="Informational",
                details=line[:120],
                is_anomaly=False
            ))

    stats = {
        "ip_counter": ip_counter,
        "ua_counter": ua_counter,
        "tactics": list(detected_tactics),
        "anomalies": anomalies
    }
    return events, stats


# ==============================================================================
# 2. PARSER FOR LINUX AUTH.LOG / SECURE
# ==============================================================================

# Example: Oct  6 14:10:02 debian sshd[12345]: Failed password for invalid user admin from 198.51.100.42 port 52311 ssh2
# Example: Oct  6 14:12:00 debian sudo: pam_unix(sudo:session): session opened for user root by admin(uid=1000)
AUTH_LOG_REGEX = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<daemon>\w+)(?:\[\d+\])?:\s+(?P<message>.*)$'
)

def parse_linux_auth_logs(raw_content: str) -> Tuple[List[TimelineEvent], Dict[str, Any]]:
    events: List[TimelineEvent] = []
    failed_login_counter = Counter()
    ip_counter = Counter()
    detected_tactics = set()
    anomalies = 0

    lines = raw_content.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        match = AUTH_LOG_REGEX.match(line)
        if match:
            month = match.group("month")
            day = match.group("day")
            time_str = match.group("time")
            daemon = match.group("daemon")
            msg = match.group("message")
            full_time = f"{month} {day} {time_str}"

            ip_match = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', msg)
            user_match = re.search(r'(?:for|by|user)\s+([a-zA-Z0-9_\-]+)', msg)
            
            ip = ip_match.group(1) if ip_match else None
            user = user_match.group(1) if user_match else None

            if ip:
                ip_counter[ip] += 1

            is_anomaly = False
            severity = "Informational"
            mitre_tactic = None

            if "Failed password" in msg or "authentication failure" in msg:
                if ip:
                    failed_login_counter[ip] += 1
                is_anomaly = True
                severity = "Medium"
                mitre_tactic = "T1110.001 Password Guessing"
                detected_tactics.add("Credential Access (T1110)")
            elif "Accepted password" in msg or "Accepted publickey" in msg:
                severity = "Low"
                mitre_tactic = "T1078 Valid Accounts"
            elif "sudo:" in line and "session opened" in msg:
                is_anomaly = True
                severity = "High"
                mitre_tactic = "T1548.003 Sudo and Sudo Caching"
                detected_tactics.add("Privilege Escalation (T1548)")
            elif "Invalid user" in msg:
                is_anomaly = True
                severity = "Medium"
                mitre_tactic = "T1110 Brute Force"
                detected_tactics.add("Credential Access (T1110)")

            if is_anomaly:
                anomalies += 1

            events.append(TimelineEvent(
                timestamp=full_time,
                source_ip=ip,
                user=user,
                event_type=f"{daemon.upper()} Event",
                severity=severity,
                details=msg[:140],
                mitre_attack=mitre_tactic,
                is_anomaly=is_anomaly
            ))
        else:
            events.append(TimelineEvent(
                timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                event_type="Auth Log",
                severity="Informational",
                details=line[:120],
                is_anomaly=False
            ))

    stats = {
        "ip_counter": ip_counter,
        "failed_login_counter": failed_login_counter,
        "tactics": list(detected_tactics),
        "anomalies": anomalies
    }
    return events, stats


# ==============================================================================
# 3. PARSER FOR WINDOWS EVENT LOG (JSON EXPORTS)
# ==============================================================================

WIN_EVENT_DESCRIPTIONS = {
    4624: ("Successful Logon", "Low", "T1078 Valid Accounts"),
    4625: ("An account failed to log on", "High", "T1110 Brute Force"),
    4672: ("Special privileges assigned to new logon", "Medium", "T1078.001 Domain Admin"),
    4688: ("A new process has been created", "Medium", "T1059 Command and Scripting Interpreter"),
    4720: ("A user account was created", "High", "T1136 Create Account"),
    7045: ("A new service was installed in the system", "High", "T1543.003 Windows Service Persistence")
}

def parse_windows_event_logs(raw_content: str) -> Tuple[List[TimelineEvent], Dict[str, Any]]:
    events: List[TimelineEvent] = []
    ip_counter = Counter()
    failed_login_counter = Counter()
    detected_tactics = set()
    anomalies = 0

    records: List[Dict[str, Any]] = []
    try:
        parsed = json.loads(raw_content)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            records = parsed.get("Events", [parsed])
    except Exception:
        # Try JSON Lines
        for line in raw_content.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass

    for r in records:
        event_id = r.get("EventID") or r.get("System", {}).get("EventID")
        try:
            event_id = int(event_id)
        except (ValueError, TypeError):
            event_id = 0

        time_created = (
            r.get("TimeCreated") or 
            r.get("System", {}).get("TimeCreated", {}).get("SystemTime") or
            datetime.utcnow().isoformat()
        )
        
        event_data = r.get("EventData", {})
        target_user = event_data.get("TargetUserName") or r.get("TargetUserName") or event_data.get("SubjectUserName")
        ip = event_data.get("IpAddress") or r.get("IpAddress")
        workstation = event_data.get("WorkstationName") or r.get("WorkstationName")

        if ip and ip != "-" and ip != "::1" and ip != "127.0.0.1":
            ip_counter[ip] += 1

        info = WIN_EVENT_DESCRIPTIONS.get(event_id, ("Windows Security Event", "Informational", None))
        desc, severity, tactic = info

        is_anomaly = False
        if event_id in [4625, 4720, 7045]:
            is_anomaly = True
            anomalies += 1
            if event_id == 4625 and ip:
                failed_login_counter[ip] += 1

        if tactic:
            detected_tactics.add(tactic)

        detail_text = f"EventID {event_id}: {desc}"
        if target_user:
            detail_text += f" (User: {target_user})"
        if workstation:
            detail_text += f" [Station: {workstation}]"

        events.append(TimelineEvent(
            timestamp=str(time_created),
            source_ip=ip if ip and ip != "-" else None,
            user=target_user,
            event_type=f"WinEvent {event_id}",
            severity=severity,
            details=detail_text,
            mitre_attack=tactic,
            is_anomaly=is_anomaly
        ))

    stats = {
        "ip_counter": ip_counter,
        "failed_login_counter": failed_login_counter,
        "tactics": list(detected_tactics),
        "anomalies": anomalies
    }
    return events, stats


# ==============================================================================
# 4. FORENSIC PIPELINE & ANOMALY AGGREGATION
# ==============================================================================

def analyze_forensic_logs(log_type: str, raw_content: str) -> ForensicsAnalysisResponse:
    lt = log_type.lower()
    if "apache" in lt or "nginx" in lt or "web" in lt:
        events, stats = parse_apache_nginx_logs(raw_content)
    elif "linux" in lt or "auth" in lt or "syslog" in lt:
        events, stats = parse_linux_auth_logs(raw_content)
    elif "win" in lt or "evtx" in lt:
        events, stats = parse_windows_event_logs(raw_content)
    else:
        # Auto-detect format
        if "{" in raw_content and "EventID" in raw_content:
            events, stats = parse_windows_event_logs(raw_content)
        elif "sshd" in raw_content or "sudo:" in raw_content:
            events, stats = parse_linux_auth_logs(raw_content)
        else:
            events, stats = parse_apache_nginx_logs(raw_content)

    ip_counter: Counter = stats.get("ip_counter", Counter())
    failed_logins: Counter = stats.get("failed_login_counter", Counter())
    ua_counter: Counter = stats.get("ua_counter", Counter())

    # Detect Brute Force (> 4 failed login attempts from same IP)
    brute_force_detected = any(count >= 4 for count in failed_logins.values())

    top_ips = [
        {"ip": ip, "count": count, "failed_logins": failed_logins.get(ip, 0), "risk": "High" if failed_logins.get(ip, 0) >= 4 else "Normal"}
        for ip, count in ip_counter.most_common(10)
    ]

    suspicious_uas = [
        {"user_agent": ua[:60], "count": count}
        for ua, count in ua_counter.most_common(10)
    ]

    return ForensicsAnalysisResponse(
        log_type=log_type,
        total_lines_parsed=len(raw_content.splitlines()),
        total_events=len(events),
        anomalies_detected=stats.get("anomalies", 0),
        brute_force_detected=brute_force_detected,
        top_source_ips=top_ips,
        suspicious_user_agents=suspicious_uas,
        timeline=events[:250],  # Return up to 250 top events for fast UI rendering
        mitre_tactics=stats.get("tactics", [])
    )
