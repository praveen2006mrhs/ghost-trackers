import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.schemas import (
    LogParseRequest, ForensicsAnalysisResponse, ForensicInvestigation
)
from app.services.forensics_engine import analyze_forensic_logs

router = APIRouter(prefix="/forensics", tags=["Incident Response & Forensics"])

SAMPLE_LOGS = {
    "apache_nginx": """192.168.1.105 - - [06/Oct/2026:14:02:11 +0000] "GET /index.html HTTP/1.1" 200 4520 "https://google.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.88 - - [06/Oct/2026:14:03:02 +0000] "GET /wp-login.php HTTP/1.1" 404 182 "-" "sqlmap/1.7.2#stable (http://sqlmap.org)"
203.0.113.88 - - [06/Oct/2026:14:03:05 +0000] "GET /api/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 890 "-" "sqlmap/1.7.2#stable"
203.0.113.88 - - [06/Oct/2026:14:03:10 +0000] "GET /.env HTTP/1.1" 403 240 "-" "Nikto/2.1.6"
198.51.100.14 - - [06/Oct/2026:14:04:12 +0000] "GET /../../../../etc/passwd HTTP/1.1" 400 310 "-" "curl/7.88.1"
192.168.1.105 - - [06/Oct/2026:14:05:00 +0000] "POST /api/login HTTP/1.1" 200 1204 "https://example.com/login" "Mozilla/5.0"
""",
    "linux_auth": """Oct  6 14:10:01 srv-prod sshd[1024]: Invalid user admin from 198.51.100.22 port 48212 ssh2
Oct  6 14:10:04 srv-prod sshd[1024]: Failed password for invalid user admin from 198.51.100.22 port 48212 ssh2
Oct  6 14:10:08 srv-prod sshd[1025]: Failed password for invalid user admin from 198.51.100.22 port 48214 ssh2
Oct  6 14:10:12 srv-prod sshd[1026]: Failed password for invalid user admin from 198.51.100.22 port 48216 ssh2
Oct  6 14:10:16 srv-prod sshd[1027]: Failed password for invalid user admin from 198.51.100.22 port 48218 ssh2
Oct  6 14:10:20 srv-prod sshd[1028]: Failed password for invalid user admin from 198.51.100.22 port 48220 ssh2
Oct  6 14:12:00 srv-prod sudo: pam_unix(sudo:session): session opened for user root by secops(uid=1000)
Oct  6 14:15:33 srv-prod sshd[1090]: Accepted publickey for secops from 10.0.4.15 port 55122 ssh2
""",
    "windows_evtx_json": """[
  {
    "EventID": 4625,
    "TimeCreated": "2026-10-06T14:20:00Z",
    "TargetUserName": "Administrator",
    "IpAddress": "192.0.2.77",
    "WorkstationName": "WORKSTATION-X"
  },
  {
    "EventID": 4625,
    "TimeCreated": "2026-10-06T14:20:05Z",
    "TargetUserName": "Administrator",
    "IpAddress": "192.0.2.77",
    "WorkstationName": "WORKSTATION-X"
  },
  {
    "EventID": 4625,
    "TimeCreated": "2026-10-06T14:20:10Z",
    "TargetUserName": "Administrator",
    "IpAddress": "192.0.2.77",
    "WorkstationName": "WORKSTATION-X"
  },
  {
    "EventID": 4625,
    "TimeCreated": "2026-10-06T14:20:15Z",
    "TargetUserName": "Administrator",
    "IpAddress": "192.0.2.77",
    "WorkstationName": "WORKSTATION-X"
  },
  {
    "EventID": 4720,
    "TimeCreated": "2026-10-06T14:22:00Z",
    "TargetUserName": "backdoor_user",
    "IpAddress": "192.0.2.77",
    "WorkstationName": "DC-PRIMARY"
  },
  {
    "EventID": 4624,
    "TimeCreated": "2026-10-06T14:25:00Z",
    "TargetUserName": "corp_auditor",
    "IpAddress": "10.0.1.50",
    "WorkstationName": "LAPTOP-AUDIT"
  }
]"""
}

@router.post("/parse-logs", response_model=ForensicsAnalysisResponse)
def parse_logs_endpoint(req: LogParseRequest, db: Session = Depends(get_db)):
    """Parses raw server logs, generates chronological timeline, and identifies anomalies and brute force."""
    if not req.log_content.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty.")

    analysis = analyze_forensic_logs(req.log_type, req.log_content)

    # Persist in DB
    record = ForensicInvestigation(
        log_type=req.log_type,
        total_events=analysis.total_events,
        anomalies_count=analysis.anomalies_detected,
        brute_force_detected=analysis.brute_force_detected,
        suspicious_ips_json=json.dumps(analysis.top_source_ips),
        timeline_json=json.dumps([e.model_dump() for e in analysis.timeline[:50]])
    )
    db.add(record)
    db.commit()

    return analysis

@router.post("/generate-timeline", response_model=ForensicsAnalysisResponse)
def generate_timeline_endpoint(req: LogParseRequest, db: Session = Depends(get_db)):
    return parse_logs_endpoint(req, db)

@router.get("/sample-logs")
def get_sample_logs():
    """Returns realistic forensic sample logs for quick demonstration."""
    return SAMPLE_LOGS

@router.get("/reports")
def get_forensic_reports(db: Session = Depends(get_db)):
    records = db.query(ForensicInvestigation).order_by(ForensicInvestigation.created_at.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "log_type": r.log_type,
            "total_events": r.total_events,
            "anomalies_count": r.anomalies_count,
            "brute_force_detected": r.brute_force_detected,
            "created_at": r.created_at.isoformat()
        }
        for r in records
    ]
