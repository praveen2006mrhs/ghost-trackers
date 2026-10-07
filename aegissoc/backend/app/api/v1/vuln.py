import json
from datetime import datetime, timezone
from collections import Counter
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.schemas import (
    CodeScanRequest, CodeScanResponse,
    CVSS31CalculationRequest, CVSS31CalculationResponse,
    DependencyScanRequest, DependencyScanResponse,
    ScanRecord
)
from app.services.vuln_scanner import (
    scan_source_code, calculate_cvss_31,
    scan_manifest_dependencies, RULES
)

router = APIRouter(prefix="/vuln", tags=["Vulnerability Assessment"])

@router.post("/scan-code", response_model=CodeScanResponse)
def run_code_scan(req: CodeScanRequest, db: Session = Depends(get_db)):
    """Heuristic static code analysis detecting secrets, SQLi, command injection, and deserialization."""
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Source code input cannot be empty.")

    findings = scan_source_code(req.code, language=req.language or "python")
    
    # Severity tally
    counts = Counter(f.severity for f in findings)
    breakdown = {
        "Critical": counts.get("Critical", 0),
        "High": counts.get("High", 0),
        "Medium": counts.get("Medium", 0),
        "Low": counts.get("Low", 0),
        "Informational": counts.get("Informational", 0)
    }

    # Persist in DB
    record = ScanRecord(
        target_name=req.target_name or "Direct Snippet",
        scan_type="source_code",
        language=req.language or "python",
        total_findings=len(findings),
        critical_count=breakdown["Critical"],
        high_count=breakdown["High"],
        medium_count=breakdown["Medium"],
        low_count=breakdown["Low"],
        info_count=breakdown["Informational"],
        findings_json=json.dumps([f.model_dump() for f in findings])
    )
    db.add(record)
    db.commit()

    return CodeScanResponse(
        target_name=req.target_name or "Direct Snippet",
        language=req.language or "python",
        total_findings=len(findings),
        severity_breakdown=breakdown,
        findings=findings,
        scan_timestamp=datetime.now(timezone.utc).isoformat()
    )

@router.post("/scan-dependencies", response_model=DependencyScanResponse)
def run_dependency_scan(req: DependencyScanRequest):
    """Parses manifest files (requirements.txt or package.json) and flags vulnerable packages."""
    if not req.manifest_content.strip():
        raise HTTPException(status_code=400, detail="Manifest content cannot be empty.")

    checked_count, findings = scan_manifest_dependencies(req.manifest_type, req.manifest_content)
    return DependencyScanResponse(
        manifest_type=req.manifest_type,
        total_packages_checked=checked_count,
        vulnerable_packages_count=len(findings),
        findings=findings
    )

@router.post("/cvss-calculate", response_model=CVSS31CalculationResponse)
def calculate_cvss(req: CVSS31CalculationRequest):
    """Calculates official CVSS 3.1 base score from metric vector parameters."""
    score, rating, vector, iss, exp = calculate_cvss_31(
        attack_vector=req.attack_vector,
        attack_complexity=req.attack_complexity,
        privileges_required=req.privileges_required,
        user_interaction=req.user_interaction,
        scope=req.scope,
        confidentiality=req.confidentiality,
        integrity=req.integrity,
        availability=req.availability
    )
    return CVSS31CalculationResponse(
        base_score=score,
        severity_rating=rating,
        vector_string=vector,
        impact_sub_score=iss,
        exploitability_sub_score=exp
    )

@router.get("/rules")
def list_detection_rules():
    """Lists all active heuristic rules in the scanner engine."""
    return {
        "total_rules": len(RULES),
        "rules": [
            {
                "id": r["id"],
                "name": r["name"],
                "category": r["category"],
                "severity": r["severity"],
                "cwe": r["cwe"],
                "description": r["description"]
            }
            for r in RULES
        ]
    }

@router.get("/history")
def get_scan_history(db: Session = Depends(get_db)):
    """Returns past vulnerability scans stored in database."""
    records = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "target_name": r.target_name,
            "language": r.language,
            "total_findings": r.total_findings,
            "critical_count": r.critical_count,
            "high_count": r.high_count,
            "medium_count": r.medium_count,
            "created_at": r.created_at.isoformat()
        }
        for r in records
    ]
