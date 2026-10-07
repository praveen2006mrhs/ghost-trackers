import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.schemas import (
    DastRunRequest, DastRunResponse, DastFinding, DastTestRecord
)
from app.services.security_tester import (
    execute_dast_audit, generate_junit_xml, generate_sarif_json
)

router = APIRouter(prefix="/security-tests", tags=["Automated Security Testing"])

@router.get("/mock-target")
def mock_target_endpoint():
    """
    Simulated target server for defensive DAST verification.
    Intentionally emits baseline headers with a few missing headers for audit demonstration.
    """
    response_content = {
        "status": "online",
        "service": "GhostTrackers-MockTargetService",
        "environment": "sandboxed-audit",
        "timestamp": datetime.utcnow().isoformat()
    }
    resp = Response(content=json.dumps(response_content), media_type="application/json")
    # Setting partial security headers to demo realistic scoring
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Access-Control-Allow-Origin"] = "https://aegissoc.internal"
    resp.headers["Server"] = "AegisSOC-TestDaemon/1.0"
    # Note: Content-Security-Policy and Strict-Transport-Security are deliberately omitted for the test to detect!
    return resp

@router.post("/run-dast", response_model=DastRunResponse)
async def run_dast_tests(req: DastRunRequest, db: Session = Depends(get_db)):
    """Executes automated DAST security header, CORS, and SSL/TLS checks."""
    score, findings, duration = await execute_dast_audit(
        target_url=req.target_url,
        check_cors=req.check_cors,
        check_security_headers=req.check_security_headers,
        check_clickjacking=req.check_clickjacking,
        check_ssl=req.check_ssl
    )

    passed_count = sum(1 for f in findings if f.passed)
    failed_count = len(findings) - passed_count

    junit_data = generate_junit_xml(test_run_id=1, target_url=req.target_url, findings=findings)
    sarif_data = generate_sarif_json(test_run_id=1, target_url=req.target_url, findings=findings)

    # Persist in DB
    record = DastTestRecord(
        target_url=req.target_url,
        passed_tests=passed_count,
        failed_tests=failed_count,
        security_score=score,
        findings_json=json.dumps([f.model_dump() for f in findings]),
        junit_xml=junit_data,
        sarif_json=json.dumps(sarif_data)
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Update ID inside XML / SARIF
    record.junit_xml = generate_junit_xml(test_run_id=record.id, target_url=req.target_url, findings=findings)
    record.sarif_json = json.dumps(generate_sarif_json(test_run_id=record.id, target_url=req.target_url, findings=findings))
    db.commit()

    return DastRunResponse(
        id=record.id,
        target_url=req.target_url,
        security_score=score,
        total_tests=len(findings),
        passed_tests=passed_count,
        failed_tests=failed_count,
        findings=findings,
        scan_duration_ms=duration,
        executed_at=record.created_at.isoformat()
    )

@router.get("/export/junit/{test_run_id}")
def export_junit_xml(test_run_id: int, db: Session = Depends(get_db)):
    """Exports test run report as JUnit XML format for Jenkins, GitLab CI, and GitHub Actions."""
    record = db.query(DastTestRecord).filter(DastTestRecord.id == test_run_id).first()
    if not record or not record.junit_xml:
        raise HTTPException(status_code=404, detail="Test run report not found.")

    return Response(
        content=record.junit_xml,
        media_type="application/xml",
        headers={"Content-Disposition": f"attachment; filename=dast_report_{test_run_id}.xml"}
    )

@router.get("/export/sarif/{test_run_id}")
def export_sarif_json(test_run_id: int, db: Session = Depends(get_db)):
    """Exports test run report as OASIS SARIF v2.1.0 for GitHub Advanced Security and IDE integration."""
    record = db.query(DastTestRecord).filter(DastTestRecord.id == test_run_id).first()
    if not record or not record.sarif_json:
        raise HTTPException(status_code=404, detail="Test run report not found.")

    return Response(
        content=record.sarif_json,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=dast_report_{test_run_id}.sarif"}
    )

@router.get("/history")
def get_dast_history(db: Session = Depends(get_db)):
    records = db.query(DastTestRecord).order_by(DastTestRecord.created_at.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "target_url": r.target_url,
            "security_score": r.security_score,
            "passed_tests": r.passed_tests,
            "failed_tests": r.failed_tests,
            "created_at": r.created_at.isoformat()
        }
        for r in records
    ]
