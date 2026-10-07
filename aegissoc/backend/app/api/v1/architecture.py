import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.schemas import (
    ArchitectureReviewRequest, ArchitectureReviewResponse,
    ArchitectureReview
)
from app.services.architecture_linter import (
    review_infrastructure_architecture, lint_aws_iam,
    lint_k8s_manifest, lint_dockerfile, get_compliance_framework_catalog
)

router = APIRouter(prefix="/architecture", tags=["Security Architecture Review"])

@router.post("/review", response_model=ArchitectureReviewResponse)
def review_config(req: ArchitectureReviewRequest, db: Session = Depends(get_db)):
    """Generic configuration linter for IAM JSON, K8s manifests, or Dockerfiles."""
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="Configuration content cannot be empty.")

    score, findings = review_infrastructure_architecture(req.config_type, req.content)
    passed_count = sum(1 for f in findings if f.passed)
    failed_count = len(findings) - passed_count

    # Persist in DB
    record = ArchitectureReview(
        config_type=req.config_type,
        total_checks=len(findings),
        passed_checks=passed_count,
        failed_checks=failed_count,
        compliance_score=score,
        findings_json=json.dumps([f.model_dump() for f in findings]),
        remediations_json=json.dumps([f.remediation_playbook for f in findings if not f.passed])
    )
    db.add(record)
    db.commit()

    return ArchitectureReviewResponse(
        config_type=req.config_type,
        compliance_score=score,
        total_checks=len(findings),
        passed_checks=passed_count,
        failed_checks=failed_count,
        findings=findings
    )

@router.post("/review-iam", response_model=ArchitectureReviewResponse)
def review_iam_endpoint(req: ArchitectureReviewRequest, db: Session = Depends(get_db)):
    req.config_type = "iam"
    return review_config(req, db)

@router.post("/review-k8s", response_model=ArchitectureReviewResponse)
def review_k8s_endpoint(req: ArchitectureReviewRequest, db: Session = Depends(get_db)):
    req.config_type = "k8s"
    return review_config(req, db)

@router.post("/review-dockerfile", response_model=ArchitectureReviewResponse)
def review_dockerfile_endpoint(req: ArchitectureReviewRequest, db: Session = Depends(get_db)):
    req.config_type = "dockerfile"
    return review_config(req, db)

@router.get("/compliance-frameworks")
def list_compliance_frameworks():
    """Returns CIS Benchmarks, NIST SP 800-53, and OWASP Top 10 catalog."""
    return get_compliance_framework_catalog()

@router.get("/history")
def get_architecture_history(db: Session = Depends(get_db)):
    records = db.query(ArchitectureReview).order_by(ArchitectureReview.created_at.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "config_type": r.config_type,
            "compliance_score": r.compliance_score,
            "passed_checks": r.passed_checks,
            "failed_checks": r.failed_checks,
            "created_at": r.created_at.isoformat()
        }
        for r in records
    ]
