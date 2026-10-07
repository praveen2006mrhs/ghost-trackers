from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.schemas import (
    ThreatModelCreate, ThreatModelOut,
    ThreatItemCreate, ThreatItemUpdate, ThreatItemOut,
    HeatmapMatrixResponse,
    ThreatModelRecord, ThreatItemRecord
)
from app.services.threat_modeler import (
    compute_risk, generate_5x5_heatmap, get_default_stride_templates
)

router = APIRouter(prefix="/threat-model", tags=["Threat Modeling & Risk Assessment"])

@router.post("/models", response_model=ThreatModelOut)
def create_threat_model(req: ThreatModelCreate, db: Session = Depends(get_db)):
    """Creates a new threat model with optional initial STRIDE threat vectors."""
    model = ThreatModelRecord(
        name=req.name,
        description=req.description,
        system_boundary=req.system_boundary
    )
    db.add(model)
    db.commit()
    db.refresh(model)

    # If no initial threats provided, seed with standard STRIDE templates
    threats_to_add = req.initial_threats if req.initial_threats else []
    if not threats_to_add:
        defaults = get_default_stride_templates()
        for d in defaults:
            score, level = compute_risk(d["likelihood"], d["impact"])
            item = ThreatItemRecord(
                model_id=model.id,
                stride_category=d["category"],
                title=d["title"],
                description=d["description"],
                likelihood=d["likelihood"],
                impact=d["impact"],
                risk_score=score,
                risk_level=level,
                mitigation_status="Open",
                mitigation_controls=d["mitigation_controls"]
            )
            db.add(item)
    else:
        for t in threats_to_add:
            score, level = compute_risk(t.likelihood, t.impact)
            item = ThreatItemRecord(
                model_id=model.id,
                stride_category=t.stride_category,
                title=t.title,
                description=t.description,
                likelihood=t.likelihood,
                impact=t.impact,
                risk_score=score,
                risk_level=level,
                mitigation_status="Open",
                mitigation_controls=t.mitigation_controls or ""
            )
            db.add(item)

    db.commit()
    db.refresh(model)
    return model

@router.get("/models", response_model=List[ThreatModelOut])
def list_threat_models(db: Session = Depends(get_db)):
    """Retrieves all threat models."""
    return db.query(ThreatModelRecord).order_by(ThreatModelRecord.created_at.desc()).all()

@router.get("/models/{model_id}", response_model=ThreatModelOut)
def get_threat_model(model_id: int, db: Session = Depends(get_db)):
    model = db.query(ThreatModelRecord).filter(ThreatModelRecord.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Threat model not found.")
    return model

@router.post("/models/{model_id}/threats", response_model=ThreatItemOut)
def add_threat_to_model(model_id: int, req: ThreatItemCreate, db: Session = Depends(get_db)):
    """Appends a new STRIDE threat to an existing model."""
    model = db.query(ThreatModelRecord).filter(ThreatModelRecord.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Threat model not found.")

    score, level = compute_risk(req.likelihood, req.impact)
    item = ThreatItemRecord(
        model_id=model.id,
        stride_category=req.stride_category,
        title=req.title,
        description=req.description,
        likelihood=req.likelihood,
        impact=req.impact,
        risk_score=score,
        risk_level=level,
        mitigation_status="Open",
        mitigation_controls=req.mitigation_controls or ""
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

@router.put("/threats/{threat_id}/mitigate", response_model=ThreatItemOut)
def update_threat_mitigation(threat_id: int, req: ThreatItemUpdate, db: Session = Depends(get_db)):
    """Updates mitigation status and controls, adjusting residual risk if mitigated."""
    item = db.query(ThreatItemRecord).filter(ThreatItemRecord.id == threat_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Threat item not found.")

    item.mitigation_status = req.mitigation_status
    if req.mitigation_controls is not None:
        item.mitigation_controls = req.mitigation_controls

    if req.likelihood is not None:
        item.likelihood = req.likelihood
    elif req.mitigation_status == "Mitigated":
        # Automatically lower residual likelihood upon mitigation
        item.likelihood = max(1, item.likelihood - 1)

    if req.impact is not None:
        item.impact = req.impact

    score, level = compute_risk(item.likelihood, item.impact)
    item.risk_score = score
    item.risk_level = level

    db.commit()
    db.refresh(item)
    return item

@router.get("/matrix/{model_id}", response_model=HeatmapMatrixResponse)
def get_heatmap_matrix(model_id: int, db: Session = Depends(get_db)):
    """Renders interactive 5x5 Likelihood x Impact heat map."""
    model = db.query(ThreatModelRecord).filter(ThreatModelRecord.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Threat model not found.")

    threat_items = [
        ThreatItemOut(
            id=t.id,
            stride_category=t.stride_category,
            title=t.title,
            description=t.description,
            likelihood=t.likelihood,
            impact=t.impact,
            risk_score=t.risk_score,
            risk_level=t.risk_level,
            mitigation_status=t.mitigation_status,
            mitigation_controls=t.mitigation_controls
        )
        for t in model.threats
    ]

    return generate_5x5_heatmap(threat_items, model_id=model.id)

@router.get("/templates")
def get_stride_templates():
    return get_default_stride_templates()
