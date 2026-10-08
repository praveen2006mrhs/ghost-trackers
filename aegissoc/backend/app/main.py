import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.api.api import api_router
from app.models.schemas import ThreatModelRecord, ThreatItemRecord
from app.services.threat_modeler import get_default_stride_templates, compute_risk

# Ensure database tables exist immediately upon module import
Base.metadata.create_all(bind=engine)

def seed_default_threat_models():
    db = SessionLocal()
    try:
        existing_model = db.query(ThreatModelRecord).first()
        if not existing_model:
            demo_model = ThreatModelRecord(
                name="Aegis Cloud Perimeter & Microservices",
                description="Enterprise defensive perimeter including API Gateway, Auth Microservice, and Database.",
                system_boundary="Cloud AWS Multi-VPC"
            )
            db.add(demo_model)
            db.commit()
            db.refresh(demo_model)

            for d in get_default_stride_templates():
                score, level = compute_risk(d["likelihood"], d["impact"])
                item = ThreatItemRecord(
                    model_id=demo_model.id,
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
            db.commit()
    finally:
        db.close()

seed_default_threat_models()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    seed_default_threat_models()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)

# Enable CORS for frontend Vite development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers_and_timing(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    response.headers["X-Response-Time-Ms"] = str(round(duration * 1000, 2))
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# Mount API routers
app.include_router(api_router, prefix=settings.API_V1_PREFIX)

@app.get("/")
def root():
    return {
        "suite": settings.PROJECT_NAME,
        "status": "operational",
        "version": settings.VERSION,
        "docs_url": "/docs",
        "api_prefix": settings.API_V1_PREFIX,
        "modules": [
            "Vulnerability Assessment & Static Detection (/api/v1/vuln)",
            "Security Architecture Reviewer (/api/v1/architecture)",
            "Incident Response & Forensics (/api/v1/forensics)",
            "Threat Modeling & Risk Assessment (/api/v1/threat-model)",
            "Automated Security Testing Harness (/api/v1/security-tests)",
            "Defensive Malware Analysis & Artifact Triage (/api/v1/malware)"
        ]
    }

@app.get("/health")
@app.get("/api/health")
@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "database": "sqlite_connected",
        "sandbox_mode": settings.SANDBOX_MODE
    }
