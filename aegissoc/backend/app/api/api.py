from fastapi import APIRouter
from app.api.v1.vuln import router as vuln_router
from app.api.v1.architecture import router as architecture_router
from app.api.v1.forensics import router as forensics_router
from app.api.v1.threat_model import router as threat_model_router
from app.api.v1.security_tests import router as security_tests_router
from app.api.v1.malware import router as malware_router

api_router = APIRouter()

api_router.include_router(vuln_router)
api_router.include_router(architecture_router)
api_router.include_router(forensics_router)
api_router.include_router(threat_model_router)
api_router.include_router(security_tests_router)
api_router.include_router(malware_router)
