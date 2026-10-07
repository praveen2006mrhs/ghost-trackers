from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field
from app.core.database import Base

# ==========================================
# SQLAlchemy ORM Models
# ==========================================

class ScanRecord(Base):
    __tablename__ = "scan_records"
    id = Column(Integer, primary_key=True, index=True)
    target_name = Column(String(255), default="Direct Snippet")
    scan_type = Column(String(50), default="source_code")
    language = Column(String(50), default="generic")
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    findings_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=datetime.now)

class ArchitectureReview(Base):
    __tablename__ = "architecture_reviews"
    id = Column(Integer, primary_key=True, index=True)
    config_type = Column(String(50))  # iam, k8s, dockerfile
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    compliance_score = Column(Float, default=0.0)
    findings_json = Column(Text, default="[]")
    remediations_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=datetime.now)

class ForensicInvestigation(Base):
    __tablename__ = "forensic_investigations"
    id = Column(Integer, primary_key=True, index=True)
    log_type = Column(String(50))  # apache_nginx, linux_auth, windows_evtx
    total_events = Column(Integer, default=0)
    anomalies_count = Column(Integer, default=0)
    brute_force_detected = Column(Boolean, default=False)
    suspicious_ips_json = Column(Text, default="[]")
    timeline_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=datetime.now)

class ThreatModelRecord(Base):
    __tablename__ = "threat_models"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    description = Column(Text, default="")
    system_boundary = Column(String(255), default="Enterprise Cloud Perimeter")
    created_at = Column(DateTime, default=datetime.now)
    threats = relationship("ThreatItemRecord", back_populates="model", cascade="all, delete-orphan")

class ThreatItemRecord(Base):
    __tablename__ = "threat_items"
    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("threat_models.id"))
    stride_category = Column(String(50))  # Spoofing, Tampering, etc.
    title = Column(String(255))
    description = Column(Text)
    likelihood = Column(Integer, default=3)  # 1-5
    impact = Column(Integer, default=3)      # 1-5
    risk_score = Column(Integer, default=9)   # Likelihood * Impact
    risk_level = Column(String(50), default="Medium")
    mitigation_status = Column(String(50), default="Open")  # Open, In Progress, Mitigated, Accepted
    mitigation_controls = Column(Text, default="")
    model = relationship("ThreatModelRecord", back_populates="threats")

class DastTestRecord(Base):
    __tablename__ = "dast_tests"
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(512))
    passed_tests = Column(Integer, default=0)
    failed_tests = Column(Integer, default=0)
    security_score = Column(Float, default=0.0)
    findings_json = Column(Text, default="[]")
    junit_xml = Column(Text, default="")
    sarif_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.now)

class MalwareRecord(Base):
    __tablename__ = "malware_records"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255))
    file_size = Column(Integer, default=0)
    sha256 = Column(String(64))
    md5 = Column(String(32))
    ssdeep = Column(String(128), default="")
    entropy = Column(Float, default=0.0)
    is_packed = Column(Boolean, default=False)
    file_type = Column(String(50), default="Unknown")
    yara_matches_json = Column(Text, default="[]")
    pe_metadata_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.now)


# ==========================================
# Pydantic v2 Schemas for Requests / Responses
# ==========================================

# 1. Vulnerability Assessment Schemas
class CodeScanRequest(BaseModel):
    code: str
    target_name: Optional[str] = "Snippet"
    language: Optional[str] = "python"

class VulnerabilityFinding(BaseModel):
    id: str
    rule_name: str
    category: str
    severity: str  # Critical, High, Medium, Low, Informational
    cvss_score: float
    cvss_vector: str
    line_number: int
    matched_snippet: str
    description: str
    cwe_id: str
    remediation: str

class CodeScanResponse(BaseModel):
    target_name: str
    language: str
    total_findings: int
    severity_breakdown: Dict[str, int]
    findings: List[VulnerabilityFinding]
    scan_timestamp: str

class CVSS31CalculationRequest(BaseModel):
    attack_vector: str = Field("NETWORK", pattern="^(NETWORK|ADJACENT|LOCAL|PHYSICAL)$")
    attack_complexity: str = Field("LOW", pattern="^(LOW|HIGH)$")
    privileges_required: str = Field("NONE", pattern="^(NONE|LOW|HIGH)$")
    user_interaction: str = Field("NONE", pattern="^(NONE|REQUIRED)$")
    scope: str = Field("UNCHANGED", pattern="^(UNCHANGED|CHANGED)$")
    confidentiality: str = Field("HIGH", pattern="^(NONE|LOW|HIGH)$")
    integrity: str = Field("HIGH", pattern="^(NONE|LOW|HIGH)$")
    availability: str = Field("HIGH", pattern="^(NONE|LOW|HIGH)$")

class CVSS31CalculationResponse(BaseModel):
    base_score: float
    severity_rating: str
    vector_string: str
    impact_sub_score: float
    exploitability_sub_score: float

class DependencyScanRequest(BaseModel):
    manifest_type: str = "requirements.txt"  # requirements.txt or package.json
    manifest_content: str

class DependencyFinding(BaseModel):
    package: str
    installed_version: str
    fixed_version: str
    cve_id: str
    severity: str
    cvss_score: float
    advisory: str

class DependencyScanResponse(BaseModel):
    manifest_type: str
    total_packages_checked: int
    vulnerable_packages_count: int
    findings: List[DependencyFinding]


# 2. Security Architecture Schemas
class ArchitectureReviewRequest(BaseModel):
    config_type: str  # iam, k8s, dockerfile
    content: str
    name: Optional[str] = "Infrastructure Asset"

class ArchitectureFinding(BaseModel):
    check_id: str
    title: str
    severity: str
    cis_benchmark: str
    nist_control: str
    owasp_mapping: str
    description: str
    remediation_playbook: str
    fixed_snippet: Optional[str] = None
    passed: bool

class ArchitectureReviewResponse(BaseModel):
    config_type: str
    compliance_score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    findings: List[ArchitectureFinding]


# 3. Incident Response & Forensics Schemas
class LogParseRequest(BaseModel):
    log_type: str  # apache_nginx, linux_auth, windows_evtx_json
    log_content: str

class TimelineEvent(BaseModel):
    timestamp: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    event_type: str
    severity: str
    details: str
    mitre_attack: Optional[str] = None
    is_anomaly: bool = False

class ForensicsAnalysisResponse(BaseModel):
    log_type: str
    total_lines_parsed: int
    total_events: int
    anomalies_detected: int
    brute_force_detected: bool
    top_source_ips: List[Dict[str, Any]]
    suspicious_user_agents: List[Dict[str, Any]]
    timeline: List[TimelineEvent]
    mitre_tactics: List[str]


# 4. Threat Modeling Schemas
class ThreatItemCreate(BaseModel):
    stride_category: str  # Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
    title: str
    description: str
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    mitigation_controls: Optional[str] = ""

class ThreatItemUpdate(BaseModel):
    mitigation_status: str  # Open, In Progress, Mitigated, Accepted
    mitigation_controls: Optional[str] = None
    likelihood: Optional[int] = Field(None, ge=1, le=5)
    impact: Optional[int] = Field(None, ge=1, le=5)

class ThreatItemOut(BaseModel):
    id: int
    stride_category: str
    title: str
    description: str
    likelihood: int
    impact: int
    risk_score: int
    risk_level: str
    mitigation_status: str
    mitigation_controls: str

class ThreatModelCreate(BaseModel):
    name: str
    description: str
    system_boundary: str = "Cloud Perimeter"
    initial_threats: Optional[List[ThreatItemCreate]] = []

class ThreatModelOut(BaseModel):
    id: int
    name: str
    description: str
    system_boundary: str
    created_at: datetime
    threats: List[ThreatItemOut]

class HeatmapCell(BaseModel):
    likelihood: int
    impact: int
    risk_level: str
    threat_count: int
    threat_ids: List[int]

class HeatmapMatrixResponse(BaseModel):
    model_id: int
    total_threats: int
    matrix: List[HeatmapCell]
    open_threats: int
    mitigated_threats: int


# 5. Security Testing (DAST) Schemas
class DastRunRequest(BaseModel):
    target_url: str = "http://localhost:8000/api/v1/security-tests/mock-target"
    check_cors: bool = True
    check_security_headers: bool = True
    check_clickjacking: bool = True
    check_ssl: bool = True

class DastFinding(BaseModel):
    test_id: str
    name: str
    category: str
    severity: str
    passed: bool
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation: str
    cwe: str

class DastRunResponse(BaseModel):
    id: int
    target_url: str
    security_score: float
    total_tests: int
    passed_tests: int
    failed_tests: int
    findings: List[DastFinding]
    scan_duration_ms: float
    executed_at: str


# 6. Malware Triage Schemas
class MalwareAnalyzeRequest(BaseModel):
    filename: str
    raw_content_b64: Optional[str] = None
    text_content: Optional[str] = None

class SectionEntropy(BaseModel):
    name: str
    entropy: float
    size_bytes: int
    is_suspicious: bool

class YaraMatch(BaseModel):
    rule_name: str
    tags: List[str]
    severity: str
    description: str
    matched_patterns: List[str]

class MalwareAnalysisResponse(BaseModel):
    id: Optional[int] = None
    filename: str
    file_size_bytes: int
    file_type: str
    sha256: str
    md5: str
    ssdeep: str
    overall_entropy: float
    is_likely_packed: bool
    sections: List[SectionEntropy]
    imported_dlls: List[str]
    suspicious_api_calls: List[str]
    yara_matches: List[YaraMatch]
    triage_verdict: str  # CLEAN, SUSPICIOUS, MALICIOUS
