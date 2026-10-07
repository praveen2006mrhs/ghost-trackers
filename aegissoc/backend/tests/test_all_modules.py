import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_and_health():
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert "Ghost Trackers" in data["suite"] or "AegisSOC" in data["suite"]
    assert len(data["modules"]) == 6

    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "healthy"

# 1. Vulnerability Assessment Tests
def test_vuln_code_scan():
    code_snippet = """
import pickle
api_key = "AKIA1234567890ABCDEF"
db_password = "supersecret_password_123456"

def login(user, pw):
    query = f"SELECT * FROM users WHERE username = '{user}'"
    eval(f"print('{user}')")
    data = pickle.loads(b"cos\\nsystem\\n(S'ls'\\ntR.")
    return query
"""
    res = client.post("/api/v1/vuln/scan-code", json={"code": code_snippet, "language": "python"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_findings"] >= 4
    assert data["severity_breakdown"]["Critical"] >= 1
    
    # Check rule IDs
    rule_ids = [f["id"] for f in data["findings"]]
    assert any("AEGIS-SEC-001" in r for r in rule_ids) # AWS key
    assert any("AEGIS-DES-001" in r for r in rule_ids) # pickle
    assert any("AEGIS-CMD-002" in r for r in rule_ids) # eval

def test_cvss_31_calculation():
    payload = {
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality": "HIGH",
        "integrity": "HIGH",
        "availability": "HIGH"
    }
    res = client.post("/api/v1/vuln/cvss-calculate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["base_score"] == 9.8
    assert data["severity_rating"] == "Critical"
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in data["vector_string"]

def test_dependency_scan():
    req_txt = """
requests==2.28.0
urllib3==1.26.5
flask==2.1.0
safe-package==9.0.0
"""
    res = client.post("/api/v1/vuln/scan-dependencies", json={
        "manifest_type": "requirements.txt",
        "manifest_content": req_txt
    })
    assert res.status_code == 200
    data = res.json()
    assert data["vulnerable_packages_count"] >= 3
    pkgs = [f["package"] for f in data["findings"]]
    assert "requests" in pkgs
    assert "flask" in pkgs

# 2. Security Architecture Review Tests
def test_architecture_iam():
    bad_policy = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        }
      ]
    }"""
    res = client.post("/api/v1/architecture/review-iam", json={"config_type": "iam", "content": bad_policy})
    assert res.status_code == 200
    data = res.json()
    assert data["compliance_score"] < 100.0
    failed_checks = [f["check_id"] for f in data["findings"] if not f["passed"]]
    assert "IAM-CHK-001" in failed_checks # Wildcard Action
    assert "IAM-CHK-002" in failed_checks # Wildcard Resource

def test_architecture_k8s():
    k8s_manifest = """apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
"""
    res = client.post("/api/v1/architecture/review-k8s", json={"config_type": "k8s", "content": k8s_manifest})
    assert res.status_code == 200
    data = res.json()
    failed_checks = [f["check_id"] for f in data["findings"] if not f["passed"]]
    assert "K8S-SEC-001" in failed_checks # Privileged container

def test_architecture_dockerfile():
    dockerfile = """FROM python:latest
ENV AWS_SECRET_ACCESS_KEY=abcd1234efgh5678
EXPOSE 22
ADD http://example.com/mal.tar.gz /tmp/
CMD ["python", "app.py"]
"""
    res = client.post("/api/v1/architecture/review-dockerfile", json={"config_type": "dockerfile", "content": dockerfile})
    assert res.status_code == 200
    data = res.json()
    failed = [f["check_id"] for f in data["findings"] if not f["passed"]]
    assert "DCK-SEC-001" in failed # Missing USER
    assert "DCK-SEC-003" in failed # Secret in ENV
    assert "DCK-SEC-005" in failed # Port 22

# 3. Forensics & Incident Response Tests
def test_forensics_analysis():
    sample_res = client.get("/api/v1/forensics/sample-logs")
    assert sample_res.status_code == 200
    samples = sample_res.json()
    
    # Test Linux Auth Log with brute force
    res = client.post("/api/v1/forensics/parse-logs", json={
        "log_type": "linux_auth",
        "log_content": samples["linux_auth"]
    })
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] >= 6
    assert data["brute_force_detected"] is True
    assert len(data["timeline"]) > 0

# 4. Threat Modeling Tests
def test_threat_model_lifecycle():
    # Create model
    create_res = client.post("/api/v1/threat-model/models", json={
        "name": "Payment Gateway Test Model",
        "description": "Integration testing model",
        "system_boundary": "PCI-DSS Environment"
    })
    assert create_res.status_code == 200
    model = create_res.json()
    model_id = model["id"]
    assert len(model["threats"]) == 6 # 6 STRIDE templates auto-seeded

    # Add custom threat
    threat_res = client.post(f"/api/v1/threat-model/models/{model_id}/threats", json={
        "stride_category": "Information Disclosure",
        "title": "Database Credential Exposure via Debug Endpoint",
        "description": "Debug route returns plaintext DB password.",
        "likelihood": 4,
        "impact": 5,
        "mitigation_controls": "Disable debug routes in production."
    })
    assert threat_res.status_code == 200
    threat = threat_res.json()
    threat_id = threat["id"]
    assert threat["risk_score"] == 20
    assert threat["risk_level"] == "Critical"

    # Mitigate threat
    mitigate_res = client.put(f"/api/v1/threat-model/threats/{threat_id}/mitigate", json={
        "mitigation_status": "Mitigated",
        "mitigation_controls": "Debug endpoints disabled via environment flag."
    })
    assert mitigate_res.status_code == 200
    updated = mitigate_res.json()
    assert updated["mitigation_status"] == "Mitigated"
    assert updated["risk_score"] < 20 # Lowered residual risk

    # Heatmap
    matrix_res = client.get(f"/api/v1/threat-model/matrix/{model_id}")
    assert matrix_res.status_code == 200
    matrix = matrix_res.json()
    assert len(matrix["matrix"]) == 25 # 5x5 cells

# 5. Security Testing (DAST) Tests
def test_dast_testing_and_exports():
    res = client.post("/api/v1/security-tests/run-dast", json={
        "target_url": "http://testserver/api/v1/security-tests/mock-target",
        "check_cors": True,
        "check_security_headers": True,
        "check_clickjacking": True,
        "check_ssl": True
    })
    assert res.status_code == 200
    dast_data = res.json()
    run_id = dast_data["id"]
    assert len(dast_data["findings"]) > 0

    # Test JUnit export
    junit_res = client.get(f"/api/v1/security-tests/export/junit/{run_id}")
    assert junit_res.status_code == 200
    assert "application/xml" in junit_res.headers["content-type"]
    assert "<testsuites" in junit_res.text

    # Test SARIF export
    sarif_res = client.get(f"/api/v1/security-tests/export/sarif/{run_id}")
    assert sarif_res.status_code == 200
    assert "application/json" in sarif_res.headers["content-type"]
    assert "sarif-schema-2.1.0" in sarif_res.text

# 6. Malware Triage Tests
def test_malware_analysis():
    sample_res = client.get("/api/v1/malware/sample-artifacts")
    samples = sample_res.json()
    
    # Test extortion ransom note
    res = client.post("/api/v1/malware/analyze-file", json={
        "filename": "ransom_note.txt",
        "text_content": samples["ransomware_note"]["content"]
    })
    assert res.status_code == 200
    data = res.json()
    assert data["sha256"] != ""
    assert data["overall_entropy"] > 0.0
    assert len(data["yara_matches"]) >= 1
    assert any(m["rule_name"] == "Ransomware_Extortion_Note_Strings" for m in data["yara_matches"])
    assert data["triage_verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    # Test mock PE
    pe_res = client.post("/api/v1/malware/analyze-file", json={
        "filename": "suspicious.exe",
        "raw_content_b64": samples["mock_pe_binary"]["b64"]
    })
    assert pe_res.status_code == 200
    pe_data = pe_res.json()
    assert "Windows Executable" in pe_data["file_type"]
    assert pe_data["is_likely_packed"] is True
