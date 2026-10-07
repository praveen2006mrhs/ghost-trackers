from typing import List, Dict, Any
from app.models.schemas import ThreatItemOut, HeatmapCell, HeatmapMatrixResponse

STRIDE_CATEGORIES = {
    "Spoofing": "Illegitimate access using forged identity, compromised session tokens, or credential stuffing.",
    "Tampering": "Unauthorized modification of data in transit or persistent storage, parameter tampering, or database alteration.",
    "Repudiation": "Denial of performing actions due to lack of non-repudiation, tamper-evident logging, or auditing.",
    "Information Disclosure": "Exposure of sensitive data (PII, secrets, database schemas) to unauthorized parties.",
    "Denial of Service": "Degradation or complete exhaustion of system availability and resources through volumetric requests or resource leaks.",
    "Elevation of Privilege": "Unprivileged actor gaining higher administrative or system-level access through privilege escalation vulnerabilities."
}

def calculate_risk_level(score: int) -> str:
    if score >= 15:
        return "Critical"
    elif score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"

def compute_risk(likelihood: int, impact: int) -> tuple[int, str]:
    score = likelihood * impact
    level = calculate_risk_level(score)
    return score, level

def generate_5x5_heatmap(threats: List[ThreatItemOut], model_id: int) -> HeatmapMatrixResponse:
    # 5x5 Grid (Likelihood: 1..5, Impact: 1..5)
    matrix_cells: List[HeatmapCell] = []
    
    # Pre-populate all 25 cells
    grid_map: Dict[tuple[int, int], List[int]] = {(l, i): [] for l in range(1, 6) for i in range(1, 6)}
    
    open_count = 0
    mitigated_count = 0

    for t in threats:
        if t.mitigation_status in ["Mitigated", "Accepted"]:
            mitigated_count += 1
        else:
            open_count += 1
            
        l = max(1, min(5, t.likelihood))
        i = max(1, min(5, t.impact))
        grid_map[(l, i)].append(t.id)

    for l in range(1, 6):
        for i in range(1, 6):
            cell_threats = grid_map[(l, i)]
            score, level = compute_risk(l, i)
            matrix_cells.append(HeatmapCell(
                likelihood=l,
                impact=i,
                risk_level=level,
                threat_count=len(cell_threats),
                threat_ids=cell_threats
            ))

    return HeatmapMatrixResponse(
        model_id=model_id,
        total_threats=len(threats),
        matrix=matrix_cells,
        open_threats=open_count,
        mitigated_threats=mitigated_count
    )

def get_default_stride_templates() -> List[Dict[str, Any]]:
    return [
        {
            "category": "Spoofing",
            "title": "Bypass Authentication via JWT None Algorithm",
            "description": "Attacker provides forged token with alg='none' allowing identity impersonation.",
            "likelihood": 3,
            "impact": 5,
            "mitigation_controls": "Enforce RS256/ES256 asymmetric signing and reject alg=none in signature verification."
        },
        {
            "category": "Tampering",
            "title": "Parameter Tampering on User Account Role",
            "description": "Client-side request contains role='admin' payload that server accepts without authorization check.",
            "likelihood": 4,
            "impact": 5,
            "mitigation_controls": "Derive user roles strictly from authenticated server-side session or verified cryptographically bound claims."
        },
        {
            "category": "Repudiation",
            "title": "Insufficient Audit Logging on Financial Transactions",
            "description": "High-value fund transfers do not record cryptographically verifiable audit trails with immutable timestamps.",
            "likelihood": 2,
            "impact": 4,
            "mitigation_controls": "Forward structured audit logs to an append-only WORM-compliant SIEM cluster."
        },
        {
            "category": "Information Disclosure",
            "title": "Internal Error Stack Traces Exposed to Public Endpoints",
            "description": "500 Internal Server Error returns unhandled database connection strings and system paths.",
            "likelihood": 4,
            "impact": 3,
            "mitigation_controls": "Implement global exception handlers returning sanitized error identifiers without stack traces."
        },
        {
            "category": "Denial of Service",
            "title": "API Gateway Rate Limit Bypass via Header Spoofing",
            "description": "Attacker rotates X-Forwarded-For headers to evade IP-based rate limiting causing database exhaustion.",
            "likelihood": 4,
            "impact": 4,
            "mitigation_controls": "Configure API Gateway to strip untrusted X-Forwarded-For headers and enforce token bucket per client API key."
        },
        {
            "category": "Elevation of Privilege",
            "title": "Insecure Direct Object Reference (IDOR) on Tenant Admin",
            "description": "User modifies tenant_id in URL path to view and administer resources of rival organizational tenants.",
            "likelihood": 3,
            "impact": 5,
            "mitigation_controls": "Implement mandatory object-level authorization (ABAC/RBAC) middleware verifying caller tenant ownership."
        }
    ]
