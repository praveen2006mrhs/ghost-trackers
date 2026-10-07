import re
import math
from typing import List, Dict, Any, Tuple
from app.models.schemas import VulnerabilityFinding, DependencyFinding

# ==============================================================================
# 1. HEURISTIC SOURCE CODE RULES (Bandit / Semgrep style)
# ==============================================================================

RULES = [
    {
        "id": "AEGIS-SEC-001",
        "name": "Hardcoded AWS Access Key",
        "category": "Secrets & Credentials",
        "severity": "Critical",
        "cwe": "CWE-798",
        "regex": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        "description": "Hardcoded AWS Access Key ID discovered in source code.",
        "remediation": "Revoke AWS credential immediately and migrate to IAM Roles or AWS Secrets Manager.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "NONE", "ui": "NONE", "s": "CHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-SEC-002",
        "name": "Hardcoded Private Key Block",
        "category": "Cryptography",
        "severity": "Critical",
        "cwe": "CWE-312",
        "regex": r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----',
        "description": "Embedded private encryption/signing key block found in code.",
        "remediation": "Never commit private cryptographic keys. Store in Vault or environment variables.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "NONE", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-SEC-003",
        "name": "Generic Secret or API Token Assignment",
        "category": "Secrets & Credentials",
        "severity": "High",
        "cwe": "CWE-798",
        "regex": r'(?i)(?:api_key|api_secret|auth_token|client_secret|db_password|access_token)\s*=\s*[\'"][A-Za-z0-9_\-\.\$\!\#\%]{12,}[\'"]',
        "description": "High-entropy API token or secret variable assigned directly in source.",
        "remediation": "Load secrets from environment variables or a secure key management service.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "NONE", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "LOW", "a": "NONE"}
    },
    {
        "id": "AEGIS-SEC-004",
        "name": "GitHub Personal Access Token",
        "category": "Secrets & Credentials",
        "severity": "Critical",
        "cwe": "CWE-798",
        "regex": r'gh[pousr]_[A-Za-z0-9]{36,255}',
        "description": "Hardcoded GitHub personal access or OAuth token detected.",
        "remediation": "Revoke token via GitHub Settings and use GitHub Secrets in CI/CD.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "NONE", "ui": "NONE", "s": "CHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-INJ-001",
        "name": "SQL Injection via Dynamic String Formatting",
        "category": "Injection",
        "severity": "High",
        "cwe": "CWE-89",
        "regex": r'(?i)(?:execute|raw|cursor\.execute|db\.query)\s*\(\s*(?:f[\'"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*?\{|[\'"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?%\s*\w+)',
        "description": "SQL query dynamically composed via f-string or % formatting without parameterized queries.",
        "remediation": "Use parameterized queries or ORM query builders (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))).",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "LOW", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-INJ-002",
        "name": "Raw SQL String Concatenation",
        "category": "Injection",
        "severity": "High",
        "cwe": "CWE-89",
        "regex": r'(?i)(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+.*?\s*[\'"]\s*\+\s*[a-zA-Z_]\w*',
        "description": "Direct concatenation of untrusted variables into SQL query string.",
        "remediation": "Enforce prepared statements with bind variables to prevent SQL injection.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "LOW", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-DES-001",
        "name": "Insecure Deserialization via Python Pickle",
        "category": "Insecure Deserialization",
        "severity": "Critical",
        "cwe": "CWE-502",
        "regex": r'\bpickle\.(?:loads|load)\s*\(',
        "description": "Arbitrary code execution risk: unpickling untrusted data allows arbitrary object reconstruction.",
        "remediation": "Use safer serialization formats like JSON, Protocol Buffers, or messagepack instead of pickle.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "NONE", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-DES-002",
        "name": "Unsafe PyYAML Loader",
        "category": "Insecure Deserialization",
        "severity": "High",
        "cwe": "CWE-502",
        "regex": r'yaml\.(?:load|load_all)\s*\([^,)]*(?!\bLoader\s*=\s*(?:yaml\.)?SafeLoader)[^,)]*\)',
        "description": "PyYAML load() used without SafeLoader permits arbitrary Python object instantiation.",
        "remediation": "Replace with yaml.safe_load() or specify Loader=yaml.SafeLoader.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "NONE", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-CMD-001",
        "name": "Subprocess Execution with shell=True",
        "category": "Command Injection",
        "severity": "High",
        "cwe": "CWE-78",
        "regex": r'subprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True',
        "description": "Executing command through system shell (shell=True) invites shell metacharacter injection.",
        "remediation": "Pass arguments as an argument list with shell=False (default) and validate parameters.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "LOW", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-CMD-002",
        "name": "Dangerous eval/exec Execution",
        "category": "Code Injection",
        "severity": "Critical",
        "cwe": "CWE-95",
        "regex": r'\b(?:eval|exec)\s*\([^)]*\)',
        "description": "Dynamic evaluation of string expressions using eval/exec executes arbitrary Python instructions.",
        "remediation": "Refactor logic to eliminate dynamic code evaluation or use ast.literal_eval for literals.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "LOW", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "HIGH", "a": "HIGH"}
    },
    {
        "id": "AEGIS-CRY-001",
        "name": "Weak Cryptographic Hash (MD5 / SHA-1)",
        "category": "Weak Cryptography",
        "severity": "Medium",
        "cwe": "CWE-328",
        "regex": r'hashlib\.(?:md5|sha1)\s*\(',
        "description": "MD5 and SHA-1 suffer from known collision vulnerabilities and must not be used for security.",
        "remediation": "Upgrade to SHA-256 or SHA-3 (e.g. hashlib.sha256()) or Argon2id/bcrypt for password hashing.",
        "cvss": {"av": "NETWORK", "ac": "HIGH", "pr": "NONE", "ui": "NONE", "s": "UNCHANGED", "c": "LOW", "i": "LOW", "a": "NONE"}
    },
    {
        "id": "AEGIS-PTH-001",
        "name": "Potential Path Traversal",
        "category": "Path Traversal",
        "severity": "Medium",
        "cwe": "CWE-22",
        "regex": r'open\s*\(\s*(?:os\.path\.join\([^)]*request|f[\'"].*?\{.*?request)',
        "description": "Opening file paths derived directly from untrusted user requests without validation.",
        "remediation": "Resolve path with os.path.realpath() and verify it starts with the intended base directory.",
        "cvss": {"av": "NETWORK", "ac": "LOW", "pr": "LOW", "ui": "NONE", "s": "UNCHANGED", "c": "HIGH", "i": "NONE", "a": "NONE"}
    }
]

# ==============================================================================
# 2. CVSS 3.1 BASE SCORE CALCULATION ENGINE
# ==============================================================================

CVSS_WEIGHTS = {
    "av": {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20},
    "ac": {"LOW": 0.77, "HIGH": 0.44},
    "pr": {
        "UNCHANGED": {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27},
        "CHANGED": {"NONE": 0.85, "LOW": 0.68, "HIGH": 0.50}
    },
    "ui": {"NONE": 0.85, "REQUIRED": 0.62},
    "c": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0},
    "i": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0},
    "a": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0}
}

def roundup(val: float) -> float:
    """CVSS 3.1 official roundup function: round up to nearest 0.1."""
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return (math.floor(int_val / 10000) + 1) / 10.0

def calculate_cvss_31(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str
) -> Tuple[float, str, str, float, float]:
    """
    Computes CVSS 3.1 Base Score, Rating, Vector string, Impact Sub-score, and Exploitability Sub-score.
    """
    av_val = CVSS_WEIGHTS["av"][attack_vector]
    ac_val = CVSS_WEIGHTS["ac"][attack_complexity]
    pr_val = CVSS_WEIGHTS["pr"][scope][privileges_required]
    ui_val = CVSS_WEIGHTS["ui"][user_interaction]
    
    c_val = CVSS_WEIGHTS["c"][confidentiality]
    i_val = CVSS_WEIGHTS["i"][integrity]
    a_val = CVSS_WEIGHTS["a"][availability]
    
    # ISS (Impact Sub Score)
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
    
    if scope == "UNCHANGED":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val
    
    if impact <= 0:
        base_score = 0.0
    else:
        if scope == "UNCHANGED":
            base_score = min(roundup(min((impact + exploitability), 10.0)), 10.0)
        else:
            base_score = min(roundup(min(1.08 * (impact + exploitability), 10.0)), 10.0)
            
    # Severity rating
    if base_score == 0.0:
        rating = "None"
    elif base_score <= 3.9:
        rating = "Low"
    elif base_score <= 6.9:
        rating = "Medium"
    elif base_score <= 8.9:
        rating = "High"
    else:
        rating = "Critical"
        
    av_code = {"NETWORK": "N", "ADJACENT": "A", "LOCAL": "L", "PHYSICAL": "P"}[attack_vector]
    ac_code = {"LOW": "L", "HIGH": "H"}[attack_complexity]
    pr_code = {"NONE": "N", "LOW": "L", "HIGH": "H"}[privileges_required]
    ui_code = {"NONE": "N", "REQUIRED": "R"}[user_interaction]
    s_code = {"UNCHANGED": "U", "CHANGED": "C"}[scope]
    c_code = {"HIGH": "H", "LOW": "L", "NONE": "N"}[confidentiality]
    i_code = {"HIGH": "H", "LOW": "L", "NONE": "N"}[integrity]
    a_code = {"HIGH": "H", "LOW": "L", "NONE": "N"}[availability]
    
    vector = f"CVSS:3.1/AV:{av_code}/AC:{ac_code}/PR:{pr_code}/UI:{ui_code}/S:{s_code}/C:{c_code}/I:{i_code}/A:{a_code}"
    
    return base_score, rating, vector, round(impact, 2), round(exploitability, 2)


# ==============================================================================
# 3. CODE SCANNER LOGIC
# ==============================================================================

def scan_source_code(code: str, language: str = "python") -> List[VulnerabilityFinding]:
    """Scans code text against regex rules and attaches calculated CVSS scores."""
    findings: List[VulnerabilityFinding] = []
    lines = code.split("\n")
    
    for rule in RULES:
        pattern = re.compile(rule["regex"])
        for idx, line in enumerate(lines, 1):
            match = pattern.search(line)
            if match:
                cvss_cfg = rule["cvss"]
                score, _, vector, _, _ = calculate_cvss_31(
                    attack_vector=cvss_cfg["av"],
                    attack_complexity=cvss_cfg["ac"],
                    privileges_required=cvss_cfg["pr"],
                    user_interaction=cvss_cfg["ui"],
                    scope=cvss_cfg["s"],
                    confidentiality=cvss_cfg["c"],
                    integrity=cvss_cfg["i"],
                    availability=cvss_cfg["a"]
                )
                
                finding = VulnerabilityFinding(
                    id=f"{rule['id']}-{idx}",
                    rule_name=rule["name"],
                    category=rule["category"],
                    severity=rule["severity"],
                    cvss_score=score,
                    cvss_vector=vector,
                    line_number=idx,
                    matched_snippet=match.group(0)[:120],
                    description=rule["description"],
                    cwe_id=rule["cwe"],
                    remediation=rule["remediation"]
                )
                findings.append(finding)
                
    return findings


# ==============================================================================
# 4. DEPENDENCY SCANNER LOGIC
# ==============================================================================

KNOWN_VULNERABLE_PACKAGES: Dict[str, List[Dict[str, Any]]] = {
    "requests": [
        {
            "max_version": "2.31.0",
            "fixed": "2.31.0",
            "cve": "CVE-2023-32681",
            "severity": "Medium",
            "cvss": 6.1,
            "advisory": "Unintended leak of Proxy-Authorization header during redirect to an HTTPS proxy."
        }
    ],
    "urllib3": [
        {
            "max_version": "2.0.7",
            "fixed": "2.0.7",
            "cve": "CVE-2023-45803",
            "severity": "High",
            "cvss": 7.5,
            "advisory": "Request body not stripped after HTTP 303 redirect leading to request leakage."
        }
    ],
    "flask": [
        {
            "max_version": "2.2.5",
            "fixed": "2.2.5",
            "cve": "CVE-2023-30861",
            "severity": "High",
            "cvss": 7.5,
            "advisory": "Session cookie disclosure through missing Vary: Cookie response header."
        }
    ],
    "pyyaml": [
        {
            "max_version": "5.4.0",
            "fixed": "5.4",
            "cve": "CVE-2020-14343",
            "severity": "Critical",
            "cvss": 9.8,
            "advisory": "Arbitrary code execution via full_load method deserialization."
        }
    ],
    "cryptography": [
        {
            "max_version": "41.0.6",
            "fixed": "41.0.6",
            "cve": "CVE-2023-49083",
            "severity": "High",
            "cvss": 7.5,
            "advisory": "NULL pointer dereference when parsing PKCS7 structures."
        }
    ],
    "paramiko": [
        {
            "max_version": "3.4.0",
            "fixed": "3.4.0",
            "cve": "CVE-2023-48795",
            "severity": "Medium",
            "cvss": 5.9,
            "advisory": "Terrapin attack: Prefix truncation attack in SSH transport protocol."
        }
    ],
    "lodash": [
        {
            "max_version": "4.17.21",
            "fixed": "4.17.21",
            "cve": "CVE-2021-23337",
            "severity": "High",
            "cvss": 7.2,
            "advisory": "Command injection via template function when given malicious options."
        }
    ],
    "axios": [
        {
            "max_version": "1.6.0",
            "fixed": "1.6.0",
            "cve": "CVE-2023-45857",
            "severity": "Medium",
            "cvss": 6.5,
            "advisory": "Cross-site request forgery (CSRF) via unauthorized header forwarding."
        }
    ],
    "express": [
        {
            "max_version": "4.19.2",
            "fixed": "4.19.2",
            "cve": "CVE-2024-29041",
            "severity": "Medium",
            "cvss": 6.1,
            "advisory": "Open redirect vulnerability when handling encoded slash characters."
        }
    ]
}

def parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    clean = re.sub(r'[^0-9\.]', '', v_str)
    parts = clean.split(".")
    try:
        return tuple(int(p) for p in parts if p)
    except ValueError:
        return (0, 0, 0)

def scan_manifest_dependencies(manifest_type: str, content: str) -> Tuple[int, List[DependencyFinding]]:
    """Analyzes requirements.txt or package.json for known CVE vulnerabilities."""
    findings: List[DependencyFinding] = []
    packages_checked = 0

    if "requirements" in manifest_type or "txt" in manifest_type:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9a-zA-Z\.\-]+)', line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(2)
                packages_checked += 1
                
                if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                    for vuln in KNOWN_VULNERABLE_PACKAGES[pkg_name]:
                        if parse_version_tuple(version) < parse_version_tuple(vuln["max_version"]):
                            findings.append(DependencyFinding(
                                package=pkg_name,
                                installed_version=version,
                                fixed_version=vuln["fixed"],
                                cve_id=vuln["cve"],
                                severity=vuln["severity"],
                                cvss_score=vuln["cvss"],
                                advisory=vuln["advisory"]
                            ))
                            
    elif "json" in manifest_type:
        # Simple regex or json parser for "dependencies": { "pkg": "^1.2.3" }
        dep_matches = re.findall(r'"([a-zA-Z0-9_\-\.\@\/]+)"\s*:\s*"[\^~]?([0-9\.]+)"', content)
        for pkg, ver in dep_matches:
            pkg_name = pkg.lower()
            packages_checked += 1
            if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                for vuln in KNOWN_VULNERABLE_PACKAGES[pkg_name]:
                    if parse_version_tuple(ver) < parse_version_tuple(vuln["max_version"]):
                        findings.append(DependencyFinding(
                            package=pkg_name,
                            installed_version=ver,
                            fixed_version=vuln["fixed"],
                            cve_id=vuln["cve"],
                            severity=vuln["severity"],
                            cvss_score=vuln["cvss"],
                            advisory=vuln["advisory"]
                        ))

    return packages_checked, findings
