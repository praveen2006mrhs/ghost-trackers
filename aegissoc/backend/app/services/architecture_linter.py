import json
import re
from typing import List, Tuple, Dict, Any
from app.models.schemas import ArchitectureFinding

# ==============================================================================
# 1. AWS IAM POLICY LINTER
# ==============================================================================

def lint_aws_iam(policy_str: str) -> Tuple[float, List[ArchitectureFinding]]:
    findings: List[ArchitectureFinding] = []
    
    try:
        data = json.loads(policy_str)
    except Exception as e:
        # If not valid JSON, return syntax failure finding
        return 0.0, [ArchitectureFinding(
            check_id="IAM-SYN-001",
            title="Invalid JSON Syntax in IAM Policy",
            severity="High",
            cis_benchmark="CIS AWS 1.16",
            nist_control="AC-3 Access Enforcement",
            owasp_mapping="A05:2021 Security Misconfiguration",
            description=f"IAM document could not be parsed as valid JSON: {str(e)}",
            remediation_playbook="Format IAM policy as valid RFC 8259 JSON before deployment.",
            passed=False
        )]

    statements = data.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    # Check 1: Wildcard Action
    has_wildcard_action = False
    for stmt in statements:
        if stmt.get("Effect") == "Allow":
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if "*" in actions or any(a.endswith(":*") for a in actions):
                has_wildcard_action = True
                break

    findings.append(ArchitectureFinding(
        check_id="IAM-CHK-001",
        title="Avoid Wildcard Actions ('*') in Allow Statements",
        severity="Critical",
        cis_benchmark="CIS AWS Foundations 1.16",
        nist_control="AC-6 Least Privilege",
        owasp_mapping="A01:2021 Broken Access Control",
        description="Allow statement grants unrestricted administrative actions using wildcard '*'.",
        remediation_playbook="Scope down policy actions to exact API methods needed (e.g. s3:GetObject, s3:PutObject).",
        fixed_snippet='{\n  "Effect": "Allow",\n  "Action": ["s3:GetObject", "s3:ListBucket"],\n  "Resource": "arn:aws:s3:::my-bucket/*"\n}',
        passed=not has_wildcard_action
    ))

    # Check 2: Wildcard Resource on Sensitive Operations
    has_wildcard_resource = False
    for stmt in statements:
        if stmt.get("Effect") == "Allow":
            res = stmt.get("Resource", [])
            if isinstance(res, str):
                res = [res]
            if "*" in res:
                has_wildcard_resource = True
                break

    findings.append(ArchitectureFinding(
        check_id="IAM-CHK-002",
        title="Restrict Resource ARNs from Wildcard ('*')",
        severity="High",
        cis_benchmark="CIS AWS Foundations 1.20",
        nist_control="AC-3 Access Enforcement",
        owasp_mapping="A01:2021 Broken Access Control",
        description="Resources are set to '*' allowing operations across all current and future accounts/buckets.",
        remediation_playbook="Specify specific ARN identifiers (e.g. arn:aws:iam::123456789012:role/SpecificRole).",
        fixed_snippet='"Resource": "arn:aws:s3:::production-app-bucket/*"',
        passed=not has_wildcard_resource
    ))

    # Check 3: Missing Multi-Factor Authentication (MFA) Condition for Destructive Actions
    has_mfa_check = False
    for stmt in statements:
        condition = stmt.get("Condition", {})
        if "Bool" in condition and ("aws:MultiFactorAuthPresent" in condition["Bool"]):
            has_mfa_check = True
            break
            
    findings.append(ArchitectureFinding(
        check_id="IAM-CHK-003",
        title="Require MFA for Privileged Administrative Actions",
        severity="Medium",
        cis_benchmark="CIS AWS Foundations 1.5",
        nist_control="IA-2 Identification and Authentication",
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        description="Policy lacks aws:MultiFactorAuthPresent condition constraint for sensitive management calls.",
        remediation_playbook="Add Condition: {\"Bool\": {\"aws:MultiFactorAuthPresent\": \"true\"}} to privileged operations.",
        fixed_snippet='"Condition": {\n  "Bool": {"aws:MultiFactorAuthPresent": "true"}\n}',
        passed=has_mfa_check
    ))

    # Check 4: Broad AssumeRole Trust (Principal: *)
    has_broad_principal = False
    for stmt in statements:
        principal = stmt.get("Principal", {})
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            has_broad_principal = True
            break

    findings.append(ArchitectureFinding(
        check_id="IAM-CHK-004",
        title="Disallow Unauthenticated Public AssumeRole Trust Policy",
        severity="Critical",
        cis_benchmark="CIS AWS Foundations 1.22",
        nist_control="AC-2 Account Management",
        owasp_mapping="A01:2021 Broken Access Control",
        description="AssumeRole trust relationship allows any arbitrary AWS entity ('Principal': '*') to assume role.",
        remediation_playbook="Explicitly lock Principal to trusted account ARNs or specific Federated OIDC providers.",
        fixed_snippet='"Principal": {\n  "AWS": "arn:aws:iam::112233445566:root"\n}',
        passed=not has_broad_principal
    ))

    passed_count = sum(1 for f in findings if f.passed)
    score = round((passed_count / len(findings)) * 100, 1)
    return score, findings


# ==============================================================================
# 2. KUBERNETES MANIFEST LINTER
# ==============================================================================

def lint_k8s_manifest(manifest_str: str) -> Tuple[float, List[ArchitectureFinding]]:
    findings: List[ArchitectureFinding] = []
    
    # Check 1: Privileged Containers
    is_privileged = bool(re.search(r'privileged:\s*true', manifest_str, re.IGNORECASE))
    findings.append(ArchitectureFinding(
        check_id="K8S-SEC-001",
        title="Disallow Privileged Container Execution",
        severity="Critical",
        cis_benchmark="CIS Kubernetes Benchmark 5.2.1",
        nist_control="AC-6 Least Privilege",
        owasp_mapping="A05:2021 Security Misconfiguration",
        description="Container runs with privileged=true flag, allowing host container breakout and full kernel access.",
        remediation_playbook="Set securityContext.privileged: false and grant only granular Linux capabilities.",
        fixed_snippet='securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false',
        passed=not is_privileged
    ))

    # Check 2: Run as Non-Root
    run_as_non_root = bool(re.search(r'runAsNonRoot:\s*true', manifest_str, re.IGNORECASE))
    findings.append(ArchitectureFinding(
        check_id="K8S-SEC-002",
        title="Enforce Non-Root Execution (runAsNonRoot)",
        severity="High",
        cis_benchmark="CIS Kubernetes Benchmark 5.2.6",
        nist_control="AC-6 Least Privilege",
        owasp_mapping="A01:2021 Broken Access Control",
        description="Pod or container does not enforce runAsNonRoot: true, allowing pod processes to run with UID 0.",
        remediation_playbook="Specify runAsNonRoot: true and runAsUser: 10001 in pod securityContext.",
        fixed_snippet='securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001',
        passed=run_as_non_root
    ))

    # Check 3: Host Network / Host PID Sharing
    host_sharing = bool(re.search(r'(?:hostNetwork|hostPID|hostIPC):\s*true', manifest_str, re.IGNORECASE))
    findings.append(ArchitectureFinding(
        check_id="K8S-SEC-003",
        title="Prevent Host Namespace Sharing (hostNetwork/hostPID)",
        severity="High",
        cis_benchmark="CIS Kubernetes Benchmark 5.2.2",
        nist_control="SC-7 Boundary Protection",
        owasp_mapping="A05:2021 Security Misconfiguration",
        description="Host namespace sharing (hostNetwork, hostPID, or hostIPC) bypasses Kubernetes network policies.",
        remediation_playbook="Ensure hostNetwork, hostPID, and hostIPC are set to false or omitted.",
        fixed_snippet='spec:\n  hostNetwork: false\n  hostPID: false\n  hostIPC: false',
        passed=not host_sharing
    ))

    # Check 4: Resource Limits (CPU & Memory Limits)
    has_limits = bool(re.search(r'limits:\s*[\r\n]+\s*(?:cpu|memory):', manifest_str, re.IGNORECASE))
    findings.append(ArchitectureFinding(
        check_id="K8S-SEC-004",
        title="Configure Resource Limits to Prevent Denial of Service",
        severity="Medium",
        cis_benchmark="CIS Kubernetes Benchmark 5.4.1",
        nist_control="SC-5 Denial of Service Protection",
        owasp_mapping="A05:2021 Security Misconfiguration",
        description="Containers without CPU and memory limits are susceptible to resource starvation and DoS.",
        remediation_playbook="Define resource requests and limits for all container definitions in the manifest.",
        fixed_snippet='resources:\n  limits:\n    cpu: "500m"\n    memory: "512Mi"\n  requests:\n    cpu: "100m"\n    memory: "128Mi"',
        passed=has_limits
    ))

    # Check 5: Read-Only Root Filesystem
    read_only_root = bool(re.search(r'readOnlyRootFilesystem:\s*true', manifest_str, re.IGNORECASE))
    findings.append(ArchitectureFinding(
        check_id="K8S-SEC-005",
        title="Enforce Read-Only Root Filesystem",
        severity="Medium",
        cis_benchmark="CIS Kubernetes Benchmark 5.2.8",
        nist_control="CM-2 Baseline Configuration",
        owasp_mapping="A05:2021 Security Misconfiguration",
        description="Writable root filesystem allows attackers to download and execute persistence payloads.",
        remediation_playbook="Set readOnlyRootFilesystem: true and mount ephemeral emptyDir volumes for temp directories.",
        fixed_snippet='securityContext:\n  readOnlyRootFilesystem: true',
        passed=read_only_root
    ))

    passed_count = sum(1 for f in findings if f.passed)
    score = round((passed_count / len(findings)) * 100, 1)
    return score, findings


# ==============================================================================
# 3. DOCKERFILE LINTER
# ==============================================================================

def lint_dockerfile(dockerfile_str: str) -> Tuple[float, List[ArchitectureFinding]]:
    findings: List[ArchitectureFinding] = []
    lines = dockerfile_str.splitlines()

    # Check 1: Non-root USER declaration
    has_user_directive = False
    for line in lines:
        cleaned = line.strip()
        if cleaned.upper().startswith("USER") and not "root" in cleaned.lower():
            has_user_directive = True

    findings.append(ArchitectureFinding(
        check_id="DCK-SEC-001",
        title="Specify Non-Root USER Directive",
        severity="High",
        cis_benchmark="CIS Docker Benchmark 4.1",
        nist_control="AC-6 Least Privilege",
        owasp_mapping="A05:2021 Security Misconfiguration",
        description="Dockerfile executes default processes as root user inside the container.",
        remediation_playbook="Create a dedicated group/user and switch with 'USER nonroot:nonroot' before entrypoint.",
        fixed_snippet='RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser',
        passed=has_user_directive
    ))

    # Check 2: Immutable Base Image Tag (Avoid :latest)
    has_latest_tag = False
    for line in lines:
        cleaned = line.strip()
        if cleaned.upper().startswith("FROM"):
            if ":latest" in cleaned or not ":" in cleaned or re.search(r'FROM\s+[\w\.\-]+(?:\s|$)', cleaned):
                has_latest_tag = True
                break

    findings.append(ArchitectureFinding(
        check_id="DCK-SEC-002",
        title="Avoid Untagged or ':latest' Base Image",
        severity="Medium",
        cis_benchmark="CIS Docker Benchmark 4.2",
        nist_control="CM-2 Baseline Configuration",
        owasp_mapping="A06:2021 Vulnerable and Outdated Components",
        description="Using ':latest' creates non-deterministic builds and risks pulling unvetted upstream updates.",
        remediation_playbook="Pin base image to explicit version digest or specific semantic tag (e.g. python:3.11.8-slim).",
        fixed_snippet='FROM python:3.11.8-slim-bookworm@sha256:7f082e6...',
        passed=not has_latest_tag
    ))

    # Check 3: Secrets in ENV / ARG
    has_hardcoded_secrets = False
    for line in lines:
        cleaned = line.strip()
        if re.search(r'^(?:ENV|ARG)\s+[A-Za-z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY)[A-Za-z0-9_]*\s*=', cleaned, re.IGNORECASE):
            has_hardcoded_secrets = True
            break

    findings.append(ArchitectureFinding(
        check_id="DCK-SEC-003",
        title="No Hardcoded Secrets in ENV or ARG Directives",
        severity="Critical",
        cis_benchmark="CIS Docker Benchmark 4.9",
        nist_control="IA-2 Identification and Authentication",
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        description="Secrets declared in ENV/ARG persist in image layers and metadata, visible to anyone with image pull rights.",
        remediation_playbook="Use Docker BuildKit secret mounts ('--mount=type=secret') or runtime environment variables.",
        fixed_snippet='RUN --mount=type=secret,id=npmrc npm install',
        passed=not has_hardcoded_secrets
    ))

    # Check 4: Prefer COPY over ADD
    uses_add = False
    for line in lines:
        cleaned = line.strip()
        if cleaned.upper().startswith("ADD") and not re.search(r'\.(tar|gz|bz2|xz)\b', cleaned):
            uses_add = True
            break

    findings.append(ArchitectureFinding(
        check_id="DCK-SEC-004",
        title="Prefer COPY Over ADD Directive",
        severity="Low",
        cis_benchmark="CIS Docker Benchmark 4.6",
        nist_control="SI-3 Malicious Code Protection",
        owasp_mapping="A05:2021 Security Misconfiguration",
        description="ADD command can implicitly fetch remote URLs or extract untrusted tarballs during build.",
        remediation_playbook="Use COPY for standard local file copy operations.",
        fixed_snippet='COPY ./src /app/src',
        passed=not uses_add
    ))

    # Check 5: Sensitive Ports (22, 23, 3389)
    exposes_sensitive_port = False
    for line in lines:
        cleaned = line.strip()
        if re.search(r'^EXPOSE\s+.*?\b(22|23|3389)\b', cleaned):
            exposes_sensitive_port = True
            break

    findings.append(ArchitectureFinding(
        check_id="DCK-SEC-005",
        title="Do Not Expose Insecure Administrative Ports",
        severity="High",
        cis_benchmark="CIS Docker Benchmark 4.5",
        nist_control="SC-7 Boundary Protection",
        owasp_mapping="A01:2021 Broken Access Control",
        description="Exposing SSH (22), Telnet (23), or RDP (3389) inside containers violates microservice isolation.",
        remediation_playbook="Remove SSH server from containers and access instances via container orchestrator logs/exec.",
        fixed_snippet='EXPOSE 8080',
        passed=not exposes_sensitive_port
    ))

    passed_count = sum(1 for f in findings if f.passed)
    score = round((passed_count / len(findings)) * 100, 1)
    return score, findings


# ==============================================================================
# 4. DISPATCHER & COMPLIANCE FRAMEWORKS LIST
# ==============================================================================

def review_infrastructure_architecture(config_type: str, content: str) -> Tuple[float, List[ArchitectureFinding]]:
    cfg = config_type.lower()
    if "iam" in cfg:
        return lint_aws_iam(content)
    elif "k8s" in cfg or "kubernetes" in cfg or "helm" in cfg:
        return lint_k8s_manifest(content)
    elif "docker" in cfg or "dockerfile" in cfg:
        return lint_dockerfile(content)
    else:
        # Default to dockerfile or try detecting
        if "apiVersion" in content or "kind:" in content:
            return lint_k8s_manifest(content)
        elif "Statement" in content:
            return lint_aws_iam(content)
        return lint_dockerfile(content)

def get_compliance_framework_catalog() -> Dict[str, Any]:
    return {
        "frameworks": [
            {
                "name": "CIS Benchmarks",
                "version": "v1.5.0",
                "coverage": ["AWS Foundations", "Kubernetes Ingress & Pod Security", "Docker Engine v20.10"],
                "focus": "Configuration hardening and least privilege baselines"
            },
            {
                "name": "NIST SP 800-53",
                "version": "Revision 5",
                "controls": ["AC-2", "AC-3", "AC-6", "CM-2", "IA-2", "SC-5", "SC-7", "SI-3"],
                "focus": "Federal security and privacy controls for information systems"
            },
            {
                "name": "OWASP Top 10",
                "version": "2021 Edition",
                "categories": ["A01 Broken Access Control", "A05 Security Misconfiguration", "A06 Vulnerable Components", "A07 Auth Failures"],
                "focus": "Critical web application and cloud architectural security risks"
            }
        ]
    }
