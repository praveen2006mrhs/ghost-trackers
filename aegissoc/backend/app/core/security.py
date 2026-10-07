import re
import ipaddress
import hashlib
from typing import Tuple

def sanitize_input_text(text: str) -> str:
    """Sanitize raw text for safe rendering and processing."""
    if not text:
        return ""
    # Strip null bytes and control chars while keeping newlines and tabs
    clean = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return clean

def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash."""
    return hashlib.sha256(data).hexdigest()

def is_safe_target_url(url: str, allow_localhost: bool = True) -> Tuple[bool, str]:
    """
    Defensive safety check to prevent unintended SSRF or scans against cloud metadata.
    Enforces safe defensive scanning policy.
    """
    if not url:
        return False, "Target URL is required."
    
    # Must be http or https
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return False, "Only HTTP and HTTPS protocols are permitted."
    
    # Block cloud metadata addresses
    if "169.254.169.254" in url or "metadata.google.internal" in url:
        return False, "Access to cloud instance metadata services is strictly prohibited."
    
    # Host extraction
    match = re.search(r'^https?://([^/:]+)', url, re.IGNORECASE)
    if not match:
        return False, "Invalid URL host structure."
    
    host = match.group(1).lower()
    
    if host in ["localhost", "127.0.0.1", "::1"]:
        if allow_localhost:
            return True, "Localhost target allowed in sandbox mode."
        return False, "Direct localhost scanning is disabled."

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private and not allow_localhost:
            return False, "Target resolved to a private non-routable network address."
    except ValueError:
        # Host is a domain name
        pass

    return True, "Target validation passed."
