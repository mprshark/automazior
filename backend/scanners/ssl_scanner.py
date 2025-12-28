import ssl
import socket
from datetime import datetime
from typing import Dict, Optional


# -----------------------------
# TLS CONTEXTS
# -----------------------------
def _strict_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    return ctx


def _relaxed_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# -----------------------------
# ADDRESS RESOLUTION
# -----------------------------
def _resolve_addresses(domain: str):
    infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    ipv6 = [i for i in infos if i[0] == socket.AF_INET6]
    ipv4 = [i for i in infos if i[0] == socket.AF_INET]
    return ipv6 + ipv4


# -----------------------------
# TLS HANDSHAKE (single try)
# -----------------------------
def _handshake(
    domain: str,
    context: ssl.SSLContext,
    server_hostname: Optional[str],
    timeout: int = 5
) -> Dict:
    for family, socktype, proto, _, sockaddr in _resolve_addresses(domain):
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                with context.wrap_socket(
                    sock,
                    server_hostname=server_hostname
                ) as ssock:
                    return {
                        "success": True,
                        "cert": ssock.getpeercert(),
                        "ip_family": "ipv6" if family == socket.AF_INET6 else "ipv4",
                        "sni_used": bool(server_hostname)
                    }
        except Exception:
            continue

    return {"success": False}


# -----------------------------
# PUBLIC SSL SCANNER
# -----------------------------
def check_ssl(domain: str, attempts: int = 5) -> Dict:
    strict_ctx = _strict_context()
    relaxed_ctx = _relaxed_context()

    hostnames = [domain, f"www.{domain}"]
    notes = set()

    success_attempts = 0
    cert_data = None
    strict_used = False
    relaxed_used = False

    for _ in range(attempts):
        attempt_success = False

        # ---- strict phase ----
        for hn in hostnames:
            res = _handshake(domain, strict_ctx, hn)
            if res.get("success"):
                attempt_success = True
                success_attempts += 1
                cert_data = res.get("cert")
                strict_used = True
                notes.add(f"strict_tls:{res['ip_family']}")
                break

        if attempt_success:
            continue

        # ---- relaxed phase ----
        for hn in hostnames:
            res = _handshake(domain, relaxed_ctx, hn)
            if res.get("success"):
                attempt_success = True
                success_attempts += 1
                cert_data = res.get("cert")
                relaxed_used = True
                notes.add("relaxed_tls")
                break

        # ---- no SNI fallback ----
        if not attempt_success:
            res = _handshake(domain, relaxed_ctx, None)
            if res.get("success"):
                success_attempts += 1
                relaxed_used = True
                notes.add("no_sni_fallback")

    failure_attempts = attempts - success_attempts

    # -----------------------------
    # DECISION LOGIC
    # -----------------------------
    if strict_used:
        status = "enabled"
        confidence = "high" if success_attempts >= attempts // 2 else "medium"
        reason = "Strict TLS negotiation successful"

    elif relaxed_used:
        status = "enabled"
        confidence = "medium"
        reason = "TLS negotiated with relaxed verification"

    else:
        status = "disabled"
        confidence = "high"
        reason = "All TLS handshake attempts failed"

    # -----------------------------
    # CERT EXPIRY (best effort)
    # -----------------------------
    expires_on = None
    days_left = None

    if cert_data and "notAfter" in cert_data:
        try:
            expires = datetime.strptime(
                cert_data["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            expires_on = expires.date().isoformat()
            days_left = (expires.date() - datetime.utcnow().date()).days
        except Exception:
            pass

    return {
        "status": status,
        "confidence": confidence,
        "attempts": attempts,
        "results": {
            "success": success_attempts,
            "failure": failure_attempts
        },
        "expires_on": expires_on,
        "days_left": days_left,
        "reason": reason,
        "trust_context": "system_ca_store",
        "trust_notes": [
            "TLS verification performed using system CA trust store",
            "Browser trust decisions may differ from system trust store"
        ],
        "notes": sorted(notes)
    }
