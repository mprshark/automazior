import ssl
import socket
from datetime import datetime
from typing import Dict


def _create_strict_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    return ctx


def _create_relaxed_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _tls_handshake(domain: str, context: ssl.SSLContext, timeout: int = 5):
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return {
                    "success": True,
                    "cert": ssock.getpeercert()
                }
    except socket.timeout:
        return {"success": False, "error": "timeout"}
    except ssl.SSLError as e:
        return {"success": False, "error": f"ssl:{type(e).__name__}"}
    except Exception as e:
        return {"success": False, "error": f"net:{type(e).__name__}"}


def check_ssl(domain: str, attempts: int = 5) -> Dict:
    strict_ctx = _create_strict_context()
    relaxed_ctx = _create_relaxed_context()

    strict_results = []
    relaxed_results = []
    cert_data = None

    # Phase 1: strict capability detection
    for _ in range(attempts):
        res = _tls_handshake(domain, strict_ctx)
        strict_results.append(res)
        if res["success"]:
            cert_data = res.get("cert")
            break

    strict_successes = sum(1 for r in strict_results if r["success"])

    # Phase 2: confidence evaluation
    if strict_successes > 0:
        for _ in range(attempts - len(strict_results)):
            res = _tls_handshake(domain, strict_ctx)
            strict_results.append(res)
            if res["success"] and not cert_data:
                cert_data = res.get("cert")

        strict_successes = sum(1 for r in strict_results if r["success"])
        success_count = strict_successes
        failure_count = attempts - strict_successes

        confidence = "high" if strict_successes >= attempts // 2 else "medium"
        status = "enabled"
        reason = "Strict TLS negotiation successful"

    else:
        for _ in range(attempts):
            res = _tls_handshake(domain, relaxed_ctx)
            relaxed_results.append(res)
            if res["success"] and not cert_data:
                cert_data = res.get("cert")

        relaxed_successes = sum(1 for r in relaxed_results if r["success"])

        if relaxed_successes > 0:
            status = "enabled"
            confidence = "medium"
            reason = "TLS negotiated only with relaxed verification"
            success_count = relaxed_successes
            failure_count = attempts - relaxed_successes
        else:
            status = "disabled"
            confidence = "high"
            reason = "All TLS handshake attempts failed"
            success_count = 0
            failure_count = attempts

    expires_on = None
    days_left = None

    if cert_data and "notAfter" in cert_data:
        expires = datetime.strptime(
            cert_data["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        expires_on = expires.date().isoformat()
        days_left = (expires.date() - datetime.utcnow().date()).days

    return {
        "status": status,
        "confidence": confidence,
        "attempts": attempts,
        "results": {
            "success": success_count,
            "failure": failure_count
        },
        "expires_on": expires_on,
        "days_left": days_left,
        "reason": reason
    }
