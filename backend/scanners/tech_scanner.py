import requests
from typing import Dict, List


def detect_tech(domain: str, timeout: int = 5) -> Dict:
    url = f"https://{domain}"
    observed = {}
    inferred = {}
    notes: List[str] = []

    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = r.headers

        # ---------- OBSERVED ----------
        if "Server" in headers:
            observed["server"] = headers.get("Server")

        exposed_headers = list(headers.keys())
        observed["headers"] = exposed_headers

        # ---------- INFERRED ----------
        cdn_signals = [
            h for h in headers.keys()
            if h.lower().startswith(("cf-", "x-amz-", "x-cache", "via"))
        ]

        if cdn_signals:
            inferred["cdn"] = {
                "value": True,
                "confidence": "high",
                "reason": "CDN-specific response headers detected",
                "signals": cdn_signals
            }
        else:
            inferred["cdn"] = {
                "value": False,
                "confidence": "low",
                "reason": "No CDN-specific headers detected"
            }

        if "X-Powered-By" in headers:
            observed["powered_by"] = headers.get("X-Powered-By")

        # ---------- NOTES ----------
        notes.extend([
            "Technology detection based on HTTP response headers only",
            "Absence of headers does not guarantee absence of technology",
            "Results reflect external network perspective"
        ])

    except Exception as e:
        notes.append(f"Technology scan failed: {type(e).__name__}")

    return {
        "observed": observed,
        "inferred": inferred,
        "notes": notes
    }
