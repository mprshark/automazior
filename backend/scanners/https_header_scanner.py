import requests
from typing import Dict

SECURITY_HEADERS = {
    "Strict-Transport-Security": "hsts",
    "Content-Security-Policy": "csp",
    "X-Frame-Options": "xfo",
    "X-Content-Type-Options": "xcto",
    "Referrer-Policy": "referrer",
    "Permissions-Policy": "permissions",
}


def scan_https_headers(domain: str, timeout: int = 6) -> Dict:
    url = f"https://{domain}"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Automazior-ASM/1.3"}
        )
        headers = response.headers

    except requests.exceptions.RequestException as e:
        return {
            "status": "unreachable",
            "error": str(e),
            "summary": {
                "strong": 0,
                "missing": len(SECURITY_HEADERS),
                "permissive": 0
            },
            "details": {}
        }

    results = {}
    strong = 0
    missing = 0
    permissive = 0

    for header, key in SECURITY_HEADERS.items():
        value = headers.get(header)

        if not value:
            results[key] = {
                "status": "missing",
                "value": None
            }
            missing += 1
            continue

        # Header-specific evaluation
        if header == "Strict-Transport-Security":
            if "max-age=" in value and "includeSubDomains" in value:
                status = "strong"
                strong += 1
            else:
                status = "permissive"
                permissive += 1

        elif header == "Content-Security-Policy":
            if "default-src" in value:
                status = "strong"
                strong += 1
            else:
                status = "permissive"
                permissive += 1

        elif header == "X-Frame-Options":
            if value.lower() in ["deny", "sameorigin"]:
                status = "strong"
                strong += 1
            else:
                status = "permissive"
                permissive += 1

        elif header == "X-Content-Type-Options":
            if value.lower() == "nosniff":
                status = "strong"
                strong += 1
            else:
                status = "permissive"
                permissive += 1

        else:
            status = "present"
            strong += 1

        results[key] = {
            "status": status,
            "value": value
        }

    return {
        "status": "ok",
        "summary": {
            "strong": strong,
            "missing": missing,
            "permissive": permissive
        },
        "details": results
    }
