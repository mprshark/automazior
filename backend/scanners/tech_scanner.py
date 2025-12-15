import requests


def detect_tech(domain: str) -> dict:
    url = f"http://{domain}"

    try:
        response = requests.get(url, timeout=5)

        headers = response.headers

        return {
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By"),
            "via": headers.get("Via"),
            "cdn": headers.get("CF-Ray") is not None or "cloudflare" in (headers.get("Server", "").lower()),
            "headers_exposed": list(headers.keys())
        }

    except Exception:
        return {
            "server": None,
            "powered_by": None,
            "via": None,
            "cdn": False,
            "headers_exposed": []
        }
