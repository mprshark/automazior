import requests


def enumerate_subdomains(domain: str) -> list:
    """
    Uses Certificate Transparency logs (crt.sh)
    to find subdomains.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()
        subdomains = set()

        for entry in data:
            name_value = entry.get("name_value")
            if name_value:
                for sub in name_value.split("\n"):
                    if sub.endswith(domain):
                        subdomains.add(sub.strip().lower())

        return sorted(subdomains)

    except Exception:
        return []
