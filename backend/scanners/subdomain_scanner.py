import socket
import requests
from typing import Dict, List

COMMON_SUBS = [
    "www", "api", "admin", "portal", "app",
    "auth", "dev", "test", "stage", "beta"
]

INTERNAL_KEYWORDS = [
    "corp", "internal", "sandbox", "test",
    "qa", "staging", "dev"
]


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def _from_ct(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        hosts = set()

        for entry in data:
            name = entry.get("name_value", "")
            for h in name.splitlines():
                hosts.add(h.strip())

        return list(hosts)
    except Exception:
        return []


def enumerate_subdomains(domain: str) -> Dict:
    confirmed = set()

    discarded = {
        "wildcards": 0,
        "emails": 0,
        "out_of_scope": 0,
        "unresolvable": 0,
        "internal": 0
    }

    # ---------- CT LOGS ----------
    ct_hosts = _from_ct(domain)

    # ---------- DNS BRUTE ----------
    brute_hosts = [f"{sub}.{domain}" for sub in COMMON_SUBS]

    for host in set(ct_hosts + brute_hosts):

        if host.startswith("*."):
            discarded["wildcards"] += 1
            continue

        if "@" in host:
            discarded["emails"] += 1
            continue

        if not host.endswith(domain):
            discarded["out_of_scope"] += 1
            continue

        if any(k in host for k in INTERNAL_KEYWORDS):
            discarded["internal"] += 1
            continue

        if not _resolves(host):
            discarded["unresolvable"] += 1
            continue

        confirmed.add(host)

    return {
        "count": len(confirmed),
        "confirmed": sorted(confirmed),
        "discarded": discarded
    }
