from typing import Dict, List
from datetime import datetime


def asset_id(kind: str, value: str) -> str:
    return f"{kind}:{value.lower()}"


def normalize_scan(scan: Dict) -> Dict:
    assets: Dict[str, Dict] = {}
    relationships: List[Dict] = []
    findings: List[Dict] = []

    now = datetime.utcnow().isoformat()

    # Domain
    domain = scan["domain"]
    domain_id = asset_id("domain", domain)

    assets[domain_id] = {
        "id": domain_id,
        "type": "domain",
        "value": domain,
        "first_seen": now,
        "last_seen": now
    }

    # Subdomains
    subdomains = scan.get("subdomains", {}).get("confirmed", [])
    for sub in subdomains:
        sub_id = asset_id("subdomain", sub)
        assets[sub_id] = {
            "id": sub_id,
            "type": "subdomain",
            "value": sub,
            "first_seen": now,
            "last_seen": now
        }
        relationships.append({
            "from": domain_id,
            "to": sub_id,
            "type": "owns"
        })

    # Services
    ports = scan.get("ports", {})
    for port, data in ports.items():
        if data.get("status") != "open":
            continue

        service_id = asset_id("service", f"{domain}:{port}/tcp")
        assets[service_id] = {
            "id": service_id,
            "type": "service",
            "port": int(port),
            "protocol": "tcp",
            "first_seen": now,
            "last_seen": now
        }
        relationships.append({
            "from": domain_id,
            "to": service_id,
            "type": "exposes"
        })

    # SSL Certificate
    ssl = scan.get("ssl")
    if ssl and ssl.get("status") == "enabled":
        cert_id = asset_id("certificate", f"{domain}:{ssl.get('expires_on', 'unknown')}")
        assets[cert_id] = {
            "id": cert_id,
            "type": "certificate",
            "expires_on": ssl.get("expires_on"),
            "confidence": ssl.get("confidence"),
            "first_seen": now,
            "last_seen": now
        }
        relationships.append({
            "from": domain_id,
            "to": cert_id,
            "type": "uses"
        })

    # Findings
    risk = scan.get("risk", {})
    for reason in risk.get("reasons", []):
        findings.append({
            "type": "risk_reason",
            "target": domain_id,
            "description": reason,
            "severity": risk.get("level"),
            "observed_at": now
        })

    return {
        "assets": list(assets.values()),
        "relationships": relationships,
        "findings": findings
    }
