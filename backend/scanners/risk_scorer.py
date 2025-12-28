from typing import Dict, List


def calculate_risk(result: Dict) -> Dict:
    score = 0
    reasons: List[str] = []

    # ---------- PORTS ----------
    ports = result.get("ports", {})
    if ports.get("80") == "open":
        score += 10
        reasons.append("HTTP (port 80) is open")

    # ---------- SSL ----------
    ssl = result.get("ssl", {})
    if ssl.get("status") == "disabled":
        score += 20
        reasons.append("SSL is disabled")
    elif ssl.get("status") == "enabled" and ssl.get("confidence") != "high":
        score += 8
        reasons.append("SSL enabled with limited verification confidence")

    # ---------- HTTPS HEADERS ----------
    headers = result.get("https_headers", {})
    if headers:
        missing = headers.get("summary", {}).get("missing", 0)
        if missing >= 3:
            score += 10
            reasons.append("Multiple security headers are missing")

    # ---------- TECHNOLOGY ----------
    tech = result.get("technology", {})
    observed = tech.get("observed", {})
    inferred = tech.get("inferred", {})

    if "server" in observed:
        score += 5
        reasons.append("Server version is exposed")

    cdn = inferred.get("cdn")
    if cdn and cdn["value"] is False:
        if cdn["confidence"] == "high":
            score += 8
            reasons.append("No CDN detected with high confidence")
        elif cdn["confidence"] == "medium":
            score += 4
            reasons.append("No CDN detected (medium confidence)")
        else:
            score += 2
            reasons.append("No CDN detected (low confidence)")

    # ---------- SUBDOMAINS ----------
    subs = result.get("subdomains", {})
    if isinstance(subs, dict):
        count = subs.get("count", 0)
        if count >= 20:
            score += 12
            reasons.append("Large number of exposed subdomains")
        elif count > 0:
            score += 5
            reasons.append("Exposed subdomains detected")

    # ---------- NORMALIZE ----------
    score = min(score, 100)

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }
