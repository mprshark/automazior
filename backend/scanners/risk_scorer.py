from typing import Dict, List


def calculate_risk(scan: Dict) -> Dict:
    score = 0
    reasons: List[str] = []

    # -----------------------------
    # PORTS
    # -----------------------------
    ports = scan.get("ports", {})

    if ports.get("80") == "open":
        score += 10
        reasons.append("HTTP (port 80) is open")

    # We do NOT penalize 443 being open
    # HTTPS being open is expected


    # -----------------------------
    # SSL / TLS
    # -----------------------------
    ssl = scan.get("ssl", {})

    if ssl.get("status") != "enabled":
        score += 20
        reasons.append("SSL is not enabled")

    else:
        confidence = ssl.get("confidence")

        if confidence == "medium":
            score += 5
            reasons.append("SSL enabled with limited verification confidence")

        elif confidence == "low":
            score += 10
            reasons.append("SSL enabled but reliability is uncertain")


    # -----------------------------
    # HTTPS SECURITY HEADERS
    # -----------------------------
    https_headers = scan.get("https_headers")

    if https_headers:
        summary = https_headers.get("summary", {})

        missing = summary.get("missing", 0)
        permissive = summary.get("permissive", 0)

        # Headers reduce risk slightly if strong
        if summary.get("strong", 0) >= 3:
            score -= 5

        # But missing headers alone are not critical
        if missing >= 3:
            score += 5
            reasons.append("Multiple security headers are missing")

        if permissive >= 2:
            score += 5
            reasons.append("Permissive HTTPS security headers detected")


    # -----------------------------
    # SUBDOMAINS
    # -----------------------------
    subdomains = scan.get("subdomains")

    if isinstance(subdomains, dict):
        count = subdomains.get("count", 0)

        if count >= 10:
            score += 15
            reasons.append("Large number of exposed subdomains")
        elif count >= 3:
            score += 5
            reasons.append("Exposed subdomains detected")

    elif isinstance(subdomains, list):
        # Backward compatibility
        if len(subdomains) >= 10:
            score += 15
            reasons.append("Large number of exposed subdomains")
        elif len(subdomains) >= 3:
            score += 5
            reasons.append("Exposed subdomains detected")


    # -----------------------------
    # TECHNOLOGY EXPOSURE
    # -----------------------------
    tech = scan.get("technology", {})

    if tech.get("server"):
        score += 5
        reasons.append("Server version is exposed")

    if tech.get("cdn") is False:
        score += 5
        reasons.append("No CDN detected")


    # -----------------------------
    # NORMALIZATION
    # -----------------------------
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    if score < 25:
        level = "low"
    elif score < 60:
        level = "medium"
    else:
        level = "high"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }
