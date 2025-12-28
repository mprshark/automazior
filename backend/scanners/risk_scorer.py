from typing import Dict, Set


def calculate_risk(scan: Dict) -> Dict:
    score = 0
    reasons: Set[str] = set()

    # --------------------
    # PORT EXPOSURE (TCP CONNECT)
    # --------------------
    ports = scan.get("ports", {})

    port_80 = ports.get("80")
    port_443 = ports.get("443")

    if isinstance(port_80, dict) and port_80.get("status") == "open":
        score += 10
        reasons.add("HTTP (port 80) is open")

    if isinstance(port_443, dict) and port_443.get("status") != "open":
        score += 5
        reasons.add("HTTPS (port 443) is not accessible")

    # --------------------
    # SYN SCAN (GROUND TRUTH, OPTIONAL)
    # --------------------
    syn = scan.get("syn_scan", {})

    if syn.get("status") == "completed":
        open_ports = syn.get("open_ports", [])

        if 22 in open_ports:
            score += 15
            reasons.add("SSH exposed (confirmed via SYN scan)")

        if 80 in open_ports:
            reasons.add("HTTP exposure confirmed via SYN scan")

    elif syn.get("status") == "error":
        reasons.add("SYN scan unavailable from current execution context")

    # --------------------
    # SSL / TLS
    # --------------------
    ssl = scan.get("ssl", {})

    if ssl.get("status") != "enabled":
        score += 20
        reasons.add("SSL is not enabled")
    else:
        confidence = ssl.get("confidence")
        if confidence != "high":
            score += 10
            reasons.add("SSL enabled with limited verification confidence")

    # --------------------
    # HTTPS SECURITY HEADERS
    # --------------------
    headers = scan.get("https_headers", {})
    summary = headers.get("summary", {})

    missing_headers = summary.get("missing", 0)
    permissive_headers = summary.get("permissive", 0)

    if missing_headers > 0:
        score += min(10, missing_headers * 2)
        reasons.add("Multiple security headers are missing")

    if permissive_headers > 0:
        score += 5
        reasons.add("Permissive security header configuration detected")

    # --------------------
    # SUBDOMAIN EXPOSURE
    # --------------------
    subs = scan.get("subdomains", {})

    if isinstance(subs, dict):
        count = subs.get("count", 0)

        if count >= 20:
            score += 15
            reasons.add("Large number of exposed subdomains")
        elif count >= 5:
            score += 5
            reasons.add("Multiple exposed subdomains detected")

    # --------------------
    # TECHNOLOGY EXPOSURE
    # --------------------
    tech = scan.get("technology", {})

    observed = tech.get("observed", {})
    inferred = tech.get("inferred", {})

    if observed.get("server"):
        score += 5
        reasons.add("Server header is exposed")

    cdn_info = inferred.get("cdn")
    if isinstance(cdn_info, dict):
        if cdn_info.get("value") is False:
            score += 5
            reasons.add("No CDN detected")

    # --------------------
    # NORMALIZE SCORE
    # --------------------
    score = max(0, min(score, 100))

    if score < 30:
        level = "low"
    elif score < 70:
        level = "medium"
    else:
        level = "high"

    return {
        "score": score,
        "level": level,
        "reasons": sorted(reasons)
    }
