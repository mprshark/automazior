def calculate_risk(scan: dict) -> dict:
    score = 0
    reasons = set()

    # --------------------
    # Ports
    # --------------------
    ports = scan.get("ports", {})

    if ports.get("80") == "open":
        score += 10
        reasons.add("HTTP (port 80) is open")

    # --------------------
    # SSL / TLS
    # --------------------
    ssl = scan.get("ssl", {})

    ssl_status = ssl.get("status")
    ssl_confidence = ssl.get("confidence")

    if ssl_status == "disabled" and ssl_confidence == "high":
        score += 20
        reasons.add("SSL is disabled")

    elif ssl_status == "enabled" and ssl_confidence == "medium":
        score += 5
        reasons.add("SSL enabled with limited verification confidence")

    # --------------------
    # Technology exposure
    # --------------------
    tech = scan.get("technology", {})

    if tech.get("server"):
        score += 5
        reasons.add("Server version is exposed")

    if not tech.get("cdn"):
        score += 5
        reasons.add("No CDN detected")

    # --------------------
    # Subdomains
    # --------------------
    subdomains = scan.get("subdomains", [])

    if len(subdomains) > 20:
        score += 15
        reasons.add("Large number of exposed subdomains")
    elif len(subdomains) > 0:
        score += 5
        reasons.add("Exposed subdomains detected")

    # --------------------
    # Nmap services
    # --------------------
    nmap = scan.get("nmap", {})
    services = nmap.get("services", [])

    sensitive_ports = {21, 22, 23, 3389}

    for svc in services:
        port = svc.get("port")
        product = svc.get("product")
        version = svc.get("version")

        if port in sensitive_ports:
            score += 10
            reasons.add(f"Sensitive service exposed on port {port}")

        if product and version:
            reasons.add(f"Service version detected: {product} {version}")

    # --------------------
    # Normalize & classify
    # --------------------
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
        "reasons": sorted(reasons)
    }
