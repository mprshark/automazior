def calculate_risk(scan_result: dict) -> dict:
    score = 0
    reasons = []

    ports = scan_result.get("ports", {})
    ssl = scan_result.get("ssl", {})
    tech = scan_result.get("technology", {})
    subdomains = scan_result.get("subdomains", [])
    nmap = scan_result.get("nmap", {})
    services = nmap.get("services", [])

    # ==============================
    # PORT EXPOSURE (FAST SCAN)
    # ==============================
    if ports.get("80") == "open":
        score += 10
        reasons.append("HTTP (port 80) is open")

    if ports.get("443") == "open":
        score += 5

    # ==============================
    # SSL POSTURE
    # ==============================
    if not ssl.get("enabled"):
        score += 25
        reasons.append("SSL is not enabled")
    else:
        days_left = ssl.get("days_left")
        if days_left is not None:
            if days_left < 15:
                score += 25
                reasons.append("SSL certificate expires very soon")
            elif days_left < 45:
                score += 15
                reasons.append("SSL certificate expires soon")

    # ==============================
    # TECHNOLOGY EXPOSURE
    # ==============================
    server = tech.get("server")
    if server and "/" in server:
        score += 10
        reasons.append("Server version is exposed")

    if not tech.get("cdn"):
        score += 10
        reasons.append("No CDN detected")

    # ==============================
    # SUBDOMAIN EXPOSURE
    # ==============================
    if len(subdomains) > 5:
        score += 15
        reasons.append("Large number of exposed subdomains")
    elif len(subdomains) > 0:
        score += 5
        reasons.append("Exposed subdomains detected")

    # ==============================
    # NMAP-BASED RISK (DEDUPED)
    # ==============================
    sensitive_ports = {
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        3389   # RDP
    }

    seen_sensitive_ports = set()
    seen_service_versions = set()

    for svc in services:
        port = svc.get("port")
        product = svc.get("product")
        version = svc.get("version")

        # Sensitive port exposure (count once per port)
        if port in sensitive_ports and port not in seen_sensitive_ports:
            score += 10
            reasons.append(f"Sensitive service exposed on port {port}")
            seen_sensitive_ports.add(port)

        # Service version exposure (count once per product+version)
        if product and version:
            key = f"{product}:{version}"
            if key not in seen_service_versions:
                score += 5
                reasons.append(f"Service version detected: {product} {version}")
                seen_service_versions.add(key)

    # Multiple exposed services
    if len(services) >= 5:
        score += 10
        reasons.append("Multiple services exposed via active scan")

    # ==============================
    # FINALIZE SCORE
    # ==============================
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
