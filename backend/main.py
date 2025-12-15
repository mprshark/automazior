from fastapi import FastAPI
from concurrent.futures import ThreadPoolExecutor

from schemas import ScanRequest

from scanners.port_scanner import check_port
from scanners.ssl_scanner import check_ssl
from scanners.tech_scanner import detect_tech
from scanners.subdomain_scanner import enumerate_subdomains
from scanners.nmap_service_scanner import scan_services
from scanners.risk_scorer import calculate_risk


app = FastAPI()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
def scan_domain(request: ScanRequest):
    domain = request.domain

    # Run independent scanners concurrently
    with ThreadPoolExecutor(max_workers=5) as executor:
        port_80_future = executor.submit(check_port, domain, 80)
        port_443_future = executor.submit(check_port, domain, 443)

        ssl_future = executor.submit(check_ssl, domain)
        tech_future = executor.submit(detect_tech, domain)
        subdomain_future = executor.submit(enumerate_subdomains, domain)
        nmap_future = executor.submit(scan_services, domain)

        result = {
            "domain": domain,
            "ports": {
                "80": port_80_future.result(),
                "443": port_443_future.result()
            },
            "ssl": ssl_future.result(),
            "technology": tech_future.result(),
            "subdomains": subdomain_future.result(),
            "nmap": nmap_future.result()
        }

    # Risk scoring must run AFTER all scanners finish
    result["risk"] = calculate_risk(result)

    return result
