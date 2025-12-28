from fastapi import FastAPI
from concurrent.futures import ThreadPoolExecutor

from backend.schemas import ScanRequest

from backend.scanners.port_scanner import check_port
from backend.scanners.ssl_scanner import check_ssl
from backend.scanners.tech_scanner import detect_tech
from backend.scanners.subdomain_scanner import enumerate_subdomains
from backend.scanners.nmap_service_scanner import scan_services
from backend.scanners.https_header_scanner import scan_https_headers
from backend.scanners.risk_scorer import calculate_risk


app = FastAPI(title="Automazior ASM", version="1.3")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
def scan_domain(request: ScanRequest):
    domain = request.domain

    with ThreadPoolExecutor(max_workers=6) as executor:
        port_80 = executor.submit(check_port, domain, 80)
        port_443 = executor.submit(check_port, domain, 443)

        ssl_future = executor.submit(check_ssl, domain)
        tech_future = executor.submit(detect_tech, domain)
        subdomain_future = executor.submit(enumerate_subdomains, domain)
        headers_future = executor.submit(scan_https_headers, domain)
        nmap_future = executor.submit(scan_services, domain)

        result = {
            "domain": domain,
            "ports": {
                "80": port_80.result(),
                "443": port_443.result()
            },
            "ssl": ssl_future.result(),
            "https_headers": headers_future.result(),
            "technology": tech_future.result(),
            "subdomains": subdomain_future.result(),
            "nmap": nmap_future.result()
        }

    result["risk"] = calculate_risk(result)
    return result
