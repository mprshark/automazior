from fastapi import FastAPI
from concurrent.futures import ThreadPoolExecutor

from backend.schemas import ScanRequest

from backend.scanners.port_scanner import check_port
from backend.scanners.ssl_scanner import check_ssl
from backend.scanners.tech_scanner import detect_tech
from backend.scanners.subdomain_scanner import enumerate_subdomains
from backend.scanners.nmap_service_scanner import scan_services
from backend.scanners.syn_scanner import syn_scan
from backend.scanners.https_header_scanner import scan_https_headers
from backend.scanners.risk_scorer import calculate_risk

app = FastAPI()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
def scan_domain(request: ScanRequest):
    domain = request.domain

    with ThreadPoolExecutor(max_workers=8) as executor:
        port_80 = executor.submit(check_port, domain, 80)
        port_443 = executor.submit(check_port, domain, 443)

        ssl_future = executor.submit(check_ssl, domain)
        tech_future = executor.submit(detect_tech, domain)
        sub_future = executor.submit(enumerate_subdomains, domain)
        nmap_future = executor.submit(scan_services, domain)
        syn_future = executor.submit(syn_scan, domain, [80, 443, 22])
        headers_future = executor.submit(scan_https_headers, domain)

        result = {
            "domain": domain,
            "ports": {
                "80": port_80.result(),
                "443": port_443.result()
            },
            "ssl": ssl_future.result(),
            "https_headers": headers_future.result(),
            "technology": tech_future.result(),
            "subdomains": sub_future.result(),
            "nmap": nmap_future.result(),
            "syn_scan": syn_future.result()
        }

    result["risk"] = calculate_risk(result)
    return result
