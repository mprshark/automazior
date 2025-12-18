from scanners.nmap_scanner import run_nmap_scan
from scanners.nmap_parser import parse_nmap_xml


def scan_services(domain: str) -> dict:
    """
    Runs Nmap safely and returns structured results.
    """
    xml_output = run_nmap_scan(domain)

    if not xml_output:
        return {
            "status": "skipped",
            "reason": "nmap timed out or failed",
            "services": []
        }

    services = parse_nmap_xml(xml_output)

    return {
        "status": "completed",
        "services": services
    }
