from backend.scanners.nmap_scanner import run_nmap_scan
from backend.config import config


def scan_services(domain: str) -> dict:
    """
    Run Nmap service detection if enabled.
    This scanner is optional and must never break the scan.
    """

    if not config.ENABLE_NMAP:
        return {
            "status": "disabled",
            "services": []
        }

    try:
        services = run_nmap_scan(domain)
        return {
            "status": "enabled",
            "services": services
        }
    except Exception as e:
        return {
            "status": "error",
            "services": [],
            "reason": str(e)
        }
