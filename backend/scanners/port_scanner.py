import socket
from typing import Dict, List


def _tcp_probe(domain: str, port: int, timeout: int = 3) -> str:
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except Exception:
        return "filtered"


def check_port(
    domain: str,
    port: int,
    attempts: int = 3,
    timeout: int = 3
) -> Dict:
    results: List[str] = []

    for _ in range(attempts):
        result = _tcp_probe(domain, port, timeout)
        results.append(result)

    open_count = results.count("open")
    closed_count = results.count("closed")
    filtered_count = results.count("filtered")

    # Decision logic
    if open_count > 0:
        status = "open"
        confidence = "high" if open_count >= attempts // 2 else "medium"
        reason = "TCP connection successful"
    elif closed_count == attempts:
        status = "closed"
        confidence = "high"
        reason = "Connection refused consistently"
    else:
        status = "filtered"
        confidence = "medium"
        reason = "No definitive TCP response (possible firewall)"

    notes = [
        "TCP connect scan from external network perspective",
        "Filtered does not confirm firewall presence",
        "Result based on repeated attempts"
    ]

    return {
        "status": status,
        "confidence": confidence,
        "attempts": attempts,
        "results": {
            "open": open_count,
            "closed": closed_count,
            "filtered": filtered_count
        },
        "reason": reason,
        "notes": notes
    }
