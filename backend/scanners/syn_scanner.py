import subprocess
from typing import List, Dict


def syn_scan(domain: str, ports: List[int], timeout: int = 120) -> Dict:
    """
    Performs a TCP SYN scan using Nmap.
    Requires elevated privileges on most systems.
    """

    cmd = [
        "nmap",
        "-sS",
        "-Pn",
        "-n",
        "--open",
        "-p", ",".join(map(str, ports)),
        domain,
        "-oX", "-"
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "confidence": "low",
            "reason": "SYN scan timed out",
            "open_ports": [],
            "notes": ["scan_timeout"]
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "confidence": "low",
            "reason": "Nmap execution failed",
            "open_ports": [],
            "notes": ["nmap_error"]
        }

    open_ports = []

    for line in proc.stdout.splitlines():
        if 'portid="' in line and 'state="open"' in line:
            try:
                port = int(line.split('portid="')[1].split('"')[0])
                open_ports.append(port)
            except Exception:
                continue

    return {
        "status": "completed",
        "method": "tcp_syn",
        "confidence": "high",
        "open_ports": sorted(set(open_ports)),
        "notes": [
            "syn_scan_via_nmap",
            "network_level_visibility",
            "requires_elevated_privileges"
        ]
    }
