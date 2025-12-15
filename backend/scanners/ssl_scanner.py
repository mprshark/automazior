import ssl
import socket
from datetime import datetime


def check_ssl(domain: str) -> dict:
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Extract expiry date
        expiry_str = cert.get("notAfter")
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_date - datetime.utcnow()).days

        return {
            "enabled": True,
            "valid": days_left > 0,
            "expires_on": expiry_date.strftime("%Y-%m-%d"),
            "days_left": days_left
        }

    except Exception:
        return {
            "enabled": False,
            "valid": False,
            "expires_on": None,
            "days_left": None
        }
