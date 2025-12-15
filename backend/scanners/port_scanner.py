import socket

def check_port(domain: str, port: int) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((domain, port))
        sock.close()

        if result == 0:
            return "open"
        else:
            return "closed"
    except Exception:
        return "error"
