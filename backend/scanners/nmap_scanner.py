import subprocess


def run_nmap_scan(domain: str) -> str:
    command = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        "-sT",
        "-sV",
        "--top-ports", "20",
        "-T3",
        "--open",
        "-oX", "-",
        domain
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            print("Nmap stderr:", result.stderr)
            return ""

        return result.stdout

    except Exception as e:
        print("Exception running Nmap:", e)
        return ""
