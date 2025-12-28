import subprocess
import shutil
import xml.etree.ElementTree as ET


def run_nmap_scan(domain: str) -> list:
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap not installed")

    cmd = [
        "nmap",
        "-sT",
        "-sV",
        "--top-ports", "20",
        "-T3",
        "--open",
        "-oX", "-",
        domain
    ]

    process = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120
    )

    return _parse_nmap_xml(process.stdout)


def _parse_nmap_xml(xml_data: str) -> list:
    services = []
    root = ET.fromstring(xml_data)

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            service = port.find("service")
            if service is not None:
                services.append({
                    "port": int(port.attrib["portid"]),
                    "protocol": port.attrib["protocol"],
                    "service": service.attrib.get("name"),
                    "product": service.attrib.get("product"),
                    "version": service.attrib.get("version")
                })

    return services
