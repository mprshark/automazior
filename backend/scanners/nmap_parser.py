import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_data: str) -> list:
    """
    Parses Nmap XML output and extracts open ports with service details.
    """
    results = []

    try:
        root = ET.fromstring(xml_data)

        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                service = port.find("service")

                results.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None
                })

        return results

    except Exception as e:
        print("Error parsing Nmap XML:", e)
        return []
