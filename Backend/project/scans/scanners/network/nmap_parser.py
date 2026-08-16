import xml.etree.ElementTree as ET

class NmapParser:
    @classmethod
    def parse_xml(cls, xml_content: str) -> list:
        """
        Parses Nmap XML output string.
        Returns a list of dictionaries representing hosts and their ports:
        [
            {
                "ip": "127.0.0.1",
                "status": "up" | "down" | "unknown",
                "hostnames": ["localhost"],
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open" | "closed" | "filtered" | "unknown",
                        "service": "http"
                    }
                ]
            }
        ]
        """
        if not xml_content or not xml_content.strip():
            raise ValueError("Empty or invalid Nmap XML output.")

        try:
            # Parse XML
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse Nmap XML output: {str(e)}")

        hosts_data = []

        # Find all host elements
        for host_node in root.findall("host"):
            host_info = {
                "ip": "",
                "status": "unknown",
                "hostnames": [],
                "ports": []
            }

            # 1. Host status (up/down)
            status_node = host_node.find("status")
            if status_node is not None:
                host_info["status"] = status_node.get("state", "unknown")

            # 2. IP Address (looks up ipv4 or ipv6 addresses)
            for addr_node in host_node.findall("address"):
                addr_type = addr_node.get("addrtype", "")
                if addr_type in ["ipv4", "ipv6"]:
                    host_info["ip"] = addr_node.get("addr", "")
                    break

            # Fallback for address if no explicit ipv4/ipv6 type matches
            if not host_info["ip"]:
                addr_node = host_node.find("address")
                if addr_node is not None:
                    host_info["ip"] = addr_node.get("addr", "")

            # 3. Hostnames list
            hostnames_node = host_node.find("hostnames")
            if hostnames_node is not None:
                for hn in hostnames_node.findall("hostname"):
                    name = hn.get("name", "")
                    if name:
                        host_info["hostnames"].append(name)

            # 4. Port scans list
            ports_node = host_node.find("ports")
            if ports_node is not None:
                for port_node in ports_node.findall("port"):
                    port_info = {
                        "port": None,
                        "protocol": "tcp",
                        "state": "unknown",
                        "service": "unknown"
                    }

                    # Port number
                    try:
                        port_info["port"] = int(port_node.get("portid", 0))
                    except (ValueError, TypeError):
                        continue

                    # Protocol (tcp / udp)
                    port_info["protocol"] = port_node.get("protocol", "tcp")

                    # Port state
                    state_node = port_node.find("state")
                    if state_node is not None:
                        port_info["state"] = state_node.get("state", "unknown")

                    # Service name
                    service_node = port_node.find("service")
                    if service_node is not None:
                        port_info["service"] = service_node.get("name", "unknown")

                    host_info["ports"].append(port_info)

            hosts_data.append(host_info)

        return hosts_data
