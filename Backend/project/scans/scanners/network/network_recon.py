import ipaddress
from scans.scanners.base import BaseScanner
from scans.scanners.placeholders.placeholder_scanner import ScopeException
from scans.scanners.network.host_discovery import HostDiscovery
from scans.scanners.network.nmap_runner import NmapRunner
from scans.scanners.network.nmap_parser import NmapParser

class NetworkReconScanner(BaseScanner):
    # Backend-controlled scanner constants
    NMAP_DEFAULT_PORTS = "1-1024"
    NMAP_CONNECT_TIMEOUT = 5
    NMAP_MAX_HOSTS = 256
    NMAP_EXECUTION_TIMEOUT = 300 # 5 minutes execution timeout

    def __init__(self, context):
        super().__init__(context)
        self.is_cancelled = False
        self.ports = []
        self.targets_to_scan = []
        self.domain_to_ip_map = {}

    def validate(self, assessment, project):
        """
        Scope Guard: Validates that all targets resolved from scopes lie within authorized boundaries.
        """
        if not self.context.scopes:
            raise ScopeException("No valid assessment scope available.")

        authorized_subnets = []
        authorized_hosts = set()

        for scope in self.context.scopes:
            target_str = scope.target.strip()
            if not target_str:
                continue
                
            # Normalize target representation (extract bare host/IP/domain from URL)
            target_clean = target_str
            if '://' in target_clean:
                from urllib.parse import urlparse
                parsed = urlparse(target_clean)
                target_clean = parsed.netloc or parsed.path
            target_clean = target_clean.rstrip('/')
            
            # If target has a slash, parse as CIDR subnet boundary
            if '/' in target_clean:
                try:
                    authorized_subnets.append(ipaddress.ip_network(target_clean, strict=False))
                except ValueError:
                    raise ScopeException(f"Invalid authorized CIDR range in scope: '{target_str}'")
            else:
                # HostDiscovery resolution returns standard IPs/domains list
                try:
                    hosts = HostDiscovery.resolve_target(target_clean)
                    for h in hosts:
                        authorized_hosts.add(h)
                except ValueError as e:
                    raise ScopeException(f"Invalid target scope definition: {str(e)}")

        # Build list of targets to scan from scope targets
        for scope in self.context.scopes:
            raw_target = scope.target.strip()
            if not raw_target:
                continue
            
            # Normalize target representation (extract bare host/IP/domain from URL)
            target_clean = raw_target
            if '://' in target_clean:
                from urllib.parse import urlparse
                parsed = urlparse(target_clean)
                target_clean = parsed.netloc or parsed.path
            target_clean = target_clean.rstrip('/')

            resolved_hosts = HostDiscovery.resolve_target(target_clean)
            if len(resolved_hosts) > self.NMAP_MAX_HOSTS:
                raise ScopeException(
                    f"Resolved target '{raw_target}' yields {len(resolved_hosts)} hosts, "
                    f"exceeding authorized cap of {self.NMAP_MAX_HOSTS}."
                )

            for host in resolved_hosts:
                # Check Domain resolution
                try:
                    ipaddress.ip_address(host)
                    self.targets_to_scan.append(host)
                except ValueError:
                    # Resolve domain name
                    ip = HostDiscovery.resolve_dns(host)
                    if ip:
                        self.domain_to_ip_map[host] = ip
                        self.targets_to_scan.append(ip)
                    else:
                        self.targets_to_scan.append(host)

        # Enforce Scope Guard: Ensure resolved IPs fit inside authorized subnets or hosts
        for target in self.targets_to_scan:
            is_authorized = False
            # Direct host mapping check
            if target in authorized_hosts:
                is_authorized = True
            else:
                # Check if this IP was resolved from an authorized domain name
                for domain, resolved_ip in self.domain_to_ip_map.items():
                    if resolved_ip == target and domain in authorized_hosts:
                        is_authorized = True
                        break
            
            if not is_authorized:
                # Subnet containment check
                try:
                    ip_obj = ipaddress.ip_address(target)
                    for subnet in authorized_subnets:
                        if ip_obj in subnet:
                            is_authorized = True
                            break
                except ValueError:
                    pass
            
            if not is_authorized:
                raise ScopeException(f"Target host '{target}' lies outside authorized assessment scope.")

    def prepare(self):
        # Verify Nmap exists before scanning starts
        if not NmapRunner.is_nmap_installed():
            raise RuntimeError("Nmap is not installed or is unavailable on the AttackLens worker.")

    def run(self, progress_callback=None):
        if not self.targets_to_scan:
            return {
                "scanner": "network_recon",
                "scanner_version": "2.0.0",
                "status": "completed",
                "scan_type": "tcp_port_scan",
                "hosts_scanned": 0,
                "ports_checked": 0,
                "open_ports": 0,
                "assets": [],
                "findings": []
            }

        if progress_callback:
            progress_callback(10, f"Initializing Nmap scanner targeting {len(self.targets_to_scan)} hosts...")

        runner = NmapRunner(timeout=self.NMAP_EXECUTION_TIMEOUT)

        def cancel_check():
            if self.is_cancelled:
                return True
            try:
                self.scan_job.refresh_from_db()
                if self.scan_job.status == 'CANCELLED':
                    self.is_cancelled = True
                    return True
            except Exception:
                pass
            return False

        if progress_callback:
            progress_callback(20, "Running TCP port scan using Nmap...")

        # Run Nmap on targets list
        res = runner.run_scan(
            target=self.targets_to_scan,
            port_range=self.NMAP_DEFAULT_PORTS,
            cancel_check=cancel_check
        )

        if res["status"] == "cancelled" or self.is_cancelled:
            return {
                "scanner": "network_recon",
                "scanner_version": "2.0.0",
                "status": "cancelled",
                "scan_type": "tcp_port_scan",
                "hosts_scanned": 0,
                "ports_checked": 0,
                "open_ports": 0,
                "assets": [],
                "findings": []
            }

        if res["status"] == "timeout":
            raise RuntimeError(res["error_message"])

        if res["status"] == "failed":
            raise RuntimeError(res["error_message"])

        if progress_callback:
            progress_callback(80, "Parsing XML scan output...")

        # Parse XML outputs
        parsed_hosts = NmapParser.parse_xml(res["xml_output"])

        assets = []
        findings = []
        open_ports_count = 0

        # Iterate parsed host outputs and build standard AttackLens outputs
        for host_info in parsed_hosts:
            ip = host_info["ip"]
            if not ip:
                continue

            # Resolve domain mapping
            domain_name = None
            if host_info["hostnames"]:
                domain_name = host_info["hostnames"][0]
            else:
                for d, resolved_ip in self.domain_to_ip_map.items():
                    if resolved_ip == ip:
                        domain_name = d
                        break

            # 1. Register Domain Asset
            if domain_name:
                assets.append({
                    "asset_type": "DOMAIN",
                    "value": domain_name,
                    "metadata": {"resolved_ip": ip}
                })

            # 2. Register IP Asset
            assets.append({
                "asset_type": "IP",
                "value": ip,
                "metadata": {"hostname": domain_name or ""}
            })

            # 3. Process open ports
            for port_info in host_info["ports"]:
                if port_info["state"].upper() == "OPEN":
                    port_num = port_info["port"]
                    open_ports_count += 1

                    srv = {
                        "service": port_info["service"],
                        "banner": "",
                        "version": "",
                        "version_confidence": "LOW"
                    }

                    assets.append({
                        "asset_type": "PORT",
                        "value": f"{ip}:{port_num}",
                        "metadata": {
                            "host": ip,
                            "port": port_num,
                            "state": "OPEN",
                            "service": port_info["service"],
                            "banner": "",
                            "version": "",
                            "version_confidence": "LOW"
                        }
                    })

                    # Findings evaluation mapping
                    finding_data = self._evaluate_exposed_port_findings(ip, port_num, srv)
                    if finding_data:
                        findings.append(finding_data)

        if progress_callback:
            progress_callback(100, "Scan execution completed.")

        # Estimate ports checked as default port size * hosts scanned
        ports_checked = 1024 * len(self.targets_to_scan)

        return {
            "scanner": "network_recon",
            "scanner_version": "2.0.0",
            "status": "completed",
            "scan_type": "tcp_port_scan",
            "hosts_scanned": len(self.targets_to_scan),
            "ports_checked": ports_checked,
            "open_ports": open_ports_count,
            "assets": assets,
            "findings": findings
        }

    def cancel(self):
        self.is_cancelled = True

    def cleanup(self):
        pass

    def _evaluate_exposed_port_findings(self, host, port, srv):
        """
        Creates informational/medium exposure findings for exposed services.
        """
        service_name = srv["service"]
        
        # Database service exposed
        if port in [1433, 1521, 3306, 5432, 6379, 27017, 9200]:
            return {
                "title": f"Exposed Database Service ({service_name})",
                "description": f"A database service is publicly exposed on host {host} port {port}. Exposure of databases allows attackers to perform brute-force attacks.",
                "category": "CONFIGURATION",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "location": f"{host}:{port}",
                "remediation": "Restrict access to database ports using firewall access lists.",
                "references": [
                    {"title": "Exposed Databases Exposure Guidance", "url": "https://owasp.org/www-project-top-ten/"}
                ],
                "evidence": [
                    {
                        "evidence_type": "NETWORK",
                        "title": "Database exposure details",
                        "location": f"{host}:{port}",
                        "payload": f"Port: {port}, Service: {service_name}",
                        "metadata": srv
                    }
                ]
            }
            
        # Remote administration services exposed
        elif port in [22, 23, 3389, 5900]:
            # Check if cleartext telnet
            if port == 23:
                return {
                    "title": "Exposed Cleartext Remote Management (Telnet)",
                    "description": f"Telnet service exposed on host {host} port {port}. Telnet transmits credentials in plain text.",
                    "category": "CRYPTOGRAPHY",
                    "severity": "MEDIUM",
                    "confidence": "CONFIRMED",
                    "location": f"{host}:{port}",
                    "remediation": "Disable Telnet and use SSH instead for remote management.",
                    "references": [],
                    "evidence": [
                        {
                            "evidence_type": "NETWORK",
                            "title": "Exposed telnet port details",
                            "location": f"{host}:{port}",
                            "payload": f"Port: {port}, Service: {service_name}",
                            "metadata": srv
                        }
                    ]
                }
            return {
                "title": f"Exposed Remote Administration Service ({service_name})",
                "description": f"A remote administration service is exposed on host {host} port {port}.",
                "category": "CONFIGURATION",
                "severity": "LOW",
                "confidence": "HIGH",
                "location": f"{host}:{port}",
                "remediation": "Restrict remote admin services to authorized VPN IP ranges.",
                "references": [],
                "evidence": [
                    {
                        "evidence_type": "NETWORK",
                        "title": "Remote administration exposed port",
                        "location": f"{host}:{port}",
                        "payload": f"Port: {port}, Service: {service_name}",
                        "metadata": srv
                    }
                ]
            }

        # Cleartext exposed protocols
        elif port in [21, 25, 110, 143]:
            return {
                "title": f"Exposed Cleartext Protocol ({service_name})",
                "description": f"Exposed cleartext communication port {port} on host {host}.",
                "category": "TLS",
                "severity": "LOW",
                "confidence": "HIGH",
                "location": f"{host}:{port}",
                "remediation": "Enforce SSL/TLS wrapper protocols (e.g. FTPS, SMTPS, POP3S).",
                "references": [],
                "evidence": [
                    {
                        "evidence_type": "NETWORK",
                        "title": "Cleartext exposed port details",
                        "location": f"{host}:{port}",
                        "payload": f"Port: {port}, Service: {service_name}",
                        "metadata": srv
                    }
                ]
            }

        return None
