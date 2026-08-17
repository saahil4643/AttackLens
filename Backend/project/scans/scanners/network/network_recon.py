import ipaddress
from scans.scanners.base import BaseScanner
from scans.scanners.placeholders.placeholder_scanner import ScopeException
from scans.scanners.network.host_discovery import HostDiscovery
from scans.scanners.network.resolver import DNSResolver
from scans.scanners.network.socket_scanner import SocketScanner, NETWORK_SCAN_START_PORT, NETWORK_SCAN_END_PORT, SOCKET_TIMEOUT, MAX_CONCURRENCY
from scans.publisher import ScanEventPublisher

class NetworkReconScanner(BaseScanner):
    # Backend-controlled scanner constants
    MAX_HOSTS = 256
    EXECUTION_TIMEOUT = 300 # 5 minutes execution timeout

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
                
            # Normalize target representation using HostDiscovery helper
            target_clean = HostDiscovery.normalize_target_input(target_str)
            if not target_clean:
                continue
            
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
            
            # Normalize target representation using HostDiscovery helper
            target_clean = HostDiscovery.normalize_target_input(raw_target)
            if not target_clean:
                continue

            resolved_hosts = HostDiscovery.resolve_target(target_clean)
            if len(resolved_hosts) > self.MAX_HOSTS:
                raise ScopeException(
                    f"Resolved target '{raw_target}' yields {len(resolved_hosts)} hosts, "
                    f"exceeding authorized cap of {self.MAX_HOSTS}."
                )

            for host in resolved_hosts:
                # Check Domain resolution
                try:
                    ipaddress.ip_address(host)
                    self.targets_to_scan.append(host)
                except ValueError:
                    # Resolve domain name using native DNSResolver
                    ips = DNSResolver.resolve(host)
                    if ips:
                        for ip in ips:
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
        pass

    def run(self, progress_callback=None):
        assessment_id = self.context.assessment.id
        job_id = self.scan_job.id

        # Publish scan.started
        ScanEventPublisher.publish(
            assessment_id,
            "scan.started",
            {"message": "Starting AttackLens network scan..."},
            job_id
        )

        if not self.targets_to_scan:
            ScanEventPublisher.publish(
                assessment_id,
                "scan.completed",
                {"message": "No targets to scan.", "hosts_scanned": 0, "ports_checked": 0, "open_ports": 0},
                job_id
            )
            return {
                "scanner": "network_recon",
                "scanner_version": "2.0.0",
                "status": "completed",
                "scan_type": "tcp_socket_port_scan",
                "hosts_scanned": 0,
                "ports_checked": 0,
                "open_ports": 0,
                "closed_ports": 0,
                "timeouts": 0,
                "assets": [],
                "findings": []
            }

        # DNS resolution event
        ScanEventPublisher.publish(
            assessment_id,
            "scan.dns_resolution",
            {"message": "DNS resolution completed for targets."},
            job_id
        )
        ScanEventPublisher.publish(
            assessment_id,
            "scan.log",
            {"message": f"Resolved target scopes. Target IPs to scan: {', '.join(self.targets_to_scan)}"},
            job_id
        )

        # Host discovery events
        for domain, ip in self.domain_to_ip_map.items():
            ScanEventPublisher.publish(
                assessment_id,
                "scan.host_discovered",
                {"hostname": domain, "resolved_ip": ip},
                job_id
            )
            ScanEventPublisher.publish(
                assessment_id,
                "scan.log",
                {"message": f"Discovered mapped target host: {domain} -> {ip}"},
                job_id
            )

        # Instantiate socket scanner
        scanner = SocketScanner(
            start_port=NETWORK_SCAN_START_PORT,
            end_port=NETWORK_SCAN_END_PORT,
            timeout=SOCKET_TIMEOUT,
            concurrency=MAX_CONCURRENCY
        )
        self.scanner = scanner

        assets = []
        findings = []
        open_ports_count = 0
        total_closed_ports = 0
        total_timeouts = 0
        total_ports_checked = 0

        # Define check callbacks
        def on_port_check(ip, port_res):
            port = port_res["port"]
            state = port_res["state"]
            
            # Send immediately for open ports
            if state == "OPEN":
                service = SocketScanner.PORT_SERVICE_MAP.get(port, "unknown")
                ScanEventPublisher.publish(
                    assessment_id,
                    "scan.port_open",
                    {
                        "host": ip,
                        "port": port,
                        "state": state,
                        "service": service
                    },
                    job_id
                )
                ScanEventPublisher.publish(
                    assessment_id,
                    "scan.log",
                    {"message": f"[+] Port {port} OPEN ({service}) discovered on {ip}."},
                    job_id
                )
            elif scanner.ports_checked % 50 == 0:
                # Throttle closed/timeout port events
                ScanEventPublisher.publish(
                    assessment_id,
                    "scan.port_check",
                    {
                        "host": ip,
                        "port": port,
                        "state": state
                    },
                    job_id
                )

        def on_progress(checked, total):
            # Map port checking progress to overall percentage range 20% - 95%
            progress_pct = 20 + int((checked / total) * 75)
            if progress_callback:
                progress_callback(progress_pct, f"Scanning TCP ports: {checked}/{total} checked...")
            
            # Emit progress update log every 100 ports or at completion
            if checked % 100 == 0 or checked == total:
                ScanEventPublisher.publish(
                    assessment_id,
                    "scan.log",
                    {"message": f"Progress: {checked}/{total} ports checked ({int(checked / total * 100)}%)..."},
                    job_id
                )

            ScanEventPublisher.publish(
                assessment_id,
                "scan.progress",
                {
                    "progress": progress_pct,
                    "message": "Scanning TCP ports...",
                    "ports_checked": checked,
                    "ports_total": total,
                    "open_ports": scanner.open_ports,
                    "closed_ports": scanner.closed_ports,
                    "timeouts": scanner.timeouts
                },
                job_id
            )

        # Scan each scoped target IP
        for ip in self.targets_to_scan:
            # Check for cancellation before/during scan
            if self.is_cancelled or scanner.is_cancelled:
                break
                
            ScanEventPublisher.publish(
                assessment_id,
                "scan.log",
                {"message": f"Starting TCP socket connect scan on host {ip} (ports {NETWORK_SCAN_START_PORT}-{NETWORK_SCAN_END_PORT})..."},
                job_id
            )

            results = scanner.scan_host(
                ip,
                progress_callback=on_progress,
                port_callback=on_port_check
            )

            total_ports_checked += scanner.ports_checked
            open_ports_count += scanner.open_ports
            total_closed_ports += scanner.closed_ports
            total_timeouts += scanner.timeouts

            ScanEventPublisher.publish(
                assessment_id,
                "scan.log",
                {"message": f"Host {ip} scan completed. Checked {scanner.ports_checked} ports. Open: {scanner.open_ports}, Closed/Filtered: {scanner.closed_ports + scanner.timeouts}"},
                job_id
            )

            # Resolve domain name mapping
            domain_name = None
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
            for port_res in results:
                if port_res["state"] == "OPEN":
                    port_num = port_res["port"]
                    service = SocketScanner.PORT_SERVICE_MAP.get(port_num, "unknown")
                    
                    assets.append({
                        "asset_type": "PORT",
                        "value": f"{ip}:{port_num}",
                        "metadata": {
                            "host": ip,
                            "port": port_num,
                            "state": "OPEN",
                            "service": service,
                            "banner": "",
                            "version": "",
                            "version_confidence": "LOW"
                        }
                    })

                    # Findings evaluation mapping
                    srv_obj = {"service": service}
                    finding_data = self._evaluate_exposed_port_findings(ip, port_num, srv_obj)
                    if finding_data:
                        findings.append(finding_data)

        # Handle Cancellation
        if self.is_cancelled or scanner.is_cancelled:
            ScanEventPublisher.publish(
                assessment_id,
                "scan.cancelled",
                {"message": "Scan execution cancelled by client."},
                job_id
            )
            return {
                "scanner": "network_recon",
                "scanner_version": "2.0.0",
                "status": "cancelled",
                "scan_type": "tcp_socket_port_scan",
                "hosts_scanned": len(self.targets_to_scan),
                "ports_checked": total_ports_checked,
                "open_ports": open_ports_count,
                "closed_ports": total_closed_ports,
                "timeouts": total_timeouts,
                "assets": [],
                "findings": []
            }

        # Completed successfully
        ScanEventPublisher.publish(
            assessment_id,
            "scan.completed",
            {
                "message": "TCP port scan execution completed successfully.",
                "hosts_scanned": len(self.targets_to_scan),
                "ports_checked": total_ports_checked,
                "open_ports": open_ports_count,
                "closed_ports": total_closed_ports,
                "timeouts": total_timeouts
            },
            job_id
        )

        if progress_callback:
            progress_callback(100, "Scan execution completed.")

        return {
            "scanner": "network_recon",
            "scanner_version": "2.0.0",
            "status": "completed",
            "scan_type": "tcp_socket_port_scan",
            "hosts_scanned": len(self.targets_to_scan),
            "ports_checked": total_ports_checked,
            "open_ports": open_ports_count,
            "closed_ports": total_closed_ports,
            "timeouts": total_timeouts,
            "assets": assets,
            "findings": findings
        }

    def cancel(self):
        self.is_cancelled = True
        if hasattr(self, 'scanner') and self.scanner:
            self.scanner.cancel()

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
