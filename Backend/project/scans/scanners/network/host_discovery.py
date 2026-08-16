import ipaddress
import socket
from urllib.parse import urlparse

class HostDiscovery:
    @classmethod
    def resolve_target(cls, target_str):
        """
        Parses a target string and returns resolved target hosts/IPs list.
        Supports URL, Domain, IP, and CIDR notation.
        """
        target_str = target_str.strip()
        if not target_str:
            return []

        # 1. Parse URL to extract hostname
        if '://' in target_str or target_str.startswith('//'):
            try:
                # Add scheme if missing for urlparse
                temp_target = target_str if '://' in target_str else f"http:{target_str}"
                parsed = urlparse(temp_target)
                host = parsed.hostname
                if not host:
                    host = parsed.path.split('/')[0].split(':')[0]
                return cls.resolve_target(host)
            except Exception:
                pass

        # 2. Check if CIDR notation
        if '/' in target_str:
            try:
                net = ipaddress.ip_network(target_str, strict=False)
                if net.num_addresses == 0:
                    raise ValueError("Network has no usable addresses.")
                # We return all hosts in the subnet
                return [str(ip) for ip in net.hosts()]
            except ValueError as e:
                raise ValueError(f"Invalid CIDR network '{target_str}': {str(e)}")

        # 3. Check if explicit IP address
        try:
            ipaddress.ip_address(target_str)
            return [target_str]
        except ValueError:
            pass

        # 4. Otherwise treat as Domain name
        return [target_str]

    @classmethod
    def resolve_dns(cls, domain):
        """
        Resolves domain to its IP address.
        """
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    @classmethod
    def is_host_reachable(cls, host, timeout=2.0):
        """
        Check if a host is alive by trying to connect to standard ports (80, 443, 22).
        """
        ports = [80, 443, 22]
        for port in ports:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((host, port))
                return True
            except Exception:
                pass
            finally:
                if s:
                    s.close()
        return False
