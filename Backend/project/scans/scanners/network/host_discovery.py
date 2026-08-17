import ipaddress
import socket
from urllib.parse import urlparse

class HostDiscovery:
    @classmethod
    def normalize_target_input(cls, target_str):
        """
        Normalizes any input target (URL, domain, IP, CIDR, or path) into
        either a valid CIDR network string or a clean domain/IP string.
        """
        target_str = target_str.strip()
        if not target_str:
            return ""

        # 1. Handle protocol/scheme prefixes (e.g. http://, https://, //)
        if '://' in target_str or target_str.startswith('//'):
            try:
                # Add scheme if missing for urlparse to work correctly
                temp = target_str if '://' in target_str else f"http:{target_str}"
                parsed = urlparse(temp)
                # parsed.hostname handles bracketed IPv6 and strips ports automatically
                host = parsed.hostname
                if not host:
                    # Fallback if parsing fails to get hostname
                    host = parsed.netloc or parsed.path
                target_str = host
            except Exception:
                pass

        # 2. Distinguish between a CIDR network range and a URL path
        if '/' in target_str:
            try:
                # Try parsing as a valid IP network CIDR range
                ipaddress.ip_network(target_str, strict=False)
                # If it succeeds, it's a CIDR block. Keep it.
                return target_str
            except ValueError:
                # If it fails, it's a URL path (e.g. google.com/some/path).
                # Split by '/' and take the host part
                target_str = target_str.split('/')[0]

        # 3. Strip port suffix if present (e.g. google.com:8080 or 192.168.1.1:8080)
        # Avoid breaking IPv6 addresses which have colons but no brackets unless bracketed
        if ':' in target_str:
            if target_str.startswith('[') and ']' in target_str:
                parts = target_str.split(']')
                target_str = parts[0][1:]
            elif target_str.count(':') == 1:
                target_str = target_str.split(':')[0]

        return target_str.strip()

    @classmethod
    def resolve_target(cls, target_str):
        """
        Parses a target string and returns resolved target hosts/IPs list.
        Supports URL, Domain, IP, and CIDR notation.
        """
        clean_target = cls.normalize_target_input(target_str)
        if not clean_target:
            return []

        # Check if CIDR notation
        if '/' in clean_target:
            try:
                net = ipaddress.ip_network(clean_target, strict=False)
                if net.num_addresses == 0:
                    raise ValueError("Network has no usable addresses.")
                # We return all hosts in the subnet
                return [str(ip) for ip in net.hosts()]
            except ValueError as e:
                raise ValueError(f"Invalid CIDR network '{clean_target}': {str(e)}")

        # Otherwise treat as explicit IP or Domain name
        return [clean_target]

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
