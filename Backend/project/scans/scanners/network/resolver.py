import socket
from urllib.parse import urlparse
import ipaddress

class DNSResolver:
    @classmethod
    def resolve(cls, target_str):
        """
        Resolves domain or URL hostname to IP addresses using socket.getaddrinfo().
        Only IPv4 addresses are returned for scanning, as required.
        """
        target_str = target_str.strip()
        if not target_str:
            return []

        # Remove scheme if present
        host = target_str
        if '://' in host or host.startswith('//'):
            try:
                temp = host if '://' in host else f"http:{host}"
                parsed = urlparse(temp)
                host = parsed.hostname or parsed.netloc or parsed.path
            except Exception:
                pass

        if '/' in host:
            host = host.split('/')[0]

        if ':' in host:
            if host.startswith('[') and ']' in host:
                host = host.split(']')[0][1:]
            elif host.count(':') == 1:
                host = host.split(':')[0]

        # If it is already a valid IP address, just return it
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass

        try:
            # getaddrinfo returns a list of 5-tuples: (family, type, proto, canonname, sockaddr)
            # sockaddr is (address, port) for IPv4
            results = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            ips = list(set([res[4][0] for res in results]))
            return sorted(ips)
        except Exception:
            return []
