import socket
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed

PORT_PROFILES = {
    'COMMON': [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 
        8443, 9200, 27017
    ],
    'WEB': [80, 443, 8000, 8080, 8443],
    'DATABASE': [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    'FULL': list(range(1, 65536)),
}

class PortScanner:
    @classmethod
    def resolve_ports(cls, profile, custom_ports=None):
        """
        Resolves the target ports list based on profile and custom inputs.
        """
        profile = (profile or 'COMMON').upper()
        if profile == 'CUSTOM':
            ports = custom_ports or []
            # Validate custom ports are within valid range 1-65535
            valid_ports = []
            for p in ports:
                try:
                    p_val = int(p)
                    if 1 <= p_val <= 65535:
                        valid_ports.append(p_val)
                except (ValueError, TypeError):
                    pass
            return sorted(list(set(valid_ports)))
            
        return PORT_PROFILES.get(profile, PORT_PROFILES['COMMON'])

    @classmethod
    def scan_port(cls, host, port, timeout=2.0):
        """
        Scans a single TCP port on a target host.
        """
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            return {
                "port": port,
                "state": "OPEN",
                "error": None
            }
        except socket.timeout:
            return {
                "port": port,
                "state": "FILTERED",
                "error": "Timeout"
            }
        except socket.error as e:
            if getattr(e, 'errno', None) == errno.ECONNREFUSED or "refused" in str(e).lower():
                return {
                    "port": port,
                    "state": "CLOSED",
                    "error": "Connection Refused"
                }
            return {
                "port": port,
                "state": "FILTERED",
                "error": str(e)
            }
        finally:
            if s:
                s.close()

    @classmethod
    def scan_host_ports(cls, host, ports, timeout=2.0, concurrency=20, cancel_check=None):
        """
        Scans a list of ports concurrently for a given host.
        """
        results = []
        # Cap workers count to prevent excessive OS threading
        workers = min(max(1, concurrency), 100)
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(cls.scan_port, host, port, timeout): port for port in ports}
            for future in as_completed(futures):
                if cancel_check and cancel_check():
                    break
                try:
                    res = future.result()
                    results.append(res)
                except Exception:
                    pass
        return results
