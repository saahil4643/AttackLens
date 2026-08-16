import socket

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "OracleDB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

class ServiceDetection:
    @classmethod
    def detect_service(cls, host, port, timeout=2.0):
        """
        Connects to open ports to identify service version and retrieve banners safely.
        """
        service_name = PORT_SERVICE_MAP.get(port, "unknown")
        banner = ""
        version = ""
        version_confidence = "LOW"
        
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            
            # FTP, SSH, SMTP and Mail protocols reveal banners immediately
            if port in [21, 22, 23, 25, 110, 143]:
                raw = s.recv(512)
                if raw:
                    banner = raw.decode('utf-8', errors='ignore').strip()
                    if port == 22 and "SSH-" in banner:
                        version = banner.split("\n")[0]
                        version_confidence = "HIGH"
            
            # HTTP/HTTPS protocols Server banner discovery
            elif port in [80, 443, 8000, 8080, 8443]:
                req = "HEAD / HTTP/1.0\r\n\r\n"
                s.sendall(req.encode('utf-8'))
                res = s.recv(1024).decode('utf-8', errors='ignore')
                for line in res.split("\r\n"):
                    if line.lower().startswith("server:"):
                        banner = line.split(":", 1)[1].strip()
                        version = banner
                        version_confidence = "MEDIUM"
                        break
        except Exception:
            pass
        finally:
            if s:
                s.close()
                
        return {
            "service": service_name,
            "banner": banner,
            "version": version,
            "version_confidence": version_confidence
        }
