import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor

NETWORK_SCAN_START_PORT = 1
NETWORK_SCAN_END_PORT = 1024
SOCKET_TIMEOUT = 1.0
MAX_CONCURRENCY = 50

class SocketScanner:
    PORT_SERVICE_MAP = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        587: "smtp-submission",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        9200: "elasticsearch",
        27017: "mongodb",
        8000: "http-alt",
        8080: "http-alt",
    }

    def __init__(self, start_port=NETWORK_SCAN_START_PORT, end_port=NETWORK_SCAN_END_PORT, timeout=SOCKET_TIMEOUT, concurrency=MAX_CONCURRENCY):
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.concurrency = concurrency
        self.is_cancelled = False
        self._lock = threading.Lock()
        
        # Thread-safe counters
        self.ports_checked = 0
        self.open_ports = 0
        self.closed_ports = 0
        self.timeouts = 0

    def cancel(self):
        self.is_cancelled = True

    def scan_port(self, ip, port):
        if self.is_cancelled:
            return None
            
        start_time = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            err = s.connect_ex((ip, port))
            response_time = time.time() - start_time
            if err == 0:
                state = "OPEN"
                error_msg = None
            else:
                state = "CLOSED"
                error_msg = f"Closed or filtered (code {err})"
            return {
                "port": port,
                "state": state,
                "response_time": response_time,
                "error": error_msg
            }
        except (socket.timeout, TimeoutError):
            return {
                "port": port,
                "state": "TIMEOUT",
                "response_time": time.time() - start_time,
                "error": "Timeout"
            }
        except Exception as e:
            return {
                "port": port,
                "state": "CLOSED",
                "response_time": time.time() - start_time,
                "error": str(e)
            }
        finally:
            s.close()

    def scan_host(self, ip, progress_callback=None, port_callback=None):
        # Reset host counters per scan run
        with self._lock:
            self.ports_checked = 0
            self.open_ports = 0
            self.closed_ports = 0
            self.timeouts = 0

        ports = list(range(self.start_port, self.end_port + 1))
        total_ports = len(ports)
        results = []

        workers = min(self.concurrency, 100)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all port scanning tasks
            futures = {executor.submit(self.scan_port, ip, p): p for p in ports}
            
            for future in futures:
                if self.is_cancelled:
                    # Cancel any pending / non-started futures
                    future.cancel()
            
            # Process results as they complete
            from concurrent.futures import as_completed
            for future in as_completed(futures):
                if self.is_cancelled:
                    break
                    
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                        
                        # Thread-safe updates
                        with self._lock:
                            self.ports_checked += 1
                            if res["state"] == "OPEN":
                                self.open_ports += 1
                            elif res["state"] == "TIMEOUT":
                                self.timeouts += 1
                            elif res["state"] == "CLOSED":
                                self.closed_ports += 1
                                
                        # Trigger callbacks
                        if port_callback:
                            port_callback(ip, res)
                            
                        # Report progress
                        if progress_callback:
                            progress_callback(self.ports_checked, total_ports)
                except Exception:
                    pass

        return results
