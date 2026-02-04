import socket
import threading
import requests
from queue import Queue

# Top 20 common ports for demonstration + range for others if needed
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]
# Add more to reach ~1000 if needed, or just scan a range. 
# For speed and demo purposes, we'll scan a mix of specific common ports and a range.
# Let's define a list of top 1000 ports (simplified for this context to a range + common list)
# In a real "Kali" style tool, we'd have a massive list. 
# We will scan 1-1024 to cover most privileged ports.

TARGET_PORTS = list(range(1, 1025))

class PortScanner:
    def __init__(self, target, ports=None):
        self.target = target
        self.ports = ports if ports else TARGET_PORTS
        self.results = []
        self.lock = threading.Lock()
        self.queue = Queue()

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                # Verify HTTP service if applicable
                http_status = None
                if port in [80, 443, 8080, 8443] or service == 'http':
                    http_status = self.verify_http(port)

                with self.lock:
                    self.results.append({
                        "port": port, 
                        "status": "open", 
                        "service": service,
                        "http_status": http_status
                    })
            sock.close()
        except:
            pass

    def verify_http(self, port):
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{self.target}:{port}"
            res = requests.head(url, timeout=2, verify=False)
            return res.status_code
        except:
            return None

    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()

    def run(self):
        for port in self.ports:
            self.queue.put(port)

        thread_list = []
        for _ in range(50): # 50 threads
            thread = threading.Thread(target=self.worker)
            thread_list.append(thread)
            thread.start()

        for thread in thread_list:
            thread.join()

        return sorted(self.results, key=lambda x: x['port'])
