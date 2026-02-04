import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import ssl
import socket
import re

# Common backup extensions and files
BACKUP_EXTENSIONS = ['.bak', '.old', '.swp', '.zip', '.tar.gz', '.sql']
COMMON_FILES = ['index.php', 'config.php', 'wp-config.php', '.env', 'web.config']

# Common directories to check
COMMON_DIRS = [
    'admin', 'backup', 'db', 'database', 'files', 'images', 'includes', 'js', 'css', 'logs', 'private', 'scripts', 'src', 'static', 'temp', 'test', 'tmp', 'upload', 'uploads', 'vendor'
]

class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.results = {
            "backup_files": [],
            "sensitive_dirs": [],
            "headers": [],
            "cms": None,
            "ssl_info": None,
            "robots_txt": [],
            "vulnerabilities": []
        }

    def check_backups(self):
        checks = []
        for file in COMMON_FILES:
            for ext in BACKUP_EXTENSIONS:
                checks.append(file + ext)
        
        for check in checks:
            url = urljoin(self.target_url, check)
            try:
                res = requests.head(url, timeout=2)
                if res.status_code == 200:
                    self.results["backup_files"].append(url)
            except:
                pass

    def check_directories(self):
        for directory in COMMON_DIRS:
            url = urljoin(self.target_url, directory)
            try:
                res = requests.head(url, timeout=2)
                if res.status_code in [200, 403]:
                    self.results["sensitive_dirs"].append({"url": url, "status": res.status_code})
            except:
                pass

    def check_headers(self):
        try:
            res = requests.head(self.target_url, timeout=3)
            headers = res.headers
            
            security_headers = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options"
            ]
            
            missing = []
            for h in security_headers:
                if h not in headers:
                    missing.append(h)
            
            self.results["headers"] = {"missing": missing, "present": {k:v for k,v in headers.items() if k in security_headers}}
            
        except:
            self.results["headers"] = {"error": "Could not retrieve headers"}

    def check_cms(self):
        try:
            res = requests.get(self.target_url, timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # Meta generator check
            meta_gen = soup.find("meta", attrs={"name": "generator"})
            if meta_gen:
                self.results["cms"] = meta_gen.get("content")
                return

            # Common paths/content checks
            if "wp-content" in res.text:
                self.results["cms"] = "WordPress"
            elif "Joomla" in res.text or "/templates/" in res.text:
                self.results["cms"] = "Joomla"
            elif "Drupal" in res.text:
                self.results["cms"] = "Drupal"
            else:
                self.results["cms"] = "Unknown"
        except:
            self.results["cms"] = "Detection Failed"

    def check_ssl(self):
        if not self.target_url.startswith("https"):
            self.results["ssl_info"] = "Not using HTTPS"
            return

        try:
            hostname = self.target_url.replace("https://", "").split("/")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                self.results["ssl_info"] = {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert['version'],
                    "expires": cert['notAfter']
                }
        except Exception as e:
            self.results["ssl_info"] = f"SSL Error: {str(e)}"

    def check_robots(self):
        try:
            url = urljoin(self.target_url, "robots.txt")
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                lines = res.text.split('\n')
                disallowed = [line.strip() for line in lines if line.lower().startswith('disallow:')]
                self.results["robots_txt"] = disallowed
        except:
            pass

    def check_vulnerabilities(self):
        # Basic heuristic checks
        
        # 1. SQL Injection (Error-based)
        sqli_payloads = ["'", "\"", " OR 1=1"]
        sqli_errors = ["SQL syntax", "mysql_fetch", "ORA-01756", "SQLite3::"]
        
        # 2. XSS (Reflected)
        xss_payload = "<script>alert('ALTRON')</script>"
        
        # We need a parameter to test. If no params, we can't easily test without a crawler.
        # For this demo, we'll assume the target might have params or we just test the base URL (unlikely to work but shows intent)
        # A real scanner would crawl links. Here we will just append to URL if it has params, or warn.
        
        if "?" in self.target_url:
            # Simple test on existing params
            base, params = self.target_url.split("?", 1)
            # This is very basic, just appending payload to the whole query string for demo
            
            # SQLi Test
            for payload in sqli_payloads:
                test_url = f"{self.target_url}{payload}"
                try:
                    res = requests.get(test_url, timeout=3)
                    for error in sqli_errors:
                        if error in res.text:
                            self.results["vulnerabilities"].append(f"Possible SQL Injection found with payload: {payload}")
                            break
                except:
                    pass
            
            # XSS Test
            try:
                test_url = f"{self.target_url}&test={xss_payload}"
                res = requests.get(test_url, timeout=3)
                if xss_payload in res.text:
                    self.results["vulnerabilities"].append("Possible Reflected XSS found")
            except:
                pass

    def run(self):
        self.check_headers()
        self.check_backups()
        self.check_directories()
        self.check_cms()
        self.check_ssl()
        self.check_robots()
        self.check_vulnerabilities()
        return self.results
