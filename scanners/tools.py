import socket
import requests
import whois
import dns.resolver
import ssl
import re
import os
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Suppress SSL warnings for security scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tool IDs mapping
TOOLS = {
    1: "Port Scanner",
    2: "Whois Lookup",
    3: "DNS Enumerator",
    4: "Subdomain Finder",
    6: "SSL/TLS Validator",
    7: "HTTP Header Analyzer",
    8: "Robots.txt Analyzer",
    9: "Social Media Finder",
    10: "Directory Buster",
    11: "Backup File Finder",
    12: "Clickjacking Tester",
    13: "Git Exposure Scanner",
    14: "CORS Tester",
    15: "Open Redirect Scanner",
    16: "Directory Traversal Tester"
}

class SecurityTools:
    def __init__(self, target):
        # Expanded User-Agent list (50+) for better firewall evasion
        self.user_agents = [
            # Chrome Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Chrome Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            # Chrome Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            # Firefox Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
            # Firefox Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:120.0) Gecko/20100101 Firefox/120.0",
            # Firefox Linux
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            # Safari Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            # Edge Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            # Mobile - iPhone
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1",
            # Mobile - iPad
            "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
            # Mobile - Android Chrome
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
            # Mobile - Samsung Internet
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/22.0 Chrome/111.0.0.0 Mobile Safari/537.36",
            # Tablets
            "Mozilla/5.0 (Linux; Android 13; Pixel Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Bots (less suspicious for some sites)
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            "Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)",
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            # Additional Desktop Browsers
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Opera
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
            # Brave
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/119",
            # Vivaldi
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.50",
            # Legacy browsers (some sites trust older versions more)
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        self.target = target
        # Ensure target has protocol for web requests
        if not target.startswith("http"):
            self.url = "http://" + target
        else:
            self.url = target
        
        # Hostname for network tools
        parsed = urlparse(self.url)
        self.hostname = parsed.netloc.split(":")[0]
        if not self.hostname:
            self.hostname = target.split("/")[0]

    def _get_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _sleep_random(self):
        time.sleep(random.uniform(0.3, 1.0))
    
    def _make_request_with_retry(self, method='GET', url='', max_retries=3, **kwargs):
        """
        Makes HTTP request with exponential backoff retry logic.
        Handles timeouts and connection errors gracefully.
        
        Args:
            method: HTTP method ('GET' or 'HEAD')
            url: Target URL
            max_retries: Maximum number of retry attempts (default: 3)
            **kwargs: Additional arguments passed to requests (headers, timeout, verify, etc.)
        
        Returns:
            Response object if successful
        
        Raises:
            Exception after all retries exhausted
        """
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, **kwargs)
                elif method.upper() == 'HEAD':
                    response = requests.head(url, **kwargs)
                elif method.upper() == 'POST':
                    response = requests.post(url, **kwargs)
                else:
                    raise ValueError("Unsupported HTTP method: {}".format(method))
                
                return response
                
            except (requests.exceptions.Timeout, 
                    requests.exceptions.ConnectionError, 
                    requests.exceptions.RequestException) as e:
                
                if attempt < max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s
                    wait_time = 2 ** attempt
                    print("Request failed (attempt {}/{}): {}".format(attempt + 1, max_retries, e))
                    print("Retrying in {} seconds...".format(wait_time))
                    time.sleep(wait_time)
                else:
                    # Last attempt failed, raise the exception
                    print("All {} attempts failed for {}".format(max_retries, url))
                    raise

    def run_tool(self, tool_id):
        method_name = f"tool_{tool_id}"
        if hasattr(self, method_name):
            return getattr(self, method_name)()
        return {"error": "Tool not implemented"}

    # 1. Port Scanner (Enhanced)
    def tool_1(self):
        open_ports = []
        # Top 20 common ports for speed + critical ones
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        
        def scan(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                self._sleep_random()
                result = sock.connect_ex((self.hostname, port))
                if result == 0:
                    service = "unknown"
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass
                    
                    # Banner Grabbing
                    banner = "No banner"
                    try:
                        sock.send(f'HEAD / HTTP/1.1\r\nHost: {self.hostname}\r\n\r\n'.encode())
                        banner = sock.recv(1024).decode(errors='ignore').strip()[:50]
                    except:
                        pass

                    open_ports.append({"port": port, "service": service, "banner": banner})
                sock.close()
            except:
                pass

        threads = []
        for port in ports:
            t = threading.Thread(target=scan, args=(port,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
            
        return {"open_ports": sorted(open_ports, key=lambda x: x['port'])}

    # 2. Whois Lookup (Enhanced)
    def tool_2(self):
        try:
            w = whois.whois(self.hostname)
            result = {}
            # Clean up and standardize keys
            keys = ['registrar', 'creation_date', 'expiration_date', 'emails', 'org', 'country']
            for k in keys:
                val = w.get(k)
                if isinstance(val, list):
                    result[k] = str(val[0])
                else:
                    result[k] = str(val)
            return result
        except Exception as e:
            return {"error": f"Whois lookup failed: {str(e)}"}

    # 3. DNS Enumerator (Enhanced)
    def tool_3(self):
        records = {}
        for rtype in ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
            try:
                answers = dns.resolver.resolve(self.hostname, rtype)
                records[rtype] = [str(r) for r in answers]
            except:
                pass
        return records

    # 4. Subdomain Finder (Gobuster-based with Python fallback)
    def tool_4(self):
        import subprocess
        import tempfile
        
        # Try to use gobuster first (professional tool)
        gobuster_available = False
        try:
            result = subprocess.run(['gobuster', 'version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                gobuster_available = True
                print("Gobuster detected - using professional DNS enumeration")
        except:
            print("Gobuster not found - using Python implementation")
        
        if gobuster_available:
            return self._gobuster_scan()
        else:
            return self._python_subdomain_scan()
    
    def _gobuster_scan(self):
        """Use gobuster for professional subdomain enumeration"""
        import subprocess
        import tempfile
        
        # Create temporary file for results
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'common.txt')
            temp_output = f.name
        
        try:
            # Run gobuster dns mode
            cmd = [
                'gobuster', 'dns',
                '-d', self.hostname,
                '-w', wordlist_path,
                '-o', temp_output,
                '-t', '100',  # 100 threads
                '--timeout', '2s',
                '--no-error',
                '-q'  # Quiet mode
            ]
            
            print(f"Running: gobuster dns -d {self.hostname} -w {wordlist_path} -t 100")
            
            # Run gobuster with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            # Parse gobuster output
            subdomains = []
            try:
                with open(temp_output, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('['):
                            # Gobuster format: "Found: subdomain.domain.com"
                            if 'Found:' in line:
                                subdomain = line.split('Found:')[1].strip()
                                subdomains.append(subdomain)
            except:
                pass
            
            # Clean up temp file
            try:
                os.unlink(temp_output)
            except:
                pass
            
            # If gobuster found subdomains, verify them with HTTP
            if subdomains:
                print(f"Gobuster found {len(subdomains)} subdomains, verifying HTTP status...")
                return self._verify_subdomains_http(subdomains)
            else:
                print("Gobuster found no subdomains")
                return {
                    "subdomains": [],
                    "total_found": 0,
                    "total_checked": 0,
                    "active_count": 0,
                    "method": "gobuster"
                }
                
        except subprocess.TimeoutExpired:
            print("Gobuster timeout - falling back to Python")
            return self._python_subdomain_scan()
        except Exception as e:
            print(f"Gobuster error: {e} - falling back to Python")
            return self._python_subdomain_scan()
    
    def _python_subdomain_scan(self):
        """Fallback Python implementation with DNS + HTTP verification"""
        subdomains = set()
        
        # Method 1: Certificate Transparency (crt.sh)
        try:
            url = f"https://crt.sh/?q=%.{self.hostname}&output=json"
            res = self._make_request_with_retry('GET', url, headers=self._get_headers(), timeout=10)
            if res.status_code == 200:
                data = res.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if "\n" in name:
                        subdomains.update(name.split("\n"))
                    else:
                        subdomains.add(name)
        except:
            pass
        
        # Method 2: Load wordlist from common.txt
        wordlist_path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'common.txt')
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        subdomains.add(f"{subdomain}.{self.hostname}")
        except Exception as e:
            print(f"Warning: Could not load wordlist: {e}")
            fallback_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog']
            for sub in fallback_subs:
                subdomains.add(f"{sub}.{self.hostname}")
        
        # Method 3: Pattern-based generation
        patterns = ['dev', 'test', 'staging', 'prod', 'uat', 'qa', 'demo']
        numbers = ['1', '2', '3']
        for pattern in patterns:
            for num in numbers:
                subdomains.add(f"{pattern}{num}.{self.hostname}")
                subdomains.add(f"{pattern}-{num}.{self.hostname}")
        
        # Clean up wildcards
        cleaned = set()
        for sub in subdomains:
            sub = sub.strip().lower()
            if sub and not sub.startswith('*') and '.' in sub:
                if not sub.startswith('*.'):
                    cleaned.add(sub)
        
        print(f"Python scan: checking {len(cleaned)} subdomains...")
        
        # Two-phase verification
        dns_resolved = []
        
        def check_dns_only(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                return {"subdomain": subdomain, "ip": ip}
            except:
                return None
        
        # Phase 1: Fast DNS check
        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(check_dns_only, sub): sub for sub in cleaned}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    dns_resolved.append(result)
        
        print(f"Python scan: {len(dns_resolved)} subdomains resolved")
        
        # Phase 2: HTTP verification
        return self._verify_subdomains_http([item['subdomain'] for item in dns_resolved], 
                                           dns_info={item['subdomain']: item['ip'] for item in dns_resolved})
    
    def _verify_subdomains_http(self, subdomain_list, dns_info=None):
        """Verify subdomains with HTTP requests and return formatted results"""
        verified = []
        
        def check_http(subdomain):
            # Get IP if available
            ip = dns_info.get(subdomain) if dns_info else None
            if not ip:
                try:
                    ip = socket.gethostbyname(subdomain)
                except:
                    return None
            
            http_status = None
            protocol_used = None
            
            for protocol in ['https://', 'http://']:
                try:
                    url = f"{protocol}{subdomain}"
                    self._sleep_random()
                    resp = self._make_request_with_retry('HEAD', url, headers=self._get_headers(), timeout=1.5, allow_redirects=True, verify=False)
                    http_status = resp.status_code
                    protocol_used = protocol.replace('://', '').upper()
                    break
                except:
                    continue
            
            if http_status:
                return {
                    "subdomain": subdomain,
                    "status": f"{protocol_used} {http_status}",
                    "verified": True,
                    "http_status": http_status,
                    "ip": ip
                }
            else:
                return {
                    "subdomain": subdomain,
                    "status": f"DNS Only (IP: {ip})",
                    "verified": True,
                    "http_status": 0,
                    "ip": ip
                }
        
        # HTTP check with threading
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_http, sub): sub for sub in subdomain_list}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    verified.append(result)
        
        # Sort by HTTP status
        verified.sort(key=lambda x: (x.get('http_status', 999), x['subdomain']))
        
        return {
            "subdomains": verified,
            "total_found": len(subdomain_list),
            "total_checked": len(subdomain_list),
            "active_count": len(verified),
            "method": "python"
        }

    # 6. SSL/TLS Validator (Enhanced)
    def tool_6(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
                s.settimeout(3)
                s.connect((self.hostname, 443))
                cert = s.getpeercert()
                
                # Check validity
                not_after = cert['notAfter']
                # Simple check (parsing date properly requires datetime, keeping it simple str for now)
                
                return {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject']),
                    "version": cert['version'],
                    "expires": not_after,
                    "serial": cert.get('serialNumber', 'Unknown')
                }
        except Exception as e:
            return {"error": f"SSL Handshake Failed: {str(e)}"}

    # 7. HTTP Header Analyzer (Enhanced)
    def tool_7(self):
        try:
            res = self._make_request_with_retry('HEAD', self.url, headers=self._get_headers(), timeout=3, verify=False, allow_redirects=True)
            headers = res.headers
            security_headers = {
                "X-Frame-Options": "Prevents Clickjacking",
                "X-XSS-Protection": "Prevents Reflected XSS",
                "Content-Security-Policy": "Mitigates XSS/Injection",
                "Strict-Transport-Security": "Enforces HTTPS",
                "X-Content-Type-Options": "Prevents MIME Sniffing",
                "Referrer-Policy": "Controls Referrer Info"
            }
            
            analysis = []
            for h, desc in security_headers.items():
                if h in headers:
                    analysis.append({"header": h, "status": "Present", "value": headers[h], "risk": "Low"})
                else:
                    analysis.append({"header": h, "status": "Missing", "value": "-", "risk": "Medium"})
            return {"headers": analysis}
        except Exception as e:
            return {"error": str(e)}

    # 8. Robots.txt Analyzer (Enhanced)
    def tool_8(self):
        try:
            res = self._make_request_with_retry('GET', urljoin(self.url, "robots.txt"), headers=self._get_headers(), timeout=3, verify=False)
            if res.status_code == 200:
                lines = res.text.splitlines()
                entries = []
                for line in lines:
                    if line.strip() and not line.startswith("#"):
                        entries.append(line.strip())
                return {"found": True, "entries": entries[:20]} # Limit to 20
            return {"found": False, "entries": []}
        except:
            return {"error": "Failed to fetch"}

    # 9. Social Media Finder (Find all social media profiles)
    def tool_9(self):
        """
        Finds all social media profiles associated with the website.
        Searches for: Telegram, Instagram, VK, Facebook, Twitter, YouTube, LinkedIn, TikTok, etc.
        """
        social_media = {
            "telegram": [],
            "instagram": [],
            "vk": [],
            "facebook": [],
            "twitter": [],
            "youtube": [],
            "linkedin": [],
            "tiktok": [],
            "github": [],
            "whatsapp": [],
            "other": []
        }
        
        # Social media patterns
        patterns = {
            "telegram": [
                r't\.me/([a-zA-Z0-9_]+)',
                r'telegram\.me/([a-zA-Z0-9_]+)',
                r'telegram\.org/([a-zA-Z0-9_]+)'
            ],
            "instagram": [
                r'instagram\.com/([a-zA-Z0-9_.]+)',
                r'instagr\.am/([a-zA-Z0-9_.]+)'
            ],
            "vk": [
                r'vk\.com/([a-zA-Z0-9_]+)',
                r'vkontakte\.ru/([a-zA-Z0-9_]+)'
            ],
            "facebook": [
                r'facebook\.com/([a-zA-Z0-9.]+)',
                r'fb\.com/([a-zA-Z0-9.]+)',
                r'fb\.me/([a-zA-Z0-9.]+)'
            ],
            "twitter": [
                r'twitter\.com/([a-zA-Z0-9_]+)',
                r'x\.com/([a-zA-Z0-9_]+)'
            ],
            "youtube": [
                r'youtube\.com/(?:c/|channel/|user/|@)?([a-zA-Z0-9_-]+)',
                r'youtu\.be/([a-zA-Z0-9_-]+)'
            ],
            "linkedin": [
                r'linkedin\.com/(?:company|in)/([a-zA-Z0-9-]+)'
            ],
            "tiktok": [
                r'tiktok\.com/@([a-zA-Z0-9_.]+)'
            ],
            "github": [
                r'github\.com/([a-zA-Z0-9_-]+)'
            ],
            "whatsapp": [
                r'wa\.me/([0-9]+)',
                r'whatsapp\.com/([0-9]+)',
                r'chat\.whatsapp\.com/([a-zA-Z0-9]+)'
            ]
        }
        
        try:
            # Fetch page content with longer timeout
            res = self._make_request_with_retry('GET', self.url, headers=self._get_headers(), timeout=10, verify=False)
            html = res.text
            
            # Parse HTML
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract all links
            links = []
            for a in soup.find_all('a', href=True):
                links.append(a['href'])
            
            # Also search in meta tags
            for meta in soup.find_all('meta'):
                content = meta.get('content', '')
                if content:
                    links.append(content)
            
            # Search in script tags and text
            text_content = soup.get_text()
            links.append(text_content)
            
            # Search for social media profiles
            all_text = ' '.join(links)
            
            for platform, pattern_list in patterns.items():
                found_profiles = set()
                for pattern in pattern_list:
                    matches = re.findall(pattern, all_text, re.IGNORECASE)
                    for match in matches:
                        # Clean up the match
                        match = match.strip('/').strip()
                        if match and len(match) > 1:
                            # Build full URL
                            if platform == "telegram":
                                url = f"https://t.me/{match}"
                            elif platform == "instagram":
                                url = f"https://instagram.com/{match}"
                            elif platform == "vk":
                                url = f"https://vk.com/{match}"
                            elif platform == "facebook":
                                url = f"https://facebook.com/{match}"
                            elif platform == "twitter":
                                url = f"https://twitter.com/{match}"
                            elif platform == "youtube":
                                url = f"https://youtube.com/@{match}"
                            elif platform == "linkedin":
                                url = f"https://linkedin.com/company/{match}"
                            elif platform == "tiktok":
                                url = f"https://tiktok.com/@{match}"
                            elif platform == "github":
                                url = f"https://github.com/{match}"
                            elif platform == "whatsapp":
                                url = f"https://wa.me/{match}"
                            else:
                                url = match
                            
                            found_profiles.add(url)
                
                if found_profiles:
                    social_media[platform] = sorted(list(found_profiles))[:5]  # Top 5 per platform
            
            # Count total
            total_found = sum(len(profiles) for profiles in social_media.values())
            
            return {
                "social_media": social_media,
                "total_found": total_found
            }
            
        except Exception as e:
            return {"error": str(e), "social_media": social_media, "total_found": 0}

    # 10. Directory Buster (Enhanced)
    def tool_10(self):
        paths = ['admin', 'login', 'dashboard', 'api', 'uploads', 'images', 'css', 'js', 'backup', 'config', 'test']
        found = []
        for p in paths:
            try:
                u = urljoin(self.url, p)
                self._sleep_random()
                res = self._make_request_with_retry('HEAD', u, headers=self._get_headers(), timeout=1, verify=False)
                if res.status_code != 404:
                    found.append({"path": p, "status": res.status_code, "url": u})
            except:
                pass
        return {"directories": found}

    # 11. Backup File Finder (Enhanced)
    def tool_11(self):
        files = ['index.php', 'config.php', 'wp-config.php', '.env', 'database.sql', 'backup.zip']
        extensions = ['.bak', '.old', '.save', '.swp']
        found = []
        
        # Check specific files first
        for f in files:
            for ext in extensions:
                target = f + ext
                try:
                    u = urljoin(self.url, target)
                    self._sleep_random()
                    res = self._make_request_with_retry('HEAD', u, headers=self._get_headers(), timeout=1, verify=False)
                    if res.status_code == 200:
                        found.append({"file": target, "url": u, "size": res.headers.get('Content-Length', 'Unknown')})
                except:
                    pass
        return {"backups": found}

    # 12. Clickjacking Tester (Check for clickjacking protection)
    def tool_12(self):
        """
        Tests for clickjacking vulnerabilities by checking security headers.
        Checks: X-Frame-Options, Content-Security-Policy (frame-ancestors)
        """
        vulnerable = False
        risk_level = "Safe"
        issues = []
        headers_found = {}
        
        try:
            res = self._make_request_with_retry('GET', self.url, headers=self._get_headers(), timeout=5, verify=False)
            
            # Check for X-Frame-Options header
            x_frame_options = res.headers.get('X-Frame-Options', '').upper()
            
            # Check for Content-Security-Policy with frame-ancestors
            csp = res.headers.get('Content-Security-Policy', '')
            frame_ancestors = None
            if 'frame-ancestors' in csp.lower():
                for directive in csp.split(';'):
                    if 'frame-ancestors' in directive.lower():
                        frame_ancestors = directive.strip()
                        break
            
            # Store found headers
            if x_frame_options:
                headers_found['X-Frame-Options'] = x_frame_options
            if frame_ancestors:
                headers_found['CSP frame-ancestors'] = frame_ancestors
            
            # Analyze X-Frame-Options
            if not x_frame_options and not frame_ancestors:
                vulnerable = True
                risk_level = "HIGH"
                issues.append({
                    "type": "Missing Protection",
                    "severity": "HIGH",
                    "description": "No X-Frame-Options or CSP frame-ancestors header found",
                    "impact": "Page can be embedded in iframe on any domain, allowing clickjacking attacks",
                    "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'"
                })
            elif x_frame_options:
                if x_frame_options == 'ALLOW-FROM':
                    vulnerable = True
                    risk_level = "MEDIUM"
                    issues.append({
                        "type": "Deprecated Header Value",
                        "severity": "MEDIUM",
                        "description": "X-Frame-Options: ALLOW-FROM is deprecated",
                        "impact": "Protection may not work in modern browsers",
                        "recommendation": "Use CSP frame-ancestors instead"
                    })
                elif x_frame_options not in ['DENY', 'SAMEORIGIN']:
                    vulnerable = True
                    risk_level = "MEDIUM"
                    issues.append({
                        "type": "Invalid Header Value",
                        "severity": "MEDIUM",
                        "description": f"Invalid X-Frame-Options value: {x_frame_options}",
                        "impact": "Protection may not be enforced",
                        "recommendation": "Use 'DENY' or 'SAMEORIGIN'"
                    })
            
            # Analyze CSP frame-ancestors
            if frame_ancestors:
                if "'none'" not in frame_ancestors.lower() and "'self'" not in frame_ancestors.lower():
                    if '*' in frame_ancestors:
                        vulnerable = True
                        risk_level = "HIGH"
                        issues.append({
                            "type": "Permissive CSP",
                            "severity": "HIGH",
                            "description": "CSP frame-ancestors allows all origins (*)",
                            "impact": "Page can be embedded anywhere",
                            "recommendation": "Use 'frame-ancestors 'none'' or 'frame-ancestors 'self''"
                        })
            
            # Determine final status
            if not vulnerable:
                description = "Site is protected against clickjacking attacks."
            else:
                description = f"Found {len(issues)} clickjacking vulnerability/vulnerabilities."
            
            return {
                "vulnerable": vulnerable,
                "risk_level": risk_level,
                "issues": issues,
                "headers_found": headers_found,
                "description": description,
                "total_issues": len(issues)
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "vulnerable": False,
                "risk_level": "Unknown",
                "issues": [],
                "headers_found": {},
                "description": "Failed to test clickjacking protection",
                "total_issues": 0
            }

    # 13. Git Exposure Scanner (Check for exposed .git directory + GitHub users)
    def tool_13(self):
        """
        Checks if .git directory is exposed and accessible.
        Searches for GitHub users/repos associated with the domain.
        This is a critical security vulnerability that can expose source code and developers.
        """
        results = {
            "exposed": False,
            "accessible_files": [],
            "github_users": [],
            "github_repos": [],
            "emails": [],
            "risk_level": "Safe",
            "description": ""
        }
        
        # Common .git files to check
        git_files = [
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.git/logs/HEAD',
            '.git/refs/heads/master',
            '.git/refs/heads/main',
            '.git/description',
            '.git/COMMIT_EDITMSG',
            '.git/packed-refs'
        ]
        
        accessible = []
        github_users = set()
        github_repos = set()
        emails = set()
        
        # Check each .git file
        for git_file in git_files:
            try:
                url = urljoin(self.url, git_file)
                self._sleep_random()
                res = self._make_request_with_retry('GET', url, headers=self._get_headers(), timeout=3, verify=False)
                
                if res.status_code == 200 and len(res.content) > 0:
                    content = res.text
                    
                    # Verify it's actually a git file
                    is_critical = False
                    
                    if git_file.endswith('HEAD') and 'ref:' in content:
                        is_critical = True
                    elif git_file.endswith('config') and '[core]' in content:
                        is_critical = True
                        # Extract GitHub URLs from config
                        github_urls = re.findall(r'github\.com[:/]([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+)', content)
                        for user, repo in github_urls:
                            github_users.add(user)
                            github_repos.add(f"{user}/{repo}")
                    elif git_file.endswith('logs/HEAD'):
                        # Extract commit info from logs
                        log_entries = re.findall(r'<([^>]+)>', content)
                        for email in log_entries:
                            if '@' in email:
                                emails.add(email)
                                if 'github' in email.lower():
                                    username = email.split('@')[0]
                                    github_users.add(username)
                    
                    # Extract emails from any git file
                    found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                    for email in found_emails:
                        if not email.endswith(('.png', '.jpg', '.css', '.js')):
                            emails.add(email)
                    
                    accessible.append({
                        "file": git_file,
                        "status": res.status_code,
                        "size": len(res.content),
                        "url": url,
                        "critical": is_critical
                    })
            except:
                pass
        
        # Try to fetch additional commit info if logs are accessible
        if any(f['file'] == '.git/logs/HEAD' for f in accessible):
            try:
                for branch in ['master', 'main', 'develop']:
                    log_url = urljoin(self.url, f'.git/logs/refs/heads/{branch}')
                    self._sleep_random()
                    res = self._make_request_with_retry('GET', log_url, headers=self._get_headers(), timeout=3, verify=False)
                    if res.status_code == 200:
                        authors = re.findall(r'([a-zA-Z0-9._-]+)\s+<([^>]+)>', res.text)
                        for name, email in authors:
                            emails.add(email)
                            if 'github' in email.lower():
                                username = email.split('@')[0]
                                github_users.add(username)
            except:
                pass
        
        # ALWAYS search GitHub for repos/users related to domain (even if .git not exposed)
        domain_name = self.hostname.replace('www.', '').split('.')[0]  # Extract main domain name
        
        try:
            # Search GitHub for repositories matching domain
            search_url = f"https://api.github.com/search/repositories?q={domain_name}+in:name,description&sort=stars&per_page=10"
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            res = self._make_request_with_retry('GET', search_url, headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json()
                for repo in data.get('items', [])[:10]:  # Top 10 results
                    owner = repo.get('owner', {}).get('login')
                    repo_name = repo.get('name')
                    if owner and repo_name:
                        github_users.add(owner)
                        github_repos.add(f"{owner}/{repo_name}")
        except:
            pass
        
        # Also search for users with domain name
        try:
            user_search_url = f"https://api.github.com/search/users?q={domain_name}+in:login&per_page=10"
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            res = self._make_request_with_retry('GET', user_search_url, headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json()
                for user in data.get('items', [])[:10]:
                    username = user.get('login')
                    if username:
                        github_users.add(username)
        except:
            pass
        
        # Determine risk level
        if accessible:
            results["exposed"] = True
            results["accessible_files"] = accessible
            
            critical_count = sum(1 for f in accessible if f.get("critical", False))
            
            if critical_count >= 2:
                results["risk_level"] = "CRITICAL"
                desc = f"Found {len(accessible)} accessible .git files including {critical_count} critical files. Full repository may be downloadable!"
            elif critical_count == 1:
                results["risk_level"] = "HIGH"
                desc = f"Found {len(accessible)} accessible .git files. Repository structure is exposed!"
            else:
                results["risk_level"] = "MEDIUM"
                desc = f"Found {len(accessible)} accessible .git files. Partial exposure detected."
            
            if github_users:
                desc += f" Discovered {len(github_users)} GitHub user(s)."
            results["description"] = desc
        else:
            results["description"] = "No exposed .git directory detected. Server is secure."
            if github_users:
                results["description"] += f" Found {len(github_users)} related GitHub user(s) via search."
        
        results["github_users"] = sorted(list(github_users))
        results["github_repos"] = sorted(list(github_repos))
        results["emails"] = sorted(list(emails))
        
        return results

    # 14. CORS Tester (Check for CORS misconfigurations)
    def tool_14(self):
        """
        Tests for CORS (Cross-Origin Resource Sharing) misconfigurations.
        Checks for: wildcard origins, credential exposure, null origin bypass, etc.
        """
        vulnerabilities = []
        cors_headers = {}
        risk_level = "Safe"
        
        # Test origins to check
        test_origins = [
            "https://evil.com",
            "http://attacker.com",
            "null",
            self.url  # Reflected origin test
        ]
        
        try:
            # First, get baseline CORS headers
            res = self._make_request_with_retry('GET', self.url, headers=self._get_headers(), timeout=5, verify=False)
            
            # Check for CORS headers in response
            for header in res.headers:
                if header.lower().startswith('access-control'):
                    cors_headers[header] = res.headers[header]
            
            # Test 1: Check for wildcard origin (*)
            if cors_headers.get('Access-Control-Allow-Origin') == '*':
                vuln = {
                    "type": "Wildcard Origin",
                    "severity": "HIGH",
                    "description": "Server allows requests from ANY origin (*)",
                    "header": "Access-Control-Allow-Origin: *",
                    "impact": "Any website can read responses from this API"
                }
                
                # Check if credentials are also allowed (CRITICAL)
                if cors_headers.get('Access-Control-Allow-Credentials', '').lower() == 'true':
                    vuln["severity"] = "CRITICAL"
                    vuln["description"] = "Wildcard origin WITH credentials enabled!"
                    vuln["impact"] = "Any website can steal user data including cookies"
                
                vulnerabilities.append(vuln)
                risk_level = vuln["severity"]
            
            # Test 2: Check for reflected origin vulnerability
            for origin in test_origins:
                try:
                    headers = {'Origin': origin}
                    headers.update(self._get_headers())
                    res = self._make_request_with_retry('GET', self.url, headers=headers, timeout=5, verify=False)
                    
                    allowed_origin = res.headers.get('Access-Control-Allow-Origin', '')
                    allow_credentials = res.headers.get('Access-Control-Allow-Credentials', '').lower()
                    
                    # Check if origin is reflected
                    if allowed_origin == origin and origin != self.url:
                        vuln = {
                            "type": "Reflected Origin",
                            "severity": "MEDIUM",
                            "description": f"Server reflects origin: {origin}",
                            "header": f"Access-Control-Allow-Origin: {origin}",
                            "impact": "Attacker can bypass CORS by setting their origin"
                        }
                        
                        # If credentials are allowed, it's CRITICAL
                        if allow_credentials == 'true':
                            vuln["severity"] = "CRITICAL"
                            vuln["description"] = f"Reflected origin WITH credentials: {origin}"
                            vuln["impact"] = "Attacker can steal user data from their domain"
                        
                        vulnerabilities.append(vuln)
                        if vuln["severity"] == "CRITICAL":
                            risk_level = "CRITICAL"
                        elif risk_level != "CRITICAL" and vuln["severity"] == "HIGH":
                            risk_level = "HIGH"
                        elif risk_level == "Safe":
                            risk_level = "MEDIUM"
                        
                        break  # Found vulnerability, no need to test more
                    
                    # Test 3: Null origin bypass
                    if origin == "null" and allowed_origin == "null":
                        vuln = {
                            "type": "Null Origin Bypass",
                            "severity": "HIGH",
                            "description": "Server allows 'null' origin",
                            "header": "Access-Control-Allow-Origin: null",
                            "impact": "Attacker can use sandboxed iframe to bypass CORS"
                        }
                        
                        if allow_credentials == 'true':
                            vuln["severity"] = "CRITICAL"
                        
                        vulnerabilities.append(vuln)
                        if vuln["severity"] == "CRITICAL":
                            risk_level = "CRITICAL"
                        elif risk_level != "CRITICAL":
                            risk_level = "HIGH"
                        
                        break
                        
                except:
                    continue
            
            # Test 4: Check for overly permissive methods
            if 'Access-Control-Allow-Methods' in cors_headers:
                methods = cors_headers['Access-Control-Allow-Methods']
                dangerous_methods = ['DELETE', 'PUT', 'PATCH']
                found_dangerous = [m for m in dangerous_methods if m in methods.upper()]
                
                if found_dangerous and len(vulnerabilities) > 0:
                    vulnerabilities[0]["dangerous_methods"] = found_dangerous
            
            # Determine final risk level
            if not vulnerabilities:
                description = "No CORS misconfigurations detected. Server has secure CORS policy."
            else:
                description = f"Found {len(vulnerabilities)} CORS misconfiguration(s). "
                if risk_level == "CRITICAL":
                    description += "CRITICAL: Credentials can be stolen!"
                elif risk_level == "HIGH":
                    description += "HIGH: Significant security risk."
                else:
                    description += "MEDIUM: Potential security issue."
            
            return {
                "vulnerabilities": vulnerabilities,
                "cors_headers": cors_headers,
                "risk_level": risk_level,
                "description": description,
                "total_found": len(vulnerabilities)
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "vulnerabilities": [],
                "cors_headers": {},
                "risk_level": "Unknown",
                "description": "Failed to test CORS configuration",
                "total_found": 0
            }

    # 15. Open Redirect Scanner (Enhanced)
    def tool_15(self):
        payload = "http://google.com"
        params = ["url", "next", "redirect", "target", "dest"]
        vulns = []
        
        base = self.url.split("?")[0]
        for p in params:
            try:
                target = f"{base}?{p}={payload}"
                self._sleep_random()
                res = self._make_request_with_retry('GET', target, headers=self._get_headers(), allow_redirects=False, timeout=3, verify=False)
                if res.status_code in [301, 302] and "google.com" in res.headers.get('Location', ''):
                    vulns.append({"param": p, "url": target})
            except:
                pass
        
        return {"vulnerabilities": vulns}
    def tool_16(self):
        """
        Tests for directory traversal vulnerabilities.
        Attempts to access sensitive files using various traversal payloads.
        """
        payloads = [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "..\\windows\\win.ini",
            "..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e/%2e%2e/etc/passwd",
            "%2e%2e\\%2e%2e\\windows\\win.ini",
            "/etc/passwd",
            "/windows/win.ini"
        ]
        
        vulnerable_urls = []
        risk_level = "Safe"
        
        # Determine targets to test
        targets_to_test = []
        
        # 1. Test URL path
        parsed = urlparse(self.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if not base_url.endswith('/'):
            base_url += '/'
            
        for p in payloads:
            targets_to_test.append(urljoin(base_url, p))
            
        # 2. Test Query Parameters
        if parsed.query:
            params = parsed.query.split('&')
            for p in payloads:
                for i, param in enumerate(params):
                    if '=' in param:
                        key, val = param.split('=', 1)
                        # Inject payload
                        new_query = params.copy()
                        new_query[i] = f"{key}={p}"
                        targets_to_test.append(f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(new_query)}")

        # Deduplicate
        targets_to_test = list(set(targets_to_test))
        
        print(f"Testing {len(targets_to_test)} URLs for directory traversal...")
        
        for target in targets_to_test:
            try:
                self._sleep_random()
                res = self._make_request_with_retry('GET', target, headers=self._get_headers(), timeout=5, verify=False, allow_redirects=False)
                
                is_vulnerable = False
                snippet = ""
                
                # Check for /etc/passwd signatures
                if "root:x:0:0:" in res.text:
                    is_vulnerable = True
                    snippet = "Found root:x:0:0: in response"
                
                # Check for win.ini signatures
                elif "[extensions]" in res.text or "[fonts]" in res.text:
                    is_vulnerable = True
                    snippet = "Found [extensions] or [fonts] in response"
                    
                if is_vulnerable:
                    vulnerable_urls.append({
                        "url": target,
                        "status": res.status_code,
                        "snippet": snippet
                    })
            except:
                pass
                
        if vulnerable_urls:
            risk_level = "HIGH"
            
        return {
            "vulnerable_urls": vulnerable_urls,
            "total_found": len(vulnerable_urls),
            "risk_level": risk_level,
            "description": f"Found {len(vulnerable_urls)} potential directory traversal vulnerabilities." if vulnerable_urls else "No directory traversal vulnerabilities found."
        }
