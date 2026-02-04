### **ALTRON - Web OSINT Scanner app** ###
ALTRON is a professional set of security audit tools packed into a user-friendly web interface. It is designed for DevOps engineers, pentesters, and system administrators who need a quick and secure way to analyze their own or external resources. Built with Flask and Python, it combines multiple security scanning tools for rapid vulnerability assessment and WEB OSINT gathering. 

Powerful all-in-one security scanner to test your infrastructure.

# **🚀How install?** #
```
# 1. Installation
git clone https://github.com/whitegertsok/ALTRONscannerOSINT.git
cd ALTRONscannerOSINT
pip3 install -r requirements.txt
sudo apt install -y gobuster
# 2. Launch
python3 app.py
# 3. Open in browser
# http://localhost:4568
```
# **📈 Performance & Scalability** #
**Benchmarks:**

Port Scanning: 1000 ports in < 30 seconds

Subdomain Discovery: 5000+ subdomains per minute

Concurrent Scans: Support for 10+ simultaneous operations

Memory Usage: < 200MB under heavy load


**Scalability Features:**

Multi-threaded scanning architecture

Result caching for repeated queries

Background task processing

Configurable worker processes 



# **📊 Professional Deployment Options** #
```
# Install production server
pip3 install gunicorn

# Launch with 4 worker processes
gunicorn -w 4 -b 0.0.0.0:4568 app:app
```
**Docker Deployment**
```
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 4568
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:4568", "app:app"]
```
**Nginx Reverse Proxy Configuration**
```
server {
    listen 80;
    server_name scanner.yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:4568;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```
# **⚙Technology Stack** #

🔍 Network & Port Analysis
```
◻ Port Scanner - Detect open ports and services
◻ Server Info Check - Identify web server technologies
◻ HTTP Methods Check - Test available HTTP methods
◻ SSL/TLS Check - Analyze certificate security and configuration
```
🌐 Web Application Security
```
◻ Directory Scanner - Discover hidden directories and files
◻ Security Headers Analyzer - Check for missing security headers
◻ CORS Tester - Test Cross-Origin Resource Sharing configurations
◻ Clickjacking Test - Verify X-Frame-Options protection
◻ Robots.txt Check - Examine robots.txt for sensitive information
```
🕵️ OSINT & Information Gathering
```
◻ DNS Lookup - Comprehensive DNS record analysis
◻ SubDomain Scanner - Discover subdomains using multiple techniques
◻ Social Media OSINT - Gather publicly available social media information
◻ Git Exposure Check - Search for exposed .git directories
◻ Backup Files Check - Identify common backup file patterns
```
⚡ Advanced Security Testing
```
◻ Directory Traversal Tester - Check for path traversal vulnerabilities
◻ SSRF Protection - Built-in safeguards against server-side request forgery
◻ Rate Limiting - Protection against abuse and DoS attacks
◻ Auto-Cleanup System - Automatic result expiration after 1 hour
```
# **🛡️ Security Features** #

| Mechanism | Description | Protected Against |      
|-----------|--------|-------------|
|  **SSRF Prevention** | Blocks internal IP ranges and localhost scanning | `localhost`, `127.0.0.0/8`, `192.168.x.x`, `10.x.x.x`, `172.16.x.x` |
|  **Input Validation** | Sanitizes all user inputs against injection attacks | XSS, SQL Injection, Command Injection, HTML Injection |
|  **Rate Limiting** | Configurable request limits per IP (default: 20 req/sec) | DoS attacks, brute force attempts, API abuse |
|  **Security Headers** | Automatic injection of security headers in responses | Clickjacking, MIME sniffing, CSP violations |
|  **Session Management** | Secure result storage with automatic cleanup | Data leakage, session hijacking, memory overflow |



<div align="center" style="margin-top: 30px;">
⭐ Show Your Support 
If you find ALTRON useful, please consider giving it a star on GitHub ⭐
</div>
<div align="center" style="margin-top: 20px;">
Report issues - Help improve stability 
</div>

