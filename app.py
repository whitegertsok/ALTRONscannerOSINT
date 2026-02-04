from flask import Flask, render_template, request, jsonify
from scanners.tools import SecurityTools, TOOLS
import threading
import time
import re
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)

# Rate limiting storage
request_log = {}
tool_results = {}  # Format: {scan_id: {"status": ..., "timestamp": ..., "result": ...}}
RATE_LIMIT = 20  # requests per second
BLOCK_TIME = 60  # seconds
RESULT_RETENTION_TIME = 3600  # Keep results for 1 hour (3600 seconds)

@app.before_request
def check_rate_limit():
    # Skip for static files
    if request.path.startswith('/static'):
        return
    ip = request.remote_addr
    now = time.time()
    if ip not in request_log:
        request_log[ip] = []
    # Clean old requests (window of 1 second)
    request_log[ip] = [t for t in request_log[ip] if now - t < 1.0]
    # Check limit
    if len(request_log[ip]) >= RATE_LIMIT:
        return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429
    request_log[ip].append(now)

@app.after_request
def add_security_headers(response):
    # Security Headers
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: https://fonts.googleapis.com https://fonts.gstatic.com;"
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Disable cache for HTML/CSS/JS to avoid showing old versions
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/tools', methods=['GET'])
def get_tools():
    return jsonify(TOOLS)

def validate_target(target):
    """Validate target URL/domain/IP with SSRF and injection protection"""
    if not target or not isinstance(target, str):
        return False, "Invalid target"
    target = target.strip()
    
    # Length check
    if len(target) > 500:
        return False, "Target too long"
    
    # Enhanced HTML/XSS injection patterns
    injection_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)',
        r'(--|/\*|\*/|;|xp_|sp_)',
        r"('|')",
        r'(OR|AND)\s+[\d\']',
        r'<script[\s\S]*?>',
        r'</script>',
        r'<iframe[\s\S]*?>',
        r'</iframe>',
        r'<embed[\s\S]*?>',
        r'<object[\s\S]*?>',
        r'javascript:',
        r'vbscript:',
        r'data:text/html',
        r'on(load|error|click|mouse|focus|blur|change|submit)=',
        r'<img[\s\S]*?>',
        r'<svg[\s\S]*?>',
        r'eval\s*\(',
        r'alert\s*\(',
        r'prompt\s*\(',
        r'confirm\s*\(',
        r'document\s*\.',
        r'window\s*\.',
        r'<\?php',
        r'<%',
        r'\{\{',
        r'\{%'
    ]
    for pattern in injection_patterns:
        if re.search(pattern, target, re.IGNORECASE):
            return False, "Dude, are you serious? papahapahpah"
    
    # Extract hostname for IP validation
    hostname_to_check = None
    
    # Domain and IP regexes
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    
    # URL with scheme
    if target.startswith('http://') or target.startswith('https://'):
        try:
            parsed = urlparse(target)
            if not parsed.hostname or len(parsed.hostname) < 3:
                return False, "Invalid hostname"
            hostname_to_check = parsed.hostname
        except Exception:
            return False, "Invalid URL format"
    # Plain domain or IP
    elif re.match(domain_pattern, target) or re.match(ip_pattern, target):
        hostname_to_check = target
    else:
        return False, "Invalid format (use: example.com or http://example.com - public domains only)"
    
    # SSRF Protection: Block localhost and private IP ranges
    if hostname_to_check:
        # Block localhost variations
        localhost_patterns = [
            'localhost',
            '127.', # Covers 127.0.0.1, 127.0.0.2, etc.
            '::1', # IPv6 localhost
            '0.0.0.0'
        ]
        
        hostname_lower = hostname_to_check.lower()
        for pattern in localhost_patterns:
            if pattern in hostname_lower:
                return False, "Scanning localhost/loopback addresses is not allowed"
        
        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(hostname_to_check)
            
            # Block private IP ranges
            if ip.is_private:
                return False, f"Scanning private IP addresses ({hostname_to_check}) is not allowed"
            
            # Block loopback
            if ip.is_loopback:
                return False, "Scanning loopback addresses is not allowed"
            
            # Block link-local (169.254.0.0/16)
            if ip.is_link_local:
                return False, "Scanning link-local addresses is not allowed"
            
            # Block multicast
            if ip.is_multicast:
                return False, "Scanning multicast addresses is not allowed"
            
            # Block reserved ranges
            if ip.is_reserved:
                return False, "Scanning reserved IP addresses is not allowed"
                
        except ValueError:
            # Not an IP address, it's a domain - that's fine
            pass
    
    # Return validated target
    return True, target

@app.route('/api/run/<int:tool_id>', methods=['POST'])
def run_tool(tool_id):
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        target = request.json.get('target')
        # Validate target
        is_valid, message = validate_target(target)
        if not is_valid:
            return jsonify({"error": message}), 400
        # Use validated target
        target = message
        scan_id = f"{tool_id}_{int(time.time())}"
        tool_results[scan_id] = {
            "status": "running", 
            "tool_id": tool_id,
            "timestamp": time.time()  # Store creation time for cleanup
        }
        thread = threading.Thread(target=execute_tool, args=(target, tool_id, scan_id))
        thread.start()
        return jsonify({"scan_id": scan_id})
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/api/status/<scan_id>', methods=['GET'])
def get_status(scan_id):
    return jsonify(tool_results.get(scan_id, {"error": "Not found"}))

def execute_tool(target, tool_id, scan_id):
    print(f"Starting tool {tool_id} for {target}")  # Debug
    try:
        scanner = SecurityTools(target)
        result = scanner.run_tool(tool_id)
        tool_results[scan_id]["status"] = "completed"
        tool_results[scan_id]["result"] = result
        print(f"Tool {tool_id} completed")  # Debug
    except Exception as e:
        print(f"Tool {tool_id} failed: {e}")  # Debug
        tool_results[scan_id]["status"] = "error"
        tool_results[scan_id]["error"] = str(e)

def cleanup_old_results():
    """
    Background task to clean up old scan results.
    Runs every 10 minutes and removes results older than 1 hour.
    Prevents memory leak from unlimited result storage.
    """
    while True:
        try:
            time.sleep(600)  # Run every 10 minutes
            current_time = time.time()
            expired_scans = []
            
            # Find expired results
            for scan_id, result_data in tool_results.items():
                timestamp = result_data.get('timestamp', 0)
                age = current_time - timestamp
                
                if age > RESULT_RETENTION_TIME:
                    expired_scans.append(scan_id)
            
            # Remove expired results
            for scan_id in expired_scans:
                del tool_results[scan_id]
            
            if expired_scans:
                print(f"[CLEANUP] Removed {len(expired_scans)} old scan results (older than 1 hour)")
            
        except Exception as e:
            print(f"[CLEANUP ERROR] {e}")

if __name__ == '__main__':
    # SECURITY: Debug disabled, bound to localhost only
    print("Starting ALTRON Security Suite...")
    print("Access at: http://127.0.0.1:4568")
    
    # Start background cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_old_results, daemon=True)
    cleanup_thread.start()
    print("[SECURITY] Auto-cleanup enabled: results expire after 1 hour")
    print("[SECURITY] SSRF protection enabled: localhost and private IPs blocked")
    
    app.run(port=4568, debug=False, host='0.0.0.0')
