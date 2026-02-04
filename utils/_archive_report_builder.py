def build_report(target, port_results, web_results):
    report = []
    
    # Header
    report.append(f"Security Scan Report for: {target}")
    report.append("=" * 50)
    report.append("")

    # Port Scan Section
    report.append("## Network Exposure (Port Scan)")
    if port_results:
        report.append(f"Found {len(port_results)} open ports.")
        for res in port_results:
            service_info = f"Port {res['port']} ({res['service']}) is OPEN"
            if res.get("http_status"):
                service_info += f" [HTTP Status: {res['http_status']}]"
            report.append(f"- {service_info}")
            
        # Recommendations based on ports
        open_ports = [r['port'] for r in port_results]
        if 21 in open_ports:
            report.append("  [!] Recommendation: FTP is insecure. Use SFTP or FTPS instead.")
        if 23 in open_ports:
            report.append("  [!] Recommendation: Telnet is insecure. Use SSH (Port 22).")
        if 3389 in open_ports:
            report.append("  [!] Recommendation: RDP exposed. Ensure strong passwords and NLA are enabled, or restrict access via VPN.")
    else:
        report.append("No open ports found in the top 1000 range. Good job!")
    report.append("")

    # Web Scan Section
    report.append("## Web Application Security")
    
    # CMS
    cms = web_results.get("cms")
    if cms:
        report.append(f"### CMS Detection")
        report.append(f"Detected CMS/Framework: {cms}")
        report.append("")

    # SSL
    ssl_info = web_results.get("ssl_info")
    if ssl_info:
        report.append("### SSL/TLS Configuration")
        if isinstance(ssl_info, dict):
            report.append(f"- Issuer: {ssl_info.get('issuer', {}).get('commonName', 'Unknown')}")
            report.append(f"- Expires: {ssl_info.get('expires')}")
            report.append(f"- Version: {ssl_info.get('version')}")
        else:
            report.append(f"- Status: {ssl_info}")
        report.append("")

    # Headers
    headers = web_results.get("headers", {})
    if "missing" in headers and headers["missing"]:
        report.append("### Missing Security Headers")
        for h in headers["missing"]:
            report.append(f"- {h}")
        report.append("  [!] Recommendation: Implement these headers to protect against XSS, Clickjacking, and other attacks.")
    else:
        report.append("### Security Headers")
        report.append("All checked security headers are present. Excellent!")
    report.append("")

    # Robots.txt
    robots = web_results.get("robots_txt")
    if robots:
        report.append("### Robots.txt Analysis")
        report.append("Found Disallowed Paths (Potential Sensitive Areas):")
        for r in robots:
            report.append(f"- {r}")
        report.append("")

    # Vulnerabilities
    vulns = web_results.get("vulnerabilities")
    if vulns:
        report.append("### Vulnerability Scan (Basic)")
        for v in vulns:
            report.append(f"- [!] {v}")
        report.append("  [!] CRITICAL: These are potential high-severity issues. Verify manually immediately.")
    else:
        report.append("### Vulnerability Scan (Basic)")
        report.append("No obvious SQLi or XSS vulnerabilities found with basic heuristics.")
    report.append("")

    # Sensitive Directories
    dirs = web_results.get("sensitive_dirs", [])
    if dirs:
        report.append("### Exposed Directories")
        for d in dirs:
            report.append(f"- {d['url']} (Status: {d['status']})")
        report.append("  [!] Recommendation: Restrict access to these directories if they contain sensitive information.")
    else:
        report.append("### Directory Enumeration")
        report.append("No common sensitive directories found.")
    report.append("")

    # Backup Files
    backups = web_results.get("backup_files", [])
    if backups:
        report.append("### Exposed Backup Files")
        for b in backups:
            report.append(f"- {b}")
        report.append("  [!] CRITICAL: Backup files often contain source code, credentials, or configuration secrets. Remove them immediately!")
    else:
        report.append("### Backup File Check")
        report.append("No exposed backup files found.")
    
    report.append("")
    report.append("=" * 50)
    report.append("End of Report")
    
    return "\n".join(report)
