# 1. Connections to Known Malicious Domains & IPs
def detect_malicious_connections(network_logs, threat_intel_db):
    for log in network_logs:
        if log['destination_ip'] in threat_intel_db or log['domain'] in threat_intel_db:
            alert(f"Connection to malicious destination detected: {log['destination_ip'] or log['domain']}")

# 2. Downloads from Newly Registered Domains
def detect_new_domain_downloads(download_logs, domain_age_db, threshold_days):
    for log in download_logs:
        if domain_age_db.get(log['domain'], 999) < threshold_days:
            alert(f"Suspicious download from newly registered domain: {log['domain']}")

# 3. Unusual HTTP User-Agent Strings (Malware, Attack Tools)
def detect_suspicious_user_agents(http_logs, known_bad_agents):
    for log in http_logs:
        if log['user_agent'] in known_bad_agents:
            alert(f"Suspicious user-agent detected: {log['user_agent']}")

# 4. Indicators of Compromise (IoCs) from Threat Feeds
def detect_ioc_activity(logs, ioc_feed):
    for log in logs:
        if log['ip'] in ioc_feed or log['hash'] in ioc_feed:
            alert(f"Indicator of compromise detected: {log['ip'] or log['hash']}")

# 5. Usage of Attack Frameworks (Metasploit, Cobalt Strike, etc.)
def detect_attack_framework_usage(process_logs, known_attack_tools):
    for log in process_logs:
        if log['process_name'] in known_attack_tools:
            alert(f"Potential attack framework execution detected: {log['process_name']}")

# 6. Scanning or Probing from Known APT Groups
def detect_apt_scanning(network_logs, apt_ip_list):
    for log in network_logs:
        if log['source_ip'] in apt_ip_list:
            alert(f"Possible APT scanning activity detected from {log['source_ip']}")

# 7. Malicious Email Attachments & Links
def detect_malicious_email_attachments(email_logs, threat_intel_hashes):
    for log in email_logs:
        if log['attachment_hash'] in threat_intel_hashes:
            alert(f"Malicious email attachment detected: {log['attachment_name']}")

# 8. Domain Generation Algorithm (DGA) Detection
def detect_dga_domains(dns_logs, dga_model):
    for log in dns_logs:
        if dga_model.predict(log['domain']):
            alert(f"Potential DGA domain detected: {log['domain']}")

# 9. Unusual Encrypted Traffic (Obfuscation, Stealth C2, etc.)
def detect_unusual_encryption(network_logs, entropy_threshold):
    for log in network_logs:
        if log['entropy'] > entropy_threshold:
            alert(f"Suspicious encrypted traffic detected: {log['destination_ip']}")

# 10. Use of Legitimate Software for Malicious Purposes (AnyDesk, TeamViewer, etc.)
def detect_misused_legit_software(process_logs, remote_access_tools):
    for log in process_logs:
        if log['process_name'] in remote_access_tools:
            alert(f"Potential misuse of remote access tool: {log['process_name']}")

# Define alert function
def alert(message):
    print("ALERT:", message)