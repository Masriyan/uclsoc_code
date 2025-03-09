# CIS-Based SIEM Use Case Logic

# 1. Inventory and Control of Hardware Assets
def detect_unauthorized_hardware(device_logs, authorized_devices):
    for log in device_logs:
        if log['device_id'] not in authorized_devices:
            alert(f"Unauthorized hardware detected: {log['device_id']} connected by {log['user']}")

# 2. Inventory and Control of Software Assets
def detect_unapproved_software(software_logs, approved_software_list):
    for log in software_logs:
        if log['software_name'] not in approved_software_list:
            alert(f"Unapproved software installation detected: {log['software_name']} by {log['user']}")

# 3. Continuous Vulnerability Management
def detect_vulnerability_scans(vuln_scan_results, critical_severity):
    for log in vuln_scan_results:
        if log['severity'] >= critical_severity:
            alert(f"Critical vulnerability detected: {log['cve_id']} on {log['host']}")

# 4. Controlled Use of Administrative Privileges
def detect_admin_privilege_misuse(privilege_logs, admin_roles):
    for log in privilege_logs:
        if log['role'] not in admin_roles and log['action'] == 'elevate_privileges':
            alert(f"Unauthorized privilege escalation detected: {log['user']} attempted {log['action']}")

# 5. Secure Configuration for Hardware and Software
def detect_configuration_drift(config_audits, security_baseline):
    for log in config_audits:
        if log['setting'] not in security_baseline.get(log['system'], {}):
            alert(f"Configuration drift detected on {log['system']}: {log['setting']} does not match baseline")

# 6. Maintenance, Monitoring, and Analysis of Audit Logs
def detect_log_tampering(log_integrity_checks):
    for check in log_integrity_checks:
        if check['tampered']:
            alert(f"Log integrity violation detected: {check['log_file']}")

# 7. Email and Web Browser Protections
def detect_malicious_email(email_logs, phishing_indicators):
    for log in email_logs:
        if log['sender_domain'] in phishing_indicators:
            alert(f"Potential phishing email detected from {log['sender_domain']}")

# 8. Malware Defenses
def detect_malware_activity(endpoint_logs, malware_signatures):
    for log in endpoint_logs:
        if log['file_hash'] in malware_signatures:
            alert(f"Malware detected: {log['file_name']} executed by {log['user']}")

# 9. Limitation and Control of Network Ports, Protocols, and Services
def detect_unusual_port_usage(network_logs, allowed_ports):
    for log in network_logs:
        if log['destination_port'] not in allowed_ports:
            alert(f"Unauthorized port usage detected: {log['destination_port']} accessed by {log['source_ip']}")

# 10. Data Protection
def detect_sensitive_data_exposure(data_logs, sensitive_keywords):
    for log in data_logs:
        if any(keyword in log['file_content'] for keyword in sensitive_keywords):
            alert(f"Sensitive data exposure detected in {log['file_path']}")

# Define alert function
def alert(message):
    print("ALERT:", message)