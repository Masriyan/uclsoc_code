
# 1. Initial Access (Phishing, Exploit Public-Facing App)
def detect_initial_access(access_logs, phishing_domains, exploit_signatures):
    for log in access_logs:
        if log['source_domain'] in phishing_domains or log['attack_pattern'] in exploit_signatures:
            alert(f"Initial access attempt detected from {log['source_ip']} using {log['attack_pattern']}")

# 2. Execution (Command-Line, PowerShell, WMI)
def detect_execution(command_logs, suspicious_commands):
    for log in command_logs:
        if log['command'] in suspicious_commands:
            alert(f"Suspicious command execution detected: {log['command']} by {log['user']}")

# 3. Persistence (Registry Keys, Scheduled Tasks)
def detect_persistence(persistence_logs, persistence_methods):
    for log in persistence_logs:
        if log['method'] in persistence_methods:
            alert(f"Persistence mechanism detected: {log['method']} by {log['user']}")

# 4. Privilege Escalation (Sudo, UAC Bypass)
def detect_privilege_escalation(auth_logs, privilege_escalation_methods):
    for log in auth_logs:
        if log['method'] in privilege_escalation_methods:
            alert(f"Privilege escalation detected: {log['method']} by {log['user']}")

# 5. Defense Evasion (Obfuscated Scripts, Disabling Logs)
def detect_defense_evasion(script_logs, log_modification_logs):
    for log in script_logs:
        if log['obfuscation']:
            alert(f"Obfuscated script execution detected by {log['user']}")
    for log in log_modification_logs:
        if log['action'] == 'disable_logs':
            alert(f"Log tampering detected by {log['user']}")

# 6. Credential Access (Mimikatz, Keyloggers)
def detect_credential_access(process_logs, credential_tools):
    for log in process_logs:
        if log['process_name'] in credential_tools:
            alert(f"Credential access attempt detected: {log['process_name']} by {log['user']}")

# 7. Discovery (Network Scanning, Service Enumeration)
def detect_discovery(network_logs, discovery_methods):
    for log in network_logs:
        if log['method'] in discovery_methods:
            alert(f"Discovery activity detected: {log['method']} by {log['source_ip']}")

# 8. Lateral Movement (RDP, SMB, PsExec)
def detect_lateral_movement(network_logs, lateral_movement_methods):
    for log in network_logs:
        if log['method'] in lateral_movement_methods:
            alert(f"Lateral movement detected: {log['method']} from {log['source_ip']} to {log['destination_ip']}")

# 9. Collection (Clipboard Data, Screen Captures)
def detect_collection(activity_logs, collection_methods):
    for log in activity_logs:
        if log['method'] in collection_methods:
            alert(f"Data collection detected: {log['method']} by {log['user']}")

# 10. Exfiltration (Data Transfer via Cloud, DNS, HTTP)
def detect_exfiltration(exfiltration_logs, exfiltration_methods):
    for log in exfiltration_logs:
        if log['method'] in exfiltration_methods:
            alert(f"Data exfiltration detected: {log['method']} by {log['user']}")

# 11. Impact (Ransomware, Wiper Malware)
def detect_impact(malware_logs, impact_methods):
    for log in malware_logs:
        if log['method'] in impact_methods:
            alert(f"System impact detected: {log['method']} affecting {log['target_system']}")

# Define alert function
def alert(message):
    print("ALERT:", message)
