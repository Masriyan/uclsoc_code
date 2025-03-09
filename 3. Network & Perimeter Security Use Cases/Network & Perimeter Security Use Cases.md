# 1. Excessive Traffic to External IPs
def detect_excessive_outbound_traffic(network_logs, threshold):
    ip_traffic = {}
    for log in network_logs:
        if log['direction'] == 'outbound':
            ip_traffic[log['destination_ip']] = ip_traffic.get(log['destination_ip'], 0) + log['bytes']
    
    for ip, traffic in ip_traffic.items():
        if traffic > threshold:
            alert(f"Excessive outbound traffic detected to {ip}")

# 2. Port Scanning & Lateral Movement Detection
def detect_port_scanning(network_logs, scan_threshold):
    scan_activity = {}
    for log in network_logs:
        if log['event'] == 'connection_attempt':
            key = (log['source_ip'], log['destination_ip'])
            scan_activity[key] = scan_activity.get(key, 0) + 1
    
    for key, count in scan_activity.items():
        if count > scan_threshold:
            alert(f"Potential port scanning detected from {key[0]} to {key[1]}")

# 3. Data Exfiltration via DNS, HTTP, FTP, or Custom Protocols
def detect_data_exfiltration(network_logs, threshold):
    exfil_activity = {}
    for log in network_logs:
        if log['protocol'] in ['DNS', 'HTTP', 'FTP', 'CUSTOM']:
            exfil_activity[log['source_ip']] = exfil_activity.get(log['source_ip'], 0) + log['bytes']
    
    for ip, bytes_sent in exfil_activity.items():
        if bytes_sent > threshold:
            alert(f"Possible data exfiltration detected from {ip}")

# 4. Unusual VPN Logins (New Country, Different Device, etc.)
def detect_unusual_vpn_login(vpn_logs, user_baseline):
    for log in vpn_logs:
        user = log['username']
        if user in user_baseline:
            if log['location'] not in user_baseline[user]['locations'] or log['device'] not in user_baseline[user]['devices']:
                alert(f"Unusual VPN login detected for {user}")

# 5. Unauthorized Use of TOR or Proxies
def detect_tor_proxy_usage(network_logs, tor_ip_list):
    for log in network_logs:
        if log['destination_ip'] in tor_ip_list:
            alert(f"Possible TOR/Proxy usage detected from {log['source_ip']}")

# 6. Inbound & Outbound Traffic to Known Malicious IPs
def detect_malicious_ip_traffic(network_logs, threat_intel):
    for log in network_logs:
        if log['destination_ip'] in threat_intel:
            alert(f"Traffic to malicious IP detected: {log['destination_ip']}")

# 7. C2 (Command & Control) Callbacks
def detect_c2_communication(network_logs, beacon_threshold):
    c2_activity = {}
    for log in network_logs:
        if log['event'] == 'network_request':
            key = (log['source_ip'], log['destination_ip'])
            c2_activity[key] = c2_activity.get(key, 0) + 1
    
    for key, count in c2_activity.items():
        if count > beacon_threshold:
            alert(f"Possible C2 communication detected between {key[0]} and {key[1]}")

# 8. Unauthorized or Suspicious SMB Traffic
def detect_suspicious_smb_traffic(network_logs):
    for log in network_logs:
        if log['protocol'] == 'SMB' and log['source_ip'] not in APPROVED_SMB_CLIENTS:
            alert(f"Unauthorized SMB traffic detected from {log['source_ip']}")

# Define alert function
def alert(message):
    print("ALERT:", message)

# Constants
APPROVED_SMB_CLIENTS = ['10.10.10.1', '10.10.10.2']  # Example list of approved SMB clients
