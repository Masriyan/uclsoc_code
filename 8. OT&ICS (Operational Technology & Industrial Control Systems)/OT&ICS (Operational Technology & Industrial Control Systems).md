# 1. Unauthorized Access to SCADA Systems
def detect_unauthorized_scada_access(access_logs, authorized_users):
    for log in access_logs:
        if log['system'] == 'SCADA' and log['user'] not in authorized_users:
            alert(f"Unauthorized SCADA access detected: {log['user']} attempted access")

# 2. Suspicious Commands to PLCs (Programmable Logic Controllers)
def detect_suspicious_plc_commands(plc_logs, approved_commands):
    for log in plc_logs:
        if log['command'] not in approved_commands:
            alert(f"Suspicious PLC command detected: {log['command']} sent to {log['plc_id']}")

# 3. Changes in ICS Configuration Files
def detect_ics_config_changes(config_logs, critical_configs):
    for log in config_logs:
        if log['config_file'] in critical_configs and log['action'] == 'modify':
            alert(f"Critical ICS configuration change detected: {log['config_file']} modified by {log['user']}")

# 4. Use of Unauthorized Remote Administration Tools
def detect_remote_admin_usage(process_logs, approved_remote_tools):
    for log in process_logs:
        if log['process_name'] not in approved_remote_tools:
            alert(f"Unauthorized remote administration tool detected: {log['process_name']}")

# 5. Communication with External or Non-ICS Devices
def detect_non_ics_communication(network_logs, ics_networks):
    for log in network_logs:
        if log['source_ip'] in ics_networks and log['destination_ip'] not in ics_networks:
            alert(f"Unusual ICS communication detected: {log['source_ip']} -> {log['destination_ip']}")

# 6. Unexpected Shutdown of Critical Systems
def detect_unexpected_shutdown(system_logs, critical_systems):
    for log in system_logs:
        if log['system'] in critical_systems and log['event'] == 'shutdown':
            alert(f"Unexpected shutdown detected on {log['system']} by {log['user']}")

# 7. Malware Targeting Industrial Protocols (MODBUS, DNP3, etc.)
def detect_malware_industrial_protocols(network_logs, known_malware_ips):
    for log in network_logs:
        if log['protocol'] in ['MODBUS', 'DNP3', 'IEC 60870-5-104'] and log['source_ip'] in known_malware_ips:
            alert(f"Potential malware activity detected using {log['protocol']} from {log['source_ip']}")

# 8. Deviation from Standard Operational Baseline Behavior
def detect_ics_behavior_anomaly(ics_logs, baseline_behaviors):
    for log in ics_logs:
        if log['behavior'] not in baseline_behaviors:
            alert(f"Anomalous ICS behavior detected: {log['behavior']} by {log['user']}")

# Define alert function
def alert(message):
    print("ALERT:", message)
