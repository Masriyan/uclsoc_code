# 1. PCI-DSS: Unauthorized Access to Cardholder Data
def detect_pci_unauthorized_access(file_access_logs, pci_data_paths, authorized_roles):
    for log in file_access_logs:
        if log['file_path'] in pci_data_paths and log['user_role'] not in authorized_roles:
            alert(f"Unauthorized access to PCI data detected: {log['file_path']} by {log['user']}")

# 2. GDPR: Unauthorized Export of Personal Data
def detect_gdpr_data_export(file_transfer_logs, personal_data_keywords, external_destinations):
    for log in file_transfer_logs:
        if any(keyword in log['file_name'] for keyword in personal_data_keywords) and log['destination'] in external_destinations:
            alert(f"Potential GDPR violation: Personal data transfer detected to {log['destination']}")

# 3. HIPAA: Access to Patient Health Records by Unauthorized Users
def detect_hipaa_violation(access_logs, hipaa_data_paths, authorized_healthcare_roles):
    for log in access_logs:
        if log['file_path'] in hipaa_data_paths and log['user_role'] not in authorized_healthcare_roles:
            alert(f"HIPAA violation detected: Unauthorized access to patient records by {log['user']}")

# 4. SOX: Financial Data Tampering
def detect_sox_financial_data_modification(financial_logs, critical_financial_tables, privileged_roles):
    for log in financial_logs:
        if log['table'] in critical_financial_tables and log['action'] == 'modify' and log['user_role'] not in privileged_roles:
            alert(f"SOX violation: Unauthorized financial data modification detected by {log['user']}")

# 5. ISO 27001: Unusual Administrator Access to Critical Systems
def detect_iso_admin_access(admin_access_logs, critical_systems, expected_admins):
    for log in admin_access_logs:
        if log['system'] in critical_systems and log['admin'] not in expected_admins:
            alert(f"ISO 27001 violation: Unusual admin access detected on {log['system']} by {log['admin']}")

# 6. Data Retention & Log Integrity Monitoring
def detect_log_tampering(log_integrity_checks):
    for check in log_integrity_checks:
        if check['tampered']:
            alert(f"Log integrity violation detected: {check['log_file']}")

# 7. Access Control Violations (RBAC, Least Privilege Violations)
def detect_access_control_violations(access_logs, role_permissions):
    for log in access_logs:
        if log['action'] in ['read', 'write', 'delete'] and log['user_role'] not in role_permissions.get(log['resource'], []):
            alert(f"Access control violation detected: {log['user']} attempted {log['action']} on {log['resource']}")

# 8. Privileged User Misuse
def detect_privileged_user_misuse(privileged_logs):
    for log in privileged_logs:
        if log['action'] in ['mass deletion', 'unauthorized account changes', 'privilege escalation']:
            alert(f"Privileged user misuse detected: {log['user']} performed {log['action']}")

# 9. Encryption Policy Violations (Storing Unencrypted Sensitive Data)
def detect_unencrypted_sensitive_data(file_scans, sensitive_data_keywords):
    for log in file_scans:
        if any(keyword in log['file_content'] for keyword in sensitive_data_keywords) and not log['encrypted']:
            alert(f"Encryption policy violation detected: {log['file_path']} contains unencrypted sensitive data")

# 10. Security Configuration Drift (Non-Compliance with Security Baseline)
def detect_security_configuration_drift(config_audits, security_baseline):
    for log in config_audits:
        if log['setting'] not in security_baseline.get(log['system'], {}):
            alert(f"Configuration drift detected on {log['system']}: {log['setting']} does not match baseline")

# Define alert function
def alert(message):
    print("ALERT:", message)
