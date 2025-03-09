# Part 5: Insider Threat & Data Leakage Prevention Use Cases

# 1. Unusual File Access (Confidential, Financial, HR, etc.)
def detect_unusual_file_access(file_access_logs, sensitive_files):
    for log in file_access_logs:
        if log['file'] in sensitive_files and log['access_type'] == 'unusual':
            alert(f"Unusual access detected on sensitive file: {log['file']} by {log['user']}")

# 2. High Volume File Transfers (USB, Email, Cloud)
def detect_mass_file_transfer(file_transfer_logs, threshold):
    transfer_activity = {}
    for log in file_transfer_logs:
        transfer_activity[log['user']] = transfer_activity.get(log['user'], 0) + log['size']
    
    for user, total_size in transfer_activity.items():
        if total_size > threshold:
            alert(f"High volume file transfer detected by {user}")

# 3. Multiple File Sharing to Personal Email or External Domains
def detect_suspicious_email_sharing(email_logs, company_domain):
    for log in email_logs:
        if log['recipient'].split('@')[-1] != company_domain:
            alert(f"Suspicious file sharing detected: {log['file']} sent to {log['recipient']}")

# 4. Employees Accessing Data Outside of Job Role
def detect_unusual_data_access(access_logs, job_role_permissions):
    for log in access_logs:
        if log['user_role'] not in job_role_permissions.get(log['file'], []):
            alert(f"Unauthorized data access detected: {log['user']} accessing {log['file']}")

# 5. Large Database Query Execution
def detect_large_db_queries(db_logs, query_threshold):
    for log in db_logs:
        if log['query_size'] > query_threshold:
            alert(f"Large database query executed by {log['user']} on {log['database']}")

# 6. Use of Unauthorized Cloud Storage (Google Drive, Dropbox, etc.)
def detect_unauthorized_cloud_storage_usage(cloud_logs, approved_services):
    for log in cloud_logs:
        if log['service'] not in approved_services:
            alert(f"Unauthorized cloud storage usage detected: {log['service']} by {log['user']}")

# 7. Suspicious Privileged User Activity
def detect_privileged_user_misuse(privileged_logs):
    for log in privileged_logs:
        if log['action'] in ['mass file deletion', 'user account modification', 'privilege escalation']:
            alert(f"Suspicious privileged user activity detected: {log['user']} performed {log['action']}")

# 8. Mass Email Forwarding Rules Creation
def detect_mass_email_forwarding(email_forwarding_logs, threshold):
    user_forwarding = {}
    for log in email_forwarding_logs:
        user_forwarding[log['user']] = user_forwarding.get(log['user'], 0) + 1
    
    for user, count in user_forwarding.items():
        if count > threshold:
            alert(f"Mass email forwarding rule detected for {user}")

# 9. Suspicious Print Jobs (Printing Sensitive Data)
def detect_suspicious_print_jobs(print_logs, sensitive_keywords):
    for log in print_logs:
        if any(keyword in log['document'] for keyword in sensitive_keywords):
            alert(f"Suspicious print job detected: {log['document']} printed by {log['user']}")

# 10. High Volume Clipboard Copy/Paste Activities
def detect_mass_clipboard_usage(clipboard_logs, threshold):
    user_clipboard = {}
    for log in clipboard_logs:
        user_clipboard[log['user']] = user_clipboard.get(log['user'], 0) + log['copy_size']
    
    for user, total_size in user_clipboard.items():
        if total_size > threshold:
            alert(f"High volume clipboard activity detected by {user}")

# Define alert function
def alert(message):
    print("ALERT:", message)
