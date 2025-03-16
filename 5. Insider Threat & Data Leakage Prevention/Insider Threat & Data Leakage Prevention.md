# Insider Threat & Data Leakage Prevention Use Cases

## 1. Unusual File Access (Confidential, Financial, HR, etc.)
```python
def detect_unusual_file_access(file_access_logs, sensitive_files):
    for log in file_access_logs:
        if log['file'] in sensitive_files and log['access_type'] == 'unusual':
            alert(f"Unusual access detected on sensitive file: {log['file']} by {log['user']}")
```

## 2. High Volume File Transfers (USB, Email, Cloud)
```python
def detect_mass_file_transfer(file_transfer_logs, threshold):
    transfer_activity = {}
    for log in file_transfer_logs:
        transfer_activity[log['user']] = transfer_activity.get(log['user'], 0) + log['size']
    
    for user, total_size in transfer_activity.items():
        if total_size > threshold:
            alert(f"High volume file transfer detected by {user}")
```

## 3. Multiple File Sharing to Personal Email or External Domains
```python
def detect_suspicious_email_sharing(email_logs, company_domain):
    for log in email_logs:
        if log['recipient'].split('@')[-1] != company_domain:
            alert(f"Suspicious file sharing detected: {log['file']} sent to {log['recipient']}")
```

## 4. Employees Accessing Data Outside of Job Role
```python
def detect_unusual_data_access(access_logs, job_role_permissions):
    for log in access_logs:
        if log['user_role'] not in job_role_permissions.get(log['file'], []):
            alert(f"Unauthorized data access detected: {log['user']} accessing {log['file']}")
```

## 5. Large Database Query Execution
```python
def detect_large_db_queries(db_logs, query_threshold):
    for log in db_logs:
        if log['query_size'] > query_threshold:
            alert(f"Large database query executed by {log['user']} on {log['database']}")
```

## 6. Use of Unauthorized Cloud Storage (Google Drive, Dropbox, etc.)
```python
def detect_unauthorized_cloud_storage_usage(cloud_logs, approved_services):
    for log in cloud_logs:
        if log['service'] not in approved_services:
            alert(f"Unauthorized cloud storage usage detected: {log['service']} by {log['user']}")
```

## 7. Suspicious Privileged User Activity
```python
def detect_privileged_user_misuse(privileged_logs):
    for log in privileged_logs:
        if log['action'] in ['mass file deletion', 'user account modification', 'privilege escalation']:
            alert(f"Suspicious privileged user activity detected: {log['user']} performed {log['action']}")
```

## 8. Mass Email Forwarding Rules Creation
```python
def detect_mass_email_forwarding(email_forwarding_logs, threshold):
    user_forwarding = {}
    for log in email_forwarding_logs:
        user_forwarding[log['user']] = user_forwarding.get(log['user'], 0) + 1
    
    for user, count in user_forwarding.items():
        if count > threshold:
            alert(f"Mass email forwarding rule detected for {user}")
```

## 9. Suspicious Print Jobs (Printing Sensitive Data)
```python
def detect_suspicious_print_jobs(print_logs, sensitive_keywords):
    for log in print_logs:
        if any(keyword in log['document'] for keyword in sensitive_keywords):
            alert(f"Suspicious print job detected: {log['document']} printed by {log['user']}")
```

## 10. High Volume Clipboard Copy/Paste Activities
```python
def detect_mass_clipboard_usage(clipboard_logs, threshold):
    user_clipboard = {}
    for log in clipboard_logs:
        user_clipboard[log['user']] = user_clipboard.get(log['user'], 0) + log['copy_size']
    
    for user, total_size in user_clipboard.items():
        if total_size > threshold:
            alert(f"High volume clipboard activity detected by {user}")
```

## 11. Unauthorized Access to Shared Network Drives
```python
def detect_unauthorized_network_drive_access(network_drive_logs, authorized_users):
    for log in network_drive_logs:
        if log['user'] not in authorized_users and log['access_type'] == 'read':
            alert(f"Unauthorized access to shared network drive detected: {log['user']} accessed {log['drive']}")
```

## 12. Unusual Activity on Dormant Accounts
```python
def detect_dormant_account_activity(login_logs, dormant_users):
    for log in login_logs:
        if log['user'] in dormant_users:
            alert(f"Unusual activity detected on dormant account: {log['user']} logged in from {log['source_ip']}")
```

## 13. Unauthorized USB Device Connection
```python
def detect_unauthorized_usb_device(usb_logs, approved_devices):
    for log in usb_logs:
        if log['device_id'] not in approved_devices:
            alert(f"Unauthorized USB device connected: {log['device_id']} by {log['user']}")
```

## 14. Unusual Printing Volume per User
```python
def detect_unusual_print_volume(print_logs, print_threshold):
    print_activity = {}
    for log in print_logs:
        print_activity[log['user']] = print_activity.get(log['user'], 0) + log['pages']
    
    for user, total_pages in print_activity.items():
        if total_pages > print_threshold:
            alert(f"Unusual printing activity detected: {total_pages} pages printed by {user}")
```

## 15. Unauthorized Email Access from New Locations
```python
def detect_unusual_email_access(email_login_logs, known_locations):
    for log in email_login_logs:
        if log['location'] not in known_locations.get(log['user'], []):
            alert(f"Unusual email access detected: {log['user']} logged in from {log['location']}")
```

## 16. Multiple Employees Accessing the Same Sensitive File
```python
def detect_multiple_access_to_sensitive_files(file_access_logs, sensitive_files, threshold):
    file_access_counts = {}
    for log in file_access_logs:
        if log['file'] in sensitive_files:
            file_access_counts[log['file']] = file_access_counts.get(log['file'], set())
            file_access_counts[log['file']].add(log['user'])
    
    for file, users in file_access_counts.items():
        if len(users) > threshold:
            alert(f"Multiple employees accessed sensitive file: {file} - {len(users)} users")
```

## 17. Suspicious File Renaming Activities
```python
def detect_suspicious_file_renaming(file_activity_logs, sensitive_extensions):
    for log in file_activity_logs:
        if log['action'] == 'rename' and log['old_extension'] in sensitive_extensions:
            alert(f"Suspicious file renaming detected: {log['old_name']} -> {log['new_name']} by {log['user']}")
```

## 18. Exfiltration of Encrypted Files
```python
def detect_encrypted_file_exfiltration(file_transfer_logs, encrypted_extensions):
    for log in file_transfer_logs:
        if log['file_extension'] in encrypted_extensions and log['destination'] not in internal_networks:
            alert(f"Encrypted file exfiltration detected: {log['file']} sent to {log['destination']} by {log['user']}")
```

## 19. Unusual Usage of Screenshot Tools
```python
def detect_screenshot_tool_usage(process_logs, screenshot_tools):
    for log in process_logs:
        if log['process_name'] in screenshot_tools:
            alert(f"Suspicious screenshot tool usage detected: {log['process_name']} by {log['user']}")
```

## 20. Frequent Printing of Confidential Documents
```python
def detect_confidential_document_printing(print_logs, confidential_keywords):
    for log in print_logs:
        if any(keyword in log['document_name'] for keyword in confidential_keywords):
            alert(f"Frequent printing of confidential documents detected: {log['document_name']} by {log['user']}")
```

