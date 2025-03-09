# 1. Third-Party Remote Access Monitoring
def detect_third_party_remote_access(remote_access_logs, approved_vendors):
    for log in remote_access_logs:
        if log['vendor'] not in approved_vendors:
            alert(f"Unapproved third-party remote access detected: {log['vendor']} by {log['source_ip']}")

# 2. Unexpected External API Calls
def detect_unexpected_external_api(api_logs, allowed_apis):
    for log in api_logs:
        if log['api_endpoint'] not in allowed_apis:
            alert(f"Unexpected external API call detected: {log['api_endpoint']} by {log['source_ip']}")

# 3. Unusual SaaS or Cloud Service Usage
def detect_unusual_saas_usage(saas_logs, approved_services):
    for log in saas_logs:
        if log['service'] not in approved_services:
            alert(f"Unusual SaaS service usage detected: {log['service']} by {log['user']}")

# 4. Abuse of OAuth & SSO Tokens
def detect_oauth_sso_misuse(auth_logs, high_privilege_roles):
    for log in auth_logs:
        if log['auth_method'] in ['OAuth', 'SSO'] and log['role'] in high_privilege_roles:
            alert(f"Potential OAuth/SSO abuse detected: {log['user']} with role {log['role']}")

# 5. Access from Unapproved Vendors or Integrations
def detect_unapproved_vendor_access(integration_logs, approved_vendors):
    for log in integration_logs:
        if log['vendor'] not in approved_vendors:
            alert(f"Access from unapproved vendor detected: {log['vendor']}")

# 6. Embedded Malware in Software Updates or Packages
def detect_malware_in_software_updates(update_logs, malware_hashes):
    for log in update_logs:
        if log['file_hash'] in malware_hashes:
            alert(f"Malware detected in software update: {log['file_name']}")

# 7. Code Repositories Access by Unauthorized Users
def detect_unauthorized_repo_access(repo_logs, authorized_users):
    for log in repo_logs:
        if log['user'] not in authorized_users:
            alert(f"Unauthorized access to code repository detected: {log['repo_name']} by {log['user']}")

# 8. Use of Deprecated or Vulnerable Libraries
def detect_vulnerable_libraries(dependency_logs, vulnerability_db):
    for log in dependency_logs:
        if log['library_version'] in vulnerability_db:
            alert(f"Deprecated or vulnerable library detected: {log['library_name']} version {log['library_version']}")

# Define alert function
def alert(message):
    print("ALERT:", message)
