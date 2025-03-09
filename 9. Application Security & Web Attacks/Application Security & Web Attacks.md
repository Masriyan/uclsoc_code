# 1. SQL Injection Attempts
def detect_sql_injection(web_logs, sql_patterns):
    for log in web_logs:
        if any(pattern in log['query'] for pattern in sql_patterns):
            alert(f"SQL Injection attempt detected: {log['query']} from {log['source_ip']}")

# 2. Cross-Site Scripting (XSS) Detection
def detect_xss_attempts(web_logs, xss_patterns):
    for log in web_logs:
        if any(pattern in log['url'] or pattern in log['request_body'] for pattern in xss_patterns):
            alert(f"XSS attempt detected from {log['source_ip']}")

# 3. Path Traversal Attacks
def detect_path_traversal(web_logs, traversal_patterns):
    for log in web_logs:
        if any(pattern in log['url'] for pattern in traversal_patterns):
            alert(f"Path traversal attack detected: {log['url']} from {log['source_ip']}")

# 4. Broken Authentication Exploitation
def detect_broken_auth_attempts(auth_logs, failed_threshold):
    user_attempts = {}
    for log in auth_logs:
        user_attempts[log['user']] = user_attempts.get(log['user'], 0) + 1
        if user_attempts[log['user']] > failed_threshold:
            alert(f"Broken authentication attempt detected for user {log['user']}")

# 5. Unauthorized API Access
def detect_unauthorized_api_access(api_logs, authorized_tokens):
    for log in api_logs:
        if log['api_token'] not in authorized_tokens:
            alert(f"Unauthorized API access attempt detected: {log['endpoint']} by {log['source_ip']}")

# 6. Account Enumeration Attacks
def detect_account_enumeration(auth_logs, enumeration_patterns):
    for log in auth_logs:
        if any(pattern in log['response'] for pattern in enumeration_patterns):
            alert(f"Account enumeration detected from {log['source_ip']}")

# 7. Web Shell Upload & Execution
def detect_web_shell(web_logs, web_shell_signatures):
    for log in web_logs:
        if any(signature in log['request_body'] for signature in web_shell_signatures):
            alert(f"Potential web shell upload detected from {log['source_ip']}")

# 8. Unexpected HTTP Methods (PUT, DELETE, TRACE)
def detect_unexpected_http_methods(http_logs, allowed_methods):
    for log in http_logs:
        if log['method'] not in allowed_methods:
            alert(f"Unexpected HTTP method detected: {log['method']} from {log['source_ip']}")

# 9. Credential Stuffing Attempts
def detect_credential_stuffing(auth_logs, failed_threshold):
    failed_attempts = {}
    for log in auth_logs:
        if log['status'] == 'failed':
            failed_attempts[log['source_ip']] = failed_attempts.get(log['source_ip'], 0) + 1
            if failed_attempts[log['source_ip']] > failed_threshold:
                alert(f"Credential stuffing attempt detected from {log['source_ip']}")

# 10. Abuse of Business Logic in Web Applications
def detect_business_logic_abuse(app_logs, abuse_patterns):
    for log in app_logs:
        if log['action'] in abuse_patterns:
            alert(f"Potential business logic abuse detected: {log['action']} by {log['user']}")

# Define alert function
def alert(message):
    print("ALERT:", message)
