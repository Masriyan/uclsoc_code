# 1. Brute Force Detection (Failed Logins, Unusual Success Rate)
def detect_brute_force(logins):
    failed_attempts = {}
    for event in logins:
        user = event['username']
        if event['status'] == 'failed':
            failed_attempts[user] = failed_attempts.get(user, 0) + 1
        else:
            failed_attempts[user] = 0  # Reset on success
    
    for user, count in failed_attempts.items():
        if count > THRESHOLD:
            alert(f"Brute force detected for user {user}")

# 2. MFA Bypass Attempts
def detect_mfa_bypass(auth_events):
    for event in auth_events:
        if event['method'] == 'MFA' and event['status'] == 'bypassed':
            alert(f"MFA Bypass attempt detected for user {event['username']}")

# 3. Privilege Escalation Detection
def detect_privilege_escalation(access_logs):
    for event in access_logs:
        if event['old_role'] != event['new_role'] and event['new_role'] in ['Admin', 'Root']:
            alert(f"Privilege escalation detected for user {event['username']}")

# 4. Account Takeover (ATO) Detection
def detect_account_takeover(logins):
    user_sessions = {}
    for event in logins:
        user_sessions.setdefault(event['username'], set()).add(event['ip_address'])
    
    for user, ips in user_sessions.items():
        if len(ips) > UNUSUAL_IP_THRESHOLD:
            alert(f"Possible account takeover detected for user {user}")

# 5. Dormant Account Usage
def detect_dormant_account_usage(login_events, dormant_accounts):
    for event in login_events:
        if event['username'] in dormant_accounts:
            alert(f"Dormant account {event['username']} used")

# 6. Excessive Service Account Usage
def detect_excessive_service_usage(service_logins):
    usage_count = {}
    for event in service_logins:
        service = event['service_account']
        usage_count[service] = usage_count.get(service, 0) + 1
    
    for service, count in usage_count.items():
        if count > SERVICE_THRESHOLD:
            alert(f"Excessive usage detected for service account {service}")

# 7. Unusual Off-Hours Logins
def detect_off_hours_logins(login_events, business_hours):
    for event in login_events:
        if not business_hours.contains(event['timestamp']):
            alert(f"Off-hours login detected for user {event['username']}")

# 8. Logins from Suspicious/High-Risk Locations
def detect_suspicious_locations(login_events, risk_db):
    for event in login_events:
        if event['location'] in risk_db:
            alert(f"Login from high-risk location detected for user {event['username']}")

# 9. Impossible Travel (Login from Different Locations in Short Timeframe)
def detect_impossible_travel(login_events):
    user_travel = {}
    for event in login_events:
        user = event['username']
        timestamp = event['timestamp']
        location = event['location']
        
        if user in user_travel:
            last_location, last_time = user_travel[user]
            travel_time = abs(timestamp - last_time)
            distance = calculate_distance(last_location, location)
            if distance / travel_time > MAX_TRAVEL_SPEED:
                alert(f"Impossible travel detected for user {user}")
        
        user_travel[user] = (location, timestamp)

# Define alert function
def alert(message):
    print("ALERT:", message)

# Define helper function to calculate distance (mockup for now)
def calculate_distance(location1, location2):
    return 5000  # Assume 5000 km for testing purposes

# Constants
THRESHOLD = 5  # Example brute force threshold
UNUSUAL_IP_THRESHOLD = 3  # Multiple IP addresses in short time
SERVICE_THRESHOLD = 50  # Too many service account logins
MAX_TRAVEL_SPEED = 1000  # km per hour (impossible for humans)