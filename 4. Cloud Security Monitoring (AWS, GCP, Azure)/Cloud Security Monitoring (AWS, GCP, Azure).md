# Cloud Security Monitoring (AWS, GCP, Azure)

## 1. IAM Role Abuse & Misconfiguration
```python
def detect_iam_role_abuse(iam_logs, critical_roles):
    for log in iam_logs:
        if log['action'] == 'AssumeRole' and log['role'] in critical_roles:
            alert(f"Potential IAM role abuse detected: {log['role']} assumed by {log['user']}")
```

## 2. S3 Bucket Enumeration & Public Exposure
```python
def detect_s3_exposure(s3_logs):
    for log in s3_logs:
        if log['action'] == 'ListBucket' and log['access'] == 'public':
            alert(f"S3 bucket publicly accessible: {log['bucket']}")
```

## 3. Suspicious API Calls (ListKeys, AssumeRole, etc.)
```python
def detect_suspicious_api_calls(api_logs, sensitive_api_calls):
    for log in api_logs:
        if log['action'] in sensitive_api_calls:
            alert(f"Suspicious API call detected: {log['action']} by {log['user']}")
```

## 4. Unusual Privileged Access in Cloud Environments
```python
def detect_unusual_privileged_access(access_logs, privileged_roles):
    for log in access_logs:
        if log['role'] in privileged_roles and log['access_type'] == 'unusual':
            alert(f"Unusual privileged access detected: {log['user']} with role {log['role']}")
```

## 5. Creation or Deletion of High-Value Cloud Resources
```python
def detect_resource_modifications(resource_logs, critical_resources):
    for log in resource_logs:
        if log['resource'] in critical_resources and log['action'] in ['Create', 'Delete']:
            alert(f"Critical cloud resource {log['action']} detected: {log['resource']} by {log['user']}")
```

## 6. Unauthorized Public Exposure of Cloud Services
```python
def detect_public_exposure(service_logs):
    for log in service_logs:
        if log['exposure'] == 'public' and log['service'] in ['EC2', 'GCS', 'AzureBlob']:
            alert(f"Unauthorized public exposure detected: {log['service']} instance {log['instance_id']}")
```

## 7. Cloud Function Execution from Unknown IPs
```python
def detect_unusual_cloud_function_execution(cloud_function_logs, trusted_ips):
    for log in cloud_function_logs:
        if log['source_ip'] not in trusted_ips:
            alert(f"Cloud function executed from untrusted IP: {log['source_ip']}")
```

## 8. Mass Data Download from Cloud Storage
```python
def detect_mass_data_download(storage_logs, threshold):
    download_activity = {}
    for log in storage_logs:
        if log['action'] == 'Download':
            download_activity[log['user']] = download_activity.get(log['user'], 0) + log['bytes']
    
    for user, data_downloaded in download_activity.items():
        if data_downloaded > threshold:
            alert(f"Massive data download detected by {user}")
```

## 9. Abnormal Increase in Cloud Costs (Crypto-Mining, Resource Hijacking)
```python
def detect_abnormal_cloud_costs(billing_logs, expected_costs):
    for log in billing_logs:
        if log['cost'] > expected_costs * 2:  # Example threshold
            alert(f"Abnormal cloud cost increase detected: ${log['cost']} for {log['service']}")
```

## 10. Misuse of Serverless Functions (Lambda, Cloud Functions, etc.)
```python
def detect_serverless_misuse(serverless_logs):
    for log in serverless_logs:
        if log['execution_time'] > EXECUTION_THRESHOLD or log['invocations'] > INVOCATION_THRESHOLD:
            alert(f"Potential misuse of serverless function detected: {log['function_name']}")
```

## 11. Unauthorized Cross-Region Access
```python
def detect_cross_region_access(access_logs, allowed_regions):
    for log in access_logs:
        if log['region'] not in allowed_regions:
            alert(f"Unauthorized cross-region access detected in {log['region']} by {log['user']}")
```

## 12. Unusual IAM User Creation or Deletion
```python
def detect_iam_user_modification(iam_logs):
    for log in iam_logs:
        if log['action'] in ['CreateUser', 'DeleteUser']:
            alert(f"Unusual IAM user modification detected: {log['action']} by {log['user']}")
```

## 13. Unapproved External Data Sharing (Cloud Storage)
```python
def detect_external_data_sharing(cloud_storage_logs, internal_domains):
    for log in cloud_storage_logs:
        if log['action'] == 'Share' and log['shared_with'] not in internal_domains:
            alert(f"External data sharing detected: {log['file']} shared with {log['shared_with']}")
```

## 14. Multiple Failed Logins from Different Locations
```python
def detect_failed_logins(failed_login_logs, threshold):
    failed_attempts = {}
    for log in failed_login_logs:
        failed_attempts[log['user']] = failed_attempts.get(log['user'], []) + [log['ip']]
    
    for user, ips in failed_attempts.items():
        if len(set(ips)) > threshold:
            alert(f"Multiple failed logins from different locations detected for user {user}")
```

## 15. Suspicious Cloud API Key Usage
```python
def detect_suspicious_api_key_usage(api_key_logs, known_good_ips):
    for log in api_key_logs:
        if log['source_ip'] not in known_good_ips:
            alert(f"Suspicious API key usage detected from {log['source_ip']} for key {log['api_key_id']}")
```

## 16. Unusual Network Traffic to Cloud Databases
```python
def detect_unusual_cloud_db_traffic(db_logs, allowed_sources):
    for log in db_logs:
        if log['source_ip'] not in allowed_sources:
            alert(f"Unusual network traffic to cloud database from {log['source_ip']}")
```

## 17. Modification of Security Groups or Firewalls
```python
def detect_firewall_modification(firewall_logs, critical_rules):
    for log in firewall_logs:
        if log['rule'] in critical_rules and log['action'] == 'Modify':
            alert(f"Modification of critical firewall rule detected: {log['rule']} by {log['user']}")
```

## 18. Sudden Increase in Compute Instances (Crypto-Mining)
```python
def detect_unusual_compute_usage(compute_logs, baseline_usage):
    for log in compute_logs:
        if log['instance_count'] > baseline_usage * 2:  # Example threshold
            alert(f"Unusual spike in compute instances detected: {log['instance_count']} by {log['user']}")
```

## 19. Abuse of Temporary Credentials
```python
def detect_temporary_credential_abuse(session_logs, session_duration_threshold):
    for log in session_logs:
        if log['session_duration'] > session_duration_threshold:
            alert(f"Abuse of temporary credentials detected: session {log['session_id']} exceeded duration")
```

## 20. Unexpected Cloud Service Activation
```python
def detect_unexpected_service_activation(service_logs, expected_services):
    for log in service_logs:
        if log['service'] not in expected_services:
            alert(f"Unexpected cloud service activation detected: {log['service']} by {log['user']}")
```

## Define Alert Function
```python
def alert(message):
    print("ALERT:", message)
```

