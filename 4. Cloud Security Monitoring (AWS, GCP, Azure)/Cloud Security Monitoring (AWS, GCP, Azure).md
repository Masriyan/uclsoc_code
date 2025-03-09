# 1. IAM Role Abuse & Misconfiguration
def detect_iam_role_abuse(iam_logs, critical_roles):
    for log in iam_logs:
        if log['action'] == 'AssumeRole' and log['role'] in critical_roles:
            alert(f"Potential IAM role abuse detected: {log['role']} assumed by {log['user']}")

# 2. S3 Bucket Enumeration & Public Exposure
def detect_s3_exposure(s3_logs):
    for log in s3_logs:
        if log['action'] == 'ListBucket' and log['access'] == 'public':
            alert(f"S3 bucket publicly accessible: {log['bucket']}")

# 3. Suspicious API Calls (ListKeys, AssumeRole, etc.)
def detect_suspicious_api_calls(api_logs, sensitive_api_calls):
    for log in api_logs:
        if log['action'] in sensitive_api_calls:
            alert(f"Suspicious API call detected: {log['action']} by {log['user']}")

# 4. Unusual Privileged Access in Cloud Environments
def detect_unusual_privileged_access(access_logs, privileged_roles):
    for log in access_logs:
        if log['role'] in privileged_roles and log['access_type'] == 'unusual':
            alert(f"Unusual privileged access detected: {log['user']} with role {log['role']}")

# 5. Creation or Deletion of High-Value Cloud Resources
def detect_resource_modifications(resource_logs, critical_resources):
    for log in resource_logs:
        if log['resource'] in critical_resources and log['action'] in ['Create', 'Delete']:
            alert(f"Critical cloud resource {log['action']} detected: {log['resource']} by {log['user']}")

# 6. Unauthorized Public Exposure of Cloud Services
def detect_public_exposure(service_logs):
    for log in service_logs:
        if log['exposure'] == 'public' and log['service'] in ['EC2', 'GCS', 'AzureBlob']:
            alert(f"Unauthorized public exposure detected: {log['service']} instance {log['instance_id']}")

# 7. Cloud Function Execution from Unknown IPs
def detect_unusual_cloud_function_execution(cloud_function_logs, trusted_ips):
    for log in cloud_function_logs:
        if log['source_ip'] not in trusted_ips:
            alert(f"Cloud function executed from untrusted IP: {log['source_ip']}")

# 8. Mass Data Download from Cloud Storage
def detect_mass_data_download(storage_logs, threshold):
    download_activity = {}
    for log in storage_logs:
        if log['action'] == 'Download':
            download_activity[log['user']] = download_activity.get(log['user'], 0) + log['bytes']
    
    for user, data_downloaded in download_activity.items():
        if data_downloaded > threshold:
            alert(f"Massive data download detected by {user}")

# 9. Abnormal Increase in Cloud Costs (Crypto-Mining, Resource Hijacking)
def detect_abnormal_cloud_costs(billing_logs, expected_costs):
    for log in billing_logs:
        if log['cost'] > expected_costs * 2:  # Example threshold
            alert(f"Abnormal cloud cost increase detected: ${log['cost']} for {log['service']}")

# 10. Misuse of Serverless Functions (Lambda, Cloud Functions, etc.)
def detect_serverless_misuse(serverless_logs):
    for log in serverless_logs:
        if log['execution_time'] > EXECUTION_THRESHOLD or log['invocations'] > INVOCATION_THRESHOLD:
            alert(f"Potential misuse of serverless function detected: {log['function_name']}")

# Define alert function
def alert(message):
    print("ALERT:", message)

# Constants
EXECUTION_THRESHOLD = 300  # Example execution time threshold in seconds
INVOCATION_THRESHOLD = 1000  # Example invocation count threshold