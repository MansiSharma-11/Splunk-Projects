# Analyzing SSH Logs Using Splunk SIEM

## Introduction
SSH log files contain valuable information about remote access to servers, including login attempts, commands executed, and session details. Analyzing SSH logs using Splunk SIEM enables security professionals to monitor access to critical systems, detect anomalies, and identify potential security threats.

---

## Prerequisites:
- Splunk Enterprise installed and running
- A SSH log file to ingest (I used a sample ssh.log.gz).

---

## Steps to Upload Sample SSH Log Files to Splunk

### 1. Prepare the Log File

Before uploading, check that your log file captures the essentials:

- src_ip
- src_port
- dst_ip
- dst_port
- Request method
- URL / URI
- Status code
- Timestamp
- User agent

Keep the file somewhere Splunk can reach it.

### 2. Add the Logs to Splunk

- Open the Splunk Web Interface.
- Go to **Settings → Add Data**. (Or can use quick links on home page).
- Select **Upload**.
- Choose your SSH log file.

### 3. Configure the Log

Under **Source Type**, select `ssh` or create a custom type such as `ssh_logs`.

Then check the **Index**, **Host**, and **Source Type** settings to make sure they match your log file.

### 4. Upload and Confirm

Click **Review** and check the configuration. If everything looks correct, click **Submit**.

To make sure the data was added successfully, search:

```spl
index=* sourcetype=ssh_logs
```

---

## Analyzing SSH Logs in Splunk

### 1. Security & Authentication Failures

- Count failures by Source IP: Find out which external or internal IP addresses are generating the most failed SSH logins.

```spl
index=* OR index=_* sourcetype=ssh_logs “failure”
| stats count by src_ip
| sort — count
```

- Track failures over time (Brute-Force spikes): Visualizes spikes in authentication failures to identify targeted attack windows.

```spl
index=* OR index=_* sourcetype=ssh_logs “failure”
| timechart span=5m count by src_ip
```

- Identify targeted destination hosts: See which internal servers are receiving the most failed attempts.

```spl
index=* OR index=_* sourcetype=ssh_logs “failure” | stats count by host, dst_ip | sort — count
```

### 2. General Log Summaries & Profiling

- Authentication status breakdown: See the ratio of failures, undetermined connections, and successes.

```spl
index=* OR index=_* sourcetype=ssh_logs | top limit=20 status
```

- Top talking IP pairs: Map out the most active connections between source and destination IP addresses.

```spl
index=* OR index=_* sourcetype=ssh_logs | stats count by src_ip, dst_ip | sort — count
```

### 3. Set Up an Automated Alert (Brute-Force Detection)

- Step 1: The Alert SPL Query

```spl
index=* OR index=_* sourcetype=ssh_logs “failure” | bucket _time span=5m | stats count as failure_count by _time, src_ip, host | where failure_count > 10
```

(By using bucket _time span=5m, you create a 5-minute window. Splunk can then easily count how many times a specific src_ip attacked you within that specific 5-minute block, allowing the alert to correctly trigger if the count goes over 10.)

- Step 2: Save as an Alert

1. Click Save As in the top-right corner of the search window and select Alert.
2. Fill out the alert settings:
- Title: SSH Brute Force Detection Alert
- Alert Type: Scheduled
- Time Range: Run every 5 minutes (or use a Cron  schedule: */5 * * * *)
- Trigger Conditions: Trigger if Number of Results > 0
3. Trigger Actions: Select Add Action to configure how you want to be notified (e.g., Send Email, Webhook, or Add to Triggered Alerts).

---

## Conclusion

Splunk SIEM transforms raw SSH server logs into an active defense system by continuously parsing Linux authentication records to isolate malicious network behavior. By using Search Processing Language (SPL) to extract critical fields like source IPs and target usernames, security teams can instantly flag brute-force attacks, off-hours administrative access, and compromised accounts. This centralized visibility allows organizations to transition from passive log retention to proactive incident response, triggering real-time alerts that shut down unauthorized remote access before a breach occurs.





