# Analyzing HTTP Log Files Using Splunk SIEM

## Introduction

HTTP logs matter because they:

- Contain useful information about web server activity, like requests, responses, user agents, and more.

- Help security analysts monitor web traffic, spot unusual activity, and find possible threats when analyzed in Splunk.

---

## Prerequisites

- Splunk Enterprise installed and running.
- An HTTP log file to upload (I used a sample `http.log`).

---

## Steps to Upload Sample HTTP Log Files to Splunk SIEM

### 1. Prepare Sample HTTP Log Files

- Get sample HTTP log files in a suitable format (e.g., text files).
- Make sure the log files include key HTTP details, such as timestamps, request methods, URLs, response codes, user agents, etc.
- Save the sample log files somewhere the Splunk instance can access.

### 2. Upload Log Files to Splunk

- Log in to the Splunk web interface.
- Go to **Settings > Add Data**.
- Choose **Upload** as the data input method.

### 3. Choose File

- Click **Select File** and pick the sample HTTP log file you prepared earlier.

### 4. Set Source Type

- In the **Set Source Type** section, choose a source type for the uploaded log file.
- Pick the right source type for HTTP logs (e.g., `access_combined` or a custom one if needed).

### 5. Review Settings

- Check settings like index, host, and sourcetype.
- Make sure they match your sample HTTP log file correctly.

### 6. Click Upload

- Once everything is set, click **Review**.
- Double-check the settings one last time.
- Click **Submit** to upload the sample HTTP log file to Splunk.

### 7. Verify Upload

- After uploading, go to the search bar in Splunk.
- Run a search to check that the HTTP events show up correctly.

---

## Steps to Analyze HTTP Log Files in Splunk SIEM

### 1. Search for HTTP Events

Open the Splunk search bar and run this query to pull up HTTP events:

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
```

### 2. Extract Relevant Fields

Find key fields in the HTTP logs, such as timestamps, request methods, URLs, response codes, and user agents. Use Splunk's field extraction tools or regular expressions to pull these fields out for easier analysis.

Example extraction command:

```spl
| rex field=_raw "<regex_pattern>"
```

### 3. Analyze Web Traffic Patterns

Check how requests are spread across methods (GET, POST, etc.) to understand traffic patterns.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| stats count by method
```

Find the top URLs or pages users are visiting.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| top limit=10 uri
```

Look at response codes to see which requests failed and which succeeded.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| stats count by status
```

### 4. Detect Anomalies

Look for unusual patterns in activity over time.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| timechart span=1h count by _time
```

Check for a high number of error responses:

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| stats count by status
| where status >= 400
```

Look into activity from suspicious IP addresses.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| search src_ip="suspicious_ip"
```

### 5. Monitor User Behavior

Find users with several failed login attempts or unauthorized access tries:

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| search action="login" status="failed"
| stats count by user
```

Check how long user sessions last and how users move through the site:

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| stats range(_time) as session_duration by session_id
| stats avg(session_duration) as avg_session_duration by user
```

---

## More Ways to Analyze and Query HTTP Logs

### 6. Identify Suspicious User Agents

Bots and scripted attacks often use unusual or outdated user agent strings.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| stats count by http_user_agent
| sort -count
```

Flag known bad or bot-like user agents:

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| regex http_user_agent="(?i)(sqlmap|nikto|curl|python-requests|nmap)"
```

### 7. Detect Web Attack Patterns (SQLi, XSS, Path Traversal)

Search request URLs for common attack signs.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| regex uri="(?i)(union select|<script>|\.\./|etc/passwd)"
```

### 8. Identify Potential Brute-Force or DoS Activity

Find source IPs sending an unusually high number of requests in a short time.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| bucket _time span=1m
| stats count by _time, src_ip
| where count > 100
```

### 9. Track Bandwidth and Large Response Sizes

Find requests that send unusually large amounts of data (possible data theft).

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| stats sum(bytes) as total_bytes by src_ip
| sort -total_bytes
```

### 10. Analyze Top Referrers and Traffic Sources

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| stats count by referer
| sort -count
```

### 11. Geolocation Analysis of Source IPs

Add location data to IP addresses to spot traffic coming from unexpected places.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| iplocation src_ip
| stats count by Country, src_ip
```

### 12. Track 404/Error Spikes (Possible Reconnaissance)

A sudden jump in 404 errors from one source can mean someone is scanning for pages or endpoints.

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype> status=404
| timechart span=5m count by src_ip
```

### 13. Correlate HTTP Logs with Threat Intelligence

Compare source IPs against a list of known bad IPs (a lookup table).

```spl
index=<your_http_index> sourcetype=<your_http_sourcetype>
| lookup threat_intel_ips.csv ip AS src_ip OUTPUT threat_score
| where threat_score > 0
```

### 14. Set Up Alerts for Ongoing Monitoring

Save any of the searches above as a scheduled alert (for example, trigger one when failed logins for a user go past a set limit), so problems get flagged automatically instead of needing manual checks.

---

## Conclusion

Analyzing HTTP log files with Splunk SIEM gives useful insight into web server and web traffic activity on a network. By monitoring HTTP events, pulling out key fields, spotting issues like brute-force attempts, error spikes, and suspicious user agents, and checking findings against threat intelligence, organizations can improve their security and react faster to web-based threats.

Feel free to adjust these steps to fit your own use case and needs.

Happy analyzing!