# Analyzing HTTP Logs Using Splunk SIEM

## Introduction

Every time a client talks to a web server, that exchange gets written down in an HTTP log — things like when it happened, what was requested, which URL, how the server responded, and what client made the request.

Digging into these logs with Splunk lets security analysts:

- Get a feel for what "normal" traffic looks like
- Catch activity that stands out as odd or risky
- Dig deeper when something points to a possible web attack

---

## Prerequisites

- A working Splunk Enterprise setup.
- A sample HTTP log file ready to go (e.g., `http.log`).

Don't have a sample file handy? You can grab a public one here: [MACCDC 2012 http.log.gz](https://secrepo.com/maccdc2012/http.log.gz). Download it, and you'll have a real HTTP log ready to upload.

---

## Steps to Upload Sample HTTP Log Files to Splunk

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

- Log into the Splunk Web Interface.
- Navigate to **Settings → Add Data**.
- Pick **Upload**.

### 3. Choose the File

Hit **Select File** and pick out your HTTP log.

### 4. Set the Source Type

In the **Source Type** field, pick whatever fits HTTP data best, or set up a custom one if nothing matches.

### 5. Review the Settings

Double-check the **Index**, **Host**, and **Source Type** line up with your file before moving on.

### 6. Upload and Confirm

Click **Review**, look everything over once more, then hit **Submit**.

Once it's in, confirm it landed correctly with:

```spl
index=<your_index> sourcetype=<your_sourcetype>               
```
For example:
```spl
index=* OR index=_* sourcetype="http_logs"             
```
---

## Analyzing HTTP Logs in Splunk

### 1. View HTTP Events

Kick things off by pulling up your HTTP events:

```spl
index=<your_index> sourcetype=<your_sourcetype>
```

### 2. Review Traffic Patterns

Break down requests by method to see the mix:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| stats count by method
```

Check which URLs get hit the most:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| top limit=10 uri
```

Group by status code to spot what's succeeding versus failing:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| stats count by status
```

### 3. Look for Unusual Activity

See how traffic volume shifts over time:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| timechart span=1h count
```

Pull out just the error responses:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| stats count by status
| where status >= 400
```

Dig into activity tied to one particular IP:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| search src_ip="suspicious_ip"
```

### 4. Review User Behavior

Look for accounts hit with repeated failed logins:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| search action="login" status="failed"
| stats count by user
```

Get a sense of how long sessions typically run per user:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| stats range(_time) as session_duration by session_id
| stats avg(session_duration) as avg_session_duration by user
```

### 5. Identify Suspicious User Agents

Rank user agents by how often they show up:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| stats count by http_user_agent
| sort -count
```

Call out any agents tied to known scanning or attack tools:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| regex http_user_agent="(?i)(sqlmap|nikto|curl|python-requests|nmap)"
```

### 6. Identify Brute-Force or DoS Activity

Flag IPs firing off way more requests than normal in a tight window:

```spl
index=<your_index> sourcetype=<your_sourcetype>
| bucket _time span=1m
| stats count by _time, src_ip
| where count > 100
```

### 7. Watch for 404 Spikes

If one source suddenly racks up a lot of 404s, that can mean someone's probing for pages that shouldn't be found:

```spl
index=<your_index> sourcetype=<your_sourcetype> status=404
| timechart span=5m count by src_ip
```

### 8. Set Up Alerts

Turn any of these searches into a scheduled alert — say, one that fires on repeated failed logins — so you're notified automatically instead of having to check manually.

---

## Conclusion

Working through HTTP logs in Splunk gives you a clear window into what's happening on your web server and network. Between tracking traffic patterns, catching error spikes, and flagging suspicious user agents, analysts can pick up on problems sooner and respond to web-based threats faster.

Feel free to tweak these steps to match your own setup.