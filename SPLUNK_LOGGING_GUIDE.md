# Splunk Universal Forwarder Integration Guide

## Overview
The integrated anomaly detection system now logs anomalies in a Splunk-compatible JSON format that can be ingested by Splunk Universal Forwarder.

## Log File Location
```
/home/shannu/Documents/capstone_project/N_A_D/logs/splunk_anomalies.log
```

## Log Format
Each anomaly is logged as a single-line JSON object with the following fields:

```json
{
  "timestamp": "2024-12-27T10:30:45.123456",
  "event_type": "network_anomaly",
  "severity": "high",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.50",
  "protocol": "TCP",
  "flow_id": "192.168.1.100:45678 -> 10.0.0.50:443",
  "confidence_score": 92.5,
  "duration_seconds": 5.2,
  "packet_count": "150 fwd, 120 bwd",
  "byte_count": "75000 fwd, 60000 bwd",
  "packet_rate": 52.3,
  "detection_time": "10:30:45",
  "anomaly_id": 42,
  "interface": "wlan0",
  "threshold": 0.7
}
```

## Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO8601 | UTC timestamp of anomaly detection |
| `event_type` | string | Always "network_anomaly" |
| `severity` | string | high (≥90%), medium (75-89%), low (<75%) |
| `source_ip` | string | Source IP address |
| `destination_ip` | string | Destination IP address |
| `protocol` | string | Network protocol (TCP, UDP, etc.) |
| `flow_id` | string | Unique flow identifier |
| `confidence_score` | float | ML model confidence (0-100) |
| `duration_seconds` | float | Flow duration |
| `packet_count` | string | Packet counts (forward/backward) |
| `byte_count` | string | Byte counts (forward/backward) |
| `packet_rate` | float | Packets per second |
| `detection_time` | string | Human-readable detection time |
| `anomaly_id` | integer | Sequential anomaly ID |
| `interface` | string | Network interface monitored |
| `threshold` | float | Detection threshold used |

## Splunk Universal Forwarder Setup

### 1. Install Splunk Universal Forwarder
```bash
# Download from https://www.splunk.com/en_us/download/universal-forwarder.html
wget -O splunkforwarder.tgz "https://download.splunk.com/products/universalforwarder/releases/..."
tar xvzf splunkforwarder.tgz -C /opt
```

### 2. Configure Input
Create or edit `/opt/splunkforwarder/etc/system/local/inputs.conf`:

```ini
[monitor:///home/shannu/Documents/capstone_project/N_A_D/logs/splunk_anomalies.log]
disabled = false
index = main
sourcetype = _json
source = network_anomaly_detector
```

### 3. Configure Output (to Splunk Enterprise)
Edit `/opt/splunkforwarder/etc/system/local/outputs.conf`:

```ini
[tcpout]
defaultGroup = splunk_indexers

[tcpout:splunk_indexers]
server = <SPLUNK_INDEXER_IP>:9997
```

### 4. Start Forwarder
```bash
/opt/splunkforwarder/bin/splunk start
/opt/splunkforwarder/bin/splunk enable boot-start
```

## Splunk Search Queries

### View All Anomalies
```spl
index=main sourcetype=_json event_type=network_anomaly
```

### High Severity Anomalies
```spl
index=main sourcetype=_json event_type=network_anomaly severity=high
| table timestamp source_ip destination_ip protocol confidence_score
```

### Anomalies by Source IP
```spl
index=main sourcetype=_json event_type=network_anomaly
| stats count by source_ip
| sort -count
```

### Anomalies Over Time
```spl
index=main sourcetype=_json event_type=network_anomaly
| timechart count by severity
```

### Top Protocols with Anomalies
```spl
index=main sourcetype=_json event_type=network_anomaly
| stats count avg(confidence_score) by protocol
| sort -count
```

### High Confidence Anomalies (>90%)
```spl
index=main sourcetype=_json event_type=network_anomaly confidence_score>=90
| table timestamp source_ip destination_ip protocol confidence_score flow_id
```

## Creating Splunk Alerts

### Alert on High Severity Anomalies
1. Go to Search & Reporting
2. Run search:
   ```spl
   index=main sourcetype=_json event_type=network_anomaly severity=high
   ```
3. Save As → Alert
4. Set trigger conditions (e.g., "Number of Results > 5 in 5 minutes")
5. Add action (Email, Webhook, etc.)

### Alert on Specific IP
```spl
index=main sourcetype=_json event_type=network_anomaly 
(source_ip="<SUSPICIOUS_IP>" OR destination_ip="<SUSPICIOUS_IP>")
```

## Dashboard Creation

Create a Splunk dashboard with:

1. **Anomaly Count Over Time**
   ```spl
   index=main sourcetype=_json event_type=network_anomaly
   | timechart count
   ```

2. **Severity Distribution**
   ```spl
   index=main sourcetype=_json event_type=network_anomaly
   | stats count by severity
   ```

3. **Top Source IPs**
   ```spl
   index=main sourcetype=_json event_type=network_anomaly
   | top source_ip limit=10
   ```

4. **Average Confidence Score**
   ```spl
   index=main sourcetype=_json event_type=network_anomaly
   | stats avg(confidence_score) as "Average Confidence"
   ```

## Log Rotation

To prevent unlimited log growth, configure log rotation in `/etc/logrotate.d/splunk_anomalies`:

```
/home/shannu/Documents/capstone_project/N_A_D/logs/splunk_anomalies.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 root root
    postrotate
        systemctl reload splunkforwarder
    endscript
}
```

## Testing

Test the integration:

```bash
# 1. Start the detection system
sudo ./venv/bin/python3 integrated_web_app.py --interface wlan0 --threshold 0.7

# 2. Generate some traffic to trigger anomalies

# 3. Verify log file
tail -f logs/splunk_anomalies.log

# 4. Check in Splunk
# Open Splunk Web UI and search:
index=main sourcetype=_json event_type=network_anomaly | head 10
```

## Troubleshooting

### Forwarder Not Sending Data
```bash
# Check forwarder status
/opt/splunkforwarder/bin/splunk list forward-server

# Check internal logs
tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log
```

### JSON Parsing Issues
Verify JSON format:
```bash
tail -1 logs/splunk_anomalies.log | python3 -m json.tool
```

### Permissions
Ensure Splunk forwarder has read access:
```bash
chmod 644 logs/splunk_anomalies.log
chown root:root logs/splunk_anomalies.log
```

## Notes

- Each anomaly generates ONE JSON line in the log file
- No duplicate logging - anomalies are logged once when detected
- JSON format is automatically parsed by Splunk with `sourcetype=_json`
- All timestamps are in ISO 8601 format for consistent time parsing
- The log file persists across application restarts
