# Security Tools & Scripts 🛠️

**Python and SQL scripts for security automation, log analysis, and threat detection.**

---

## Overview

This repository contains security automation scripts built to streamline SOC workflows, detect threats in log data, and automate repetitive security analysis tasks. All scripts are written in Python and SQL with a focus on practical, production-ready security operations use cases.

---

## Scripts

### 1. Brute Force / Credential Stuffing Detector (`brute_force_detector.py`)

Analyzes security log files to detect potential brute force attacks and credential stuffing by identifying IP addresses with excessive failed login attempts.

```python
import re
from collections import defaultdict

def detect_brute_force(log_file, threshold=5):
    """
    Analyzes security logs to detect brute force attempts.
    
    Args:
        log_file: Path to security log file
        threshold: Number of failed attempts to trigger alert
    
    Returns:
        Dictionary of suspicious IPs and attempt counts
    """
    attempts = defaultdict(int)
    
    with open(log_file, 'r') as f:
        for line in f:
            if "failed login" in line.lower():
                ip = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip:
                    attempts[ip.group()] += 1
    
    suspicious = {ip: count for ip, count in attempts.items() 
                  if count > threshold}
    
    for ip, count in sorted(suspicious.items(), 
                            key=lambda x: x[1], reverse=True):
        level = "CRITICAL" if count > 20 else "WARNING"
        print(f"[{level}] {ip} — {count} failed login attempts")
    
    return suspicious

if __name__ == "__main__":
    import sys
    log_path = sys.argv[1] if len(sys.argv) > 1 else "security_logs.txt"
    print(f"Analyzing {log_path}...\n")
    results = detect_brute_force(log_path)
    print(f"\nScan complete: {len(results)} suspicious IPs flagged")
```

**Sample Output:**
```
Analyzing security_logs.txt...

[CRITICAL] 192.168.4.22 — 47 failed login attempts
[CRITICAL] 10.0.0.187   — 23 failed login attempts
[WARNING]  172.16.3.91  — 11 failed login attempts

Scan complete: 3 suspicious IPs flagged
```

---

### 2. SQL Security Queries

#### Detect Credential Stuffing
```sql
SELECT 
    user_id, 
    source_ip, 
    COUNT(*) AS failed_attempts,
    MIN(attempt_time) AS first_attempt,
    MAX(attempt_time) AS last_attempt
FROM login_attempts
WHERE status = 'failed'
  AND attempt_time > NOW() - INTERVAL '1 hour'
GROUP BY user_id, source_ip
HAVING COUNT(*) > 5
ORDER BY failed_attempts DESC;
```

#### Detect Suspicious Login Times (After-Hours Access)
```sql
SELECT user_id, login_time, source_ip, status
FROM login_attempts
WHERE EXTRACT(HOUR FROM login_time) NOT BETWEEN 6 AND 22
  AND status = 'success'
ORDER BY login_time DESC;
```

#### Identify Privilege Escalation Attempts
```sql
SELECT user_id, action, target_resource, timestamp
FROM audit_logs
WHERE action IN ('GRANT', 'ALTER USER', 'CREATE USER', 'DROP USER')
  AND timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;
```

#### Detect Data Exfiltration Patterns
```sql
SELECT user_id, COUNT(*) AS export_count, SUM(file_size_mb) AS total_mb
FROM file_exports
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY user_id
HAVING SUM(file_size_mb) > 500
ORDER BY total_mb DESC;
```

---

### 3. Log Parser (`log_parser.py`)

Parses and categorizes security events from raw log files into structured output for SIEM ingestion or manual review.

```python
import re
from datetime import datetime

def parse_security_log(log_file):
    """Parse raw security logs into structured events."""
    events = []
    
    patterns = {
        'failed_login': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*failed login.*from (\d+\.\d+\.\d+\.\d+)',
        'port_scan': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*port scan.*from (\d+\.\d+\.\d+\.\d+)',
        'malware': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*malware.*detected.*(\w+\.exe)',
    }
    
    with open(log_file, 'r') as f:
        for line in f:
            for event_type, pattern in patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    events.append({
                        'type': event_type,
                        'timestamp': match.group(1),
                        'indicator': match.group(2),
                        'raw': line.strip()
                    })
    
    return events
```

---

## Requirements

```
Python 3.8+
re (built-in)
collections (built-in)
datetime (built-in)
```

No external dependencies required for core scripts.

---

## Usage

```bash
# Clone the repo
git clone https://github.com/Nangobiiriham/security-tools-scripts.git

# Run brute force detector
python brute_force_detector.py security_logs.txt

# Run log parser
python log_parser.py /var/log/auth.log
```

---

## Skills Demonstrated

- Python scripting for security automation
- SQL security query development
- Log analysis and pattern detection
- IOC identification from raw data
- SIEM workflow automation

---

## Author

**Iriham Nangobi Mukoka**
Cybersecurity Analyst | MBA Candidate — UNC Greensboro

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/nangobi-iriham-mukoka)
[![Portfolio](https://img.shields.io/badge/Portfolio-00d4aa?style=flat&logo=github&logoColor=white)](https://nangobiiriham.github.io)
