# P1.Bugs 

A powerful and personalized Bash script designed to automate Nuclei scans. It integrates real-time Slack notifications, provides switchable performance profiles, and generates organized output for efficient vulnerability management.

This script streamlines the process of running Nuclei scans against a list of targets. It's built for security researchers and bug bounty hunters who need an efficient, automated workflow that provides immediate feedback and a clear summary of results.

## Features
- Real-time Slack notifications
- Two scanning profiles (safe/aggressive)
- Prioritized template execution (technologies → CVEs → vulnerabilities)
- Intelligent output saving (only creates files when vulnerabilities found)
- Automatic proxychains integration (if installed)
- Color-coded terminal output
- JSONL logs and human-readable summaries

## Prerequisites
- `nuclei` - The core scanning engine
- `jq` - For JSON processing
- `curl` - For Slack notifications
- (Optional) `proxychains` - For traffic routing

## Installation
1. Clone Nuclei templates:
```bash
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
```

# Basic safe scan with default severities
``./P1.bugs.sh -f targets.txt``

# Aggressive mode scan
``./P1.bugs.sh -f targets.txt -p aggressive``

# Critical severity only
``./P1.bugs.sh -f targets.txt -s critical``

# Aggressive + high & critical
``./P1.bugs.sh -f targets.txt -p aggressive -s high,critical``


```
🚨 <!channel> Vivek New P1 Discovered

Severity: high  
Host: https://vulnerable.example.com  
Affected URL: https://vulnerable.example.com/login.php  
Template: cves/2021/CVE-2021-XXXX.yaml


✅ Scan Completed for Target File: targets.txt

Summary of Findings:
  Critical: 2
  High: 5
  Medium: 12

Detailed results saved to nuclei-results/targets.json  
Summary written to nuclei-results/targets_vulns.txt
```


## Author

Vivek Kashyap
Bugcrowd: (https://bugcrowd.com/realvivek)
X (Twitter): (https://x.com/starkcharry)
GitHub: (https://github.com/7ealvivek)
