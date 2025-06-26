# Email Threat Analyzer

A Python-based tool that detects potentially malicious emails by analyzing headers and embedded links. It’s designed for cybersecurity students and junior analysts to understand real-world phishing signals using SPF, DKIM, DMARC checks and URL scanning via urlscan.io.

---

## Features

- Parses and displays key email headers
- Extracts & scans embedded URLs using [urlscan.io](https://urlscan.io)
- Checks sender authentication (SPF, DKIM, DMARC)
- Detects `From` and `Return-Path` mismatches
- Assigns a total risk score (Safe / Suspicious / Dangerous)
- CLI-based, modular, and easy to extend

---

##  How It Works

1. You provide a `.eml` file (downloaded from Gmail or created manually).
2. The tool parses headers and body content.
3. It checks for:
   - SPF/DKIM/DMARC results
   - Mismatched sender headers
   - Embedded links and their scan results
4. It outputs a report with a **risk score** and explanation.

