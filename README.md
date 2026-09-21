# Ransomware Behavior Detection System

A real-time ransomware detection tool that monitors file system activity and identifies suspicious encryption patterns using behavioral analysis.

---

## Problem It Solves

Traditional antivirus software uses **signature-based detection** — it can only catch known ransomware. New ransomware variants bypass this easily.

This tool uses **behavioral analysis** to detect ransomware-like activity even if the malware is brand new and has never been seen before.

---

## How It Works

1. **Real-time Monitoring** — Uses the `watchdog` library to monitor file system events (create, modify, delete, move)
2. **Behavioral Analysis** — Tracks the rate of file changes within a rolling time window
3. **Threat Detection** — If more than 10 files change within 2 seconds (configurable), it flags ransomware behavior
4. **Signature Detection** — Also watches for known ransomware file extensions (`.locked`, `.encrypted`, `.crypto`, etc.)
5. **Logging** — All detections are logged to a JSON file for forensic analysis

---

## Features

- Real-time file system monitoring
- Configurable threshold and time window
- Suspicious file extension detection
- Colored terminal alerts
- JSON logging for post-incident analysis
- Lightweight and fast
- Zero dependencies on external services

---

## Tech Stack

- Python 3
- watchdog — file system event monitoring
- psutil — system and process utilities
- colorama — colored terminal output
