import os
import sys
import time
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import Fore, Style, init

init(autoreset=True)

CONFIG = {
    "threshold": 10,
    "time_window": 2,
    "suspicious_extensions": [
        ".locked", ".encrypted", ".crypto", ".crypt",
        ".locky", ".zepto", ".cerber", ".wncry"
    ],
    "log_file": "detection_log.json"
}


class RansomwareDetector(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.file_changes = []
        self.threats_detected = 0
        self.total_events = 0

    def log_event(self, event_type, filepath, details):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "file": filepath,
            "details": details
        }
        with open(self.config["log_file"], "a") as f:
            f.write(json.dumps(entry) + "\n")

    def is_suspicious_extension(self, filepath):
        return any(
            filepath.lower().endswith(ext)
            for ext in self.config["suspicious_extensions"]
        )

    def check_behavior(self, filepath, event_type):
        current_time = time.time()
        self.total_events += 1
        self.file_changes.append(current_time)

        self.file_changes = [
            t for t in self.file_changes
            if current_time - t <= self.config["time_window"]
        ]

        change_rate = len(self.file_changes)

        if change_rate >= self.config["threshold"]:
            self.alert_ransomware(filepath, change_rate)
            self.file_changes = []

        if self.is_suspicious_extension(filepath):
            self.alert_suspicious_file(filepath)

    def alert_ransomware(self, filepath, rate):
        self.threats_detected += 1
        print("\n" + Fore.RED + "!" * 60)
        print(Fore.RED + Style.BRIGHT + "!!! RANSOMWARE BEHAVIOR DETECTED !!!")
        print(Fore.RED + "!" * 60)
        print(Fore.YELLOW + f"  File: {filepath}")
        print(Fore.YELLOW + f"  Change rate: {rate} files in {self.config['time_window']}s")
        print(Fore.YELLOW + f"  Time: {datetime.now().strftime('%H:%M:%S')}")
        print(Fore.RED + "!" * 60 + "\n")
        self.log_event("RANSOMWARE_BEHAVIOR", filepath, f"rate={rate}")

    def alert_suspicious_file(self, filepath):
        self.threats_detected += 1
        print(Fore.MAGENTA + f"[!] Suspicious file detected: {filepath}")
        self.log_event("SUSPICIOUS_EXTENSION", filepath, "encrypted extension")

    def on_modified(self, event):
        if event.is_directory:
            return
        self.check_behavior(event.src_path, "modified")

    def on_created(self, event):
        if event.is_directory:
            return
        self.check_behavior(event.src_path, "created")

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.check_behavior(event.src_path, "deleted")

    def on_moved(self, event):
        if event.is_directory:
            return
        self.check_behavior(event.dest_path, "moved")


def show_banner():
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "   RANSOMWARE BEHAVIOR DETECTION SYSTEM")
    print(Fore.CYAN + "   Real-time Behavioral Analysis Engine")
    print(Fore.CYAN + "   Version 1.0")
    print(Fore.CYAN + "=" * 60)


def main():
    show_banner()

    folder = input(Fore.WHITE + "\n[?] Enter folder to monitor: ").strip().strip('"')

    if not os.path.isdir(folder):
        print(Fore.RED + "[!] Folder not found!")
        sys.exit(1)

    print(Fore.GREEN + f"\n[+] Monitoring: {folder}")
    print(Fore.GREEN + f"[+] Threshold: {CONFIG['threshold']} changes / {CONFIG['time_window']}s")
    print(Fore.YELLOW + "[!] Press Ctrl+C to stop\n")

    detector = RansomwareDetector(CONFIG)
    observer = Observer()
    observer.schedule(detector, folder, recursive=True)

    try:
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(Fore.CYAN + "\n\n[i] Stopping monitor...")
        print(Fore.CYAN + f"[i] Total events monitored: {detector.total_events}")
        print(Fore.CYAN + f"[i] Threats detected: {detector.threats_detected}")
        print(Fore.CYAN + f"[i] Log saved to: {CONFIG['log_file']}")

    observer.join()


if __name__ == "__main__":
    main()