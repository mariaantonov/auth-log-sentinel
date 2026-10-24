import sys
import os
import config
from src.parser import parse_log_line
from src.detector import ThreatDetector
from src.responder import block_ip, send_alert

def process_log(file_path: str):
    if not os.path.exists(file_path):
        print(f"File {file_path} not found.")
        sys.exit(1)

    detector = ThreatDetector()
    print(f"[*] Processing {file_path} (DRY_RUN={config.DRY_RUN})...\n")

    with open(file_path, "r") as f:
        for line in f:
            event = parse_log_line(line)
            if not event:
                continue

            if detector.process_event(event):
                ip = event["ip"]
                print(f"[!] Alert: High-rate failed attempts from {ip}")
                intel = detector.check_reputation(ip)
                block_ip(ip)
                send_alert(ip, config.THRESHOLD, intel)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "samples/test_auth.log"
    process_log(target)
