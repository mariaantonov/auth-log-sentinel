from collections import defaultdict
from datetime import timedelta
import requests
import config

class ThreatDetector:
    def __init__(self):
        self.ip_tracker = defaultdict(list)
        self.blocked_ips = set()

    def process_event(self, event: dict) -> bool:
        ip = event["ip"]
        now = event["timestamp"]

        if ip in config.WHITELIST or ip in self.blocked_ips:
            return False

        cutoff = now - timedelta(seconds=config.TIME_WINDOW)
        self.ip_tracker[ip] = [t for t in self.ip_tracker[ip] if t >= cutoff]
        self.ip_tracker[ip].append(now)

        if len(self.ip_tracker[ip]) >= config.THRESHOLD:
            self.blocked_ips.add(ip)
            return True
        return False

    def check_reputation(self, ip: str) -> dict:
        if not config.ABUSEIPDB_API_KEY:
            return {"abuseConfidenceScore": "N/A", "totalReports": "N/A"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            res = requests.get(url, headers=headers, params=params, timeout=5)
            if res.status_code == 200:
                data = res.json().get("data", {})
                return {
                    "abuseConfidenceScore": f"{data.get('abuseConfidenceScore')}%",
                    "totalReports": data.get("totalReports", 0)
                }
        except Exception:
            pass
        return {"abuseConfidenceScore": "Error", "totalReports": "Error"}
