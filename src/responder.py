import subprocess
import requests
import config

def block_ip(ip: str):
    command = ["sudo", "ufw", "insert", "1", "deny", "from", ip]

    if config.DRY_RUN:
        print(f"[DRY RUN] Would execute: {' '.join(command)}")
        return True

    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[BLOCKED] IP {ip} blocked via UFW.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block {ip}: {e.stderr.decode().strip()}")
        return False

def send_alert(ip: str, attempts: int, intel: dict):
    if not config.DISCORD_WEBHOOK_URL:
        return

    payload = {
        "embeds": [{
            "title": "🚨 Brute-Force Attack Detected",
            "color": 15158332,
            "fields": [
                {"name": "Offending IP", "value": f"`{ip}`", "inline": True},
                {"name": "Failed Attempts", "value": str(attempts), "inline": True},
                {"name": "Abuse Score", "value": str(intel.get("abuseConfidenceScore")), "inline": True},
                {"name": "Total Abuse Reports", "value": str(intel.get("totalReports")), "inline": True},
                {"name": "Action Taken", "value": "Rule Injected (DRY_RUN)" if config.DRY_RUN else "UFW Rule Injected", "inline": False}
            ]
        }]
    }
    try:
        requests.post(config.DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"[ERROR] Webhook notification failed: {e}")
