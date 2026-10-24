import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
DRY_RUN = os.getenv("DRY_RUN", "True").lower() == "true"
THRESHOLD = int(os.getenv("THRESHOLD_FAILED_ATTEMPTS", 4))
TIME_WINDOW = int(os.getenv("TIME_WINDOW_SECONDS", 120))
WHITELIST = [ip.strip() for ip in os.getenv("WHITELIST_IPS", "127.0.0.1").split(",")]
