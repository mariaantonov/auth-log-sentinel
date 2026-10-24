import re
from datetime import datetime

FAILED_LOGIN_REGEX = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_log_line(line: str, current_year: int = datetime.now().year):
    match = FAILED_LOGIN_REGEX.search(line)
    if not match:
        return None

    raw_time = match.group("timestamp")
    parsed_dt = datetime.strptime(f"{current_year} {raw_time}", "%Y %b %d %H:%M:%S")

    return {
        "timestamp": parsed_dt,
        "user": match.group("user"),
        "ip": match.group("ip")
    }
