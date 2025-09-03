from pathlib import Path
from src.loghunter import detect_bruteforce, parse_linux_auth_line

def test_detection_generates_alerts():
    lines = Path("samples/linux_auth.log").read_text(encoding="utf-8").splitlines()
    events = [parse_linux_auth_line(l) for l in lines if parse_linux_auth_line(l)]
    rules = {"threshold": 5, "window_minutes": 10}
    alerts = detect_bruteforce(events, rules)
    assert isinstance(alerts, list) and len(alerts) >= 1
