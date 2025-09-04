import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

import yaml


LINUX_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) .* Failed password for "
    r"(?P<user>\w+) from (?P<ip>[\d\.]+)"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="LogHunter - brute force detector (synthetic logs)"
    )
    parser.add_argument("--logs", required=True, help="Caminho do arquivo de log (texto)")
    parser.add_argument("--rules", required=True, help="Arquivo YAML com regras")
    parser.add_argument("--out", required=True, help="Arquivo de saída (JSON) com alertas")
    return parser.parse_args()


def load_rules(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_linux_auth_line(line: str):
    match = LINUX_RE.match(line.strip())
    if not match:
        return None
    d = match.groupdict()
    return {
        "ts": datetime.fromisoformat(d["ts"]),
        "user": d["user"],
        "ip": d["ip"],
        "event": "failed_password",
    }


def detect_bruteforce(events: list[dict], rules: dict) -> list[dict]:
    threshold = int(rules.get("threshold", 5))
    window_min = int(rules.get("window_minutes", 10))
    window = timedelta(minutes=window_min)

    alerts: list[dict] = []
    grouped: dict[tuple[str, str], list[datetime]] = defaultdict(list)  # (user, ip) -> times

    for e in events:
        if e.get("event") != "failed_password":
            continue
        grouped[(e["user"], e["ip"])].append(e["ts"])

    for (user, ip), times in grouped.items():
        times.sort()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                alerts.append(
                    {
                        "rule": "bruteforce_failed_password",
                        "user": user,
                        "ip": ip,
                        "count": count,
                        "window_minutes": window_min,
                        "first_seen": times[start].isoformat(),
                        "last_seen": times[end].isoformat(),
                        "severity": "medium",
                    }
                )
                break

    return alerts


def main():
    args = parse_args()
    rules = load_rules(args.rules)

    events = []
    with open(args.logs, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_linux_auth_line(line)
            if parsed:
                events.append(parsed)

    alerts = detect_bruteforce(events, rules)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    print(json.dumps(alerts, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
