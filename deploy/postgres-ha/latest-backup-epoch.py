#!/usr/bin/env python3
import json
import sys


def main() -> None:
    payload = json.load(sys.stdin)
    stops = [
        backup["timestamp"]["stop"]
        for stanza in payload
        for backup in stanza.get("backup", [])
        if backup.get("timestamp", {}).get("stop")
    ]
    if not stops:
        raise SystemExit("no completed pgBackRest backup is available")
    print(max(stops))


if __name__ == "__main__":
    main()
