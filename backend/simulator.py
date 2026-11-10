import json
import os

from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


BASE_DIR = Path(__file__).resolve().parent.parent

SCENARIO_FILE = BASE_DIR / "scenarios" / "test_incident.json"

API_URL = "http://127.0.0.1:8000/events"

TOKEN = os.getenv("BLACKBOX_TOKEN")


def load_scenario():
    with open(SCENARIO_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def send_event(event, scenario_id):
    payload = {
        "source": "blackbox_simulator",
        "event_type": event["event_type"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": event["severity"],
        "data": {
            **event["data"],
            "scenario_id": scenario_id,
            "synthetic": True
        }
    }

    headers = {
        "Content-Type": "application/json"
    }

    if TOKEN:
        headers["X-Collector-Token"] = TOKEN

    request = Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST"
    )

    try:
        with urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))

            print(
                f"[+] Event saved | "
                f"ID: {result['id']} | "
                f"Type: {payload['event_type']}"
            )

    except HTTPError as error:
        print(f"[-] HTTP error: {error.code}")
        print(error.read().decode("utf-8"))

    except URLError as error:
        print(f"[-] Connection error: {error.reason}")


def run_scenario():
    scenario = load_scenario()

    print("=" * 45)
    print(f"BLACKBOX Scenario: {scenario['name']}")
    print(f"Scenario ID: {scenario['scenario_id']}")
    print("=" * 45)

    for event in scenario["events"]:
        send_event(event, scenario["scenario_id"])

    print("=" * 45)
    print("Scenario execution completed")


if __name__ == "__main__":
    run_scenario()
