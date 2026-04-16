#!/usr/bin/env python3
"""
Container-friendly Optimus checker.

- Authenticates to Optimus Tracking
- Fetches latest positions
- Publishes to MQTT topic cars/<name>
- Skips MQTT publish when lat/lon did not change per device
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

import paho.mqtt.client as mqtt
import requests

BASE_URL = "https://www.optimustracking.com"
LOGIN_URL = f"{BASE_URL}/Account/Login"
GET_DEVICES_URL = f"{BASE_URL}/Home/GetDevices"
SESSION_FILE = "/data/optimus_session.json"
MQ_STATE_FILE = "/data/optimus_mq_state.json"

USERNAME = os.environ.get("OPTIMUS_USER", "")
PASSWORD = os.environ.get("OPTIMUS_PASS", "")
MQ_ADDRESS = os.environ.get("MQ_ADDRESS", "mosquitto.dickinson")
MQ_PORT = int(os.environ.get("MQ_PORT", "1883"))
MQ_TOPIC_PREFIX = os.environ.get("MQ_TOPIC_PREFIX", "cars").strip("/") or "cars"

DEVICE_ID = os.environ.get("OPTIMUS_DEVICE_ID", "7521b464-3e59-4af2-8f6a-5a93500dd555")


def load_session(session: requests.Session) -> bool:
    if not os.path.exists(SESSION_FILE):
        return False
    try:
        with open(SESSION_FILE, encoding="utf-8") as f:
            cookies = json.load(f)
        for name, value in cookies.items():
            session.cookies.set(name, value, domain="www.optimustracking.com")
        print(f"[auth] Loaded saved session from {SESSION_FILE}")
        return True
    except Exception as exc:
        print(f"[auth] Could not load session file: {exc}")
        return False


def save_session(session: requests.Session) -> None:
    cookies = {c.name: c.value for c in session.cookies}
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(cookies, f)
    os.chmod(SESSION_FILE, 0o600)
    print(f"[auth] Session saved to {SESSION_FILE}")


def session_is_valid(session: requests.Session) -> bool:
    try:
        response = session.post(GET_DEVICES_URL, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return isinstance(data, dict) and len(data) > 0
    except Exception:
        pass
    return False


def login(session: requests.Session) -> bool:
    if not USERNAME or not PASSWORD:
        print("[error] Set OPTIMUS_USER and OPTIMUS_PASS in environment.")
        return False

    print("[auth] Logging in...")
    payload = {
        "DeviceId": DEVICE_ID,
        "Username": USERNAME,
        "Password": PASSWORD,
    }
    response = session.post(LOGIN_URL, data=payload, allow_redirects=True, timeout=15)

    if "verify" in response.url.lower() or "twofactor" in response.url.lower() or "code" in response.url.lower():
        print("[error] 2FA required. Container mode is non-interactive.")
        return False

    if session_is_valid(session):
        print("[auth] Login successful.")
        save_session(session)
        return True

    print(f"[auth] Login failed. Status {response.status_code}, landed at: {response.url}")
    return False


def get_devices(session: requests.Session) -> dict:
    response = session.post(GET_DEVICES_URL, timeout=15)
    response.raise_for_status()
    return response.json()


def parse_report_date(raw_value: str | None) -> tuple[str | None, str | None]:
    if not isinstance(raw_value, str):
        return None, None
    match = re.search(r"/Date\((\d+)(?:[+-]\d+)?\)/", raw_value)
    if not match:
        return None, None
    epoch_ms = int(match.group(1))
    dt_utc = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    dt_local = dt_utc.astimezone()
    return dt_utc.isoformat(), dt_local.isoformat()


def extract_positions(devices: dict) -> list[dict]:
    positions: list[dict] = []
    for device_id, device in devices.items():
        last_position = device.get("LastPosition")
        if not last_position:
            continue
        raw_report_date = last_position.get("ReportDate")
        report_date_utc, report_date_local = parse_report_date(raw_report_date)
        positions.append(
            {
                "device_id": device_id,
                "description": device.get("Description", ""),
                "latitude": last_position.get("Latitude"),
                "longitude": last_position.get("Longitude"),
                "speed_mph": last_position.get("Speed"),
                "azimuth": last_position.get("Azimuth"),
                "altitude_ft": last_position.get("Altitude"),
                "report_date": raw_report_date,
                "report_date_utc": report_date_utc,
                "report_date_local": report_date_local,
                "event": last_position.get("Event"),
                "signal": last_position.get("Signal"),
                "idling": last_position.get("IsVehicleIdling"),
            }
        )
    return positions


def topic_from_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "unknown"


def load_publish_state() -> dict[str, dict[str, float | None]]:
    if not os.path.exists(MQ_STATE_FILE):
        return {}
    try:
        with open(MQ_STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_publish_state(state: dict[str, dict[str, float | None]]) -> None:
    with open(MQ_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.chmod(MQ_STATE_FILE, 0o600)


def location_key(position: dict) -> dict[str, float | None]:
    return {"latitude": position.get("latitude"), "longitude": position.get("longitude")}


def publish_positions(positions: list[dict]) -> None:
    state = load_publish_state()
    changed = False
    published_count = 0
    skipped_count = 0

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(MQ_ADDRESS, MQ_PORT, keepalive=60)
    client.loop_start()
    try:
        for position in positions:
            device_id = str(position.get("device_id", ""))
            current_loc = location_key(position)
            if state.get(device_id) == current_loc:
                skipped_count += 1
                print(f"[mq] Skipped {device_id} (location unchanged)")
                continue

            topic = f"{MQ_TOPIC_PREFIX}/{topic_from_name(position.get('description', ''))}"
            payload = json.dumps(position, separators=(",", ":"))
            info = client.publish(topic, payload=payload, qos=0, retain=False)
            info.wait_for_publish()
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f"publish failed for topic {topic} with rc={info.rc}")

            state[device_id] = current_loc
            changed = True
            published_count += 1
            print(f"[mq] Published {device_id} to {topic}")
    finally:
        client.loop_stop()
        client.disconnect()

    if changed:
        save_publish_state(state)
    print(f"[mq] Publish summary: {published_count} sent, {skipped_count} skipped")


def run_once() -> int:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Referer": BASE_URL,
        }
    )

    loaded = load_session(session)
    if loaded and session_is_valid(session):
        print("[auth] Saved session is still valid, skipping login.")
    else:
        if loaded:
            print("[auth] Saved session has expired, re-authenticating.")
        if not login(session):
            print("[error] Could not authenticate.")
            return 1

    print("[data] Fetching device positions...")
    devices = get_devices(session)
    positions = extract_positions(devices)
    if not positions:
        print("[data] No positions returned.")
        return 0

    print(f"[mq] Publishing to broker {MQ_ADDRESS}:{MQ_PORT} ...")
    publish_positions(positions)
    print(json.dumps(positions, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(run_once())
