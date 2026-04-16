#!/usr/bin/env python3
"""
Container-friendly Optimus checker.

- Authenticates to Optimus Tracking
- Fetches latest positions
- Publishes to MQTT topic cars/<name>
- Skips MQTT publish when lat/lon did not change per device

Refresh session (including SMS 2FA) inside the running container:

    docker exec -it optimus-checker python /app/app.py login

Non-interactive SMS code:

    docker exec optimus-checker python /app/app.py login --code 123456
"""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

import paho.mqtt.client as mqtt
import requests

BASE_URL = "https://www.optimustracking.com"
LOGIN_URL = f"{BASE_URL}/Account/Login"
GET_DEVICES_URL = f"{BASE_URL}/Home/GetDevices"
SESSION_FILE = "/data/optimus_session.json"
MQ_STATE_FILE = "/data/optimus_mq_state.json"
DEVICE_ID_FILE = "/data/optimus_device_id.txt"

USERNAME = os.environ.get("OPTIMUS_USER", "")
PASSWORD = os.environ.get("OPTIMUS_PASS", "")
MQ_ADDRESS = os.environ.get("MQ_ADDRESS", "mosquitto.dickinson")
MQ_PORT = int(os.environ.get("MQ_PORT", "1883"))
MQ_TOPIC_PREFIX = os.environ.get("MQ_TOPIC_PREFIX", "cars").strip("/") or "cars"


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
    os.makedirs(os.path.dirname(SESSION_FILE) or ".", exist_ok=True)
    cookies = {c.name: c.value for c in session.cookies}
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(cookies, f)
    os.chmod(SESSION_FILE, 0o600)
    print(f"[auth] Session saved to {SESSION_FILE}")


def get_device_id() -> str:
    """
    Resolve login DeviceId with this precedence:
    1) OPTIMUS_DEVICE_ID environment override
    2) persisted /data device id file
    3) generated UUID persisted for future runs
    """
    env_device_id = os.environ.get("OPTIMUS_DEVICE_ID", "").strip()
    if env_device_id:
        return env_device_id

    try:
        if os.path.exists(DEVICE_ID_FILE):
            with open(DEVICE_ID_FILE, encoding="utf-8") as f:
                persisted = f.read().strip()
            if persisted:
                return persisted
    except OSError:
        pass

    generated = str(uuid.uuid4())
    try:
        os.makedirs(os.path.dirname(DEVICE_ID_FILE) or ".", exist_ok=True)
        with open(DEVICE_ID_FILE, "w", encoding="utf-8") as f:
            f.write(generated + "\n")
        os.chmod(DEVICE_ID_FILE, 0o600)
        print(f"[auth] Generated persistent DeviceId at {DEVICE_ID_FILE}")
    except OSError as exc:
        # Continue with in-memory ID if file write fails.
        print(f"[auth] Could not persist DeviceId ({exc}); using generated value for this run.")
    return generated


def session_is_valid(session: requests.Session) -> bool:
    try:
        response = session.post(GET_DEVICES_URL, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return isinstance(data, dict) and len(data) > 0
    except Exception:
        pass
    return False


def _two_factor_url(response: requests.Response) -> str | None:
    url = response.url.lower()
    # Optimus has used routes like /Account/M2FactorAuth for SMS flows.
    # Detect broader 2FA patterns so login --code works reliably.
    if (
        "verify" in url
        or "twofactor" in url
        or "2factor" in url
        or "factorauth" in url
        or "code" in url
    ):
        return response.url
    return None


def handle_2fa(session: requests.Session, two_factor_url: str, code: str) -> bool:
    payload = {"Code": code}
    response = session.post(two_factor_url, data=payload, allow_redirects=True, timeout=15)
    if session_is_valid(session):
        print("[auth] 2FA verified, login successful.")
        save_session(session)
        return True
    print(f"[auth] 2FA verification failed. Status {response.status_code}, url: {response.url}")
    return False


def _read_sms_code(cli_code: str | None) -> str | None:
    if cli_code:
        return cli_code.strip()
    env_code = os.environ.get("OPTIMUS_SMS_CODE", "").strip()
    if env_code:
        return env_code
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line:
            return line.strip()
        return None
    try:
        return input("[auth] Enter the SMS verification code: ").strip()
    except EOFError:
        return None


def login_interactive(session: requests.Session, sms_code: str | None = None) -> bool:
    """
    Full login; prompts for SMS or uses --code (and optional env/stdin fallbacks).
    """
    if not USERNAME or not PASSWORD:
        print("[error] Set OPTIMUS_USER and OPTIMUS_PASS in environment.")
        return False

    print("[auth] Logging in (interactive)...")
    device_id = get_device_id()
    payload = {
        "DeviceId": device_id,
        "Username": USERNAME,
        "Password": PASSWORD,
    }
    response = session.post(LOGIN_URL, data=payload, allow_redirects=True, timeout=15)
    two_factor = _two_factor_url(response)

    if two_factor:
        print("[auth] SMS 2FA required.")
        code = _read_sms_code(sms_code)
        if not code:
            print("[error] No SMS code provided. Use one of:")
            print("  docker exec -it optimus-checker python /app/app.py login")
            print("  docker exec optimus-checker python /app/app.py login --code 123456")
            return False
        return handle_2fa(session, two_factor, code)

    if session_is_valid(session):
        print("[auth] Login successful.")
        save_session(session)
        return True

    print(f"[auth] Login failed. Status {response.status_code}, landed at: {response.url}")
    return False


def login_noninteractive(session: requests.Session) -> bool:
    if not USERNAME or not PASSWORD:
        print("[error] Set OPTIMUS_USER and OPTIMUS_PASS in environment.")
        return False

    print("[auth] Logging in...")
    device_id = get_device_id()
    payload = {
        "DeviceId": device_id,
        "Username": USERNAME,
        "Password": PASSWORD,
    }
    response = session.post(LOGIN_URL, data=payload, allow_redirects=True, timeout=15)

    if _two_factor_url(response):
        print("[error] SMS 2FA required. Refresh session with:")
        print("  docker exec -it optimus-checker python /app/app.py login")
        print("  docker exec optimus-checker python /app/app.py login --code 'CODE'")
        return False

    if session_is_valid(session):
        print("[auth] Login successful.")
        save_session(session)
        return True

    print(f"[auth] Login failed. Status {response.status_code}, landed at: {response.url}")
    return False


def build_http_session() -> requests.Session:
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
    return session


def cmd_login(sms_code: str | None) -> int:
    """CLI entry: obtain a new session cookie (handles 2FA)."""
    session = build_http_session()
    if login_interactive(session, sms_code=sms_code):
        return 0
    return 1


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
    session = build_http_session()

    loaded = load_session(session)
    if loaded and session_is_valid(session):
        print("[auth] Saved session is still valid, skipping login.")
    else:
        if loaded:
            print("[auth] Saved session has expired, re-authenticating.")
        if not login_noninteractive(session):
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Optimus tracker MQTT poller")
    sub = parser.add_subparsers(dest="command")

    login_p = sub.add_parser("login", help="Refresh Optimus session cookie (SMS 2FA supported)")
    login_p.add_argument(
        "--code",
        metavar="SMS",
        help="SMS verification code (omit for prompt, or use with -it)",
    )

    sub.add_parser("poll", help="Run a single fetch/publish cycle (default)")

    args = parser.parse_args()

    if args.command == "login":
        return cmd_login(args.code)
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
