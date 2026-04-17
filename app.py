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
from html.parser import HTMLParser
from urllib.parse import urljoin

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
OPTIMUS_DEBUG = os.environ.get("OPTIMUS_DEBUG", "").strip().lower() in ("1", "true", "yes")
# Optimus M2FactorAuth form leaves these empty in HTML (browser JS fills them). Must match login POST.
OPTIMUS_PLATFORM = os.environ.get("OPTIMUS_PLATFORM", "Web").strip() or "Web"
# Single source of truth with build_http_session() — hidden field "UserAgent" must align.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


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


def session_is_valid(session: requests.Session) -> bool | None:
    """
    True  = session cookies work.
    False = server rejected (need to re-auth).
    None  = network error / timeout; status unknown, caller should NOT re-auth
            (re-auth triggers a fresh SMS 2FA even when cookies are still good).
    """
    try:
        response = session.post(GET_DEVICES_URL, timeout=10)
    except requests.RequestException as exc:
        print(f"[auth] Session check network error: {exc}")
        return None
    if response.status_code == 200:
        try:
            data = response.json()
        except ValueError:
            return False
        return isinstance(data, dict) and len(data) > 0
    return False


class _MultiFormParser(HTMLParser):
    """Collect each <form> on the page with its action and <input> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._cur: dict[str, object] | None = None
        self._depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        ad = {k.lower(): v for k, v in attrs}
        if tag == "form":
            if self._depth == 0:
                self._cur = {"action": ad.get("action", "").strip(), "inputs": []}
            self._depth += 1
            return
        if self._cur is not None and tag == "input":
            inputs_list = self._cur["inputs"]
            assert isinstance(inputs_list, list)
            inputs_list.append(ad)
        elif self._cur is not None and tag == "button":
            # MVC sites often use <button type="submit" name="..."> instead of <input type="submit">.
            typ = (ad.get("type") or "submit").lower()
            if typ in ("submit", "button", ""):
                inputs_list = self._cur["inputs"]
                assert isinstance(inputs_list, list)
                inputs_list.append({**ad, "_element": "button"})

    def handle_endtag(self, tag: str) -> None:
        if tag != "form" or self._depth == 0:
            return
        self._depth -= 1
        if self._depth == 0 and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _parse_forms(html: str) -> list[dict[str, object]]:
    parser = _MultiFormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.forms


def _request_verification_token_from_html(html: str) -> str | None:
    for pattern in (
        r'name=["\']__RequestVerificationToken["\']\s+value=["\']([^"\']*)["\']',
        r'value=["\']([^"\']*)["\']\s+name=["\']__RequestVerificationToken["\']',
    ):
        m = re.search(pattern, html, re.I)
        if m:
            return m.group(1)
    return None


def _pick_2fa_form(forms: list[dict[str, object]], page_url: str) -> dict[str, object] | None:
    """Prefer the real 2FA form over layout forms (search bar, etc.)."""
    if not forms:
        return None
    scored: list[tuple[int, dict[str, object]]] = []
    for form in forms:
        action = str(form.get("action") or "")
        full = urljoin(page_url, action).lower()
        score = 0
        if any(s in full for s in ("m2factor", "factorauth", "twofactor", "verify", "2fa")):
            score += 20
        inputs = form.get("inputs")
        if not isinstance(inputs, list):
            continue
        names = " ".join(
            (str(inp.get("name") or "")).lower()
            for inp in inputs
            if isinstance(inp, dict)
        )
        if "__requestverificationtoken" in names:
            score += 10
        if any(x in names for x in ("code", "sms", "verify", "otp", "mfa", "pin", "twofactor")):
            score += 5
        for inp in inputs:
            if not isinstance(inp, dict):
                continue
            typ = (inp.get("type") or "text").lower()
            if typ == "hidden":
                continue
            if typ in ("text", "tel", "number", "password", ""):
                score += 3
                break
        scored.append((score, form))
    scored.sort(key=lambda x: -x[0])
    if scored[0][0] > 0:
        return scored[0][1]
    return forms[0]


def _code_field_name(inputs: list[dict]) -> str:
    text_names: list[str] = []
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = inp.get("name")
        if not name:
            continue
        typ = (inp.get("type") or "text").lower()
        if typ == "hidden":
            continue
        if typ in ("text", "tel", "number", "password", ""):
            text_names.append(str(name))
    lower = [n.lower() for n in text_names]
    # Optimus uses name="Otp" for SMS (match before generic "code").
    for hint in ("otp", "twofactor", "verifycode", "smscode", "mfa", "2fa"):
        for i, n in enumerate(lower):
            if hint in n:
                return text_names[i]
    for hint in ("code", "verify", "sms", "pin"):
        for i, n in enumerate(lower):
            if hint in n and "verification" not in n:
                return text_names[i]
    if text_names:
        return text_names[0]
    return "Code"


def _build_m2fa_payload(form: dict[str, object], html: str, sms_code: str) -> dict[str, str]:
    inputs = form.get("inputs")
    if not isinstance(inputs, list):
        inputs = []
    payload: dict[str, str] = {}
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = inp.get("name")
        if not name:
            continue
        typ = (inp.get("type") or "text").lower()
        if typ == "hidden":
            payload[str(name)] = str(inp.get("value", ""))
        elif typ == "checkbox":
            # Browsers only submit checked boxes.
            if inp.get("checked") is None and "checked" not in inp:
                continue
            payload[str(name)] = str(inp.get("value", "true"))
    code_name = _code_field_name(inputs)
    payload[code_name] = sms_code.strip()
    if "__RequestVerificationToken" not in payload:
        token = _request_verification_token_from_html(html)
        if token is not None:
            payload["__RequestVerificationToken"] = token
    # Named submit controls are often required (ASP.NET MVC).
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = inp.get("name")
        if not name:
            continue
        typ = (inp.get("type") or "text").lower()
        is_button = inp.get("_element") == "button"
        if typ == "submit" or (is_button and typ in ("submit", "button", "")):
            payload[str(name)] = str(inp.get("value", ""))
    _merge_lone_select(html, payload)
    _apply_m2fa_client_hiddens(payload)
    return payload


def _apply_m2fa_client_hiddens(payload: dict[str, str]) -> None:
    """
    M2FactorAuth HTML often ships empty DeviceId / Platform / UserAgent; the live site
    fills them in script. Server validation still requires them — mirror login fingerprint.
    """
    if not str(payload.get("DeviceId", "")).strip():
        payload["DeviceId"] = get_device_id()
    if not str(payload.get("Platform", "")).strip():
        payload["Platform"] = OPTIMUS_PLATFORM
    if not str(payload.get("UserAgent", "")).strip():
        payload["UserAgent"] = BROWSER_USER_AGENT


def _extract_mvc_validation_messages(html: str) -> list[str]:
    """Pull user-visible validation text from typical ASP.NET MVC markup."""
    messages: list[str] = []
    block = re.search(
        r'class="[^"]*validation-summary-errors[^"]*"[^>]*>(.*?)</div>',
        html,
        re.I | re.DOTALL,
    )
    if block:
        for li in re.finditer(r"<li[^>]*>([^<]+)</li>", block.group(1), re.I):
            t = li.group(1).strip()
            if t:
                messages.append(t)
    for m in re.finditer(
        r'class="[^"]*field-validation-error[^"]*"[^>]*>([^<]+)',
        html,
        re.I,
    ):
        t = m.group(1).strip()
        if t and t not in messages:
            messages.append(t)
    for m in re.finditer(
        r'class="[^"]*(?:alert-danger|text-danger)[^"]*"[^>]*>([^<]+)',
        html,
        re.I,
    ):
        t = m.group(1).strip()
        if t and len(t) < 500 and t not in messages:
            messages.append(t)
    return messages


def _merge_lone_select(html: str, payload: dict[str, str]) -> None:
    """If the page has exactly one <select>, include it (e.g. SMS vs authenticator)."""
    matches = list(
        re.finditer(
            r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
            html,
            re.I | re.DOTALL,
        )
    )
    if len(matches) != 1:
        return
    m = matches[0]
    name = m.group(1)
    if name in payload:
        return
    block = m.group(2)
    opt = re.search(
        r'<option[^>]+selected[^>]+value=["\']([^"\']*)["\']',
        block,
        re.I,
    )
    if not opt:
        opt = re.search(r'<option[^>]+value=["\']([^"\']*)["\']', block, re.I)
    if opt:
        payload[name] = opt.group(1)


def _m2fa_post_url(form: dict[str, object], page_url: str) -> str:
    action = str(form.get("action") or "").strip()
    if action:
        return urljoin(page_url, action)
    return page_url


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


def handle_2fa(
    session: requests.Session,
    two_factor_url: str,
    code: str,
    *,
    login_response: requests.Response | None = None,
) -> bool:
    """
    ASP.NET MVC expects __RequestVerificationToken and the correct form fields.
    A bare POST with only Code often returns HTTP 500. We also avoid submitting
    the site's first form (e.g. header search) by scoring forms on the page.

    If login_response is the immediate POST /Login redirect to M2FactorAuth, we use
    that response body instead of issuing a second GET. A fresh GET can rotate
    antiforgery tokens and break the partial-login cookie pair.
    """
    page_url: str
    html: str

    if (
        login_response is not None
        and login_response.status_code == 200
        and _two_factor_url(login_response)
        and "<form" in login_response.text.lower()
    ):
        html = login_response.text
        page_url = login_response.url
        print("[auth] Using 2FA page HTML from login redirect (no extra GET).")
    else:
        page = session.get(two_factor_url, timeout=15)
        if page.status_code != 200:
            print(f"[auth] Could not load 2FA page: HTTP {page.status_code}")
            return False
        html = page.text
        page_url = page.url

    forms = _parse_forms(html)
    form = _pick_2fa_form(forms, page_url)
    if form is None:
        print("[auth] No HTML form found on 2FA page.")
        return False

    post_url = _m2fa_post_url(form, page_url)
    payload = _build_m2fa_payload(form, html, code)
    if OPTIMUS_DEBUG:
        safe = {}
        for k, v in payload.items():
            if "token" in k.lower() or "verification" in k.lower():
                safe[k] = "<redacted>"
            else:
                s = str(v)
                safe[k] = s[:12] + ("…" if len(s) > 12 else "")
        print(f"[auth] debug: posting to {post_url} fields={list(payload.keys())} preview={safe}")

    headers = {
        "Referer": page_url,
        "Origin": BASE_URL,
    }
    response = session.post(
        post_url,
        data=payload,
        headers=headers,
        allow_redirects=True,
        timeout=15,
    )
    if session_is_valid(session) is True:
        print("[auth] 2FA verified, login successful.")
        save_session(session)
        return True

    print(f"[auth] 2FA verification failed. Status {response.status_code}, url: {response.url}")
    final = response.url.lower()
    body = response.text
    msgs = _extract_mvc_validation_messages(body)
    for msg in msgs:
        print(f"[auth] Server message: {msg}")

    if "/account/login" in final:
        print(
            "[auth] Optimus sent you back to the login page. Common causes: wrong SMS code, "
            "code already used, or the 2FA step timed out. Request a new text and run "
            "login again within a minute or two."
        )
    elif "m2factorauth" in final or "factorauth" in final:
        print(
            "[auth] Still on the 2FA page — the code was rejected or a required field was missing. "
            "Use a fresh SMS code, run login immediately, or set OPTIMUS_DEBUG=1 to inspect the response."
        )
        if not msgs:
            err = re.search(
                r'class="[^"]*field-validation-error[^"]*"[^>]*>([^<]+)',
                body,
                re.I,
            )
            if err:
                print(f"[auth] Server message: {err.group(1).strip()}")

    if response.status_code >= 400 or OPTIMUS_DEBUG or (not msgs and "m2factorauth" in final):
        snippet = re.sub(r"\s+", " ", body[:3500])
        print(f"[auth] Response body (truncated): {snippet}")
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
        return handle_2fa(session, two_factor, code, login_response=response)

    if session_is_valid(session) is True:
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
    try:
        response = session.post(LOGIN_URL, data=payload, allow_redirects=True, timeout=15)
    except requests.RequestException as exc:
        print(f"[auth] Login request failed: {exc}")
        return False

    if _two_factor_url(response):
        print("[error] SMS 2FA required. Refresh session with:")
        print("  docker exec -it optimus-checker python /app/app.py login")
        print("  docker exec optimus-checker python /app/app.py login --code 'CODE'")
        return False

    if session_is_valid(session) is True:
        print("[auth] Login successful.")
        save_session(session)
        return True

    print(f"[auth] Login failed. Status {response.status_code}, landed at: {response.url}")
    return False


def build_http_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": BROWSER_USER_AGENT,
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


def parse_report_date_ms(raw_value: str | None) -> int | None:
    """
    Optimus sends ASP.NET JSON dates like /Date(1776419940000)/ (milliseconds since epoch).
    """
    if not isinstance(raw_value, str):
        return None
    match = re.search(r"/Date\((\d+)(?:[+-]\d+)?\)/", raw_value)
    if not match:
        return None
    return int(match.group(1))


def report_date_local_from_ms(epoch_ms: int) -> str:
    # Vendor clock value; no extra offset conversion. Naive ISO string matches former utcfromtimestamp output.
    dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    return dt.replace(tzinfo=None).isoformat()


def extract_positions(devices: dict) -> list[dict]:
    positions: list[dict] = []
    for device_id, device in devices.items():
        last_position = device.get("LastPosition")
        if not last_position:
            continue
        raw_report_date = last_position.get("ReportDate")
        epoch_ms = parse_report_date_ms(raw_report_date)
        report_date_local = report_date_local_from_ms(epoch_ms) if epoch_ms is not None else None
        positions.append(
            {
                "device_id": device_id,
                "description": device.get("Description", ""),
                "latitude": last_position.get("Latitude"),
                "longitude": last_position.get("Longitude"),
                "speed_mph": last_position.get("Speed"),
                "azimuth": last_position.get("Azimuth"),
                "altitude_ft": last_position.get("Altitude"),
                "report_date": epoch_ms,
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
    validity = session_is_valid(session) if loaded else False
    if validity is True:
        print("[auth] Saved session is still valid, skipping login.")
    elif validity is None:
        # Network blip during the check: do NOT try to log in (would spam SMS 2FA).
        print("[auth] Could not verify saved session (network error); skipping this cycle.")
        return 0
    else:
        if loaded:
            print("[auth] Saved session has expired, re-authenticating.")
        if not login_noninteractive(session):
            print("[error] Could not authenticate.")
            return 1

    print("[data] Fetching device positions...")
    try:
        devices = get_devices(session)
    except requests.RequestException as exc:
        print(f"[data] Fetch failed: {exc}; skipping this cycle.")
        return 0
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
