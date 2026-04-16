# optimus_checker

Polls Optimus Tracking for vehicle positions on a fixed interval, publishes JSON to MQTT, and skips MQTT publishes when latitude and longitude are unchanged.

## Version

Image and release versions are read from `version.txt` (single line, for example `1.0.0`). Bump this file when you cut a new release.

## Configuration

Set these via `docker-compose.yml` or any orchestrator that injects environment variables into the container.

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `OPTIMUS_USER` | Optimus login email | Yes | `you@example.com` |
| `OPTIMUS_PASS` | Optimus password | Yes | (secret) |
| `MQ_ADDRESS` | MQTT broker hostname | Yes | `mqtt.example.com` |
| `MQ_PORT` | MQTT broker port | No | `1883` |
| `MQ_TOPIC_PREFIX` | Topic prefix before vehicle slug | No | `cars` → topic `cars/f350` |
| `INTERVAL_SECONDS` | Seconds between poll loops | No | `10` |
| `OPTIMUS_DEVICE_ID` | Login form `DeviceId` fingerprint | No | default in `app.py` |

### MQTT topics and payload

Each vehicle is published under `{MQ_TOPIC_PREFIX}/{slug}`, where `slug` is derived from the Optimus device description (lowercase, non-alphanumeric become `-`). Example with `MQ_TOPIC_PREFIX=cars` and description `Example Truck`:

- **Topic:** `cars/example-truck`
- **Payload:** single JSON object (one message per vehicle per publish), for example (illustrative numbers only, not a real position):

```json
{
  "device_id": "000000000000000",
  "description": "Example Truck",
  "latitude": 12.345678,
  "longitude": -98.765432,
  "speed_mph": 0,
  "azimuth": 90,
  "altitude_ft": 500.0,
  "report_date": "/Date(1700000000000)/",
  "report_date_utc": "2023-11-14T22:13:20+00:00",
  "report_date_local": "2023-11-14T15:13:20-07:00",
  "event": "Parked",
  "signal": 1,
  "idling": false
}
```

Values mirror Optimus `LastPosition` fields where present; `report_date_*` may be `null` if the vendor date string cannot be parsed.

### Session refresh and SMS 2FA

The background loop uses non-interactive login. If Optimus requires SMS 2FA, the poll will log an error until you refresh cookies.

Run **`login`** inside the **same** container (it reads `OPTIMUS_USER` / `OPTIMUS_PASS` from the container environment and writes `/data/optimus_session.json`):

**Interactive (prompt for SMS code):**

```bash
docker exec -it optimus-checker python /app/app.py login
```

**Pass the code on the command line:**

```bash
docker exec optimus-checker python /app/app.py login --code 123456
```

Replace `optimus-checker` with your `container_name` from `docker-compose.yml` if different.

Optional: `python /app/app.py poll` runs a single fetch/publish cycle; with no arguments the app does the same (used by the entrypoint loop).

## Persistent data

`./data` on the host is mounted to `/data` in the container. It stores:

- `optimus_session.json` — session cookies
- `optimus_mq_state.json` — last published coordinates for de-duplication
