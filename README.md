# optimus_checker

Polls Optimus Tracking for vehicle positions on a fixed interval, publishes JSON to MQTT, and skips MQTT publishes when latitude and longitude are unchanged.

## Version

Image and release versions are read from `version.txt` (single line, for example `1.0.0`). Bump this file when you cut a new release.

## Configuration

Set these via `docker-compose.yml` (same pattern as the `awspaghetti` project in this workspace) or any orchestrator that injects environment variables.

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `OPTIMUS_USER` | Optimus login email | Yes | `you@example.com` |
| `OPTIMUS_PASS` | Optimus password | Yes | (secret) |
| `MQ_ADDRESS` | MQTT broker hostname | Yes | `mqtt.example.com` |
| `MQ_PORT` | MQTT broker port | No | `1883` |
| `MQ_TOPIC_PREFIX` | Topic prefix before vehicle slug | No | `cars` → topic `cars/f350` |
| `INTERVAL_SECONDS` | Seconds between poll loops | No | `10` |
| `OPTIMUS_DEVICE_ID` | Login form `DeviceId` fingerprint | No | default in `app.py` |

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
