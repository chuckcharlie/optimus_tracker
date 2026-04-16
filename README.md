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

## Local run (build from source)

1. Edit `docker-compose.yml`: replace `YOUR_DOCKERHUB_USERNAME`, credentials, and `MQ_ADDRESS` with your values.
2. Start:

```bash
docker compose up -d --build
```

3. Logs:

```bash
docker compose logs -f
```

## Persistent data

`./data` on the host is mounted to `/data` in the container. It stores:

- `optimus_session.json` — session cookies
- `optimus_mq_state.json` — last published coordinates for de-duplication

## AWS CodeBuild (Docker Hub)

This repo mirrors the layout used in `awspaghetti`:

- `buildspec.yml` — per-architecture image build and push (`VERSION` from `version.txt`)
- `buildspec-manifest.yml` — multi-arch manifest after `arm64` and `amd64` builds exist

CodeBuild environment variables expected (same as `awspaghetti`):

- `IMAGE_REPO_NAME` — Docker Hub repository name (for example `optimus-checker`)
- `IMAGE_TAG` — extra tag segment (for example `latest` or `dev`)
- `ARCH` — `arm64` or `amd64` for the single-arch build project

Secrets Manager (adjust paths to match your account):

- `/dockerhub/credentials:username`
- `/dockerhub/credentials:password`

Build command excerpt:

```bash
VERSION=$(cat version.txt)
docker build -t $DOCKERHUB_USERNAME/$IMAGE_REPO_NAME:$VERSION-$ARCH ...
```

After images exist for both architectures, run the manifest buildspec to publish `$VERSION` and `latest` manifest lists.

## Public repository hygiene

- Do not commit real passwords or broker hostnames you consider private; use placeholders in `docker-compose.yml` and replace locally.
- `data/` is gitignored so session and de-dupe files are not committed.
