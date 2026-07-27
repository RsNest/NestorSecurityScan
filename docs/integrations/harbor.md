# Harbor end-to-end smoke

This guide reproduces the full Harbor → Scanner integration on a developer
laptop. It is a manual procedure (not part of the regular pytest suite)
because standing up Harbor requires ~3 GB of disk and a few minutes of
start-up time.

## What gets verified

1. The scanner can authenticate to Harbor, list projects, repositories,
   and artifacts via the API exposed under `/api/v1/harbor/*`.
2. The Harbor integration in the web UI (`/harbor`) works — selecting an
   artifact and pressing “Сканировать выбранные” enqueues an RQ job.
3. Harbor's webhook on `PUSH_ARTIFACT` reaches
   `/api/v1/webhooks/harbor`, is accepted with HMAC-verified
   `?secret=…`, and queues an automatic scan.
4. The scanner can pull images from a private Harbor registry using
   `temporary_docker_auth` and a `registry:` source prefix for Syft.

## Prerequisites

- Docker + Docker Compose v2 with `host.docker.internal` reachability
  (Docker Desktop on macOS/Windows, or Linux with
  `--add-host=host.docker.internal:host-gateway`)
- ~3 GB of free disk for Harbor's PostgreSQL + registry data
- Outgoing HTTPS to `registry-1.docker.io` (Syft pulls catalogers on
  first scan) and to `grype.anchore.io` (Grype DB)

## Bring up Harbor

```bash
cd tests/integration/harbor
tar xzf harbor.tgz
cd harbor
./prepare                       # generate docker-compose.yml + secrets
docker compose up -d
# Wait until /api/v2.0/ping returns "Pong":
until [ "$(curl -sf http://localhost:8081/api/v2.0/ping)" = "Pong" ]; do
  sleep 3
done
```

> **Note on Apple Silicon (arm64).** The official Harbor images are
> `linux/amd64`. The generated `docker-compose.yml` is patched at runtime
> with `platform: linux/amd64` so Docker Desktop can pull them via Rosetta.

> **Note on disk.** The installer defaults to `data_volume: /data`, which
> is *not* shared with Docker on macOS. Override it to a path under this
> repo (already shared), e.g.
> `data_volume: /…/tests/integration/harbor/data`.

## Wire the scanner to Harbor

Put the following in `.env` (the scanner's working directory):

```env
HARBOR_ENABLED=true
HARBOR_URL=http://host.docker.internal:8081
HARBOR_USERNAME=admin
HARBOR_PASSWORD=Harbor12345
HARBOR_VERIFY_TLS=false
HARBOR_PROJECTS=nestortest
HARBOR_WEBHOOK_SECRET=harbor-webhook-secret-please-rotate
REGISTRY_INSECURE_HTTP=1
```

Rebuild so the api picks up the new env:

```bash
docker compose down api worker scheduler
docker compose up -d --build
```

## Configure Harbor + push a test image

```bash
python tests/integration/harbor/run.py
```

The script logs in as `admin`, creates project `nestortest`, a system
robot account scoped to that project, a webhook policy pointing at the
scanner, and pushes `alpine:3.20` to the project. Output coordinates go
to `/tmp/harbor_env.json`.

## Drive the integration

- Open http://localhost:8080/harbor (login as `admin`/`admin`).
  The project list should include `nestortest`; the repository list should
  show `nestortest/alpine`.
- Tick one or more artifacts and press **Сканировать выбранные** to
  verify the manual trigger path.
- Push a *new* tag and watch the **История** page fill up automatically
  (webhook → scanner):

  ```bash
  cfgdir=/tmp/harbor-docker-cfg
  eval "$(cat /tmp/harbor_env.json | \
    python -c 'import json,sys; d=json.load(sys.stdin); print(f"docker --config={cfgdir} login localhost:8081 -u {d[\"harbor_user\"]} --password {d[\"harbor_password\"]}")')"
  docker tag alpine:3.20 localhost:8081/nestortest/alpine:3.20-wh
  docker push localhost:8081/nestortest/alpine:3.20-wh
  ```

## Cleanup

```bash
cd tests/integration/harbor/harbor
docker compose down -v   # destroys Postgres + registry data (~3 GB)
```

The local test artifacts under `tests/integration/harbor/data/`,
`harbor.tgz`, and the unpacked `harbor/` directory are git-ignored.
