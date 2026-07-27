"""Manual end-to-end smoke test against a locally-running Harbor instance.

This script does NOT run under pytest (Harbor requires ~3 GB of disk and a
short-lived multi-container compose stack). It is meant for developers who
want to reproduce the integration path locally:

    # 1. Start Harbor on http://localhost:8081 (admin / Harbor12345)
    cd tests/integration/harbor
    tar xzf harbor.tgz && cd harbor
    ./prepare && docker compose up -d
    # Wait for /api/v2.0/ping → 200 "Pong"

    # 2. Start Nestor Security Scanner (with admin creds wired to Harbor)
    cd -
    docker compose up -d --build

    # 3. Run this script
    python tests/integration/harbor/run.py

What it does:
- Logs in to Harbor as admin
- Creates project `nestortest`, a system robot account with pull/push on it,
  and a webhook policy pointing at the scanner /api/v1/webhooks/harbor
- Pulls alpine:3.20, tags it into the project, and pushes it
- Writes the resulting coordinates to /tmp/harbor_env.json for later stages
  (manual scan via /harbor UI, or push-triggered scan via webhook)

After running this script, drive the scanner UI at http://localhost:8080
(user: admin / admin) and watch the History page fill up.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import urllib.error
import urllib.request

HARBOR = "http://localhost:8081"
SCANNER = "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = "Harbor12345"

PROJECT = "nestortest"
SECRET = "harbor-webhook-secret-please-rotate"


# ────────────────── tiny HTTP helper ──────────────────


def req(
    method: str,
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict[str, str], bytes]:
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)
    if data is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/json"
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        h["Authorization"] = f"Basic {token}"
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# ────────────────── Harbor setup ──────────────────


def harbor_login() -> str:
    s, _, body = req("GET", f"{HARBOR}/api/v2.0/users/current",
                     auth=(ADMIN_USER, ADMIN_PASS))
    if s != 200:
        raise SystemExit(f"harbor login failed: {s} {body[:200]!r}")
    return json.loads(body)["username"]


def create_project(name: str) -> int:
    payload = json.dumps({
        "project_name": name,
        "public_read": False,
        "storage_limit": -1,
    }).encode()
    s, _, body = req("POST", f"{HARBOR}/api/v2.0/projects",
                     auth=(ADMIN_USER, ADMIN_PASS), data=payload)
    if s == 409:
        print(f"  project {name!r} already exists")
    elif s not in (200, 201):
        raise SystemExit(f"create project failed: {s} {body[:200]!r}")
    s2, _, b2 = req("GET", f"{HARBOR}/api/v2.0/projects/{name}",
                    auth=(ADMIN_USER, ADMIN_PASS))
    if s2 != 200:
        raise SystemExit(f"get project failed: {s2} {b2[:200]!r}")
    return json.loads(b2)["project_id"]


def create_robot() -> tuple[str, str]:
    """Create a system-level robot with pull+push on the test project.

    Note: Harbor v2.12.2 changed the robot payload shape to the
    {permissions: [{kind, namespace, access[]}]} form. Project robot
    accounts (POST /projects/{id}/robots) still accept the old
    {name, access[]} shape but v2.12 has known issues with both shapes
    that resolve to "NOT_FOUND" or "FORBIDDEN" depending on the order
    of fixes applied. We therefore provision via the system endpoint
    and scope permissions to one project.
    """
    payload = {
        "name": "sysrobot-scanner",
        "level": "system",
        "duration": -1,
        "disable": False,
        "description": "Scanner integration robot",
        "permissions": [
            {
                "kind": "project",
                "namespace": PROJECT,
                "access": [
                    {"resource": "repository", "action": "pull"},
                    {"resource": "repository", "action": "push"},
                    {"resource": "repository", "action": "list"},
                    {"resource": "artifact", "action": "read"},
                    {"resource": "tag", "action": "list"},
                    {"resource": "tag", "action": "create"},
                ],
            }
        ],
    }
    s, _, body = req("POST", f"{HARBOR}/api/v2.0/robots",
                     auth=(ADMIN_USER, ADMIN_PASS),
                     data=json.dumps(payload).encode())
    if s in (200, 201):
        j = json.loads(body)
        return j["name"], j["secret"]
    if s == 409:
        print("  sysrobot-scanner already exists, deleting and recreating")
        s2, _, b2 = req("GET", f"{HARBOR}/api/v2.0/robots",
                        auth=(ADMIN_USER, ADMIN_PASS))
        if s2 == 200:
            for r in json.loads(b2):
                if r["name"] == "robot$sysrobot-scanner":
                    req("DELETE",
                        f"{HARBOR}/api/v2.0/robots/{r['id']}",
                        auth=(ADMIN_USER, ADMIN_PASS))
        return create_robot()
    raise SystemExit(f"create robot failed: {s} {body[:300]!r}")


def create_webhook(project_id: int) -> int:
    s, _, body = req("GET",
        f"{HARBOR}/api/v2.0/projects/{project_id}/webhook/policies",
        auth=(ADMIN_USER, ADMIN_PASS))
    if s == 200:
        for p in json.loads(body):
            if p.get("name") == "nestor-webhook":
                print(f"  webhook already exists (id={p['id']})")
                return p["id"]
    # The scanner's webhook endpoint lives on the host of the Harbor
    # compose network; host.docker.internal resolves there on Docker
    # Desktop for Mac/Windows. On Linux add `extra_hosts` to the Harbor
    # compose or run both stacks on a shared network.
    webhook_url = (
        f"http://host.docker.internal:8080/api/v1/webhooks/harbor"
        f"?secret={SECRET}"
    )
    payload = json.dumps({
        "name": "nestor-webhook",
        "description": "Trigger NestorScanner on PUSH_ARTIFACT",
        "project_id": project_id,
        "targets": [{
            "type": "http",
            "address": webhook_url,
            "skip_cert_verify": True,
            "payload_format": "Default",
        }],
        "event_types": ["PUSH_ARTIFACT", "PULL_ARTIFACT"],
        "enabled": True,
    }).encode()
    s, _, body = req("POST",
        f"{HARBOR}/api/v2.0/projects/{project_id}/webhook/policies",
        auth=(ADMIN_USER, ADMIN_PASS), data=payload)
    if s not in (200, 201):
        raise SystemExit(f"create webhook failed: {s} {body[:200]!r}")
    s2, _, b2 = req("GET",
        f"{HARBOR}/api/v2.0/projects/{project_id}/webhook/policies",
        auth=(ADMIN_USER, ADMIN_PASS))
    for p in json.loads(b2):
        if p.get("name") == "nestor-webhook":
            return p["id"]
    raise SystemExit("webhook created but not found in list")


# ────────────────── Main ──────────────────


def main() -> dict:
    print("[1/5] Harbor admin login")
    assert harbor_login() == "admin"

    print(f"[2/5] create project {PROJECT!r}")
    pid = create_project(PROJECT)
    print(f"  project_id={pid}")

    print("[3/5] create robot account")
    robot_name, robot_secret = create_robot()
    print(f"  name={robot_name!r}")
    print(f"  secret={robot_secret[:8]}…")

    print("[4/5] create webhook → scanner")
    wh_id = create_webhook(pid)
    print(f"  webhook_id={wh_id}")

    print("[5/5] push image alpine:3.20 to Harbor project")
    cfgdir = "/tmp/harbor-docker-cfg"
    os.makedirs(cfgdir, exist_ok=True)
    env = {**os.environ, "DOCKER_CONFIG": cfgdir}
    login_url = "localhost:8081"
    r = subprocess.run(
        ["docker", "login", login_url, "-u", robot_name, "--password-stdin"],
        input=robot_secret.encode(), env=env, capture_output=True,
    )
    if r.returncode != 0:
        print(r.stderr.decode())
        raise SystemExit("docker login failed")
    print(f"  docker login OK ({login_url})")

    img = f"{login_url}/{PROJECT}/alpine:3.20"
    for cmd in (["docker", "pull", "alpine:3.20"],
                ["docker", "tag", "alpine:3.20", img],
                ["docker", "push", img]):
        print("  $", " ".join(cmd))
        r = subprocess.run(cmd, env=env, capture_output=True)
        if r.returncode != 0:
            print(r.stdout.decode())
            print(r.stderr.decode())
            raise SystemExit(f"docker {' '.join(cmd)} failed")
    print(f"  pushed {img}")

    out = {
        "harbor_url": HARBOR,
        "harbor_user": robot_name,
        "harbor_password": robot_secret,
        "harbor_project": PROJECT,
        "harbor_secret": SECRET,
        "webhook_id": wh_id,
        "image": img,
    }
    with open("/tmp/harbor_env.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\nWrote /tmp/harbor_env.json — next stages can pick it up.")
    return out


if __name__ == "__main__":
    main()
