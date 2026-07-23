"""Harbor webhook endpoint."""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.workers.queue import enqueue_scan

logger = logging.getLogger(__name__)
router = APIRouter(tags=["webhooks"])


def _extract_secret(
    request: Request,
    x_harbor_auth: str | None,
    authorization: str | None,
) -> str | None:
    # Harbor can send auth header or query param
    if x_harbor_auth:
        return x_harbor_auth
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return request.query_params.get("secret")


def verify_webhook_secret(provided: str | None, expected: str) -> bool:
    if not expected:
        return True
    if not provided:
        return False
    return hmac.compare_digest(provided, expected)


def parse_push_artifact(payload: dict[str, Any]) -> tuple[str, str | None] | None:
    """Return (image_ref, event_id) for PUSH_ARTIFACT or None."""
    event_type = payload.get("type") or payload.get("event_type")
    if event_type and event_type != "PUSH_ARTIFACT":
        return None

    event_data = payload.get("event_data") or payload
    resources = event_data.get("resources") or []
    repository = event_data.get("repository") or {}
    if not resources and "resource_url" not in event_data:
        # Harbor webhook v2 format
        if not repository:
            return None

    repo_ns = repository.get("namespace") or repository.get("project_name") or ""
    repo_name = repository.get("name") or repository.get("repo_full_name") or ""
    # repo_full_name may already include project
    if repo_name.startswith(f"{repo_ns}/"):
        full_repo = repo_name
    elif repo_ns and repo_name:
        full_repo = f"{repo_ns}/{repo_name}"
    else:
        full_repo = repo_name or repository.get("repo_full_name") or ""

    settings = get_settings()
    host = ""
    if settings.harbor_url:
        host = (
            settings.harbor_url.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )

    digest = None
    tag = None
    for resource in resources:
        digest = resource.get("digest") or digest
        tag = resource.get("tag") or tag
        resource_url = resource.get("resource_url")
        if resource_url and "@" in resource_url:
            return resource_url, payload.get("occur_at") and str(payload.get("occur_at"))

    event_id = None
    if payload.get("occur_at") is not None:
        event_id = f"{full_repo}:{digest or tag}:{payload.get('occur_at')}"
    elif digest:
        event_id = f"{full_repo}@{digest}"

    if digest and full_repo and host:
        return f"{host}/{full_repo}@{digest}", event_id
    if tag and full_repo and host:
        return f"{host}/{full_repo}:{tag}", event_id
    return None


@router.post("/api/v1/webhooks/harbor")
async def harbor_webhook(
    request: Request,
    x_harbor_auth: str | None = Header(default=None, alias="X-Harbor-Auth"),
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    settings = get_settings()
    body = await request.body()
    if len(body) > settings.webhook_max_body_bytes:
        raise HTTPException(status_code=413, detail="Слишком большой webhook body")

    provided = _extract_secret(request, x_harbor_auth, authorization)
    if not verify_webhook_secret(provided, settings.harbor_webhook_secret):
        raise HTTPException(status_code=401, detail="Неверный webhook secret")

    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Некорректный JSON") from exc

    event_type = payload.get("type") or payload.get("event_type")
    if event_type and event_type != "PUSH_ARTIFACT":
        return JSONResponse(
            status_code=202,
            content={"accepted": False, "reason": f"ignored event {event_type}"},
        )

    parsed = parse_push_artifact(payload)
    if not parsed:
        return JSONResponse(
            status_code=202,
            content={"accepted": False, "reason": "no artifact reference"},
        )

    image_ref, event_id = parsed
    scan, created = enqueue_scan(
        image=image_ref,
        source="webhook",
        webhook_event_id=event_id,
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "accepted": True,
            "created": created,
            "scan_id": scan.id,
            "image": image_ref,
        },
    )
