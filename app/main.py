"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api import harbor, health, scans, settings as settings_api, webhooks
from app.config import get_settings
from app.database import init_db
from app.logging_setup import setup_logging
from app.web import routes as web_routes

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    setup_logging("api")
    settings = get_settings()
    settings.ensure_dirs()
    init_db()
    if not settings.api_key:
        logger.warning(
            "API_KEY не задан — мутирующие эндпоинты не защищены"
        )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Сканирование контейнерных образов с помощью Syft и Grype",
        lifespan=lifespan,
    )
    static_dir = Path(__file__).resolve().parent / "static"
    application.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    application.include_router(health.router)
    application.include_router(scans.router)
    application.include_router(harbor.router)
    application.include_router(webhooks.router)
    application.include_router(settings_api.router)
    application.include_router(web_routes.router)
    return application


app = create_app()
