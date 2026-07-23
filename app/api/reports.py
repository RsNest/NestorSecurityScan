"""Report download aliases (also available under /api/v1/scans/...)."""

from app.api.scans import router as scans_router

# Reports live on scans router; keep module for structure compatibility.
router = scans_router
