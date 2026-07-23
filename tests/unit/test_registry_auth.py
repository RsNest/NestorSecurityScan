"""Registry auth temp config tests."""

import json

from app.config import get_settings
from app.services.registry_auth import cleanup_docker_config, create_docker_config


def test_create_and_cleanup_docker_config(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_TMP_DIR", str(tmp_path))
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.auth_tmp_dir == tmp_path

    scan_id = "11111111-1111-1111-1111-111111111111"
    path = create_docker_config(scan_id, "harbor.example.ru", "user", "pass")
    assert path is not None
    assert path.exists()
    assert oct(path.stat().st_mode)[-3:] == "700"
    cfg = path / "config.json"
    assert oct(cfg.stat().st_mode)[-3:] == "600"
    data = json.loads(cfg.read_text())
    assert "harbor.example.ru" in data["auths"]
    assert "auth" in data["auths"]["harbor.example.ru"]

    cleanup_docker_config(scan_id)
    assert not path.exists()
    get_settings.cache_clear()
