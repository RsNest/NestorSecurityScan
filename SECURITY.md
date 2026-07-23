# Security Policy

## Supported versions

Актуальная ветка `main` получает исправления безопасности.

## Reporting a vulnerability

Сообщайте об уязвимостях приватно через GitHub Security Advisories репозитория
или создателям проекта. Не публикуйте эксплойты в публичных issues до появления фикса.

## Hardening checklist

- Задайте `API_KEY` перед публикацией сервиса.
- Задайте `HARBOR_WEBHOOK_SECRET` для webhook.
- Не монтируйте Docker socket.
- Не публикуйте UI в интернет без reverse-proxy с аутентификацией.
- Храните Harbor robot credentials только в `.env` / secret store.
- Регулярно обновляйте Grype DB (`make update-db` / scheduler).
