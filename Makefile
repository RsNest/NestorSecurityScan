.PHONY: up down build logs restart test lint format clean update-db db-status scan demo

up:
	@test -f .env || cp .env.example .env
	docker compose up -d --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f --tail=200

restart:
	docker compose restart

test:
	pip install -e ".[dev]" -q
	pytest -q

lint:
	ruff check app tests

format:
	ruff format app tests

clean:
	docker compose down -v --remove-orphans
	rm -rf .pytest_cache .ruff_cache **/__pycache__

update-db:
	docker compose exec worker python -c "from app.database import init_db; from app.services.grype_db import update_grype_db; init_db(); print(update_grype_db())"

db-status:
	docker compose exec worker python -c "from app.database import init_db; from app.services.grype_db import get_grype_db_status, refresh_status_from_cli; init_db(); refresh_status_from_cli(); print(get_grype_db_status())"

scan:
	@test -n "$(IMAGE)" || (echo "Usage: make scan IMAGE=alpine:3.20" && exit 1)
	@curl -sS -X POST "http://localhost:$${WEB_PORT:-8080}/api/v1/scans" \
		-H "Content-Type: application/json" \
		$${API_KEY:+-H "X-API-Key: $$API_KEY"} \
		-d '{"image":"$(IMAGE)","source":"manual"}' | python3 -m json.tool

demo:
	@test -f .env || cp .env.example .env
	@# Demo profile intentionally runs without requiring API_KEY
	docker compose --profile demo up -d --build
	@echo "Demo registry: localhost:5001"
	@echo "Example: docker tag alpine:3.20 localhost:5001/demo/alpine:3.20 && docker push localhost:5001/demo/alpine:3.20"
