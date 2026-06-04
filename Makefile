.PHONY: up down logs api web lint smoke zip migrate migration test test-legacy runner-image preflight preflight-quick

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f

api:
	cd apps/api && uvicorn app.main:app --reload

web:
	cd apps/web && npm run dev

smoke:
	curl -fsS http://localhost:8000/health | jq .

# Schema migrations (alembic)
migrate:
	cd apps/api && alembic upgrade head

# usage: make migration MSG="add foo column"
migration:
	cd apps/api && alembic revision --autogenerate -m "$(MSG)"

test:
	python -m pytest tests/ -v

test-legacy:
	cd legacy && python -m pytest tests/ -v

runner-image:
	docker build -f apps/api/Dockerfile.runner -t reconforge-runner:dev .

# Operator preflight — safe dry-run checks before a demo / CI / live lab.
preflight:
	./scripts/preflight.sh

preflight-quick:
	./scripts/preflight.sh --quick --skip-web

zip:
	cd .. && zip -r reconforge-control-plane.zip reconforge-control-plane -x '*/node_modules/*' '*/.venv/*' '*/__pycache__/*'
