.PHONY: up down logs api web lint smoke zip

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

zip:
	cd .. && zip -r reconforge-control-plane.zip reconforge-control-plane -x '*/node_modules/*' '*/.venv/*' '*/__pycache__/*'
