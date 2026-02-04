# Anchorpoint-IT
.PHONY: run stop deploy

## run: Builds and starts the suite via Docker
run:
	@echo "Launching Anchorpoint-IT Suite..."
	docker compose up -d --build

## deploy: Standard update for anchorpoint-it.com
deploy:
	@echo "Deploying update to VPS..."
	docker compose down
	docker compose up -d --build
	@echo "Update complete."

## stop: Shuts down services
stop:
	docker compose down