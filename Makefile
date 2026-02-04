# Anchorpoint-IT Management
.PHONY: run stop deploy logs

## deploy: Full update cycle (Pull -> Down -> Build -> Up)
deploy:
	@echo "Fetching latest changes from Git..."
	git pull origin main
	@echo "Stopping existing Anchorpoint-IT containers..."
	docker compose down
	@echo "Building and launching updated suite..."
	docker compose up -d --build
	@echo "Anchorpoint-IT is live on anchorpoint-it.com."

## run: Standard launch without a git pull
run:
	docker compose up -d --build

## stop: Shuts down the suite
stop:
	docker compose down

## logs: Tail the live container logs from the terminal
logs:
	docker compose logs -f