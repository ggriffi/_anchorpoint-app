# Anchorpoint-IT Management
BINARY_NAME=anchorpoint-web
DOCKER_IMAGE=anchorpoint-it/suite

.PHONY: build run stop clean deploy

## build: Compiles the Go binary for Linux environment
build:
	@echo "Building Anchorpoint-IT binary..."
	GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY_NAME} ./cmd/web

## run: Starts the containerized application
run:
	@echo "Launching Anchorpoint-IT Suite..."
	docker compose up -d --build

## stop: Shuts down the local environment
stop:
	@echo "Stopping services..."
	docker compose down

## clean: Removes build artifacts
clean:
	@echo "Cleaning project..."
	rm -f ./bin/${BINARY_NAME}
	docker system prune -f

## deploy: Full cycle for IONOS VPS update
deploy: build
	@echo "Deploying update to anchorpoint-it.com..."
	docker compose down
	docker compose up -d --build
	@echo "Anchorpoint-IT is live."