include .env

default: help

help:
	@echo "Usage: make [target]"
	@echo "Example: make run PORT=8081"
	@echo ""
	@echo "Targets:"
	@echo "  migrate-generate  		- Generate query files"
	@echo "  migrate-up        		- Migrate up"
	@echo "  migrate-down      		- Migrate down"
	@echo "  migrate-create [name]		- Create migration with name"
	@echo "  run [PORT]        		- Run server on PORT (default: 8080) or you can set from env variable PORT"
	@echo "  help              		- Show this help"

migrate-generate:
	@echo "Generating query files..."
	sqlc generate

migrate-up:
	@echo "Migrating up..."
	migrate -path migrations/schema -database ${DATABASE_URL} -verbose up

migrate-down:
	@echo "Migrating down..."
	migrate -path migrations/schema -database ${DATABASE_URL} -verbose down

migrate-create:
	@echo "Creating migration..."
	migrate create -ext sql -dir migrations/schema -seq $(name)

run:
	@echo "Running server..."
	go run cmd/main.go
