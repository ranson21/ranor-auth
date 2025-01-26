SHELL := /bin/bash

run:
	@command . ./.env && air

use_dev:
	@command go mod edit -replace github.com/ranson21/ranor-common=../../assets/lib/common

use_prod:
	@command go mod edit -dropreplace=github.com/dot0s/http-common-go
	@command go mod edit -dropreplace=github.com/dot0s/svc-common-go
	@command go mod edit -dropreplace=github.com/ransontesting/svc-common-go

setup_auth:
	@command gcloud secrets versions access latest --secret="svc-auth-private-key" --project=mystro-ranson>credentials.json

install:
	@command go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	@command go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
	@command go install github.com/swaggo/swag/cmd/swag@latest

proto:
	@command protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/auth.proto

############
# Begin DB #
############
DB_BASE=postgres://postgres@localhost:5432
PSQL=psql $(DB_BASE)

drop-db:
	$(PSQL) -c "DROP DATABASE IF EXISTS ranor"

# Bring up the database
db: db_container create_db migrate_up

db_console:
	@command psql ${DB_URL}

# Create/Destroy DB
create_db:
	$(PSQL) -c "CREATE DATABASE ranor"
	$(PSQL) -c 'CREATE EXTENSION pgcrypto;'
	$(PSQL)/ranor -c "CREATE SCHEMA IF NOT EXISTS auth"
	@echo "Created database ${DB_NAME}"

db_container:
	@docker run --name postgres -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres >/dev/null
	@echo "Waiting for database container to be ready..."
	@for i in {1..10}; do \
		if docker exec postgres pg_isready -U postgres >/dev/null 2>&1; then \
			echo "Database is ready!"; \
			exit 0; \
		fi; \
		echo "Waiting for database... ($$i)"; \
		sleep 1; \
	done; \
	echo "Database container did not become ready in time."; \
	exit 1
	@echo "Database Container available at postgres://localhost:5432"


db_container_down:
	@command docker container rm -f postgres
	@echo "Database Container removed Successfully"

reset_db: db_container_down db

# DB Migration Commands
migrate_new:
	@command migrate create -ext sql -dir config/db/migrations/ -seq $(name)

migrate_up:
	@command migrate -path config/db/migrations/ -database ${DB_URL} -verbose up

migrate_down:
	@command migrate -path config/db/migrations/ -database ${DB_URL} -verbose down

migrate_fix:
	@command migrate -path config/db/migrations/$(name) -database ${DB} -force $(version)

# DB Seeding commands
seed_new:
	@command migrate create -ext sql -dir config/db/seeds/ -seq $(name)

seed_up:
	@command migrate -path config/db/seeds/ -database ${DB} -verbose up

seed_down:
	@command migrate -path config/db/seeds/ -database ${DB} -verbose down

seed_fix:
	@command migrate -path config/db/seeds/$(name) -database ${DB} -force $(version)