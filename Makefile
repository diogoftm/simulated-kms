# SPDX-FileCopyrightText: © 2023 Merqury Cybersecurity Ltd <info@merqury.eu>
# SPDX-License-Identifier: AGPL-3.0-only

DATABASE_PORT?=10000
DATABASE_HOST?=127.0.0.1
DATABASE_USER?=db_user
DATABASE_PASSWORD?=db_password
DATABASE_URL?=postgres://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/key_store
ETSI_014_REF_IMPL_PORT_NUM?=8443
ETSI_014_REF_IMPL_IP_ADDR?=${DATABASE_HOST}
ETSI_014_REF_IMPL_NUM_WORKER_THREADS?=2
CURDIR=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))
CERTS_DIR?=$(CURDIR)certs

.PHONY:
	db_container
	db_start
	db_stop
	db_migration
	db_clean_container
	db_clean_container_and_data
	build
	build_release
	run_tests
	run_server
	clean
	build_image

db_container:
	cd $(CURDIR) && \
	DATABASE_HOST=$(DATABASE_HOST) \
	DATABASE_PORT=$(DATABASE_PORT) \
	DATABASE_USER=$(DATABASE_USER) \
	DATABASE_PASSWORD=$(DATABASE_PASSWORD) \
	docker compose up --no-start

db_start: db_container
	cd $(CURDIR) && \
	DATABASE_HOST=$(DATABASE_HOST) \
	DATABASE_PORT=$(DATABASE_PORT) \
	DATABASE_USER=$(DATABASE_USER) \
	DATABASE_PASSWORD=$(DATABASE_PASSWORD) \
	docker compose start

db_migration:
	cd $(CURDIR) && diesel migration run --database-url $(DATABASE_URL)

db_stop:
	cd $(CURDIR) && \
	DATABASE_HOST=$(DATABASE_HOST) \
	DATABASE_PORT=$(DATABASE_PORT) \
	DATABASE_USER=$(DATABASE_USER) \
	DATABASE_PASSWORD=$(DATABASE_PASSWORD) \
	docker compose stop

db_clean_container:
	cd $(CURDIR) && \
	DATABASE_HOST=$(DATABASE_HOST) \
	DATABASE_PORT=$(DATABASE_PORT) \
	DATABASE_USER=$(DATABASE_USER) \
	DATABASE_PASSWORD=$(DATABASE_PASSWORD) \
	docker compose down

db_clean_container_and_data:
	cd $(CURDIR) && \
	DATABASE_HOST=$(DATABASE_HOST) \
	DATABASE_PORT=$(DATABASE_PORT) \
	DATABASE_USER=$(DATABASE_USER) \
	DATABASE_PASSWORD=$(DATABASE_PASSWORD) \
	docker compose down -v --rmi local

build:
	@cd $(CURDIR) && cargo build --workspace

build_release:
	@cd $(CURDIR) && cargo build --release --workspace

run_server:
	cd $(CURDIR) &&        \
	CERTS_DIR=$(CERTS_DIR) \
	ETSI_014_REF_IMPL_PORT_NUM=$(ETSI_014_REF_IMPL_PORT_NUM) \
	ETSI_014_REF_IMPL_IP_ADDR=$(ETSI_014_REF_IMPL_IP_ADDR) \
	ETSI_014_REF_IMPL_NUM_WORKER_THREADS=$(ETSI_014_REF_IMPL_NUM_WORKER_THREADS) \
	ETSI_014_REF_IMPL_DB_URL=$(DATABASE_URL) \
	./examples/run_server.sh

get_enc_key:
	cd $(CURDIR) && \
	CERTS_DIR=$(CERTS_DIR) \
	ETSI_014_REF_IMPL_PORT_NUM=$(ETSI_014_REF_IMPL_PORT_NUM) \
	ETSI_014_REF_IMPL_IP_ADDR=$(ETSI_014_REF_IMPL_IP_ADDR) \
	./examples/enc_keys.sh GET $(KEY_TYPE)

post_enc_key:
	cd $(CURDIR) && \
	CERTS_DIR=$(CERTS_DIR) \
	ETSI_014_REF_IMPL_PORT_NUM=$(ETSI_014_REF_IMPL_PORT_NUM) \
	ETSI_014_REF_IMPL_IP_ADDR=$(ETSI_014_REF_IMPL_IP_ADDR) \
 	./examples/enc_keys.sh POST $(KEY_TYPE)

get_dec_key:
	cd $(CURDIR) && \
	CERTS_DIR=$(CERTS_DIR) \
	ETSI_014_REF_IMPL_PORT_NUM=$(ETSI_014_REF_IMPL_PORT_NUM) \
	ETSI_014_REF_IMPL_IP_ADDR=$(ETSI_014_REF_IMPL_IP_ADDR) \
	./examples/dec_keys.sh GET $(KEY)

post_dec_key:
	cd $(CURDIR) && \
	CERTS_DIR=$(CERTS_DIR) \
	ETSI_014_REF_IMPL_PORT_NUM=$(ETSI_014_REF_IMPL_PORT_NUM) \
	ETSI_014_REF_IMPL_IP_ADDR=$(ETSI_014_REF_IMPL_IP_ADDR) \
	./examples/dec_keys.sh POST $(KEYS)

run_tests:
	@cd $(CURDIR) && cargo test

reqs:
	sudo apt install pkg-config libssl-dev
	sudo apt install libpq-dev
	sudo apt install moreutils
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	cargo install diesel_cli --no-default-features --features postgres
	sudo apt-get update
	sudo apt-get install ca-certificates curl
	sudo install -m 0755 -d /etc/apt/keyrings
	sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
	sudo chmod a+r /etc/apt/keyrings/docker.asc
	echo \
	"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
	$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
	sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
	sudo apt-get update
	sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
	
clean:
	@cd $(CURDIR) && cargo clean

build_image:
	docker build -t merqury/etsi_014_ref_impl -f Dockerfile .
