.PHONY: build install test test-race integration vet fmt lint clean

BIN := bin/osm
PKG := .
INSTALL_DIR := $(HOME)/.local/bin

build:
	@printf "\033[1;34m==>\033[0m Building osm...\n"
	@go build -o $(BIN) $(PKG)
	@printf "\033[1;32m✓\033[0m Build complete: %s\n" "$(BIN)"

install: build
	@printf "\033[1;34m==>\033[0m Installing to $(INSTALL_DIR)...\n"
	@mkdir -p $(INSTALL_DIR)
	@cp $(BIN) $(INSTALL_DIR)/osm
	@printf "\033[1;32m✓\033[0m Installed: %s\n" "$(INSTALL_DIR)/osm"

test:
	go test ./...

test-race:
	go test -race ./...

integration:
	go test -tags integration ./tests/...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run

clean:
	rm -rf bin
