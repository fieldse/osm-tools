.PHONY: build test test-race integration vet fmt lint clean

BIN := bin/osm
PKG := .

build:
	go build -o $(BIN) $(PKG)

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
