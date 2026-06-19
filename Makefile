BIN := cadutrace
PKG := ./...

.PHONY: build samples vet fmt clean

build:
	go build -o bin/$(BIN) ./cmd/cadutrace

# Synthesize the demo capture corpus into ./samples (git-ignored)
samples:
	go run ./cmd/gensamples

vet:
	go vet $(PKG)

fmt:
	gofmt -l -w .

clean:
	rm -rf bin
