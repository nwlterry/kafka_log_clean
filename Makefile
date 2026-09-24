BIN        := kafka_log_clean
VERSION    ?= 1.2.0
GO         ?= go
GOFLAGS    ?=
LDFLAGS    := -s -w -X main.Version=$(VERSION)
PREFIX     ?= /usr/local

.PHONY: all build test clean install fmt vet dist

all: build

build:
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/$(BIN)

test:
	$(GO) test ./...

clean:
	rm -rf bin dist
	rm -f report.yaml

install: build
	install -d $(PREFIX)/bin
	install -m 0755 bin/$(BIN) $(PREFIX)/bin/$(BIN)

dist:
	bash hack/package.sh $(VERSION)
