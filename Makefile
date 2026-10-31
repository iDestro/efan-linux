GO ?= go
BINARY ?= efan

.PHONY: build static test clean install

build:
	$(GO) build -trimpath -o $(BINARY) ./cmd/efan

static:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/efan

test:
	$(GO) test ./...

clean:
	rm -f $(BINARY)

install: static
	install -Dm755 $(BINARY) $(HOME)/.local/bin/$(BINARY)
