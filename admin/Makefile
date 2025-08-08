# Makefile for LeProxy Admin Utility

BINARY_NAME=leproxy-admin
VERSION=1.0.0
BUILD_DIR=build

# Go build flags
GOFLAGS=-ldflags="-s -w"

.PHONY: all build clean run

all: build

build:
	@echo "Building LeProxy Admin..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) server.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

run:
	@echo "Starting LeProxy Admin on http://localhost:8090..."
	@go run server.go

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

install: build
	@echo "Installing LeProxy Admin..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete. Run 'leproxy-admin' to start."

uninstall:
	@echo "Uninstalling LeProxy Admin..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstall complete"