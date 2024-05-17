# Makefile for building and running a WebAssembly app with Go

# Variables
GOROOT := $(shell go env GOROOT)
WASM_EXEC_JS := $(GOROOT)/misc/wasm/wasm_exec.js
BUILD_DIR := ./

# Default target
all: copy_js build
test_build: copy_js build test

# Build the WASM binary
build:
	@echo "Building WebAssembly module..."
	@GOOS=js GOARCH=wasm go build -o $(BUILD_DIR)/main.wasm main.go

# Copy the supporting JavaScript file
copy_js:
	@echo "Copying wasm_exec.js..."
	@cp $(WASM_EXEC_JS) $(BUILD_DIR)

# Clean up output files
clean:
	@echo "Cleaning up..."
	@rm -f $(BUILD_DIR)/main.wasm
	@rm -f $(BUILD_DIR)/wasm_exec.js

# Build WASM dev
dev:
	@echo "Building WebAssembly module..."
	find . -type f | entr -s 'make build'

# Tests
test:
	@echo "Running tests..."
	@go test -v ./...
