# Makefile for building and running a WebAssembly app with Go

# Variables
GOROOT := $(shell go env GOROOT)
WASM_EXEC_JS := $(GOROOT)/misc/wasm/wasm_exec.js
BUILD_DIR := ./static

# Default target
all: build copy_js run_server

# Build the WASM binary
build:
	@echo "Building WebAssembly module..."
	@GOOS=js GOARCH=wasm go build -o $(BUILD_DIR)/main.wasm cmd/wasm/*

# Copy the supporting JavaScript file
copy_js:
	@echo "Copying wasm_exec.js..."
	@cp $(WASM_EXEC_JS) $(BUILD_DIR)

# Start the web server
run_server:
	@echo "Starting web server..."
	@go run ./cmd/webserver/main.go

# Clean up output files
clean:
	@echo "Cleaning up..."
	@rm -f $(BUILD_DIR)/main.wasm
	@rm -f $(BUILD_DIR)/wasm_exec.js

# Web server dev
dev-web:
	@echo "Starting web server..."
	@gow run ./cmd/webserver/main.go

# Build WASM dev
dev:
	@echo "Building WebAssembly module..."
	find . -type f | entr -s 'make build'