# Variables
GOROOT := $(shell go env GOROOT)
WASM_EXEC_JS := $(GOROOT)/misc/wasm/wasm_exec.js
BUILD_DIR := ./

# Default target
all: build copy_js

# Build the WASM binary
build:
	@echo "Building WebAssembly module..."
	@GOOS=js GOARCH=wasm go build -o $(BUILD_DIR)/main.wasm cmd/*

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
