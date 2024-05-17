# Variables
BUILD_DIR := ./

# Default target
all: build

# Build the WASM binary
build:
	@echo "Building Coordinator..."
	go build -o $(BUILD_DIR)/main.wasm *.go

# Build WASM dev
dev:
	@echo "Building Coordinator..."
	find . -type f | entr -s 'make build'
