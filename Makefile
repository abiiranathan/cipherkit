# ===============================================================================
# Project: CipherKit
# File: Makefile
# Author: Dr. Abiira Nathan <nabiira2by2@gmail.com>
# Created on: 2024-09-29
#
# This Makefile is a convenience wrapper around CMake.
# It delegates all build operations to the CMakeLists.txt file.
#
# Install dependencies using:
# `sudo apt-get install build-essential libssl-dev libsodium-dev libz-dev libcjson-dev cmake`
#
# Build the library using `make`
# Install the library using `sudo make install`
# Uninstall the library using `sudo make uninstall`
# Run tests using `make test`
# Run memory checks using `make memcheck`
# NB: You need to have `valgrind` installed to run memory checks.
# ===============================================================================

# Build directory for CMake
BUILD_DIR = build

# Default target - configure and build
.PHONY: all
all: $(BUILD_DIR)
	@cmake --build $(BUILD_DIR) --parallel

# Configure CMake (create build directory and run cmake)
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Release ..

# Install the library (requires sudo for system-wide installation)
.PHONY: install
install: all
	@cd $(BUILD_DIR) && sudo cmake --install .

# Uninstall the library
.PHONY: uninstall
uninstall:
	@if [ -f $(BUILD_DIR)/install_manifest.txt ]; then \
		sudo xargs rm -f < $(BUILD_DIR)/install_manifest.txt; \
		sudo rm -rf /usr/local/include/cipherkit; \
		sudo rm -f /usr/local/lib/pkgconfig/cipherkit.pc; \
		echo "Uninstall complete"; \
	else \
		echo "Error: install_manifest.txt not found. Run 'make install' first."; \
	fi

# Run tests using CTest
.PHONY: test
test: all
	@cd $(BUILD_DIR) && ctest --output-on-failure

# Clean build artifacts
.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned"

# Reconfigure (clean and rebuild from scratch)
.PHONY: reconfigure
reconfigure: clean all

# Debug build configuration
.PHONY: debug
debug:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Debug ..
	@cmake --build $(BUILD_DIR) --parallel

# Help target
.PHONY: help
help:
	@echo "CipherKit Makefile - CMake wrapper"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build the library (default)"
	@echo "  install      - Install the library system-wide (requires sudo)"
	@echo "  uninstall    - Remove installed library files (requires sudo)"
	@echo "  test         - Run all tests"
	@echo "  clean        - Remove build directory"
	@echo "  reconfigure  - Clean and rebuild from scratch"
	@echo "  debug        - Build with debug symbols"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Dependencies:"
	@echo "  sudo apt-get install build-essential libssl-dev libsodium-dev"
	@echo "  sudo apt-get install libz-dev libcjson-dev cmake valgrind"