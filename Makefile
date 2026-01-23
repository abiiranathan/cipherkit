# Build directory for CMake
BUILD_DIR = build
BUILD_TESTS=ON

# Default target - configure and build
.PHONY: all
all: $(BUILD_DIR)
	@cmake --build $(BUILD_DIR) --parallel

# Configure CMake (create build directory and run cmake)
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DBUILD_TESTS=$(BUILD_TESTS) -DCMAKE_BUILD_TYPE=Release ..

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
	@echo "  sudo apt-get install libz-dev yyjson-dev cmake valgrind"