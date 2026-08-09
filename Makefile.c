# debork - Cross-Platform Linux Boot Rescue Tool
# Makefile for C version with Clay TUI

# Compiler and flags
CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE
DEBUG_FLAGS = -g -O0 -DDEBUG
STATIC_FLAGS = -static
SOURCES = src/c/debork.c
SOURCES_CLAY = src/c/debork_clay.c
TARGET = debork
INSTALL_DIR = /usr/local/bin
DOCS_DIR = /usr/local/share/doc/debork
BUILD_DIR = build

# Cosmopolitan libc settings
COSMO_VERSION = 3.3.2
COSMO_DIR = cosmopolitan
COSMO_URL = https://github.com/jart/cosmopolitan/releases/download/$(COSMO_VERSION)/cosmopolitan-$(COSMO_VERSION).tar.gz

# Default target
.PHONY: all
all: standard

# Standard Linux build (static)
.PHONY: standard
standard: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(SOURCES) include/clay.h
	@echo "Building standard static binary..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(STATIC_FLAGS) -I include -o $@ $(SOURCES) -lm -lpthread
	@echo "Build complete: $@"

# Debug build
.PHONY: debug
debug: $(SOURCES) include/clay.h
	@echo "Building debug version..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(DEBUG_FLAGS) -I include -o $(BUILD_DIR)/$(TARGET)-debug $(SOURCES) -lm -lpthread
	@echo "Debug build complete: $(BUILD_DIR)/$(TARGET)-debug"

# Clay version build
.PHONY: clay
clay: $(SOURCES_CLAY) include/clay.h
	@echo "Building Clay UI version..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I include -o $(BUILD_DIR)/$(TARGET)-clay $(SOURCES_CLAY) -lm -lpthread
	@echo "Clay build complete: $(BUILD_DIR)/$(TARGET)-clay"

# Clay debug build
.PHONY: clay-debug
clay-debug: $(SOURCES_CLAY) include/clay.h
	@echo "Building Clay UI debug version..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(DEBUG_FLAGS) -I include -o $(BUILD_DIR)/$(TARGET)-clay-debug $(SOURCES_CLAY) -lm -lpthread
	@echo "Clay debug build complete: $(BUILD_DIR)/$(TARGET)-clay-debug"



# Clay example build
.PHONY: clay-example
clay-example: examples/clay_simple.c include/clay.h
	@echo "Building Clay example..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I include -o $(BUILD_DIR)/clay-example examples/clay_simple.c -lm -lpthread
	@echo "Clay example build complete: $(BUILD_DIR)/clay-example"

# Cosmopolitan libc build (ultra-portable)
.PHONY: cosmopolitan
cosmopolitan: download-cosmo
	@echo "Building with Cosmopolitan libc..."
	@mkdir -p $(BUILD_DIR)
	@if [ -f "$(COSMO_DIR)/cosmopolitan.h" ]; then \
		$(CC) -g -Os \
			-static \
			-nostdlib \
			-nostdinc \
			-fno-pie \
			-no-pie \
			-mno-red-zone \
			-I include \
			-o $(BUILD_DIR)/$(TARGET).com.dbg \
			$(SOURCES) \
			-Wl,--gc-sections \
			-fuse-ld=bfd \
			-Wl,-T,$(COSMO_DIR)/ape.lds \
			-include $(COSMO_DIR)/cosmopolitan.h \
			$(COSMO_DIR)/crt.o \
			$(COSMO_DIR)/ape-no-modify-self.o \
			$(COSMO_DIR)/cosmopolitan.a && \
		objcopy -S -O binary $(BUILD_DIR)/$(TARGET).com.dbg $(BUILD_DIR)/$(TARGET).com && \
		echo "Cosmopolitan build complete: $(BUILD_DIR)/$(TARGET).com"; \
	else \
		echo "Error: Cosmopolitan not found. Run 'make download-cosmo' first."; \
		exit 1; \
	fi

# Download Cosmopolitan libc
.PHONY: download-cosmo
download-cosmo:
	@if [ ! -d "$(COSMO_DIR)" ]; then \
		echo "Downloading Cosmopolitan $(COSMO_VERSION)..."; \
		mkdir -p $(BUILD_DIR); \
		cd $(BUILD_DIR) && \
		wget -q --show-progress $(COSMO_URL) && \
		tar -xzf cosmopolitan-$(COSMO_VERSION).tar.gz && \
		mv cosmopolitan-$(COSMO_VERSION) ../$(COSMO_DIR) && \
		cd ..; \
		echo "Cosmopolitan downloaded successfully"; \
	else \
		echo "Cosmopolitan already present"; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET) $(TARGET)-debug $(TARGET).com $(TARGET).com.dbg
	@echo "Clean complete"

# Deep clean (including Cosmopolitan)
.PHONY: distclean
distclean: clean
	@echo "Removing Cosmopolitan..."
	rm -rf $(COSMO_DIR)
	@echo "Distclean complete"

# Install to system
.PHONY: install
install: $(BUILD_DIR)/$(TARGET)
	@echo "Installing debork..."
	install -D -m 755 $(BUILD_DIR)/$(TARGET) $(DESTDIR)$(INSTALL_DIR)/$(TARGET)
	install -D -m 644 README.md $(DESTDIR)$(DOCS_DIR)/README.md 2>/dev/null || true
	@echo "Installation complete. Run 'sudo debork' to start."

# Uninstall from system
.PHONY: uninstall
uninstall:
	@echo "Uninstalling debork..."
	rm -f $(INSTALL_DIR)/$(TARGET)
	rm -rf $(DOCS_DIR)
	@echo "Uninstall complete"

# Create portable package
.PHONY: package
package: standard
	@echo "Creating portable package..."
	@mkdir -p $(BUILD_DIR)/debork-portable
	cp $(BUILD_DIR)/$(TARGET) $(BUILD_DIR)/debork-portable/
	cp README.md $(BUILD_DIR)/debork-portable/ 2>/dev/null || true
	@echo '#!/bin/bash' > $(BUILD_DIR)/debork-portable/install.sh
	@echo 'echo "Installing debork to /usr/local/bin..."' >> $(BUILD_DIR)/debork-portable/install.sh
	@echo 'sudo cp debork /usr/local/bin/' >> $(BUILD_DIR)/debork-portable/install.sh
	@echo 'sudo chmod +x /usr/local/bin/debork' >> $(BUILD_DIR)/debork-portable/install.sh
	@echo 'echo "Installation complete. Run sudo debork to start."' >> $(BUILD_DIR)/debork-portable/install.sh
	chmod +x $(BUILD_DIR)/debork-portable/install.sh
	cd $(BUILD_DIR) && tar czf debork-portable.tar.gz debork-portable/
	@echo "Package created: $(BUILD_DIR)/debork-portable.tar.gz"

# Create release package with both versions
.PHONY: release
release: standard cosmopolitan package
	@echo "Creating release package..."
	@mkdir -p $(BUILD_DIR)/release
	cp $(BUILD_DIR)/$(TARGET) $(BUILD_DIR)/release/$(TARGET)-linux
	-cp $(BUILD_DIR)/$(TARGET).com $(BUILD_DIR)/release/$(TARGET)-portable.com 2>/dev/null
	cp $(BUILD_DIR)/debork-portable.tar.gz $(BUILD_DIR)/release/
	cd $(BUILD_DIR)/release && tar czf debork-release.tar.gz *
	@echo "Release package created: $(BUILD_DIR)/release/debork-release.tar.gz"

# Run tests
.PHONY: test
test: debug
	@echo "Running tests..."
	@if [ -f "test_debork.sh" ]; then \
		./test_debork.sh; \
	else \
		echo "No tests found. Create test_debork.sh to add tests."; \
	fi

# Check code style
.PHONY: check
check:
	@echo "Checking code style..."
	@which clang-format > /dev/null 2>&1 && \
		clang-format --dry-run --Werror $(SOURCES) || \
		echo "clang-format not found, skipping style check"
	@which cppcheck > /dev/null 2>&1 && \
		cppcheck --enable=all --suppress=missingIncludeSystem $(SOURCES) || \
		echo "cppcheck not found, skipping static analysis"

# Format code
.PHONY: format
format:
	@echo "Formatting code..."
	@which clang-format > /dev/null 2>&1 && \
		clang-format -i $(SOURCES) || \
		echo "clang-format not found"

# Show help
.PHONY: help
help:
	@echo "debork Build System (C Version)"
	@echo "================================"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build standard static binary (default)"
	@echo "  standard     - Build standard static Linux binary"
	@echo "  clay         - Build Clay UI version (with pretty TUI)"
	@echo "  clay-debug   - Build Clay UI with debug symbols"
	@echo "  clay-example - Build Clay example program"
	@echo "  cosmopolitan - Build with Cosmopolitan libc (ultra-portable)"
	@echo "  debug        - Build with debug symbols"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove everything including downloads"
	@echo "  install      - Install to system (requires root)"
	@echo "  uninstall    - Remove from system (requires root)"
	@echo "  package      - Create portable package"
	@echo "  release      - Create full release package"
	@echo "  test         - Run tests"
	@echo "  check        - Check code style and run static analysis"
	@echo "  format       - Auto-format code"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Build examples:"
	@echo "  make                    # Build standard static binary"
	@echo "  make clay               # Build Clay UI version (pretty TUI)"
	@echo "  make clay-example       # Build and test Clay example"
	@echo "  make cosmopolitan       # Build ultra-portable version"
	@echo "  make debug              # Build with debugging"
	@echo "  sudo make install       # Install system-wide"
	@echo "  make package            # Create distributable package"
	@echo ""
	@echo "The standard build creates a statically linked Linux binary."
	@echo "The cosmopolitan build creates a portable binary that runs on"
	@echo "Linux, Mac, Windows, FreeBSD, OpenBSD, and NetBSD."

# Set default goal
.DEFAULT_GOAL := all