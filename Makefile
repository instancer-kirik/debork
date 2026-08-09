# debork - Cross-Platform Linux Boot Rescue Tool
# Makefile for building and packaging

# Compiler and flags
DC = dmd
DFLAGS = -O -release -inline
DEBUG_FLAGS = -g -debug
SOURCES = fixer.d
TARGET = debork
INSTALL_DIR = /usr/local/bin
DOCS_DIR = /usr/local/share/doc/debork

# C compiler and flags for Clay versions
CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c11 -march=native
CFLAGS_DEBUG = -g -O0 -DDEBUG
CLAY_SOURCES = src/c/debork_clay.c
CLAY_OPT_SOURCES = src/c/debork_clay_optimized.c
CLAY_AWESOME_SOURCES = src/c/debork_clay_awesome.c
CLAY_FIXED_SOURCES = src/c/debork_clay_render_fix.c
CUTE_SOURCES = src/c/debork_cute.c
CLAY_TARGET = debork-clay
CLAY_OPT_TARGET = debork-clay-opt
CLAY_AWESOME_TARGET = debork-clay-awesome
CLAY_FIXED_TARGET = debork-clay-fixed
CUTE_TARGET = debork-cute
CLAY_LIBS = -lm

# Build targets
.PHONY: all clean install uninstall debug package help clay clay-opt clay-awesome clay-fixed clay-debug cute

all: $(TARGET)

# Clay/C builds
clay: $(CLAY_TARGET)

clay-opt: $(CLAY_OPT_TARGET)

clay-awesome: $(CLAY_AWESOME_TARGET)

clay-fixed: $(CLAY_FIXED_TARGET)

cute: $(CUTE_TARGET)

clay-debug: $(CLAY_SOURCES)
	$(CC) $(CFLAGS_DEBUG) -o $(CLAY_TARGET)-debug $(CLAY_SOURCES) $(CLAY_LIBS)

$(CLAY_TARGET): $(CLAY_SOURCES)
	$(CC) $(CFLAGS) -o $(CLAY_TARGET) $(CLAY_SOURCES) $(CLAY_LIBS)

$(CLAY_OPT_TARGET): $(CLAY_OPT_SOURCES)
	$(CC) $(CFLAGS) -o $(CLAY_OPT_TARGET) $(CLAY_OPT_SOURCES) $(CLAY_LIBS)

$(CLAY_AWESOME_TARGET): $(CLAY_AWESOME_SOURCES)
	$(CC) $(CFLAGS) -o $(CLAY_AWESOME_TARGET) $(CLAY_AWESOME_SOURCES) $(CLAY_LIBS)

$(CLAY_FIXED_TARGET): $(CLAY_FIXED_SOURCES)
	$(CC) $(CFLAGS) -o $(CLAY_FIXED_TARGET) $(CLAY_FIXED_SOURCES) $(CLAY_LIBS)

$(CUTE_TARGET): $(CUTE_SOURCES)
	$(CC) $(CFLAGS) -o $(CUTE_TARGET) $(CUTE_SOURCES) $(CLAY_LIBS)

$(TARGET): $(SOURCES)
	$(DC) $(DFLAGS) -of$(TARGET) $(SOURCES)

debug: $(SOURCES)
	$(DC) $(DEBUG_FLAGS) -of$(TARGET)-debug $(SOURCES)

clean:
	rm -f $(TARGET) $(TARGET)-debug *.o
	rm -f $(CLAY_TARGET) $(CLAY_TARGET)-debug $(CLAY_OPT_TARGET) $(CLAY_AWESOME_TARGET) $(CLAY_FIXED_TARGET) $(CUTE_TARGET)
	rm -rf package/ build/

install: $(TARGET)
	@echo "Installing debork..."
	install -D -m 755 $(TARGET) $(DESTDIR)$(INSTALL_DIR)/$(TARGET)
	install -D -m 644 README.md $(DESTDIR)$(DOCS_DIR)/README.md
	@echo "Installation complete. Run 'sudo debork' to start."

uninstall:
	@echo "Uninstalling debork..."
	rm -f $(INSTALL_DIR)/$(TARGET)
	rm -rf $(DOCS_DIR)
	@echo "Uninstall complete."

# Create portable package
package: $(TARGET)
	@echo "Creating portable package..."
	mkdir -p package/debork
	cp $(TARGET) package/debork/
	cp README.md package/debork/
	cp LICENSE package/debork/ 2>/dev/null || true
	echo '#!/bin/bash' > package/debork/install.sh
	echo 'cp debork /usr/local/bin/' >> package/debork/install.sh
	echo 'chmod +x /usr/local/bin/debork' >> package/debork/install.sh
	echo 'echo "debork installed to /usr/local/bin/debork"' >> package/debork/install.sh
	chmod +x package/debork/install.sh
	cd package && tar czf debork-portable.tar.gz debork/
	@echo "Portable package created: package/debork-portable.tar.gz"

# Test compilation with different D compilers
test-ldc:
	ldc2 $(DFLAGS) -of=$(TARGET)-ldc $(SOURCES)

test-gdc:
	gdc $(DFLAGS) -o $(TARGET)-gdc $(SOURCES)

# Static build for rescue scenarios
static: $(SOURCES)
	$(DC) $(DFLAGS) -static -of=$(TARGET)-static $(SOURCES)

help:
	@echo "debork Build System"
	@echo "==================="
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build debork (default)"
	@echo "  debug    - Build with debug symbols"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system (requires root)"
	@echo "  uninstall- Remove from system (requires root)"
	@echo "  package  - Create portable package"
	@echo "  static   - Create static binary for rescue"
	@echo "  test-ldc - Test build with LDC compiler"
	@echo "  test-gdc - Test build with GDC compiler"
	@echo ""
	@echo "Clay/C Targets:"
	@echo "  clay     - Build Clay-based TUI version"
	@echo "  clay-opt - Build optimized Clay TUI (better performance)"
	@echo "  clay-awesome - Build awesome Clay TUI (best visuals & UX)"
	@echo "  clay-fixed - Build fixed Clay TUI (no grey box issues)"
	@echo "  clay-debug - Build Clay TUI with debug symbols"
	@echo "  cute     - Build cute & lightweight TUI (no Clay, kawaii style)"
	@echo ""
	@echo "  help     - Show this help"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build debork"
	@echo "  make debug        # Build with debugging"
	@echo "  make clay-awesome # Build awesome Clay UI"
	@echo "  sudo make install # Install system-wide"
	@echo "  make package      # Create portable package"
	@echo "  make static       # Create rescue binary"
