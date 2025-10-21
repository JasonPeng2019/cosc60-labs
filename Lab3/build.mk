# build.mk - Enhanced Makefile that includes common.mk
# This provides a more sophisticated build system using the shared configuration

# Include the common configuration
include common.mk

# Override default target
.DEFAULT_GOAL := all

# Additional project-specific variables
TEST_SOURCES = test_main.c
TEST_EXECUTABLE = $(BIN_DIR)/packets_test$(EXE_EXT)

# Main targets
all: shared static test

shared: $(LIB_DIR)/$(SHARED_LIB)

static: $(LIB_DIR)/$(STATIC_LIB)

libraries: shared static

# Test target
test: $(TEST_EXECUTABLE)
	@echo "Running test..."
	$(TEST_EXECUTABLE)

$(TEST_EXECUTABLE): $(TEST_SOURCES) $(LIB_DIR)/$(STATIC_LIB) | $(BIN_DIR)
	@echo "Building test executable..."
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(TEST_SOURCES) $(LIB_DIR)/$(STATIC_LIB) $(LDFLAGS)

# Generate test source if it doesn't exist
$(TEST_SOURCES):
	@echo "Generating test source file..."
	@echo '#include "packets.h"' > $@
	@echo '#include <stdio.h>' >> $@
	@echo '' >> $@
	@echo 'int main() {' >> $@
	@echo '    printf("Packet library test (enhanced build)\\n");' >> $@
	@echo '    ' >> $@
	@echo '    uint8_t src_ip[4] = {10, 0, 0, 1};' >> $@
	@echo '    uint8_t dst_ip[4] = {10, 0, 0, 2};' >> $@
	@echo '    ' >> $@
	@echo '    ipv4_t* ip = create_ipv4(src_ip, dst_ip, 1, 20, 64);' >> $@
	@echo '    if (ip) {' >> $@
	@echo '        printf("IPv4 packet created successfully!\\n");' >> $@
	@echo '        ipv4_show(ip);' >> $@
	@echo '        ' >> $@
	@echo '        // Test ICMP creation' >> $@
	@echo '        icmp_t* icmp = create_icmp(ip, 8, 0, 1, 1);' >> $@
	@echo '        if (icmp) {' >> $@
	@echo '            printf("ICMP packet created successfully!\\n");' >> $@
	@echo '            icmp_show(icmp);' >> $@
	@echo '            free(icmp);' >> $@
	@echo '        }' >> $@
	@echo '        ' >> $@
	@echo '        free(ip);' >> $@
	@echo '    } else {' >> $@
	@echo '        printf("Failed to create IPv4 packet!\\n");' >> $@
	@echo '        return 1;' >> $@
	@echo '    }' >> $@
	@echo '    ' >> $@
	@echo '    printf("All tests passed!\\n");' >> $@
	@echo '    return 0;' >> $@
	@echo '}' >> $@

# Examples
examples: $(BIN_DIR)/ping_example$(EXE_EXT) $(BIN_DIR)/sniff_example$(EXE_EXT)

$(BIN_DIR)/ping_example$(EXE_EXT): examples/ping_example.c $(LIB_DIR)/$(STATIC_LIB) | $(BIN_DIR)
	@echo "Building ping example..."
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< $(LIB_DIR)/$(STATIC_LIB) $(LDFLAGS)

$(BIN_DIR)/sniff_example$(EXE_EXT): examples/sniff_example.c $(LIB_DIR)/$(STATIC_LIB) | $(BIN_DIR)
	@echo "Building sniff example..."
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< $(LIB_DIR)/$(STATIC_LIB) $(LDFLAGS)

# Create example directory and files
examples/ping_example.c: | examples
	@echo "Creating ping example..."
	@echo '#include "packets.h"' > $@
	@echo '#include <stdio.h>' >> $@
	@echo '#include <string.h>' >> $@
	@echo '' >> $@
	@echo 'int main() {' >> $@
	@echo '    printf("ICMP Ping Example\\n");' >> $@
	@echo '    ' >> $@
	@echo '    uint8_t src_ip[4] = {192, 168, 1, 100};' >> $@
	@echo '    uint8_t dst_ip[4] = {8, 8, 8, 8};' >> $@
	@echo '    ' >> $@
	@echo '    ipv4_t* ip = create_ipv4(src_ip, dst_ip, 1, 20, 64, 0, 0, 0, 0);' >> $@
	@echo '    icmp_t* ping = create_icmp(ip, 8, 0, 1, 1, NULL, 0);' >> $@
	@echo '    ' >> $@
	@echo '    if (ping) {' >> $@
	@echo '        printf("Created ICMP ping packet:\\n");' >> $@
	@echo '        ipv4_show(ip);' >> $@
	@echo '        icmp_show(ping);' >> $@
	@echo '        ' >> $@
	@echo '        // Note: Actual sending requires root privileges' >> $@
	@echo '        printf("To send: run as root\\n");' >> $@
	@echo '        ' >> $@
	@echo '        free(ping);' >> $@
	@echo '    }' >> $@
	@echo '    ' >> $@
	@echo '    free(ip);' >> $@
	@echo '    return 0;' >> $@
	@echo '}' >> $@

examples/sniff_example.c: | examples
	@echo "Creating sniff example..."
	@echo '#include "packets.h"' > $@
	@echo '#include <stdio.h>' >> $@
	@echo '' >> $@
	@echo 'int main() {' >> $@
	@echo '    printf("Packet Sniffing Example\\n");' >> $@
	@echo '    printf("Note: Requires root privileges to capture packets\\n");' >> $@
	@echo '    ' >> $@
	@echo '    // Uncomment to actually sniff (requires root)' >> $@
	@echo '    // ether_t* pkt = sniff();' >> $@
	@echo '    // if (pkt) {' >> $@
	@echo '    //     ether_show(pkt);' >> $@
	@echo '    //     free(pkt);' >> $@
	@echo '    // }' >> $@
	@echo '    ' >> $@
	@echo '    printf("Sniffing simulation complete\\n");' >> $@
	@echo '    return 0;' >> $@
	@echo '}' >> $@

examples:
	@mkdir -p examples

# Documentation
docs: README.md BUILD.md

README.md:
	@echo "Generating README.md..."
	@echo "# NetworkLab3 Packet Library" > $@
	@echo "" >> $@
	@echo "A comprehensive packet manipulation library for network programming." >> $@
	@echo "" >> $@
	@echo "## Features" >> $@
	@echo "- Ethernet frame construction and parsing" >> $@
	@echo "- IPv4 packet handling" >> $@
	@echo "- ICMP, TCP, UDP protocol support" >> $@
	@echo "- DNS packet manipulation" >> $@
	@echo "- Raw socket support (Linux)" >> $@
	@echo "- Layer 2 and Layer 3 packet sending/receiving" >> $@
	@echo "" >> $@
	@echo "## Building" >> $@
	@echo "### Using Make" >> $@
	@echo "\`\`\`bash" >> $@
	@echo "make all          # Build everything" >> $@
	@echo "make shared       # Build shared library" >> $@
	@echo "make static       # Build static library" >> $@
	@echo "make test         # Build and run tests" >> $@
	@echo "make examples     # Build example programs" >> $@
	@echo "\`\`\`" >> $@
	@echo "" >> $@
	@echo "### Using CMake" >> $@
	@echo "\`\`\`bash" >> $@
	@echo "mkdir build && cd build" >> $@
	@echo "cmake .." >> $@
	@echo "make" >> $@
	@echo "\`\`\`" >> $@
	@echo "" >> $@
	@echo "## Installation" >> $@
	@echo "\`\`\`bash" >> $@
	@echo "sudo make install" >> $@
	@echo "\`\`\`" >> $@

BUILD.md:
	@echo "Generating BUILD.md..."
	@echo "# Build Instructions" > $@
	@echo "" >> $@
	@echo "## Prerequisites" >> $@
	@echo "- GCC/G++ compiler with C++11 support" >> $@
	@echo "- Linux system for raw socket functionality" >> $@
	@echo "- Root privileges for packet capture/injection" >> $@
	@echo "" >> $@
	@echo "## Build Systems" >> $@
	@echo "" >> $@
	@echo "### Make (Recommended)" >> $@
	@echo "\`\`\`bash" >> $@
	@echo "make deps-ubuntu    # Install dependencies (Ubuntu)" >> $@
	@echo "make all           # Build everything" >> $@
	@echo "make BUILD_TYPE=debug all  # Debug build" >> $@
	@echo "\`\`\`" >> $@
	@echo "" >> $@
	@echo "### Enhanced Make" >> $@
	@echo "\`\`\`bash" >> $@
	@echo "make -f build.mk all" >> $@
	@echo "\`\`\`" >> $@
	@echo "" >> $@
	@echo "### CMake" >> $@
	@echo "\`\`\`bash" >> $@
	@echo "mkdir build && cd build" >> $@
	@echo "cmake -DCMAKE_BUILD_TYPE=Release .." >> $@
	@echo "make -j\$$(nproc)" >> $@
	@echo "\`\`\`" >> $@

# Clean targets
clean: clean-common
	rm -f $(TEST_SOURCES) README.md BUILD.md
	rm -rf examples

distclean: distclean-common clean
	rm -f README.md BUILD.md

# Install and uninstall
install: install-common

uninstall: uninstall-common

# Distribution package
dist: distclean docs
	@echo "Creating distribution package..."
	tar -czf NetworkLab3-$(PROJECT_VERSION).tar.gz \
		--exclude='.git*' \
		--exclude='build' \
		--exclude='*.tar.gz' \
		.

# Development targets
format:
	@echo "Formatting source code..."
	@which clang-format > /dev/null && \
		clang-format -i $(PACKET_SOURCES) $(PACKET_HEADERS) || \
		echo "clang-format not available"

lint:
	@echo "Running static analysis..."
	@which cppcheck > /dev/null && \
		cppcheck --enable=all --std=c11 $(PACKET_SOURCES) || \
		echo "cppcheck not available"

# Info and help
info: info-common

help: help-common
	@echo ""
	@echo "Additional targets:"
	@echo "  test          - Build and run test program"
	@echo "  examples      - Build example programs"
	@echo "  docs          - Generate documentation"
	@echo "  dist          - Create distribution package"
	@echo "  format        - Format source code"
	@echo "  lint          - Run static analysis"

# Phony targets
.PHONY: all shared static libraries test examples docs clean distclean
.PHONY: install uninstall dist format lint info help