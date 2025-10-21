# Makefile for Network Lab3 packet manipulation library
# Compatible with Linux VM environments

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -g
LDFLAGS = 

# Pure C compilation
COMPILER = $(CC)
FLAGS = $(CFLAGS)

# Target executable name
TARGET = packets_test

# Source files
SOURCES = packets.c main.c
HEADERS = packets.h

# Object files
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Build the main executable (assuming you'll create a test/main file)
$(TARGET): $(OBJECTS)
	@echo "Linking $@..."
	$(COMPILER) $(FLAGS) -o $@ $^ $(LDFLAGS)

# Build object files
%.o: %.c $(HEADERS)
	@echo "Compiling $<..."
	$(COMPILER) $(FLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(OBJECTS) $(TARGET)

# Clean everything including backup files
distclean: clean
	@echo "Deep cleaning..."
	rm -f *~ *.bak

# Install system dependencies (Ubuntu/Debian)
deps:
	@echo "Installing development dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential

# Create a simple test program to verify compilation
test-file:
	@echo "Creating test program..."
	@echo '#include "packets.h"' > test_main.c
	@echo '#include <stdio.h>' >> test_main.c
	@echo 'int main() {' >> test_main.c
	@echo '    printf("Packet library compiled successfully!\\n");' >> test_main.c
	@echo '    uint8_t src_ip[4] = {192, 168, 1, 1};' >> test_main.c
	@echo '    uint8_t dst_ip[4] = {192, 168, 1, 2};' >> test_main.c
	@echo '    ipv4_t* ip = create_ipv4(src_ip, dst_ip, 1, 20, 64, 0, 0, 0, 0);' >> test_main.c
	@echo '    if (ip) {' >> test_main.c
	@echo '        printf("IPv4 packet created successfully!\\n");' >> test_main.c
	@echo '        free(ip);' >> test_main.c
	@echo '    }' >> test_main.c
	@echo '    return 0;' >> test_main.c
	@echo '}' >> test_main.c

# Build and run test
test: test-file
	@echo "Building and running test..."
	$(COMPILER) $(FLAGS) -o test_main packets.c test_main.c
	./test_main

# Build library as shared object
shared: $(OBJECTS)
	@echo "Building shared library..."
	$(COMPILER) -shared -fPIC $(FLAGS) -o libpackets.so $(SOURCES)

# Build library as static archive
static: $(OBJECTS)
	@echo "Building static library..."
	ar rcs libpackets.a $(OBJECTS)

# Install libraries to system (use with caution)
install: shared static
	@echo "Installing libraries to /usr/local/lib..."
	sudo cp libpackets.so /usr/local/lib/
	sudo cp libpackets.a /usr/local/lib/
	sudo cp packets.h /usr/local/include/
	sudo ldconfig

# Show compiler and system info
info:
	@echo "=== Build Environment Info ==="
	@echo "Compiler: $(COMPILER)"
	@echo "Flags: $(FLAGS)"
	@echo "System: $$(uname -a)"
	@echo "GCC Version: $$(gcc --version | head -1)"
	@echo "GCC Version: $$(gcc --version | head -1)"

# Help target
help:
	@echo "Available targets:"
	@echo "  all       - Build the main executable (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  distclean - Remove all generated files"
	@echo "  deps      - Install system dependencies (Ubuntu/Debian)"
	@echo "  test      - Create and run a simple test program"
	@echo "  shared    - Build shared library (.so)"
	@echo "  static    - Build static library (.a)"
	@echo "  install   - Install libraries to system (requires sudo)"
	@echo "  info      - Show build environment information"
	@echo "  help      - Show this help message"

# Prevent make from interpreting these as file targets
.PHONY: all clean distclean deps test-file test shared static install info help