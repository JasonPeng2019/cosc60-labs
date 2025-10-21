# common.mk - Shared Make configuration for NetworkLab3
# Include this file in other Makefiles for consistent build settings

# Compiler configuration
CC ?= gcc
AR ?= ar
LD ?= ld

# Project information
PROJECT_NAME = NetworkLab3
PROJECT_VERSION = 1.0.0
PROJECT_DESCRIPTION = Network packet manipulation library

# Directory structure
SRC_DIR ?= .
BUILD_DIR ?= build
OBJ_DIR ?= $(BUILD_DIR)/obj
LIB_DIR ?= $(BUILD_DIR)/lib
BIN_DIR ?= $(BUILD_DIR)/bin
INSTALL_PREFIX ?= /usr/local

# Compiler flags
COMMON_CFLAGS = -Wall -Wextra -fPIC
COMMON_LDFLAGS = 

# Standard versions
C_STANDARD = -std=c11

# Build type specific flags
DEBUG_FLAGS = -g -O0 -DDEBUG
RELEASE_FLAGS = -O2 -DNDEBUG
PROFILE_FLAGS = -pg -O2

# Default to release build
BUILD_TYPE ?= release

ifeq ($(BUILD_TYPE),debug)
    CFLAGS = $(COMMON_CFLAGS) $(C_STANDARD) $(DEBUG_FLAGS)
else ifeq ($(BUILD_TYPE),profile)
    CFLAGS = $(COMMON_CFLAGS) $(C_STANDARD) $(PROFILE_FLAGS)
else
    CFLAGS = $(COMMON_CFLAGS) $(C_STANDARD) $(RELEASE_FLAGS)
endif

LDFLAGS = $(COMMON_LDFLAGS)

# Platform-specific settings
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
    PLATFORM = linux
    SHARED_EXT = .so
    STATIC_EXT = .a
    EXE_EXT = 
    LDFLAGS += -lpthread
endif

ifeq ($(UNAME_S),Darwin)
    PLATFORM = macos
    SHARED_EXT = .dylib
    STATIC_EXT = .a
    EXE_EXT = 
endif

ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    SHARED_EXT = .dll
    STATIC_EXT = .lib
    EXE_EXT = .exe
endif

# Library names
SHARED_LIB = lib$(PROJECT_NAME)$(SHARED_EXT)
STATIC_LIB = lib$(PROJECT_NAME)$(STATIC_EXT)

# Source and header files
PACKET_SOURCES = packets.c
PACKET_HEADERS = packets.h
PACKET_OBJECTS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(PACKET_SOURCES))

# Compilation rules
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(PACKET_HEADERS) | $(OBJ_DIR)
	@echo "Compiling $< (as C)..."
	$(CC) $(CFLAGS) -c $< -o $@

# Directory creation
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(OBJ_DIR): | $(BUILD_DIR)
	@mkdir -p $(OBJ_DIR)

$(LIB_DIR): | $(BUILD_DIR)
	@mkdir -p $(LIB_DIR)

$(BIN_DIR): | $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)

# Library targets
$(LIB_DIR)/$(SHARED_LIB): $(PACKET_OBJECTS) | $(LIB_DIR)
	@echo "Building shared library $@..."
	$(CC) -shared $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(LIB_DIR)/$(STATIC_LIB): $(PACKET_OBJECTS) | $(LIB_DIR)
	@echo "Building static library $@..."
	$(AR) rcs $@ $^

# Clean targets
clean-common:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

distclean-common: clean-common
	@echo "Deep cleaning..."
	rm -f *~ *.bak

# Install targets
install-common: $(LIB_DIR)/$(SHARED_LIB) $(LIB_DIR)/$(STATIC_LIB)
	@echo "Installing libraries to $(INSTALL_PREFIX)..."
	install -d $(INSTALL_PREFIX)/lib
	install -d $(INSTALL_PREFIX)/include
	install -m 644 $(LIB_DIR)/$(SHARED_LIB) $(INSTALL_PREFIX)/lib/
	install -m 644 $(LIB_DIR)/$(STATIC_LIB) $(INSTALL_PREFIX)/lib/
	install -m 644 $(PACKET_HEADERS) $(INSTALL_PREFIX)/include/
ifeq ($(PLATFORM),linux)
	ldconfig
endif

# Uninstall targets
uninstall-common:
	@echo "Uninstalling libraries from $(INSTALL_PREFIX)..."
	rm -f $(INSTALL_PREFIX)/lib/$(SHARED_LIB)
	rm -f $(INSTALL_PREFIX)/lib/$(STATIC_LIB)
	rm -f $(addprefix $(INSTALL_PREFIX)/include/,$(PACKET_HEADERS))

# Development dependencies
deps-ubuntu:
	@echo "Installing development dependencies (Ubuntu/Debian)..."
	sudo apt-get update
	sudo apt-get install -y build-essential cmake pkg-config

deps-fedora:
	@echo "Installing development dependencies (Fedora/RHEL)..."
	sudo dnf install -y gcc make cmake pkgconfig

deps-arch:
	@echo "Installing development dependencies (Arch Linux)..."
	sudo pacman -S --needed base-devel cmake pkgconf

# Information targets
info-common:
	@echo "=== Build Configuration ==="
	@echo "Project: $(PROJECT_NAME) v$(PROJECT_VERSION)"
	@echo "Platform: $(PLATFORM) ($(UNAME_S)/$(UNAME_M))"
	@echo "Build Type: $(BUILD_TYPE)"
	@echo "C Compiler: $(CC)"
	@echo "C Compiler: $(CC)"
	@echo "C Flags: $(CFLAGS)"
	@echo "LD Flags: $(LDFLAGS)"
	@echo "Install Prefix: $(INSTALL_PREFIX)"
	@echo "Shared Library: $(SHARED_LIB)"
	@echo "Static Library: $(STATIC_LIB)"

# Help target
help-common:
	@echo "Available targets:"
	@echo "  shared        - Build shared library"
	@echo "  static        - Build static library"
	@echo "  clean         - Remove build artifacts"
	@echo "  distclean     - Remove all generated files"
	@echo "  install       - Install libraries to system"
	@echo "  uninstall     - Remove libraries from system"
	@echo "  deps-ubuntu   - Install deps on Ubuntu/Debian"
	@echo "  deps-fedora   - Install deps on Fedora/RHEL"
	@echo "  deps-arch     - Install deps on Arch Linux"
	@echo "  info          - Show build configuration"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Build types (set BUILD_TYPE=type):"
	@echo "  release       - Optimized build (default)"
	@echo "  debug         - Debug build with symbols"
	@echo "  profile       - Profiling build"

# Phony targets
.PHONY: clean-common distclean-common install-common uninstall-common
.PHONY: deps-ubuntu deps-fedora deps-arch info-common help-common