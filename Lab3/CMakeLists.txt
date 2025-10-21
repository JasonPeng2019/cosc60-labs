cmake_minimum_required(VERSION 3.10)

# Project definition
project(NetworkLab3 
    VERSION 1.0.0
    DESCRIPTION "Network packet manipulation library"
    LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Debug/Release configurations
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# Find required packages (Linux-specific networking libraries)
if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
endif()

# Source files
set(PACKET_SOURCES
    packets.c
)

set(PACKET_HEADERS
    packets.h
)

# Create shared library
add_library(packets_shared SHARED ${PACKET_SOURCES})
target_include_directories(packets_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

# Create static library
add_library(packets_static STATIC ${PACKET_SOURCES})
target_include_directories(packets_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

# Set library properties
set_target_properties(packets_shared PROPERTIES
    OUTPUT_NAME packets
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

set_target_properties(packets_static PROPERTIES
    OUTPUT_NAME packets
)

# Compile as C
set_source_files_properties(packets.c PROPERTIES LANGUAGE C)

# Link libraries (Linux networking libraries)
if(UNIX AND NOT APPLE)
    target_link_libraries(packets_shared PRIVATE Threads::Threads)
    target_link_libraries(packets_static PRIVATE Threads::Threads)
endif()

# Test executable
add_executable(packets_test main.c)
target_sources(packets_test PRIVATE packets.c)

# Generate test main file (commented out - using custom main.c instead)
# file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/test_main.c
# "#include \"packets.h\"
# #include <stdio.h>
# 
# int main() {
#     printf(\"Packet library compiled successfully with CMake!\\n\");
#     
#     uint8_t src_ip[4] = {192, 168, 1, 1};
#     uint8_t dst_ip[4] = {192, 168, 1, 2};
#     
#     ipv4_t* ip = create_ipv4(src_ip, dst_ip, 1, 20, 64, 0, 0, 0, 0);
#     if (ip) {
#         printf(\"IPv4 packet created successfully!\\n\");
#         ipv4_show(ip);
#         free(ip);
#     }
#     
#     return 0;
# }
# ")

target_link_libraries(packets_test PRIVATE packets_static)
target_include_directories(packets_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Installation rules
include(GNUInstallDirs)

install(TARGETS packets_shared packets_static
    EXPORT NetworkLab3Targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES ${PACKET_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Export targets
install(EXPORT NetworkLab3Targets
    FILE NetworkLab3Targets.cmake
    NAMESPACE NetworkLab3::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkLab3
)

# Create config file
include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/NetworkLab3Config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkLab3
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/NetworkLab3ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/NetworkLab3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/NetworkLab3ConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/NetworkLab3
)

# Custom targets
add_custom_target(info
    COMMAND ${CMAKE_COMMAND} -E echo "=== CMake Build Information ==="
    COMMAND ${CMAKE_COMMAND} -E echo "Build Type: ${CMAKE_BUILD_TYPE}"
    COMMAND ${CMAKE_COMMAND} -E echo "C Compiler: ${CMAKE_C_COMPILER}"
    COMMAND ${CMAKE_COMMAND} -E echo "C Compiler: ${CMAKE_C_COMPILER}"
    COMMAND ${CMAKE_COMMAND} -E echo "Install Prefix: ${CMAKE_INSTALL_PREFIX}"
    COMMAND ${CMAKE_COMMAND} -E echo "Source Dir: ${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND ${CMAKE_COMMAND} -E echo "Binary Dir: ${CMAKE_CURRENT_BINARY_DIR}"
)

# Enable testing
enable_testing()
add_test(NAME packets_basic_test COMMAND packets_test)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "NetworkLab3")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "Dartmouth CS60")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.txt")

include(CPack)

# Print configuration summary
message(STATUS "=== NetworkLab3 Configuration Summary ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Building shared library: packets_shared")
message(STATUS "Building static library: packets_static")
message(STATUS "Building test executable: packets_test")