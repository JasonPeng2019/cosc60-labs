# packets.cmake - CMake module for NetworkLab3 packet library
# This file provides functions and macros for working with the packet library

# Include guard
if(PACKETS_CMAKE_INCLUDED)
    return()
endif()
set(PACKETS_CMAKE_INCLUDED TRUE)

# Minimum CMake version
cmake_minimum_required(VERSION 3.10)

# Function to find and configure the packet library
function(find_packets)
    # Parse arguments
    set(options REQUIRED)
    set(oneValueArgs VERSION)
    set(multiValueArgs COMPONENTS)
    cmake_parse_arguments(FIND_PACKETS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    # Try to find the installed package first
    find_package(NetworkLab3 ${FIND_PACKETS_VERSION} QUIET
                 COMPONENTS ${FIND_PACKETS_COMPONENTS})

    if(NetworkLab3_FOUND)
        message(STATUS "Found installed NetworkLab3 package")
        return()
    endif()

    # If not found, try to find in current project
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/packets.h")
        message(STATUS "Found NetworkLab3 sources in current directory")
        
        # Add the library if not already defined
        if(NOT TARGET packets_shared AND NOT TARGET NetworkLab3::packets_shared)
            add_library(packets_shared SHARED packets.c)
            set_source_files_properties(packets.c PROPERTIES LANGUAGE C)
            target_include_directories(packets_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
            
            # Create alias for consistency
            add_library(NetworkLab3::packets_shared ALIAS packets_shared)
        endif()

        if(NOT TARGET packets_static AND NOT TARGET NetworkLab3::packets_static)
            add_library(packets_static STATIC packets.c)
            set_source_files_properties(packets.c PROPERTIES LANGUAGE C)
            target_include_directories(packets_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
            
            # Create alias for consistency
            add_library(NetworkLab3::packets_static ALIAS packets_static)
        endif()

        # Set variables for compatibility
        set(NetworkLab3_FOUND TRUE PARENT_SCOPE)
        set(NetworkLab3_LIBRARIES NetworkLab3::packets_shared PARENT_SCOPE)
        set(NetworkLab3_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
        
        return()
    endif()

    # If required and not found, fail
    if(FIND_PACKETS_REQUIRED)
        message(FATAL_ERROR "Could not find NetworkLab3 packet library")
    else()
        message(WARNING "NetworkLab3 packet library not found")
    endif()
endfunction()

# Function to create a packet-based executable
function(add_packet_executable target_name)
    # Parse arguments
    set(options "")
    set(oneValueArgs "")
    set(multiValueArgs SOURCES DEPENDS)
    cmake_parse_arguments(ADD_PACKET_EXE "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    # Create the executable
    add_executable(${target_name} ${ADD_PACKET_EXE_SOURCES})

    # Link with packet library
    if(TARGET NetworkLab3::packets_shared)
        target_link_libraries(${target_name} PRIVATE NetworkLab3::packets_shared)
    elseif(TARGET packets_shared)
        target_link_libraries(${target_name} PRIVATE packets_shared)
    else()
        message(WARNING "No packet library target found for ${target_name}")
    endif()

    # Add additional dependencies
    if(ADD_PACKET_EXE_DEPENDS)
        target_link_libraries(${target_name} PRIVATE ${ADD_PACKET_EXE_DEPENDS})
    endif()

    # Set C standard
    target_compile_features(${target_name} PRIVATE c_std_11)
endfunction()

# Function to create a test for packet functionality
function(add_packet_test test_name)
    # Parse arguments
    set(options "")
    set(oneValueArgs SOURCE)
    set(multiValueArgs ARGS)
    cmake_parse_arguments(ADD_PACKET_TEST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    # Default source file
    if(NOT ADD_PACKET_TEST_SOURCE)
        set(ADD_PACKET_TEST_SOURCE "${test_name}.c")
    endif()

    # Create test executable
    add_packet_executable(${test_name} SOURCES ${ADD_PACKET_TEST_SOURCE})

    # Add to CTest
    add_test(NAME ${test_name} 
             COMMAND ${test_name} ${ADD_PACKET_TEST_ARGS})
endfunction()

# Macro to set up packet library build environment
macro(setup_packet_build)
    # Set build type if not specified
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()

    # Enable position independent code
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # Set output directories
    if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    endif()
    if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    endif()
    if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    endif()

    # Find threading library
    find_package(Threads REQUIRED)

    # Platform-specific settings
    if(UNIX AND NOT APPLE)
        # Linux-specific networking libraries are typically built-in
        set(PACKET_PLATFORM_LIBS Threads::Threads)
    endif()
endmacro()

# Function to print packet library information
function(print_packet_info)
    message(STATUS "=== NetworkLab3 Packet Library Information ===")
    
    if(TARGET NetworkLab3::packets_shared OR TARGET packets_shared)
        message(STATUS "Shared library: Available")
    else()
        message(STATUS "Shared library: Not available")
    endif()

    if(TARGET NetworkLab3::packets_static OR TARGET packets_static)
        message(STATUS "Static library: Available")
    else()
        message(STATUS "Static library: Not available")
    endif()

    if(DEFINED NetworkLab3_VERSION)
        message(STATUS "Version: ${NetworkLab3_VERSION}")
    endif()

    if(DEFINED NetworkLab3_INCLUDE_DIRS)
        message(STATUS "Include directories: ${NetworkLab3_INCLUDE_DIRS}")
    endif()
endfunction()

# Utility function to check if packet library supports required features
function(check_packet_features)
    set(options RAW_SOCKETS LAYER2_ACCESS LAYER3_ACCESS)
    cmake_parse_arguments(CHECK_FEATURES "${options}" "" "" ${ARGN})

    set(features_available TRUE)

    if(CHECK_FEATURES_RAW_SOCKETS)
        if(NOT UNIX)
            message(WARNING "Raw sockets require Unix-like system")
            set(features_available FALSE)
        endif()
    endif()

    if(CHECK_FEATURES_LAYER2_ACCESS)
        if(NOT UNIX)
            message(WARNING "Layer 2 access requires Unix-like system")
            set(features_available FALSE)
        endif()
    endif()

    if(CHECK_FEATURES_LAYER3_ACCESS)
        if(NOT UNIX)
            message(WARNING "Layer 3 access requires Unix-like system")
            set(features_available FALSE)
        endif()
    endif()

    if(NOT features_available)
        message(FATAL_ERROR "Required packet features not available on this platform")
    endif()
endfunction()

# Export all functions and macros
set(PACKETS_CMAKE_FUNCTIONS
    find_packets
    add_packet_executable
    add_packet_test
    setup_packet_build
    print_packet_info
    check_packet_features
)

message(STATUS "packets.cmake loaded with functions: ${PACKETS_CMAKE_FUNCTIONS}")