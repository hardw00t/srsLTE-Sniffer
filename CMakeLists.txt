########################################################################
# srsLTE-Sniffer CMake Build System
#
# This CMake file builds the standalone tools and provides integration
# points for srsLTE library when available.
########################################################################

cmake_minimum_required(VERSION 3.10)
project(srsLTE-Sniffer
    VERSION 1.0.0
    DESCRIPTION "LTE IMSI Catcher and Signal Analyzer"
    LANGUAGES C
)

# Build options
option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_TOOLS "Build standalone tools" ON)
option(ENABLE_SQLITE "Enable SQLite database handler" ON)
option(ENABLE_JSON_CONFIG "Enable JSON configuration support" ON)
option(ENABLE_PCAP "Enable enhanced PCAP export" ON)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wformat=2)
    add_compile_options(-Wno-unused-parameter)
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find required packages
find_package(Threads REQUIRED)

# Find optional packages
if(ENABLE_SQLITE)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SQLITE3 sqlite3)
    endif()
    if(NOT SQLITE3_FOUND)
        find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
        find_library(SQLITE3_LIBRARY sqlite3)
        if(SQLITE3_INCLUDE_DIR AND SQLITE3_LIBRARY)
            set(SQLITE3_FOUND TRUE)
            set(SQLITE3_INCLUDE_DIRS ${SQLITE3_INCLUDE_DIR})
            set(SQLITE3_LIBRARIES ${SQLITE3_LIBRARY})
        endif()
    endif()
    if(SQLITE3_FOUND)
        message(STATUS "SQLite3 found: ${SQLITE3_LIBRARIES}")
        add_definitions(-DENABLE_SQLITE)
    else()
        message(STATUS "SQLite3 not found - database handler disabled")
        set(ENABLE_SQLITE OFF)
    endif()
endif()

########################################################################
# Core Library
########################################################################

# Source files for core library
set(CORE_SOURCES
    Code/data_handler.c
    Code/sib_parser.c
    Code/logger.c
    Code/config_parser.c
    Code/memory_pool.c
    Code/identity_tracker.c
    Code/mib_parser.c
    Code/paging_parser.c
    Code/handler_identity.c
)

if(ENABLE_SQLITE)
    list(APPEND CORE_SOURCES Code/handler_sqlite.c)
endif()

if(ENABLE_PCAP)
    list(APPEND CORE_SOURCES Code/pcap_writer.c)
endif()

# Create core library
add_library(srslte_sniffer_core STATIC ${CORE_SOURCES})
target_include_directories(srslte_sniffer_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Code
)
target_link_libraries(srslte_sniffer_core
    Threads::Threads
    m
)

if(ENABLE_SQLITE AND SQLITE3_FOUND)
    target_include_directories(srslte_sniffer_core PUBLIC ${SQLITE3_INCLUDE_DIRS})
    target_link_libraries(srslte_sniffer_core ${SQLITE3_LIBRARIES})
endif()

########################################################################
# Standalone Tools
########################################################################

if(BUILD_TOOLS)
    # convert_to_csv tool
    add_executable(convert_to_csv Code/convert_to_csv.c)
    target_link_libraries(convert_to_csv srslte_sniffer_core)

    # Install tools
    install(TARGETS convert_to_csv
        RUNTIME DESTINATION bin
    )
endif()

########################################################################
# Unit Tests
########################################################################

if(BUILD_TESTS)
    enable_testing()

    # Test sources
    set(TEST_SOURCES
        tests/test_main.c
        tests/test_sib_parser.c
        tests/test_data_handler.c
        tests/test_convert_csv.c
        tests/test_bit_reader.c
        tests/test_identity_tracker.c
        tests/test_memory_pool.c
        tests/test_logger.c
        tests/test_config_parser.c
        tests/test_mib_parser.c
        tests/test_paging_parser.c
    )

    # Create test executable
    add_executable(run_tests ${TEST_SOURCES})
    target_include_directories(run_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/Code
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_link_libraries(run_tests srslte_sniffer_core)

    # Register tests
    add_test(NAME AllTests COMMAND run_tests)

    # Individual test targets for convenience
    add_custom_target(test_quick
        COMMAND run_tests
        DEPENDS run_tests
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endif()

########################################################################
# Installation
########################################################################

# Install headers
install(FILES
    Code/data_handler.h
    Code/sib_parser.h
    Code/logger.h
    Code/config_parser.h
    Code/memory_pool.h
    Code/identity_tracker.h
    Code/mib_parser.h
    Code/paging_parser.h
    Code/handler_identity.h
    DESTINATION include/srslte_sniffer
)

if(ENABLE_SQLITE)
    install(FILES Code/handler_sqlite.h DESTINATION include/srslte_sniffer)
endif()

if(ENABLE_PCAP)
    install(FILES Code/pcap_writer.h DESTINATION include/srslte_sniffer)
endif()

# Install library
install(TARGETS srslte_sniffer_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

# Install Wireshark dissector
install(FILES wireshark/srslte_sniffer.lua
    DESTINATION share/wireshark/plugins
)

########################################################################
# Package configuration
########################################################################

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/srsLTE-SnifferConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/srsLTE-SnifferConfig.cmake
    INSTALL_DESTINATION lib/cmake/srsLTE-Sniffer
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/srsLTE-SnifferConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/srsLTE-SnifferConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/srsLTE-SnifferConfigVersion.cmake
    DESTINATION lib/cmake/srsLTE-Sniffer
)

########################################################################
# Print configuration summary
########################################################################

message(STATUS "")
message(STATUS "=== srsLTE-Sniffer Build Configuration ===")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler:     ${CMAKE_C_COMPILER}")
message(STATUS "  Build tests:    ${BUILD_TESTS}")
message(STATUS "  Build tools:    ${BUILD_TOOLS}")
message(STATUS "  SQLite support: ${ENABLE_SQLITE}")
message(STATUS "  JSON config:    ${ENABLE_JSON_CONFIG}")
message(STATUS "  PCAP support:   ${ENABLE_PCAP}")
message(STATUS "")
