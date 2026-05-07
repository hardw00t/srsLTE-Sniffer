cmake_minimum_required(VERSION 3.16)
project(srslte_sniffer_v2 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(
    -Wall -Wextra -Wno-unused-parameter -Wno-unused-function
    -Wpedantic -Wshadow -Wstrict-prototypes
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# srsRAN_4G is a build-time optional dependency. When found, the C sniffer
# binaries link against it; otherwise they build as `--help` stubs and CI
# still validates the I/O code via smoke tests.
find_package(srsRAN QUIET)
if(SRSRAN_FOUND)
    message(STATUS "srsRAN_4G found at ${SRSRAN_DIR}")
else()
    message(STATUS
        "srsRAN_4G not found. Building stubs only. Set SRSRAN_DIR or "
        "install srsRAN_4G to enable RF capture.")
endif()

enable_testing()

add_subdirectory(src/pdsch_sniffer)
add_subdirectory(src/cell_measurement)
add_subdirectory(src/nr_sniffer)

# A meta-target that runs the python tests too. We use `python3 -m pytest`
# so we pick up the same interpreter that has the project's deps installed.
find_program(PYTHON3 python3)
if(PYTHON3)
    add_test(
        NAME python_tests
        COMMAND ${PYTHON3} -m pytest ${CMAKE_SOURCE_DIR}/python/tests -q
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties(python_tests PROPERTIES
        ENVIRONMENT
        "PYTHONPATH=${CMAKE_SOURCE_DIR}/python")
endif()
