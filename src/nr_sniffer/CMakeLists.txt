add_executable(nr_sniffer nr_sniffer.c)
target_link_libraries(nr_sniffer PRIVATE sniffer_io)
target_include_directories(nr_sniffer PRIVATE
    ${CMAKE_SOURCE_DIR}/src/pdsch_sniffer)

# srsRAN_Project integration is the realtime path — out of scope of this
# branch but the hook is here so when someone wires it up, the CMake
# already routes through SRSRAN_PROJECT_AVAILABLE.
find_package(srsRAN_Project QUIET)
if(srsRAN_Project_FOUND)
    target_compile_definitions(nr_sniffer PRIVATE SRSRAN_PROJECT_AVAILABLE)
    target_include_directories(nr_sniffer PRIVATE ${SRSRAN_PROJECT_INCLUDE_DIRS})
    target_link_libraries(nr_sniffer PRIVATE ${SRSRAN_PROJECT_LIBRARIES})
endif()

install(TARGETS nr_sniffer RUNTIME DESTINATION bin)
