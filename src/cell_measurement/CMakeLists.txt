add_executable(cell_measurement cell_measurement.c)
target_link_libraries(cell_measurement PRIVATE sniffer_io)
target_include_directories(cell_measurement PRIVATE
    ${CMAKE_SOURCE_DIR}/src/pdsch_sniffer)

if(SRSRAN_FOUND)
    target_compile_definitions(cell_measurement PRIVATE SRSRAN_AVAILABLE)
    target_include_directories(cell_measurement PRIVATE ${SRSRAN_INCLUDE_DIRS})
    target_link_libraries(cell_measurement PRIVATE ${SRSRAN_LIBRARIES})
endif()

install(TARGETS cell_measurement RUNTIME DESTINATION bin)
