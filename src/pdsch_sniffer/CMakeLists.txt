add_library(sniffer_io STATIC
    pcap_writer.c
    journal.c
)
target_include_directories(sniffer_io PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(pdsch_sniffer sniffer.c)
target_link_libraries(pdsch_sniffer PRIVATE sniffer_io)

if(SRSRAN_FOUND)
    target_compile_definitions(pdsch_sniffer PRIVATE SRSRAN_AVAILABLE)
    target_include_directories(pdsch_sniffer PRIVATE ${SRSRAN_INCLUDE_DIRS})
    target_link_libraries(pdsch_sniffer PRIVATE ${SRSRAN_LIBRARIES})
else()
    message(STATUS
        "srsRAN_4G not found — pdsch_sniffer will be built as a stub "
        "(--help works, capture mode disabled).")
endif()

install(TARGETS pdsch_sniffer RUNTIME DESTINATION bin)

# A tiny smoke test that exercises pcap_writer + journal without any RF
# stack — runs in CI to keep the I/O code honest.
add_executable(sniffer_io_smoke smoke_test.c)
target_link_libraries(sniffer_io_smoke PRIVATE sniffer_io)
add_test(NAME sniffer_io_smoke COMMAND sniffer_io_smoke)
