# FindsrsRAN.cmake — locate srsRAN_4G install for the C sniffer binaries.
#
# Sets:
#   SRSRAN_FOUND
#   SRSRAN_INCLUDE_DIRS
#   SRSRAN_LIBRARIES
#
# Honour SRSRAN_DIR / SRSRAN_ROOT env vars or CMake variables for non-system
# installs.

set(_srsran_search_paths
    ${SRSRAN_DIR}
    ${SRSRAN_ROOT}
    $ENV{SRSRAN_DIR}
    $ENV{SRSRAN_ROOT}
    /usr/local
    /usr
    /opt/srsran
)

find_path(SRSRAN_INCLUDE_DIR
    NAMES srsran/srsran.h
    PATHS ${_srsran_search_paths}
    PATH_SUFFIXES include
)

# srsRAN_4G splits its functionality across many .so files; we only need
# the PHY layer and the RF abstraction for the sniffer.
foreach(_lib srsran_phy srsran_common srsran_rf srsran_radio srsran_asn1)
    find_library(_srsran_${_lib}
        NAMES ${_lib}
        PATHS ${_srsran_search_paths}
        PATH_SUFFIXES lib lib64
    )
    if(_srsran_${_lib})
        list(APPEND SRSRAN_LIBRARIES ${_srsran_${_lib}})
    endif()
endforeach()

if(SRSRAN_INCLUDE_DIR AND SRSRAN_LIBRARIES)
    set(SRSRAN_FOUND TRUE)
    set(SRSRAN_INCLUDE_DIRS ${SRSRAN_INCLUDE_DIR})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(srsRAN
    REQUIRED_VARS SRSRAN_INCLUDE_DIR SRSRAN_LIBRARIES)
