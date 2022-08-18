

# add the executable
add_executable(
    ${LOADER} 
    ${OPA_DIR}/OPApplication.cc
    ${OPC_DIR}/utils.cc
    ${OPC_DIR}/OPSQLite.cc
    ${OPC_DIR}/OPLogger.cc)

target_link_libraries (${LOADER} sqlite3)

add_executable(
    ${HOOKER} 
    ${OPC_DIR}/OPSQLite.cc
    ${OPC_DIR}/OPLogger.cc
    ${OPH_DIR}/OPHooking.cc)
target_link_libraries (${HOOKER} sqlite3)

find_library(CoreFoundation CoreFoundation)
add_library(
    ${LIB} SHARED
    ${OPS_DIR}/OPScanner.cc
    ${OPC_DIR}/utils.cc
    ${OPM_DIR}/OPModule.cc
    ${OPC_DIR}/OPSQLite.cc
    ${OPC_DIR}/OPLogger.cc
    ${OPM_DIR}/TestModule.cc
    ${OPM_DIR}/BypassGKModule.cc
    ${OPM_DIR}/RootingDetectModule.cc
    ${OPM_DIR}/TCCBypassDetectModule.cc)

target_link_libraries (
    ${LIB} 
    EndpointSecurity
    sqlite3
    bsm
    ${CoreFoundation}
    )
set_target_properties(${LIB} PROPERTIES PREFIX "")
set_target_properties(${LIB} PROPERTIES SUFFIX ".dylib")

add_custom_command(
    TARGET ${LOADER} POST_BUILD
    COMMAND codesign --entitlements ${CMAKE_CURRENT_SOURCE_DIR}/OnPrivilege.entitlements --force -s -  ${LOADER}
)