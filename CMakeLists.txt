cmake_minimum_required(VERSION 3.10)

# set the project name
project(OnPrivilege)

# set binary name
set(LIB OPScanner)
set(LOADER OPApplication)
set(HOOKER OPHooker)
set(MODULE OPModule)

# set path
set(OP_SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(OPA_DIR "${OP_SRC_DIR}/OPApplication")
set(OPM_DIR "${OP_SRC_DIR}/OPModules")
set(OPS_DIR "${OP_SRC_DIR}/OPScanner")
set(OPC_DIR "${OP_SRC_DIR}/OPCommon")
set(OPH_DIR "${OP_SRC_DIR}/OPHooking")
set(OP_lib_DIR "${OP_SRC_DIR}/lib")

include_directories(${OP_lib_DIR})

link_directories(${OP_lib_DIR})

set(CMAKE_C_FLAGS -std=c++17)
set(CMAKE_CXX_FLAGS -std=c++17)

add_subdirectory(src)

#file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/OnPrivilege.entitlements
#     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})