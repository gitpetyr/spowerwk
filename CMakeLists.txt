cmake_minimum_required(VERSION 3.10)
project(spowerwkHook)

set(CMAKE_CXX_STANDARD 17)

# Setup directories
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/hook)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)

# Create shared library
add_library(spowerwkHook SHARED ${SRC_DIR}/dllmain.cpp)

# Include MinHook headers
target_include_directories(spowerwkHook PRIVATE ${INCLUDE_DIR})

# Link MinHook lib
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(spowerwkHook PRIVATE ${LIB_DIR}/libMinHook.x64.lib)
else()
    target_link_libraries(spowerwkHook PRIVATE ${LIB_DIR}/libMinHook.x86.lib)
endif()

# We need Wtsapi32, Ntdll for system calls
target_link_libraries(spowerwkHook PRIVATE Wtsapi32.lib Ntdll.lib)

# Static CRT: embed the runtime into the DLL so it has no dependency on
# msvcp140.dll / vcruntime140.dll. These are NOT guaranteed to be in
# winlogon.exe's DLL search path, causing LoadLibraryW to return NULL.
set_property(TARGET spowerwkHook PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
