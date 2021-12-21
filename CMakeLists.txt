cmake_minimum_required(VERSION 3.10)
project(ScyllaHide VERSION 0.1.0 LANGUAGES C CXX)

ENABLE_LANGUAGE(ASM_MASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE    "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
set(CXX_STANDARD 17)

add_subdirectory("3rdparty")
add_subdirectory("Scylla")

set(PluginGeneric_SOURCES "")
file(GLOB_RECURSE PluginGeneric_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/PluginGeneric/**.cpp)
add_library(PluginGeneric STATIC ${PluginGeneric_SOURCES})
target_include_directories(PluginGeneric PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(PluginGeneric PUBLIC scylla)

add_subdirectory("HookLibrary")
add_subdirectory("InjectorCLI")
add_subdirectory("ScyllaTest")
