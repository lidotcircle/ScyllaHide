cmake_minimum_required(VERSION 3.4)
project(ScyllaHide VERSION 0.1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

add_subdirectory("3rdparty")

set(scylla_SOURCES "")
file(GLOB_RECURSE scylla_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/Scylla/**.cpp)
add_library(scylla STATIC ${scylla_SOURCES})
target_include_directories(scylla PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(scylla PUBLIC ntdll)
target_link_libraries(scylla PUBLIC distorm3)

add_subdirectory("HookLibrary")
add_subdirectory("InjectorCLI")
