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

add_subdirectory("sutils")
add_subdirectory("sexchange")
add_subdirectory("slogger")
add_subdirectory("smalloc")
add_subdirectory("sinternaldlls")

add_subdirectory("Scylla")
add_subdirectory("InternalDLL")
add_subdirectory("ScyllaCLI")

add_subdirectory("ScyllaGUI")
add_subdirectory("ScyllaMon")
add_subdirectory("asplugin")

add_subdirectory("ScyllaTest")
