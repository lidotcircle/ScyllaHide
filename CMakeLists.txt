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

function(create_resource_c res_file c_variable output_file)
    # Create empty output file
    file(WRITE ${output_file} "")
    # Read the resource file
    file(READ ${res_file} filedata HEX)
    # Convert hex data for C compatibility
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," filedata ${filedata})
    # Append data to output file
    file(APPEND ${output_file} "const unsigned char ${c_variable}[] = {${filedata}};\nconst unsigned ${c_variable}_size = sizeof(${c_variable});\n")
endfunction()

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
