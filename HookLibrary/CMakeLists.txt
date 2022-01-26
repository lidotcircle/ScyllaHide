
file(GLOB_RECURSE HookLibrary_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    SET(InstrumentationCallbackSource ${CMAKE_CURRENT_LIST_DIR}/lib/InstrumentationCallbackX64.asm)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    SET(InstrumentationCallbackSource ${CMAKE_CURRENT_LIST_DIR}/lib/InstrumentationCallbackX86.asm)
endif()
LIST(APPEND HookLibrary_SOURCES ${InstrumentationCallbackSource})
SET_SOURCE_FILES_PROPERTIES(${InstrumentationCallbackSource} PROPERTIES LANGUAGE ASM_MASM)

add_library(HookLibrary SHARED ${HookLibrary_SOURCES})
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(HookLibrary PROPERTIES OUTPUT_NAME HookLibraryx64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(HookLibrary PROPERTIES OUTPUT_NAME HookLibraryx86)
endif()
target_include_directories(HookLibrary PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(HookLibrary ntdll)
target_link_libraries(HookLibrary sexchange_MT)
target_link_libraries(HookLibrary slogger_MT)
target_link_libraries(HookLibrary sutils_MT)

# staticlly link to msvcrt
target_compile_options(HookLibrary PRIVATE
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>)
#target_compile_definitions(HookLibrary PRIVATE NOT_USING_MSVC_ENTRY=1)

set(HookLibraryOutputFile $<TARGET_FILE:HookLibrary>)
set(DLL_DATA_HEADER_FILE "${CMAKE_CURRENT_BINARY_DIR}/hook_library.h")
add_custom_command(OUTPUT ${DLL_DATA_HEADER_FILE}
                   COMMAND ${CMAKE_COMMAND} 
                        -DLIB_FILENAME="${HookLibraryOutputFile}"
                        -DHEADER_FILENAME="${DLL_DATA_HEADER_FILE}"
                        -P ${CMAKE_CURRENT_LIST_DIR}/HookLibraryResource.cmake
                   DEPENDS HookLibrary)
add_custom_target(generate_monitor_header DEPENDS ${DLL_DATA_HEADER_FILE})

add_library(HookLibraryResource INTERFACE)
target_include_directories(HookLibraryResource INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(HookLibraryResource generate_monitor_header)