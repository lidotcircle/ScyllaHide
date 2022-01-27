
file(GLOB_RECURSE AntiAntiLibrary_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    SET(InstrumentationCallbackSource ${CMAKE_CURRENT_LIST_DIR}/lib/InstrumentationCallbackX64.asm)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    SET(InstrumentationCallbackSource ${CMAKE_CURRENT_LIST_DIR}/lib/InstrumentationCallbackX86.asm)
endif()
LIST(APPEND AntiAntiLibrary_SOURCES ${InstrumentationCallbackSource})
SET_SOURCE_FILES_PROPERTIES(${InstrumentationCallbackSource} PROPERTIES LANGUAGE ASM_MASM)

add_library(AntiAntiLibrary SHARED ${AntiAntiLibrary_SOURCES})
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(AntiAntiLibrary PROPERTIES OUTPUT_NAME AntiAntiLibraryx64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(AntiAntiLibrary PROPERTIES OUTPUT_NAME AntiAntiLibraryx86)
endif()
target_include_directories(AntiAntiLibrary PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(AntiAntiLibrary ntdll)
target_link_libraries(AntiAntiLibrary sexchange_MT)
target_link_libraries(AntiAntiLibrary slogger_MT)
target_link_libraries(AntiAntiLibrary sutils_MT)

# staticlly link to msvcrt
target_compile_options(AntiAntiLibrary PRIVATE
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>)
#target_compile_definitions(AntiAntiLibrary PRIVATE NOT_USING_MSVC_ENTRY=1)

set(AntiAntiLibraryOutputFile $<TARGET_FILE:AntiAntiLibrary>)
set(DLL_DATA_HEADER_FILE "${CMAKE_CURRENT_BINARY_DIR}/antianti_library.h")
add_custom_command(OUTPUT ${DLL_DATA_HEADER_FILE}
                   COMMAND ${CMAKE_COMMAND} 
                        -DLIB_FILENAME="${AntiAntiLibraryOutputFile}"
                        -DHEADER_FILENAME="${DLL_DATA_HEADER_FILE}"
                        -P ${CMAKE_CURRENT_LIST_DIR}/AntiAntiLibraryResource.cmake
                   DEPENDS AntiAntiLibrary)
add_custom_target(generate_antiantilib_header DEPENDS ${DLL_DATA_HEADER_FILE})

add_library(AntiAntiLibraryResource INTERFACE)
target_include_directories(AntiAntiLibraryResource INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(AntiAntiLibraryResource generate_antiantilib_header)