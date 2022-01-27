
file(GLOB_RECURSE IATHookMonitorLibrary_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)

add_library(IATHookMonitorLibrary SHARED ${IATHookMonitorLibrary_SOURCES})
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(IATHookMonitorLibrary PROPERTIES OUTPUT_NAME IATHookMonitorLibraryx64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(IATHookMonitorLibrary PROPERTIES OUTPUT_NAME IATHookMonitorLibraryx86)
endif()
target_include_directories(IATHookMonitorLibrary PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(IATHookMonitorLibrary ntdll)
target_link_libraries(IATHookMonitorLibrary sexchange_MT)
target_link_libraries(IATHookMonitorLibrary slogger_MT)
target_link_libraries(IATHookMonitorLibrary sutils_MT)
target_link_libraries(IATHookMonitorLibrary smalloc_MT)
target_link_libraries(IATHookMonitorLibrary nljson)

# staticlly link to msvcrt
target_compile_options(IATHookMonitorLibrary PRIVATE
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>)
#target_compile_definitions(IATHookMonitorLibrary PRIVATE NOT_USING_MSVC_ENTRY=1)

set(IATHookMonitorLibraryOutputFile $<TARGET_FILE:IATHookMonitorLibrary>)
set(DLL_DATA_HEADER_FILE "${CMAKE_CURRENT_BINARY_DIR}/iat_monitor_library.h")
add_custom_command(OUTPUT ${DLL_DATA_HEADER_FILE}
                   COMMAND ${CMAKE_COMMAND} 
                        -DLIB_FILENAME="${IATHookMonitorLibraryOutputFile}"
                        -DHEADER_FILENAME="${DLL_DATA_HEADER_FILE}"
                        -P ${CMAKE_CURRENT_LIST_DIR}/IATHookMonitorLibraryResource.cmake
                  DEPENDS IATHookMonitorLibrary)
add_custom_target(generate_iatmonitorlib_header DEPENDS ${DLL_DATA_HEADER_FILE})

add_library(IATHookMonitorLibraryResource INTERFACE)
target_include_directories(IATHookMonitorLibraryResource INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(IATHookMonitorLibraryResource generate_iatmonitorlib_header)