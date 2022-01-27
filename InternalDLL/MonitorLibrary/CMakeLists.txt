
file(GLOB_RECURSE MonitorLibrary_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)

add_library(MonitorLibrary SHARED ${MonitorLibrary_SOURCES})
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(MonitorLibrary PROPERTIES OUTPUT_NAME MonitorLibraryx64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(MonitorLibrary PROPERTIES OUTPUT_NAME MonitorLibraryx86)
endif()
target_include_directories(MonitorLibrary PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(MonitorLibrary ntdll)
target_link_libraries(MonitorLibrary sexchange_MT)
target_link_libraries(MonitorLibrary slogger_MT)
target_link_libraries(MonitorLibrary sutils_MT)
target_link_libraries(MonitorLibrary nljson)

# staticlly link to msvcrt
target_compile_options(MonitorLibrary PRIVATE
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>)
#target_compile_definitions(MonitorLibrary PRIVATE NOT_USING_MSVC_ENTRY=1)

set(MonitorLibraryOutputFile $<TARGET_FILE:MonitorLibrary>)
set(DLL_DATA_HEADER_FILE "${CMAKE_CURRENT_BINARY_DIR}/monitor_library.h")
add_custom_command(OUTPUT ${DLL_DATA_HEADER_FILE}
                   COMMAND ${CMAKE_COMMAND} 
                        -DLIB_FILENAME="${MonitorLibraryOutputFile}"
                        -DHEADER_FILENAME="${DLL_DATA_HEADER_FILE}"
                        -P ${CMAKE_CURRENT_LIST_DIR}/MonitorLibraryResource.cmake
                  DEPENDS MonitorLibrary)
add_custom_target(generate_monitorlib_header DEPENDS ${DLL_DATA_HEADER_FILE})

add_library(MonitorLibraryResource INTERFACE)
target_include_directories(MonitorLibraryResource INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(MonitorLibraryResource generate_monitorlib_header)