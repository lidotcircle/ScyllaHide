
set(distorm3_SOURCES "")
file(GLOB_RECURSE distorm3_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/distorm/**.c)
add_library(distorm3 STATIC ${distorm3_SOURCES})
target_include_directories(distorm3 PUBLIC ${CMAKE_CURRENT_LIST_DIR})

    
add_library(ntdll INTERFACE)
target_include_directories(ntdll INTERFACE ${CMAKE_CURRENT_LIST_DIR})
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(ntdll INTERFACE "${CMAKE_CURRENT_LIST_DIR}/ntdll/ntdll_x64.lib")
else()
    target_link_libraries(ntdll INTERFACE "${CMAKE_CURRENT_LIST_DIR}/ntdll/ntdll_x86.lib")
endif()