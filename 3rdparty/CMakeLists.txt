set(distorm3_SOURCES "")
file(GLOB_RECURSE distorm3_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/distorm/**.c)
add_library(distorm3 STATIC ${distorm3_SOURCES})
target_include_directories(distorm3 PUBLIC ${CMAKE_CURRENT_LIST_DIR})

    
add_library(ntdll INTERFACE)
target_include_directories(ntdll INTERFACE ${CMAKE_CURRENT_LIST_DIR})
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(ntdll INTERFACE "${CMAKE_CURRENT_LIST_DIR}/ntdll/ntdllp_x64.lib")
else()
    target_link_libraries(ntdll INTERFACE "${CMAKE_CURRENT_LIST_DIR}/ntdll/ntdllp_x86.lib")
endif()


add_library(cxxopts INTERFACE)
target_include_directories(cxxopts INTERFACE ${CMAKE_CURRENT_LIST_DIR}/cxxopts/include)


add_subdirectory(yaml-cpp)


add_subdirectory(nlohmannjson)


include(${CMAKE_CURRENT_LIST_DIR}/dearIMGUI.cmake)


add_library(printf STATIC ${CMAKE_CURRENT_LIST_DIR}/printf/printf.c)
target_include_directories(printf PUBLIC ${CMAKE_CURRENT_LIST_DIR}/printf)

add_library(printf_MT STATIC ${CMAKE_CURRENT_LIST_DIR}/printf/printf.c)
target_include_directories(printf_MT PUBLIC ${CMAKE_CURRENT_LIST_DIR}/printf)
target_compile_options(printf_MT PRIVATE
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>)


set(PEPARSE_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/pe-parse/pe-parser-library)
list(APPEND PEPARSERLIB_SOURCEFILES
  ${PEPARSE_SOURCE_DIR}/src/buffer.cpp
  ${PEPARSE_SOURCE_DIR}/src/parse.cpp
)
if(MSVC)
  list(APPEND PEPARSERLIB_SOURCEFILES ${PEPARSE_SOURCE_DIR}/src/unicode_winapi.cpp)
else()
  list(APPEND PEPARSERLIB_SOURCEFILES ${PEPARSE_SOURCE_DIR}/src/unicode_codecvt.cpp)
endif()
add_library(pe-parser-static STATIC ${PEPARSERLIB_SOURCEFILES})
target_include_directories(pe-parser-static PUBLIC ${PEPARSE_SOURCE_DIR}/include)