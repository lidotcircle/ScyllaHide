
file(GLOB_RECURSE slogger_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)

add_library(slogger STATIC ${slogger_SOURCES})
target_include_directories(slogger PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(slogger PRIVATE printf)
target_link_libraries(slogger PRIVATE sutils)

add_library(slogger_MT STATIC ${slogger_SOURCES})
target_include_directories(slogger_MT PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(slogger_MT PRIVATE printf_MT)
target_link_libraries(slogger_MT PRIVATE sutils_MT)
target_compile_options(slogger_MT PRIVATE 
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>
)
