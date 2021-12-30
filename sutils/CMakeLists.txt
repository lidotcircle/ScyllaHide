
file(GLOB_RECURSE sutils_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)

add_library(sutils STATIC ${sutils_SOURCES})
target_include_directories(sutils PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(sutils_MT STATIC ${sutils_SOURCES})
target_include_directories(sutils_MT PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_compile_options(sutils_MT PRIVATE 
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>
)
