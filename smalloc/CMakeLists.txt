file(GLOB_RECURSE smalloc_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)

add_library(smalloc STATIC ${smalloc_SOURCES})
target_include_directories(smalloc PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(smalloc_MT STATIC ${smalloc_SOURCES})
target_include_directories(smalloc_MT PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_compile_options(smalloc_MT PRIVATE 
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>
)
