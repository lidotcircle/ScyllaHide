
file(GLOB_RECURSE sexchange_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)

add_library(sexchange STATIC ${sexchange_SOURCES})
target_include_directories(sexchange PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(sexchange_MT STATIC ${sexchange_SOURCES})
target_include_directories(sexchange_MT PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_compile_options(sexchange_MT PRIVATE 
    $<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:Release>:/MT>
)
