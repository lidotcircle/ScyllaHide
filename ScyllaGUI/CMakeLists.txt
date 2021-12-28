
file(GLOB_RECURSE scyllagui_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)
add_library(scyllagui STATIC ${scyllagui_SOURCES})
target_include_directories(scyllagui PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(scyllagui PUBLIC dearimgui scylla)
