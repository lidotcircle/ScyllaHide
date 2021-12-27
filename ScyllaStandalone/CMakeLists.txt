
file(GLOB_RECURSE scyllamon_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/src/**.cpp)
add_executable(scyllamon WIN32 ${scyllamon_SOURCES} ${CMAKE_CURRENT_LIST_DIR}/icon.rc)
target_link_libraries(scyllamon PRIVATE scylla scyllagui)
