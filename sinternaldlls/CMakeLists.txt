
file(GLOB_RECURSE sinternaldlls_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)

add_library(sinternaldlls STATIC ${sinternaldlls_SOURCES})
target_include_directories(sinternaldlls PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(sinternaldlls PRIVATE HookLibraryResource)
target_link_libraries(sinternaldlls PRIVATE MonitorLibraryResource)
