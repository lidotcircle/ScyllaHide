
add_executable(scylla_test WIN32 ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
target_link_libraries(scylla_test scylla)
add_executable(nxnx WIN32 ${CMAKE_CURRENT_SOURCE_DIR}/nxnx.cpp)
