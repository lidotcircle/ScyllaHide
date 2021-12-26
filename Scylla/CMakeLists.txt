
set(scylla_SOURCES "")
file(GLOB_RECURSE scylla_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)
add_library(scylla STATIC ${scylla_SOURCES})
target_include_directories(scylla PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_include_directories(scylla PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(scylla PUBLIC ntdll)
target_link_libraries(scylla PUBLIC distorm3)
target_link_libraries(scylla PUBLIC cxxopts)
target_link_libraries(scylla PUBLIC pe-parser-static)
target_link_libraries(scylla PUBLIC printf)
target_link_libraries(scylla PUBLIC yaml-cpp::yaml-cpp)
target_compile_definitions(scylla PUBLIC YAML_CPP_STATIC_DEFINE=1)

set(scylla_conf_file ${CMAKE_CURRENT_LIST_DIR}/scylla.yaml)
add_custom_target(scylla_conf ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${scylla_conf_file} ${CMAKE_BINARY_DIR})