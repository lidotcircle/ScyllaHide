
file(GLOB_RECURSE scylla_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/lib/**.cpp)
add_library(scylla STATIC ${scylla_SOURCES})
target_include_directories(scylla PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(scylla PUBLIC ntdll)
target_link_libraries(scylla PUBLIC sexchange)
target_link_libraries(scylla PUBLIC slogger)
target_link_libraries(scylla PUBLIC sutils)
target_link_libraries(scylla PUBLIC distorm3)
target_link_libraries(scylla PUBLIC cxxopts)
target_link_libraries(scylla PUBLIC pe-parse)
target_link_libraries(scylla PUBLIC yaml-cpp::yaml-cpp)
target_link_libraries(scylla PUBLIC sinternaldlls)
target_compile_definitions(scylla PUBLIC YAML_CPP_STATIC_DEFINE=1)

set(scylla_conf_file ${CMAKE_CURRENT_LIST_DIR}/scylla.yaml)
add_custom_target(scylla_conf ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${scylla_conf_file} ${CMAKE_BINARY_DIR})

install(FILES ${scylla_conf_file} DESTINATION ${CMAKE_INSTALL_PREFIX})
install(FILES ${scylla_conf_file} DESTINATION ${CMAKE_INSTALL_PREFIX}/x64dbg)