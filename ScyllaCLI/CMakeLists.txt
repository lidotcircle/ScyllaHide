
set(ScyllaCLI_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
    )
add_executable(ScyllaCLI ${ScyllaCLI_SOURCES} ${CMAKE_CURRENT_LIST_DIR}/icon.rc)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(ScyllaCLI PROPERTIES OUTPUT_NAME scyllaCLIx64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(ScyllaCLI PROPERTIES OUTPUT_NAME scyllaCLIx86)
endif()
target_include_directories(ScyllaCLI PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(ScyllaCLI cxxopts)
target_link_libraries(ScyllaCLI scylla)

install(TARGETS ScyllaCLI DESTINATION ${CMAKE_INSTALL_PREFIX})