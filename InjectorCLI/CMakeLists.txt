
# set(InjectorCLI_SOURCES "")
# file(GLOB_RECURSE InjectorCLI_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/**.cpp)
set(InjectorCLI_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
    )
add_executable(InjectorCLI ${InjectorCLI_SOURCES} ${CMAKE_CURRENT_LIST_DIR}/icon.rc)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(InjectorCLI PROPERTIES OUTPUT_NAME InjectorCLIx64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(InjectorCLI PROPERTIES OUTPUT_NAME InjectorCLIx86)
endif()
target_include_directories(InjectorCLI PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(InjectorCLI cxxopts)
target_link_libraries(InjectorCLI scylla)
target_link_libraries(InjectorCLI HookLibraryResource)

install(TARGETS InjectorCLI DESTINATION ${CMAKE_INSTALL_PREFIX})