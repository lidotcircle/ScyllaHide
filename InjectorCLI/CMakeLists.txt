
set(InjectorCLI_SOURCES "")
file(GLOB_RECURSE InjectorCLI_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/**.cpp)
add_executable(InjectorCLI ${InjectorCLI_SOURCES})
target_include_directories(InjectorCLI PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(InjectorCLI scylla)
target_link_libraries(InjectorCLI PluginGeneric)