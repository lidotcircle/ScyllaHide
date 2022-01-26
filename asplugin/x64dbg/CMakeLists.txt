file(GLOB_RECURSE plug_x64dbg_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/src/**.cpp)

add_library(plug_x64dbg SHARED ${plug_x64dbg_SOURCES})
target_link_libraries(plug_x64dbg PRIVATE x64dbgsdk)
target_link_libraries(plug_x64dbg PRIVATE scylla)
target_link_libraries(plug_x64dbg PRIVATE scyllagui)

# Change extension
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(plug_x64dbg PROPERTIES SUFFIX ".dp64")
else()
    set_target_properties(plug_x64dbg PROPERTIES SUFFIX ".dp32")
endif()
set_target_properties(plug_x64dbg PROPERTIES OUTPUT_NAME "scyllamon")

# Set plugin name based on the target
target_compile_definitions(plug_x64dbg PRIVATE "-DPLUGIN_NAME=\"scyllamon\"")

install(TARGETS plug_x64dbg DESTINATION ${CMAKE_INSTALL_PREFIX}/x64dbg)