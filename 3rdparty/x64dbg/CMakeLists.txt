
add_library(x64dbgsdk INTERFACE)
target_include_directories(x64dbgsdk INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_directories(x64dbgsdk INTERFACE ${CMAKE_CURRENT_LIST_DIR})
