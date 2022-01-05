
add_library(nljson INTERFACE)
target_include_directories(nljson INTERFACE ${CMAKE_CURRENT_LIST_DIR}/single_include)
target_compile_definitions(nljson INTERFACE JSON_NO_IO=1)
