

file(GLOB dearimgui_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/imgui/**.cpp)
list(APPEND dearimgui_SOURCES ${CMAKE_CURRENT_LIST_DIR}/imgui/backends/imgui_impl_dx9.cpp)
list(APPEND dearimgui_SOURCES ${CMAKE_CURRENT_LIST_DIR}/imgui/backends/imgui_impl_win32.cpp)
add_library(dearimgui STATIC ${dearimgui_SOURCES})

target_include_directories(dearimgui PUBLIC ${CMAKE_CURRENT_LIST_DIR}/imgui)
target_include_directories(dearimgui PUBLIC ${CMAKE_CURRENT_LIST_DIR}/imgui/backends)
