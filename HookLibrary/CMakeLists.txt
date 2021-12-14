
set(HookLibrary_SOURCES "")
file(GLOB_RECURSE HookLibrary_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/**.cpp)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    LIST(APPEND HookLibrary_SOURCES ${CMAKE_CURRENT_LIST_DIR}/InstrumentationCallbackX64.asm)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    LIST(APPEND HookLibrary_SOURCES ${CMAKE_CURRENT_LIST_DIR}/InstrumentationCallbackX86.asm)
endif()
add_library(HookLibrary SHARED ${HookLibrary_SOURCES})
target_include_directories(HookLibrary PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(HookLibrary scylla)

