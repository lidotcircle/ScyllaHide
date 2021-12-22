
set(HookLibrary_SOURCES "")
file(GLOB_RECURSE HookLibrary_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/**.cpp)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    SET(InstrumentationCallbackSource ${CMAKE_CURRENT_LIST_DIR}/InstrumentationCallbackX64.asm)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    SET(InstrumentationCallbackSource ${CMAKE_CURRENT_LIST_DIR}/InstrumentationCallbackX86.asm)
endif()
LIST(APPEND HookLibrary_SOURCES ${InstrumentationCallbackSource})
SET_SOURCE_FILES_PROPERTIES(${InstrumentationCallbackSource} PROPERTIES LANGUAGE ASM_MASM)

add_library(HookLibrary SHARED ${HookLibrary_SOURCES})
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(HookLibrary PROPERTIES OUTPUT_NAME HookLibraryx64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(HookLibrary PROPERTIES OUTPUT_NAME HookLibraryx86)
endif()
target_include_directories(HookLibrary PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(HookLibrary scylla)

set(HookLibraryOutputFile $<TARGET_FILE:HookLibrary>)
add_custom_target(generate_c_resource COMMAND ${CMAKE_COMMAND} 
                    -DHL_FILENAME="${HookLibraryOutputFile}"
                    -P ${CMAKE_CURRENT_LIST_DIR}/HookLibraryResource.cmake)
add_dependencies(generate_c_resource HookLibrary)

add_library(HookLibraryResource INTERFACE)
target_include_directories(HookLibraryResource INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(HookLibraryResource generate_c_resource)