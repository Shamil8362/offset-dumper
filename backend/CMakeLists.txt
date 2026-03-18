cmake_minimum_required(VERSION 3.15)
project(OffsetDumperBackend LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "Only x64 builds supported.")
endif()

file(GLOB SOURCES "${CMAKE_SOURCE_DIR}/src/*.cpp")
add_executable(offset_backend ${SOURCES})
target_include_directories(offset_backend PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_compile_definitions(offset_backend PRIVATE UNICODE _UNICODE)
target_link_libraries(offset_backend PRIVATE psapi)

if(MSVC)
    target_compile_options(offset_backend PRIVATE /W3)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_compile_options(offset_backend PRIVATE -Wall -Wextra)
    target_compile_options(offset_backend PRIVATE
        $<$<CONFIG:Release>:-O2 -DNDEBUG>
    )
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
