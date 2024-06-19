cmake_minimum_required(VERSION 3.15)

project(LBR VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
add_compile_options("-w")

file(GLOB SOURCES "src/engine/*.cpp" "src/utils/*.cpp")
add_library(profiler SHARED ${SOURCES})

# file(GLOB FOO "src/test/bp/foo.cpp" "src/utils/*.cpp")
# add_executable(foo ${FOO})

target_include_directories(profiler PUBLIC ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/third_party/AMED/include)
# target_include_directories(foo PUBLIC ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/third_party/AMED/include)

add_subdirectory(third_party)
target_link_libraries(profiler PRIVATE pthread AMED)
# target_link_libraries(foo PRIVATE pthread AMED)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    add_definitions(-D__x86_64__)
    message("the arch is x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    add_definitions(-D__arm__)
    message("the arch is arm")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    add_definitions(-D__aarch64__)
    message("the arch is aarch64")
else()
    message(FATAL_ERROR "Unsupported architecture")
endif()