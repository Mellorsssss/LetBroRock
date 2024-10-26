cmake_minimum_required(VERSION 3.10)

project(test_br)

add_executable(main main.cpp)

target_compile_options(main PRIVATE -g)
target_link_libraries(main PRIVATE /home/lab/proj/LBR-melos/build/libprofiler.so pthread)
#target_link_libraries(main pthread)
