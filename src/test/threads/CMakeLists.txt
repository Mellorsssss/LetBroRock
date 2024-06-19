cmake_minimum_required(VERSION 3.10)
project(foo)

# 设置包含目录
include_directories(../../../include)

# 设置库目录
link_directories(/home/lab/proj/LetBroRock/build)

# 添加可执行文件
add_executable(foo foo.cpp)

# 链接动态库
target_link_libraries(foo PRIVATE pthread)
target_link_libraries(foo PRIVATE /home/lab/proj/LetBroRock/build/libprofiler.a)