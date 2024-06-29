project(libs)

# 添加子目录
add_subdirectory(AMED)

# 导入子项目的目标

# 设置头文件搜索路径
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/AMED)