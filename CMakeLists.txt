cmake_minimum_required(VERSION 3.10)
project(soft_hsm_cpp)

set(CMAKE_CXX_STANDARD 17)

include_directories(src/)

add_executable(soft_hsm_cpp
        src/hsm/HSMUtils.cpp
        src/main.cpp
        )
#------------------------------
# Search for dl library.
# TODO:  Is this workaround really necessary?
find_library( DL_LIBRARY libdl.so  )

target_link_libraries(soft_hsm_cpp
        ${DL_LIBRARY}
        )
