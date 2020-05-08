cmake_minimum_required(VERSION 3.10)
project(pkcs11_leak_reproducer)

set(CMAKE_CXX_STANDARD 17)

include_directories(src/)

add_executable(pkcs11_leak_reproducer
        src/hsm/HSMUtils.cpp
        src/main.cpp
        )
#------------------------------
# Search for dl library.
# TODO:  Is this workaround really necessary?
find_library( DL_LIBRARY libdl.so  )

target_link_libraries(pkcs11_leak_reproducer
        ${DL_LIBRARY}
        )
