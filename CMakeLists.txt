cmake_minimum_required(VERSION 3.28)
project(find_bug CXX)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -g")
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
add_executable(find_bug
    main.cpp
    server.cpp
    client.cpp
)
target_link_libraries(find_bug
    /opt/openssl/libcrypto.a
    /opt/openssl/libssl.a
)
