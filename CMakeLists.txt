cmake_minimum_required(VERSION 3.5)
project(openssl-cpp-example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-W -Wall -Wextra -g")

add_executable(sha src/sha.cpp)

target_include_directories(sha
PRIVATE
  /opt/homebrew/include
)

target_link_libraries(sha
  -L/opt/homebrew/lib
  ssl crypto
)
