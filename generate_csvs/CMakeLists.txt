cmake_minimum_required(VERSION 3.5)
project(get_csvs)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(TINS_LIBRARY tins)

add_executable(get_csvs main.cpp)

target_link_libraries(get_csvs "${TINS_LIBRARY}")