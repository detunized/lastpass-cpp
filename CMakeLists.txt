cmake_minimum_required(VERSION 2.6)
project(lastpass)

# Enable C++11
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -stdlib=libc++")

find_package(CURL)
add_library(lastpass src/curlwebclient.cpp
                     src/fetcher.cpp)
