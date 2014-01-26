cmake_minimum_required(VERSION 2.8)
project(lastpass)

# Enable C++11
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -stdlib=libc++")

# LastPass library
find_package(CURL)
add_library(lastpass src/curlwebclient.cpp
                     src/fetcher.cpp)

# Tests
FIND_PACKAGE(Boost COMPONENTS unit_test_framework REQUIRED)
add_executable(test test/test.cpp)
target_link_libraries(test lastpass ${CURL_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

# Example
add_executable(example example/example.cpp)
target_link_libraries(example lastpass ${CURL_LIBRARIES})
