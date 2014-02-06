cmake_minimum_required(VERSION 2.8)
project(lastpass-cpp)

# TODO: Do proper feature detection and enable libraries/compilers based on that!

# Enable C++11
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -stdlib=libc++")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

# Need cURL
find_package(CURL REQUIRED)
list(APPEND ADDITIONAL_LIBS ${CURL_LIBRARIES})

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # Need libresov
    list(APPEND ADDITIONAL_LIBS "resolv")
else()
    # Need OpenSSL
    find_package(OpenSSL REQUIRED)
    list(APPEND ADDITIONAL_LIBS ${OPENSSL_LIBRARIES})
endif()

# Need libxml2
find_package(LibXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIR})
list(APPEND ADDITIONAL_LIBS ${LIBXML2_LIBRARIES})

# LastPass library
add_library(lastpass src/curlwebclient.cpp
                     src/crypto.cpp
                     src/fetcher.cpp
                     src/parser.cpp
                     src/utils.cpp
                     src/xml.cpp)

# Tests
find_package(Boost COMPONENTS unit_test_framework REQUIRED)
add_executable(test test/test.cpp
                    test/testdata.cpp)
target_link_libraries(test lastpass ${ADDITIONAL_LIBS} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

# Example
add_executable(example example/example.cpp)
target_link_libraries(example lastpass ${ADDITIONAL_LIBS})
