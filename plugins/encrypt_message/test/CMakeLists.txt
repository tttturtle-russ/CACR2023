cmake_minimum_required(VERSION 3.27)
project(test)

set(CMAKE_CXX_STANDARD 17)
include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
include_directories(/usr/local/include/bsoncxx/v_noabi)
include_directories(../../../include)
include_directories(../../../)
include_directories(/usr/local/include/mongocxx/v_noabi)
enable_testing()
add_executable(MyTest main.cpp)
include(GoogleTest)
target_link_libraries(MyTest GTest::gtest_main mongocxx bsoncxx gmssl)
add_test(MyTest MathTest)