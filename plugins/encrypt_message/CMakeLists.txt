cmake_minimum_required(VERSION 3.10)
set(PLUGIN_NAME mosquitto_message_encrypt)
project(${PLUGIN_NAME} CXX)

include_directories(/usr/local/include/bsoncxx/v_noabi)
include_directories(../../include)
include_directories(../../)
include_directories(/usr/local/include/mongocxx/v_noabi)
add_executable(${PLUGIN_NAME}
        mosquitto_message_encrypt.cpp
        graph.hpp
        test.c
)
target_link_libraries(${PLUGIN_NAME} gmssl)