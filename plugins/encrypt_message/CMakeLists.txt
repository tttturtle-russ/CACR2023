cmake_minimum_required(VERSION 3.10)
set(PLUGIN_NAME mosquitto_message_encrypt)
project(${PLUGIN_NAME} C)

include_directories(/usr/local/include)
include_directories(../../include)

add_executable(${PLUGIN_NAME} test.c
        mosquitto_message_encrypt.c
        database.c)
target_link_libraries(${PLUGIN_NAME} gmssl)