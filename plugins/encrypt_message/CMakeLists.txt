include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR} ${STDBOOL_H_PATH} ${STDINT_H_PATH})

set(PLUGIN_NAME encrypt_message)

add_library(${PLUGIN_NAME} MODULE ${PLUGIN_NAME}.c)