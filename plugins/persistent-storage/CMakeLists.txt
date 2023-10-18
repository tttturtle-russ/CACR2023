include_directories()

set(PLUGIN_NAME persistent-storage)

add_library(${PLUGIN_NAME} MODULE ${PLUGIN_NAME}.c)