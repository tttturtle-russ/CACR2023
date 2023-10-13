//
// Created by russ on 23-10-13.
//
#include "config.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <mongoc/mongoc.h>

#include <stdbool.h>
static mosquitto_plugin_id_t *mosq_pid = NULL;

static int encrypt_message_callback(int event, void *event_data, void *userdata){

};

static int decrypt_message_callback(int event, void *event_data, void *userdata){

};

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions){
    int i;
    for(i=0; i<supported_version_count; i++){
        if(supported_versions[i] == 5){
            return 5;
        }
    }
    return -1;
}

int mosquitto_publish_v5( struct mosquitto *mosq,
                          int *mid,
                          const char *topic,
                          int payloadlen,
                          const void *payload,
                          int qos,
                          bool retain,
                          const mosquitto_property *properties)
{

}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count){
    UNUSED(user_data);
    UNUSED(opts);
    UNUSED(opt_count);
    mosq_pid = identifier;
    mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, encrypt_message_callback, NULL, NULL);
    mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count){
    UNUSED(user_data);
    UNUSED(opts);
    UNUSED(opt_count);
    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, encrypt_message_callback, NULL);
    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL);
}
