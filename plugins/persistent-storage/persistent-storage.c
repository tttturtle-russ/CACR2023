//
// Created by russ on 23-10-14.
//

#include <mongoc/mongoc.h>
#include <bson/bson.h>

#include "config.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"

static mosquitto_plugin_id_t *mosq_pid = NULL;
static mongoc_database_t *db = NULL;
static int persistent_storage_callback(int event, void *event_data, void *userdata){
    bson_error_t error;
    bson_t *doc = bson_new();
    const struct mosquitto_evt_message *ed = event_data;
    bson_append_utf8(doc, "topic", -1, ed->topic, -1);
    BSON_APPEND_BINARY(doc, "payload", BSON_SUBTYPE_BINARY, ed->payload, ed->payloadlen);
    bson_append_int32(doc, "payloadlen", -1, ed->payloadlen);
    bson_append_int32(doc, "qos", -1, ed->qos);
    bson_append_int32(doc, "retain", -1, ed->retain);
    mongoc_collection_insert_one();
};