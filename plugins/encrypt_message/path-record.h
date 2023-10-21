//
// Created by russ on 23-10-20.
//
#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <boost/graph/>

struct vertex_info {
    char* name;
    time_t timestamp;
};


