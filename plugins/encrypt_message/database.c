//
// Created by russ on 23-10-16.
//
//#include "config.h"
#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <gmssl/sm2.h>
const char* uri_str = "mongodb://localhost:27017/?ssl=false";
char *database = "mqtt";

int main(){
    SM2_KEY sm2Key;
    mongoc_init();
    mongoc_uri_t *uri = mongoc_uri_new(uri_str);
    mongoc_client_pool_t *pool = mongoc_client_pool_new(uri);
    mongoc_client_t *client = mongoc_client_pool_pop(pool);
    if (!client){
        fprintf(stderr,"Failed to pop client pool\n");
        return EXIT_FAILURE;
    }
    mongoc_collection_t *collection = mongoc_client_get_collection(client,database,"pems");
    bson_t *query ;
    query = BCON_NEW("uuid", BCON_INT32(0000));
    bson_error_t *error;
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection,query,NULL,NULL);

    if (mongoc_cursor_error(cursor,error)){
        fprintf(stderr,"Cursor Failure:%s\n",error->message);
        return EXIT_FAILURE;
    }

    bson_destroy(query);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(pool,client);
    mongoc_client_pool_destroy(pool);
    mongoc_uri_destroy(uri);
    mongoc_cleanup();
    return EXIT_SUCCESS;
}