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
const char* uri_str = "mongodb://localhost:27017/?ssl=false";
const char* database = "mqtt";
static enum error_t {
    ERROR_SUCCESS,
    ERROR_DECRYPT,
    ERROR_INTERNAL,
    ERROR_DATA,
    ERROR_VERIFY
};

#define UUID_LEN 16
#define SM3_HMAC_KEY_SIZE 16
#define info(fmt,...) {mosquitto_log_printf(MOSQ_LOG_INFO,fmt,__VA_ARGS__);fprintf(__log,fmt,__VA_ARGS__);}
#define warn(fmt,...) {mosquitto_log_printf(MOSQ_LOG_WARNING,fmt,__VA_ARGS__);fprintf(__log,fmt,__VA_ARGS__);}
#define error(fmt,...) {mosquitto_log_printf(MOSQ_LOG_ERR,fmt,__VA_ARGS__);fprintf(__log,fmt,__VA_ARGS__);}


char timebuf[32];
// 生成如下时间格式:
// [%04d-%02d-%02d %02d:%02d:%02d:%03d]
const char* get_timestamp(){
    struct timeval tv;
    struct tm* tm;
    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    sprintf(timebuf,"[%04d-%02d-%02d %02d:%02d:%02d:%03d]",
            tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,(int)tv.tv_usec/1000);
    return timebuf;
}

static mosquitto_plugin_id_t *mosq_pid = NULL;
FILE * __log = NULL;

int decrypt_sm4_key_and_iv(uint8_t * payload,
                            SM2_KEY * sm2_key,
                            uint8_t sm4_key_arr[SM4_KEY_SIZE],
                            uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],
                            size_t *offset
){
    if (payload == NULL) {
        error("%s:payload is null",get_timestamp());
        //mosquitto_log_printf(MOSQ_LOG_ERR,"%s:payload is null",get_timestamp());
        return ERROR_DATA;
    }
    uint8_t buf[SM4_KEY_SIZE + SM4_BLOCK_SIZE];
    bool success = false;
    //sm2_key_print(stdout,0,0,"",sm2_key);
    for (int i = 138; i <= 143; ++i) {
        //mosquitto_log_printf(MOSQ_LOG_INFO,"%s:at i = %d,try to decrypt:",get_timestamp(),i);
        info("%s:at i = %d,try to decrypt:",get_timestamp(),i)
        if(sm2_decrypt(sm2_key, payload, i, buf, offset) != 1){
            info("%s:at i = %d,decrypt failed",get_timestamp(),i)
            //mosquitto_log_printf(MOSQ_LOG_INFO,"%s:at i = %d,decrypt failed",get_timestamp(),i);
            continue;
        }
        info("%s:at i = %d,decrypt success",get_timestamp(),i)
        //mosquitto_log_printf(MOSQ_LOG_INFO,"%s:at i = %d,decrypt success",get_timestamp(),i);
        success = true;
        *offset = i;
        break;
    }
    if(!success) {
        error("%s:failed to decrypt sm4 key and iv",get_timestamp())
        //mosquitto_log_printf(MOSQ_LOG_INFO,"%s:failed to decrypt sm4 key and iv",get_timestamp());
        return ERROR_DECRYPT;
    }
    info("%s:success decrypt sm4 key and iv",get_timestamp());
    //mosquitto_log_printf(MOSQ_LOG_INFO,"%s:success decrypt sm4 key and iv",get_timestamp());
    memcpy(sm4_key_arr,buf,SM4_KEY_SIZE);
    memcpy(sm4_iv_arr,buf+SM4_KEY_SIZE,SM4_BLOCK_SIZE);
    return ERROR_SUCCESS;
}

int decrypt_sig_and_msg(uint8_t* cipher,
                        size_t cipher_len,
                        SM4_KEY *sm4_key,
                        uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],
                        uint8_t* decrypted_sig_and_msg,
                        size_t *decrypted_sig_and_msg_len)
{
    int ret = sm4_cbc_padding_decrypt(sm4_key,sm4_iv_arr,cipher,cipher_len,decrypted_sig_and_msg,decrypted_sig_and_msg_len);
    if (ret == 1)
        return ERROR_SUCCESS;
    return ERROR_DECRYPT;
}

int read_pem(SM2_KEY *sm2_key,const char* private,const char* public,const char* pass) {
    mongoc_init();
    mongoc_uri_t *uri = mongoc_uri_new(uri_str);
    mongoc_client_pool_t *pool = mongoc_client_pool_new(uri);
    mongoc_client_t *client = mongoc_client_pool_pop(pool);
    if (!client){
        //fprintf(stderr,"Failed to pop client pool\n");
        error("%s:Failed to pop client pool\n",get_timestamp());
        return EXIT_FAILURE;
    }
    mongoc_collection_t *collection = mongoc_client_get_collection(client,database,"pems");
    bson_t *query ;
    query = BCON_NEW("uuid", BCON_INT32(0000));
    bson_error_t *error;
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection,query,NULL,NULL);
    bson_t *doc;
    bson_iter_t iter;
    while (mongoc_cursor_next(cursor,&doc)){
        if (bson_iter_init_find(&iter,doc,"private")){
            bson_value_t* v = bson_iter_value(&iter);
            printf("%s:\n",v->value.v_utf8.str);
            FILE * test = fmemopen(v->value.v_utf8.str,v->value.v_utf8.len,"r");
            sm2_private_key_info_decrypt_from_pem(sm2_key,"123456",test);
            fclose(test);
        }
    }

    if (mongoc_cursor_error(cursor,error)){
        fprintf(stderr,"Cursor Failure:%s\n",error->message);
        return EXIT_FAILURE;
    }
    bson_destroy(doc);
    bson_destroy(query);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(pool,client);
    mongoc_client_pool_destroy(pool);
    mongoc_uri_destroy(uri);
    mongoc_cleanup();
}

int decrypt_message(struct mosquitto_evt_message *ed) {
    const char* pass = "123456";
    SM2_KEY *sm2_key = calloc(1,sizeof(SM2_KEY));
    read_pem(sm2_key,"./pems/private.pem","./pems/public.pem",pass);
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];
    for (int i = 0; i < 16; ++i) {
        sm4_iv_arr[i] = i;
        sm4_key_arr[i] = i;
        sm3_hmac_key_arr[i] = i;
    }
    enum error_t ret;
    size_t offset;
    uint8_t *payload = mosquitto_malloc(ed->payloadlen/2);
    for (int i = 0; i < ed->payloadlen / 2; ++i) {
        sscanf(ed->payload + i * 2, "%02x", &payload[i]);
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:receive payload:%s",get_timestamp(),ed->payload);
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = decrypt_sm4_key_and_iv(payload,sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return ret;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    uint8_t *decrypted_sig_and_msg = mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "%s:decrypt_message_callback: mosquitto_malloc failed", get_timestamp());
        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = decrypt_sig_and_msg(ed->payload  + offset,ed->payloadlen - offset,
                        &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:decrypt_sig_and_msg failed", get_timestamp());
        return ret;
    }
    offset = 70;
    uint8_t hmac[SM3_HMAC_SIZE];
    bool success = false;
    for (; offset <= 72; ++offset) {
        sm3_hmac(sm3_hmac_key_arr,SM3_HMAC_KEY_SIZE,decrypted_sig_and_msg + offset,decrypted_sig_and_msg_len - offset,hmac);
        success = sm2_verify(sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
    if (!success){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:sm2_verify failed",get_timestamp());
        return ERROR_VERIFY;
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:sm2_verify success",get_timestamp());
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:after decrypt,get msg: %s",get_timestamp(),decrypted_sig_and_msg + offset);
    return ERROR_SUCCESS;

//    size_t plain_len;
//    // plain 是解密后的明文
//    uint8_t* plain = mosquitto_malloc(ed->payloadlen);
//    // cipher 是密文,也就是ed->payload,长度关系是ed->payloadlen/2
//    unsigned char *cipher = mosquitto_malloc(ed->payloadlen/2);
//    if (plain == NULL || cipher == NULL){
//        mosquitto_log_printf(MOSQ_LOG_ERR, "decrypt_message_callback: mosquitto_malloc failed\n");
//        return MOSQ_ERR_NOMEM;
//    }
//    // 将16进制的字符串转换为16进制的字节流
//    for (int i = 0; i < ed->payloadlen/2; ++i)
//        sscanf(ed->payload + i * 2, "%02x", &cipher[i]);
//    mosquitto_log_printf(MOSQ_LOG_INFO, "%s:receive topic : %s", get_timestamp(),ed->topic);
//    fprintf(__log, "%s:receive topic : %s\n", get_timestamp(),ed->topic);
//    mosquitto_log_printf(MOSQ_LOG_INFO, "%s:payload : %s", get_timestamp(),ed->payload);
//    mosquitto_log_printf(MOSQ_LOG_INFO, "%s:payloadlen : %d", get_timestamp(),ed->payloadlen);
//    // 解密信息
//    sm4_cbc_padding_decrypt(sm4_key,iv,cipher, ed->payloadlen/2, plain, &plain_len);
//    plain = mosquitto_realloc(plain, plain_len);
//    if (plain == NULL){
//        mosquitto_log_printf(MOSQ_LOG_ERR, "%s:decrypt_message_callback: mosquitto_realloc failed", get_timestamp());
//        return MOSQ_ERR_NOMEM;
//    }
//    mosquitto_log_printf(MOSQ_LOG_INFO, "%s:decrypt message: %s",get_timestamp(),plain);
//    fprintf(__log, "%s:decrypt message: %s\n", get_timestamp(),plain);
//    mosquitto_free(cipher);
//    mosquitto_free(plain);
//    return true;
}

static int decrypt_message_callback(int event, void *event_data, void *userdata){
    struct mosquitto_evt_message *ed = event_data;
    return decrypt_message(ed);
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

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count){
    mosq_pid = identifier;
    unsigned char key[16];
    __log = fopen("./log.log", "w");
//    mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, encrypt_message_callback, NULL, NULL);
    return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count){
    fclose(__log);
//    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, encrypt_message_callback, NULL);
    return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL);
}
