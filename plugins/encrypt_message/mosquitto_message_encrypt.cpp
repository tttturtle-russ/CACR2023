//
// Created by russ on 23-10-13.
//
#include "config.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"

#include "graph.hpp"

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <mongocxx/uri.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>
#include <sys/time.h>

std::string database;
static mosquitto_plugin_id_t *mosq_pid = nullptr;
FILE* log_;
mongocxx::pool *p = nullptr;
char timebuf[32];


#define UUID_LEN 32
#define SM3_HMAC_KEY_SIZE 16
#define info(fmt,...) {mosquitto_log_printf(MOSQ_LOG_INFO,fmt,__VA_ARGS__);fprintf(log_,fmt,__VA_ARGS__);}
#define warn(fmt,...) {mosquitto_log_printf(MOSQ_LOG_WARNING,fmt,__VA_ARGS__);fprintf(__log,fmt,__VA_ARGS__);}
#define error(fmt,...) {mosquitto_log_printf(MOSQ_LOG_ERR,fmt,__VA_ARGS__);fprintf(log_,fmt,__VA_ARGS__);}

enum ERROR {
    ERROR_SUCCESS = 0,
    ERROR_DATA = 1,
    ERROR_DECRYPT = 2,
    ERROR_VERIFY = 3,
    ERROR_INTERNAL = 4
};

// 生成如下时间格式:
// [%04d-%02d-%02d %02d:%02d:%02d:%03d]
const char* get_timestamp(){
    struct timeval tv{};
    struct tm* tm;
    gettimeofday(&tv, nullptr);
    tm = localtime(&tv.tv_sec);
    sprintf(timebuf,"[%04d-%02d-%02d %02d:%02d:%02d:%03d]",
            tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,(int)tv.tv_usec/1000);
    return timebuf;
}

ERROR decrypt_sm4_key_and_iv(uint8_t * payload,
                             SM2_KEY * sm2_key,
                             uint8_t sm4_key_arr[SM4_KEY_SIZE],
                             uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],
                             size_t *offset
){
    if (payload == nullptr) {
        error("%s:payload is null",get_timestamp());
        //mosquitto_log_printf(MOSQ_LOG_ERR,"%s:payload is null",get_timestamp());
        return ERROR_DATA;
    }
    uint8_t buf[SM4_KEY_SIZE + SM4_BLOCK_SIZE];
    bool success = false;
    //sm2_key_print(stdout,0,0,"",sm2_key);
    for (int i = 138; i <= 143; ++i) {
        if(sm2_decrypt(sm2_key, payload, i, buf, offset) != 1){
            continue;
        }
        success = true;
        *offset = i ;
        break;
    }
    if(!success) {
        error("%s:failed to decrypt sm4 key and iv",get_timestamp())
        return ERROR_DECRYPT;
    }
    info("%s:success decrypt sm4 key and iv",get_timestamp())
    //mosquitto_log_printf(MOSQ_LOG_INFO,"%s:success decrypt sm4 key and iv",get_timestamp());
    memcpy(sm4_key_arr,buf,SM4_KEY_SIZE);
    memcpy(sm4_iv_arr,buf+SM4_KEY_SIZE,SM4_BLOCK_SIZE);
    for (int i = 0; i < 32; ++i) {
        printf("%02x",sm4_key_arr[i]);
    }
    putchar('\n');
    return ERROR_SUCCESS;
}

ERROR decrypt_sig_and_msg(uint8_t* cipher,
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

int read_pem(const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE]) {
    auto client = p->try_acquire();
    if (!client) {
        error("%s:Failed to pop client pool\n",get_timestamp());
        return ERROR_INTERNAL;
    }
    auto pems = (*client)->database(database).collection("pems");
    if (!pems){
        error("%s:Failed to get collection\n",get_timestamp());
        return ERROR_INTERNAL;
    }
    auto query = bsoncxx::builder::stream::document{} << "uuid" << uuid << bsoncxx::builder::stream::finalize;
    auto cursor = pems.find_one(query.view());
    if(cursor->empty()){
        error("%s:Failed to find uuid:%s\n",get_timestamp(),uuid.c_str());
        return ERROR_INTERNAL;
    }
    auto doc = cursor->view();
    if (doc["private_key"] && (doc["private_key"].type() == bsoncxx::type::k_string)){
        int pass = doc["pass"].get_int32().value;
        std::string private_key = doc["private_key"].get_string().value.to_string();
        FILE* fp = fmemopen((void *) private_key.c_str(), private_key.length(), "r");
        sm2_private_key_info_decrypt_from_pem(sm2_key,std::to_string(pass).c_str(),fp);
        fclose(fp);
    }else{
        error("%s:Failed to find private_key\n",get_timestamp());
        return ERROR_INTERNAL;
    }

    if(doc["sm3_hmac_key"] && (doc["sm3_hmac_key"].type() == bsoncxx::type::k_string)){
        auto sm3_hmac_key = doc["sm3_hmac_key"].get_string().value.to_string();
        for (int i = 0; i < SM3_HMAC_KEY_SIZE; ++i) {
            sscanf(sm3_hmac_key.c_str() + i * 2, "%02x", &sm3_hmac_key_arr[i]);
        }
    }else{
        error("%s:Failed to find sm3_hmac_key\n",get_timestamp());
        return ERROR_INTERNAL;
    }

    return ERROR_SUCCESS;
}

int decrypt_message(struct mosquitto_evt_message *ed) {
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];
    std::string uuid;
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:receive payload:%s",get_timestamp(),ed->payload);
    char id[UUID_LEN];
    auto payload = (uint8_t *) mosquitto_malloc(ed->payloadlen/2);
    auto payload_len = ed->payloadlen / 2;
    for (int i = 0; i < payload_len; ++i) {
        sscanf((const char*)ed->payload + i * 2, "%02x", &payload[i]);
    }
    // 从payload中解析出uuid
    for (int i = 0; i < UUID_LEN; ++i) {
        sscanf(static_cast<const char *>(ed->payload) + i * 2, "%02x", &id[i]);
        uuid += id[i];
    }
    std::cout << uuid << std::endl;
    // 从数据库中读取pem私钥
    if (read_pem(uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        error("%s:read_pem failed",get_timestamp());
        return ERROR_INTERNAL;
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return ret;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        error("%s:decrypt_message_callback: mosquitto_malloc failed", get_timestamp());
        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
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
        success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
    if (!success){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:sm2_verify failed",get_timestamp());
        return ERROR_VERIFY;
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:sm2_verify success",get_timestamp());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    info("%s:after decrypt,get msg: %s",get_timestamp(),decrypted_sig_and_msg + offset)
    mosquitto_free(decrypted_sig_and_msg);
    return ERROR_SUCCESS;
}

int public_handler(struct mosquitto_evt_message *ed){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];
    std::string uuid;
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:receive payload:%s",get_timestamp(),ed->payload);
    char id[UUID_LEN];
    auto payload = (uint8_t *) mosquitto_malloc(ed->payloadlen/2);
    auto payload_len = ed->payloadlen / 2;
    for (int i = 0; i < payload_len; ++i) {
        sscanf((const char*)ed->payload + i * 2, "%02x", &payload[i]);
    }
    // 从payload中解析出uuid
    for (int i = 0; i < UUID_LEN; ++i) {
        sscanf(static_cast<const char *>(ed->payload) + i * 2, "%02x", &id[i]);
        uuid += id[i];
    }
    std::cout << uuid << std::endl;
    // 从数据库中读取pem私钥
    if (read_pem(uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        error("%s:read_pem failed",get_timestamp());
        return ERROR_INTERNAL;
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return ret;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        error("%s:decrypt_message_callback: mosquitto_malloc failed", get_timestamp());
        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg

    ret = decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
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
        success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
    if (!success){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:sm2_verify failed",get_timestamp());
        return ERROR_VERIFY;
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:sm2_verify success",get_timestamp());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    info("%s:after decrypt,get msg: %s",get_timestamp(),decrypted_sig_and_msg + offset)
    mosquitto_free(decrypted_sig_and_msg);
    return ERROR_SUCCESS;
}

int p2p_handler(struct mosquitto_evt_message *ed){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t *sm3_hmac_key_arr = (uint8_t *) malloc(SM3_HMAC_KEY_SIZE * sizeof(uint8_t));
    uint8_t *sm4_key_arr = (uint8_t *) malloc(SM4_KEY_SIZE * sizeof(uint8_t));
    uint8_t *sm4_iv_arr = (uint8_t*) malloc(SM4_BLOCK_SIZE * sizeof(uint8_t));
    std::string sender_uuid;
    std::string receiver_uuid = ed->topic + 5;
    std::cout << receiver_uuid << std::endl;
    char id[UUID_LEN];
    auto payload = (uint8_t *) mosquitto_malloc(ed->payloadlen/2);
    auto payload_len = ed->payloadlen / 2;
    for (int i = 0; i < payload_len; ++i) {
        sscanf((const char*)ed->payload + i * 2, "%02x", &payload[i]);
    }
    // 从payload中解析出uuid
    for (int i = 0; i < UUID_LEN; ++i) {
        sscanf(static_cast<const char *>(ed->payload) + i * 2, "%02x", &id[i]);
        sender_uuid += id[i];
    }
    std::cout << sender_uuid << std::endl;
    // 从数据库中读取pem私钥
    if (read_pem(receiver_uuid, &sm2_key, sm3_hmac_key_arr) != EXIT_SUCCESS){
        error("%s:read_pem failed",get_timestamp())
        return ERROR_INTERNAL;
    }
    sm2_key_print(stdout,0,0,"", &sm2_key);

    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return ret;
    }
    if (read_pem(sender_uuid, &sm2_key, sm3_hmac_key_arr) != EXIT_SUCCESS){
        error("%s:read_pem failed",get_timestamp())
        return ERROR_INTERNAL;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        error("%s:decrypt_message_callback: mosquitto_malloc failed", get_timestamp());
        return ERROR_INTERNAL;
    }
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_key_arr[i]);
    }
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_iv_arr[i]);
    }
    printf("\n");
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    sm2_key_print(stdout,0,0,"",&sm2_key);
    // 解密sig和msg
    ret = decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                              &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:decrypt_sig_and_msg failed", get_timestamp());
        return ret;
    }
    offset = 70;
    uint8_t hmac[SM3_HMAC_SIZE];
    for (int i = 0; i < SM3_HMAC_KEY_SIZE; ++i) {
        printf("%02x",sm3_hmac_key_arr[i]);
    }
    printf("\n");
    bool success = false;
    for (; offset <= 72; ++offset) {
        sm3_hmac(sm3_hmac_key_arr,SM3_HMAC_KEY_SIZE,decrypted_sig_and_msg + offset,decrypted_sig_and_msg_len - offset,hmac);
        success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
    if (!success){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:sm2_verify failed",get_timestamp());
        return ERROR_VERIFY;
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:sm2_verify success",get_timestamp());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    info("%s:after decrypt,get msg: %s",get_timestamp(),decrypted_sig_and_msg + offset)
    mosquitto_free(decrypted_sig_and_msg);
    return ERROR_SUCCESS;
}

static int decrypt_message_callback(int event, void *event_data, void *userdata){
    auto *ed = static_cast<mosquitto_evt_message *>(event_data);
    if (!strcmp(ed->topic,"/public")){
        return public_handler(ed);
    }else if (!strncmp(ed->topic,"/p2p/",5)){
        return p2p_handler(ed);
    }
    return MOSQ_ERR_SUCCESS;
}

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
    log_ = fopen("./log.log", "w");
    if (!log_) {
        error("%s:cant open log file",get_timestamp())
        return MOSQ_ERR_NOT_FOUND;
    }

    std::string uri_str;
    uri_str.append("mongodb://");
    for (int i = 0; i < opt_count; ++i) {
        if (!strcmp(opts[i].key,"db_addr")){
            uri_str.append(opts[i].value);
        }else if (!strcmp(opts[i].key,"db_port")){
            uri_str.append(":");
            uri_str.append(opts[i].value);
            uri_str.append("/");
        }else if (!strcmp(opts[i].key,"db_connopts")){
            uri_str.append("?");
            uri_str.append(opts[i].value);
        }else if (!strcmp(opts[i].key,"db_name")){
            database = opts[i].value;
        }
    }
    mongocxx::instance instance{};
    p = new mongocxx::pool(mongocxx::uri(uri_str));
    return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count){
    delete p;
    fclose(log_);
//    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, encrypt_message_callback, NULL);
    return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL);
}
