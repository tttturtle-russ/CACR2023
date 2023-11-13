//
// Created by russ on 23-10-26.
//

#ifndef TEST_DECRYPT_HPP
#define TEST_DECRYPT_HPP
#include <gtest/gtest.h>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/instance.hpp>
#include <utility>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <random>
#include <sys/time.h>
#include <mongocxx/exception/exception.hpp>

std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#define UUID_LEN 32
#define SM3_HMAC_KEY_SIZE 16

enum ERROR {
    ERROR_SUCCESS = 0,
    ERROR_DATA = 1,
    ERROR_DECRYPT = 2,
    ERROR_VERIFY = 3,
    ERROR_INTERNAL = 4
};

size_t _siglen;
size_t _y1len;
extern FILE* log_;

namespace util{
    std::string get_timestamp();
    std::string get_uuid(const char *payload);
    bool insert_public_message(mongocxx::pool *p,const std::string & database,const std::string & uuid,const std::string & message);
    bool insert_p2p_message(mongocxx::pool *p,const std::string& database,const std::string& sender,const std::string& receiver,const std::string& message);
    int read_pem(mongocxx::pool *p,const std::string & database,const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE]);
    ERROR decrypt_sig_and_msg(uint8_t* cipher,
                              size_t cipher_len,
                              SM4_KEY *sm4_key,
                              uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],
                              uint8_t* decrypted_sig_and_msg,
                              size_t *decrypted_sig_and_msg_len);
    ERROR decrypt_sm4_key_and_iv(uint8_t * payload,
                                 SM2_KEY * sm2_key,
                                 uint8_t sm4_key_arr[SM4_KEY_SIZE],
                                 uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],
                                 size_t *offset);

    bool insert_public_message(const std::string &uuid, const std::string &message);

    bool insert_p2p_message(const std::string &sender, const std::string &receiver, const std::string &message);
    std::string select_public_message(const std::string &uuid, time_t timestamp);
    std::string select_p2p_message(const std::string &sender, const std::string &receiver, time_t timestamp);
    int read_pem(const std::string &uuid, SM2_KEY *sm2_key, uint8_t *sm3_hmac_key_arr);

    std::string get_uuid(const std::string& payload);

    std::string select_p2p_message(const std::string &sender, const std::string &receiver);

    std::string select_public_message(const std::string &uuid);
}

// 生成如下时间格式:
// [%04d-%02d-%02d %02d:%02d:%02d:%03d]
std::string util::get_timestamp(){
    char timebuf[32];
    struct timeval tv{};
    struct tm* tm;
    gettimeofday(&tv, nullptr);
    tm = localtime(&tv.tv_sec);
    sprintf(timebuf,"[%04d-%02d-%02d %02d:%02d:%02d:%03d]",
            tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,(int)tv.tv_usec/1000);
    return (timebuf);
}

std::string util::get_uuid(const std::string& payload){
    std::string uuid;
    char id[UUID_LEN];
    for (int i = 0; i < UUID_LEN; ++i) {
        sscanf(payload.c_str() + i * 2, "%02x", &id[i]);
        uuid += id[i];
    }
    return uuid;
}

int util::read_pem(const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE]) {
    auto client = mongocxx::client(mongocxx::uri("mongodb://localhost:27017"));
    if (!client) {
        return ERROR_INTERNAL;
    }
    auto pems = (client).database("mqtt").collection("pems");
    if (!pems){
        return ERROR_INTERNAL;
    }
    auto query = bsoncxx::builder::stream::document{} << "uuid" << uuid << bsoncxx::builder::stream::finalize;
    auto cursor = pems.find_one(query.view());
    if(cursor->empty()){
        return ERROR_INTERNAL;
    }
    auto doc = cursor->view();
    if (doc["sm2_key"] && (doc["sm2_key"].type() == bsoncxx::type::k_string)){
        int pass = doc["pass"].get_int32().value;
        std::string private_key = doc["sm2_key"].get_string().value.to_string();
        FILE* fp = fmemopen((void *) private_key.c_str(), private_key.length(), "r");
        sm2_private_key_info_decrypt_from_pem(sm2_key,std::to_string(pass).c_str(),fp);
        fclose(fp);
    }else{
        return ERROR_INTERNAL;
    }

    if(doc["sm3_hmac_key"] && (doc["sm3_hmac_key"].type() == bsoncxx::type::k_string)){
        auto sm3_hmac_key = doc["sm3_hmac_key"].get_string().value.to_string();
        for (int i = 0; i < SM3_HMAC_KEY_SIZE; ++i) {
            sscanf(sm3_hmac_key.c_str() + i * 2, "%02x", &sm3_hmac_key_arr[i]);
        }
    }else{
        return ERROR_INTERNAL;
    }

    return ERROR_SUCCESS;
}

bool util::insert_public_message(const std::string & uuid,const std::string & message){
    auto client = mongocxx::client(mongocxx::uri("mongodb://localhost:27017"));
    if (!client) {
        return false;
    }
//    auto public_message = (client).database("mqtt").collection("public_message");
    auto public_message = (client).database("test").collection("public_message");
    if (!public_message){
        return false;
    }
    auto doc = bsoncxx::builder::stream::document{};
    doc << "uuid" << uuid;
    doc << "message" << message;
    doc << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::now()};
    try {
        public_message.insert_one(doc.view());
    } catch (mongocxx::exception &e) {
        return false;
    }
    return true;
}

bool util::insert_p2p_message(const std::string& sender,const std::string& receiver,const std::string& message){
    auto client = mongocxx::client(mongocxx::uri("mongodb://localhost:27017"));
    if (!client) {
        return false;
    }
//    auto p2p_message = (client).database("mqtt").collection("p2p_message");
    auto p2p_message = (client).database("test").collection("p2p_message");
    if (!p2p_message){
        return false;
    }
    auto doc = bsoncxx::builder::stream::document{};
    doc << "sender" << sender;
    doc << "receiver" << receiver;
    doc << "message" << message;
    doc << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::now()};
    try {
        p2p_message.insert_one(doc.view());
    } catch (mongocxx::exception &e) {
        return false;
    }
    return true;
}

ERROR util::decrypt_sm4_key_and_iv(uint8_t * payload,
                                   SM2_KEY * sm2_key,
                                   uint8_t sm4_key_arr[SM4_KEY_SIZE],
                                   uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],
                                   size_t *offset
){
    if (payload == nullptr) {
        //mosquitto_log_printf(MOSQ_LOG_ERR,"%s:payload is null",util::get_timestamp().c_str());
        return ERROR_DATA;
    }
    uint8_t buf[SM4_KEY_SIZE + SM4_BLOCK_SIZE];
    bool success ;
//    for (int i = 138; i <= 143; ++i) {
//        if(sm2_decrypt(sm2_key, payload, i, buf, offset) != 1){
//            continue;
//        }
//        success = true;
//        *offset = i ;
//        break;
//    }
    success = sm2_decrypt(sm2_key,payload,_y1len,buf,offset) == 1;
    *offset = _y1len;
    if(!success) {
        printf("decrypt sm4 key and iv failed\n");
        return ERROR_DECRYPT;
    }
    //mosquitto_log_printf(MOSQ_LOG_INFO,"%s:success decrypt sm4 key and iv",util::get_timestamp().c_str());
    memcpy(sm4_key_arr,buf,SM4_KEY_SIZE);
    memcpy(sm4_iv_arr,buf+SM4_KEY_SIZE,SM4_BLOCK_SIZE);
    return ERROR_SUCCESS;
}

ERROR util::decrypt_sig_and_msg(uint8_t* cipher,
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


std::string get_uuid() {
    auto client = mongocxx::client(mongocxx::uri("mongodb://localhost:27017"));
    auto pems = (client).database("mqtt").collection("pems");
    if (!pems){
        return "";
    }
    auto pip = mongocxx::pipeline{};
    pip.sample(1);
    auto cursor = pems.aggregate(pip);
    for (const bsoncxx::document::view& doc : cursor) {
        if (doc["uuid"] && (doc["uuid"].type() == bsoncxx::type::k_string)) {
            return doc["uuid"].get_string().value.to_string();
        }
    }
    return "cnm";
}

int read_pem(const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm4_key_arr[SM4_KEY_SIZE],uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],uint8_t sm3_hmac_key_arr[16]) {
    auto client = mongocxx::client(mongocxx::uri("mongodb://localhost:27017"));
    if (!client) {
        return 1;
    }
    auto pems = (client).database("mqtt").collection("pems");
    if (!pems){
        return 1;
    }
    auto query = bsoncxx::builder::stream::document{} << "uuid" << uuid << bsoncxx::builder::stream::finalize;
    auto cursor = pems.find_one(query.view());
    if(cursor->empty()){
        return 1;
    }
    auto doc = cursor->view();
    if (doc["sm2_key"] && (doc["sm2_key"].type() == bsoncxx::type::k_string)){
        int pass = doc["pass"].get_int32().value;
        std::string private_key = doc["sm2_key"].get_string().value.to_string();
        FILE* fp = fmemopen((void *) private_key.c_str(), private_key.length(), "r");
        sm2_private_key_info_decrypt_from_pem(sm2_key,std::to_string(pass).c_str(),fp);
        fclose(fp);
    }else{
        printf(":Failed to find private_key\n");
        return 1;
    }
    if(doc["sm3_hmac_key"] && (doc["sm3_hmac_key"].type() == bsoncxx::type::k_string)){
        auto sm3_hmac_key = doc["sm3_hmac_key"].get_string().value.to_string();
        for (int i = 0; i < 16; ++i) {
            sscanf(sm3_hmac_key.c_str() + i * 2, "%02x", &sm3_hmac_key_arr[i]);
        }
    }else{
        return 1;
    }
    if (doc["sm4_key"] && (doc["sm4_key"].type() == bsoncxx::type::k_string)) {
        auto sm4_key = doc["sm4_key"].get_string().value.to_string();
        for (int i = 0; i < 16; ++i) {
            sscanf(sm4_key.c_str() + i * 2, "%02x", &sm4_key_arr[i]);
        }
    } else {
        return 1;
    }
    if (doc["sm4_iv"] && (doc["sm4_iv"].type() == bsoncxx::type::k_string)) {
        auto sm4_iv = doc["sm4_iv"].get_string().value.to_string();
        for (int i = 0; i < 16; ++i) {
            sscanf(sm4_iv.c_str() + i * 2, "%02x", &sm4_iv_arr[i]);
        }
    } else {
        return 1;
    }
    return 0;
}

std::string generate_public(const char * msg,const char* uuid){
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    auto *sm4_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    auto *sm4_iv = (unsigned char *)malloc(16 * sizeof (unsigned char));
    auto *sm3_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    read_pem(uuid,&sm2Key,sm4_key,sm4_iv,sm3_key);
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    sm3_hmac(sm3_key,16, (const uint8_t*)(msg), strlen(msg),sm3_hash);
    auto *sig = (uint8_t*)malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
    sm2_sign(&sm2Key,sm3_hash,sig,&siglen);
    _siglen = siglen;
    auto* needsm4 = (uint8_t*)realloc(sig,siglen + strlen(msg));
    memcpy(sig + siglen,msg,strlen(msg));
    sm4_set_encrypt_key(&sm4Key,sm4_key);
    auto *y2 = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t y2_len;
    sm4_cbc_padding_encrypt(&sm4Key,sm4_iv,needsm4,siglen + strlen(msg),y2,&y2_len);
    auto *y1 = (uint8_t *)malloc(512 * sizeof (uint8_t));
    size_t y1_len;
    auto *needy1 = (uint8_t *)malloc(32 * sizeof (uint8_t));
    memcpy(needy1,sm4_key,16);
    memcpy(needy1 + 16,sm4_iv,16);
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    _y1len = y1_len;
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result,uuid);
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    std::stringstream ss;
    // 设置输出流的十六进制格式，确保每个元素都有两位
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < y1_len + y2_len + 32; ++i) {
        ss << std::setw(2) << static_cast<int>(result[i]);
    }
    free(sm4_key);
    free(sm4_iv);
    free(sm3_key);
    free(needsm4);
    free(y1);
    free(y2);
    free(result);
    free(needy1);
    return ss.str();
}

std::string generate_p2p(const char* msg,const char* sender,const char* receiver){
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    auto sender_uuid = sender;
    auto receiver_uuid = receiver;
    auto *sm4_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    auto *sm4_iv = (unsigned char *)malloc(16 * sizeof (unsigned char));
    auto *sm3_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    read_pem(sender_uuid, &sm2Key, sm4_key, sm4_iv, sm3_key);
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    sm3_hmac(sm3_key,16, (const uint8_t*)(msg), strlen(msg),sm3_hash);
    auto *sig = (uint8_t*)malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
    sm2_sign(&sm2Key,sm3_hash,sig,&siglen);
    _siglen = siglen;
    auto* needsm4 = (uint8_t*)realloc(sig,siglen + strlen(msg));
    memcpy(sig + siglen,msg,strlen(msg));
    sm4_set_encrypt_key(&sm4Key,sm4_key);
    auto *y2 = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t y2_len;
    sm4_cbc_padding_encrypt(&sm4Key,sm4_iv,needsm4,siglen + strlen(msg),y2,&y2_len);
    auto *y1 = (uint8_t *)malloc(512 * sizeof (uint8_t));
    size_t y1_len;
    auto *needy1 = (uint8_t *)malloc(32 * sizeof (uint8_t));
    memcpy(needy1,sm4_key,16);
    memcpy(needy1 + 16,sm4_iv,16);
    read_pem(receiver_uuid, &sm2Key, sm4_key, sm4_iv, sm3_key);
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    _y1len = y1_len;
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result, sender_uuid);
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    std::stringstream ss;
    // 设置输出流的十六进制格式，确保每个元素都有两位
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < y1_len + y2_len + 32; ++i) {
        ss << std::setw(2) << static_cast<int>(result[i]);
    }
//    free(sm4_key);
//    free(sm4_iv);
//    free(sm3_key);
//    free(needsm4);
//    free(y1);
//    free(y2);
//    free(result);
//    free(needy1);
    return ss.str();
}


std::string decrypt_message(uint8_t* payload,size_t payload_len,const std::string& uuid) {
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];
    std::cout << uuid << std::endl;
    // 从数据库中读取pem私钥
    if (util::read_pem(uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        return "";
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return "";
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {

        return "";
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                                    &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        return "";
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
        return "";
    }
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';

    auto str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    free(decrypted_sig_and_msg);
    return str;
}

std::string public_handler(const std::string& p){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    auto *sm3_hmac_key_arr = (uint8_t *) malloc(SM3_HMAC_KEY_SIZE * sizeof(uint8_t));
    if (!sm3_hmac_key_arr){
        return "ERROR_INTERNAL";
    }
    auto *sm4_key_arr = (uint8_t *) malloc(SM4_KEY_SIZE * sizeof(uint8_t));
    if (!sm4_key_arr) {
        free(sm3_hmac_key_arr);
        return "ERROR_INTERNAL";
    }
    auto *sm4_iv_arr = (uint8_t*) malloc(SM4_BLOCK_SIZE * sizeof(uint8_t));
    if (!sm4_iv_arr) {
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        return "ERROR_INTERNAL";
    }
    auto payload = (uint8_t *) malloc(p.length() * sizeof (uint8_t));
    for (int i = 0; i < p.length()/2; ++i) {
        sscanf(p.c_str() + i * 2, "%02x", &payload[i]);
    }
    auto payload_len = p.length()/2;
    // 从payload中解析出uuid
    std::string uuid = util::get_uuid(p);
    // 从数据库中读取pem私钥
    if (util::read_pem(uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(payload);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_INTERNAL";
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if (util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset) != ERROR_SUCCESS){
        free(payload);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "";
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)malloc(2048 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        free(payload);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_INTERNAL";
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                                    &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        free(payload);
        free(decrypted_sig_and_msg);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "";
    }
    offset = _siglen;
    uint8_t hmac[SM3_HMAC_SIZE];
    bool success = false;
    for (; offset <= 72; ++offset) {
        sm3_hmac(sm3_hmac_key_arr,SM3_HMAC_KEY_SIZE,decrypted_sig_and_msg + offset,decrypted_sig_and_msg_len - offset,hmac);
        success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
    if (!success){
        free(payload);
        free(decrypted_sig_and_msg);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_VERIFY";
    }
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
//    if (!util::insert_public_message(uuid,str)){
//        free(payload);
//        free(decrypted_sig_and_msg);
//        free(sm3_hmac_key_arr);
//        free(sm4_key_arr);
//        free(sm4_iv_arr);
//        return "ERROR_INTERNAL";
//    }
    free(sm3_hmac_key_arr);
    free(sm4_key_arr);
    free(sm4_iv_arr);
    free(payload);
    free(decrypted_sig_and_msg);
    return str;
}

std::string p2p_handler(const std::string& p,std::string _receiver_uuid){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    auto *sm3_hmac_key_arr = (uint8_t *) malloc(SM3_HMAC_KEY_SIZE * sizeof(uint8_t));
    if (!sm3_hmac_key_arr){
        return "ERROR_INTERNAL";
    }
    auto *sm4_key_arr = (uint8_t *) malloc(SM4_KEY_SIZE * sizeof(uint8_t));
    if (!sm4_key_arr) {
        free(sm3_hmac_key_arr);
        return "ERROR_INTERNAL";
    }
    auto *sm4_iv_arr = (uint8_t*) malloc(SM4_BLOCK_SIZE * sizeof(uint8_t));
    if (!sm4_iv_arr) {
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        return "ERROR_INTERNAL";
    }
    std::string sender_uuid;
    std::string receiver_uuid = std::move(_receiver_uuid);
    auto payload = (uint8_t *) malloc(p.length() * sizeof (uint8_t));
    for (int i = 0; i < p.length()/2; ++i) {
        sscanf(p.c_str() + i * 2, "%02x", &payload[i]);
    }
    auto payload_len = p.length()/2;
    // 从payload中解析出uuid
    sender_uuid = util::get_uuid(p);
    // 从数据库中读取pem私钥
    if (read_pem(receiver_uuid, &sm2_key,sm4_key_arr,sm4_iv_arr, sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(payload);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_INTERNAL";
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        free(payload);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "";
    }
    if (read_pem(sender_uuid, &sm2_key,sm4_key_arr,sm4_iv_arr, sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(payload);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_INTERNAL";
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)malloc(2048 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        free(payload);
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_INTERNAL";
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                                    &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        return "";
    }
    offset = _siglen+1;
    uint8_t hmac[SM3_HMAC_SIZE];
    bool success;
    for (; offset <= 72; ++offset) {
        sm3_hmac(sm3_hmac_key_arr,SM3_HMAC_KEY_SIZE,decrypted_sig_and_msg + offset,decrypted_sig_and_msg_len - offset,hmac);
        success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
//    sm3_hmac(sm3_hmac_key_arr,SM3_HMAC_KEY_SIZE,decrypted_sig_and_msg + _siglen,decrypted_sig_and_msg_len - _siglen,hmac);
//    success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,_siglen) == 1;
    if (!success){
        free(payload);
        free(decrypted_sig_and_msg);
        printf("%s:sm2_verify failed",util::get_timestamp().c_str());
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "";
    }
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    free(payload);
    free(decrypted_sig_and_msg);
    free(sm3_hmac_key_arr);
    free(sm4_key_arr);
    free(sm4_iv_arr);
//    if (!util::insert_p2p_message(sender_uuid,receiver_uuid,str)){
//        return "";
//    }
    return str;
}
std::string generateRandomString(int length) {
    std::string randomString;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, characters.size() - 1);
    for (int i = 0; i < length; i++) {
        randomString += characters[dis(gen)];
    }
    return randomString;
}

std::string util::select_public_message(const std::string &uuid){
    auto client = mongocxx::client(mongocxx::uri("mongodb://localhost:27017"));
    if (!client) {
        return "";
    }
//    auto public_message = (client).database("mqtt").collection("public_message");
    auto public_message = (client).database("test").collection("public_message");
    if (!public_message){
        return "";
    }
    auto query = bsoncxx::builder::basic::document{};
    query.append(bsoncxx::builder::basic::kvp("uuid", uuid));
    auto cursor = public_message.find_one(query.view());
    if (cursor) {
        return cursor->view()["message"].get_string().value.to_string();
    } else {
        // 处理没有匹配文档的情况
        return "";
    }
}

std::string util::select_p2p_message(const std::string &sender, const std::string &receiver) {
    auto client = mongocxx::client(mongocxx::uri("mongodb://localhost:27017"));
    if (!client) {
        return "";
    }
//    auto p2p_message = (client).database("mqtt").collection("p2p_message");
    auto p2p_message = (client).database("test").collection("p2p_message");
    if (!p2p_message){
        return "";
    }
    bsoncxx::builder::stream::document query_builder;
    query_builder << "sender" << sender;
    query_builder << "receiver" << receiver;
    bsoncxx::document::value query = query_builder << bsoncxx::builder::stream::finalize;
    auto cursor = p2p_message.find(query.view());
    for (const bsoncxx::document::view& doc : cursor) {
        if (doc["message"] && (doc["message"].type() == bsoncxx::type::k_string)) {
            return doc["message"].get_string().value.to_string();
        }
    }
    return "";
}

#endif //TEST_DECRYPT_HPP
