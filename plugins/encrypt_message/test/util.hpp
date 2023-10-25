//
// Created by russ on 23-10-25.
//

#ifndef MOSQUITTO_MESSAGE_ENCRYPT_UTIL_HPP
#define MOSQUITTO_MESSAGE_ENCRYPT_UTIL_HPP

#include "mosquitto_plugin.h"
#include "mosquitto.h"

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <string>
#include <sys/time.h>
#include <ctime>
#include <mongocxx/exception/write_exception.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>

#define UUID_LEN 32
#define SM3_HMAC_KEY_SIZE 16

enum ERROR {
    ERROR_SUCCESS = 0,
    ERROR_DATA = 1,
    ERROR_DECRYPT = 2,
    ERROR_VERIFY = 3,
    ERROR_INTERNAL = 4
};


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

    int read_pem(const std::string &uuid, SM2_KEY *sm2_key, uint8_t *sm3_hmac_key_arr);

    std::string get_uuid(std::string payload);
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

std::string util::get_uuid(std::string payload){
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
    auto public_message = (client).database("mqtt").collection("public_message");
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
    auto p2p_message = (client).database("mqtt").collection("p2p_message");
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
    bool success = false;
    for (int i = 138; i <= 143; ++i) {
        if(sm2_decrypt(sm2_key, payload, i, buf, offset) != 1){
            continue;
        }
        success = true;
        *offset = i ;
        break;
    }
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

#endif //MOSQUITTO_MESSAGE_ENCRYPT_UTIL_HPP
