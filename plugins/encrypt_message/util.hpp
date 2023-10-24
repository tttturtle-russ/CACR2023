//
// Created by russ on 23-10-25.
//

#ifndef MOSQUITTO_MESSAGE_ENCRYPT_UTIL_HPP
#define MOSQUITTO_MESSAGE_ENCRYPT_UTIL_HPP

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

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <string>
#include <sys/time.h>
#include <ctime>
#include <mongocxx/exception/write_exception.hpp>
extern FILE* log_;

namespace util{
    std::string get_timestamp();
    std::string get_uuid(const char *payload);
    bool insert_public_message(mongocxx::pool *p,const std::string & database,const std::string & uuid,const std::string & message);
    bool insert_p2p_message(mongocxx::pool *p,const std::string& database,const std::string& sender,const std::string& receiver,const std::string& message);
    int read_pem(mongocxx::pool *p,const std::string & database,const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE]);
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

std::string util::get_uuid(const char *payload){
    std::string uuid;
    char id[UUID_LEN];
    for (int i = 0; i < UUID_LEN; ++i) {
        sscanf(payload + i * 2, "%02x", &id[i]);
        uuid += id[i];
    }
    return uuid;
}

int util::read_pem(mongocxx::pool *p,const std::string & database,const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE]) {
    auto client = p->try_acquire();
    if (!client) {
        error("%s:Failed to pop client pool\n",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    auto pems = (*client)->database(database).collection("pems");
    if (!pems){
        error("%s:Failed to get collection\n",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    auto query = bsoncxx::builder::stream::document{} << "uuid" << uuid << bsoncxx::builder::stream::finalize;
    auto cursor = pems.find_one(query.view());
    if(cursor->empty()){
        error("%s:Failed to find uuid:%s\n",util::get_timestamp().c_str(),uuid.c_str());
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
        error("%s:Failed to find private_key\n",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }

    if(doc["sm3_hmac_key"] && (doc["sm3_hmac_key"].type() == bsoncxx::type::k_string)){
        auto sm3_hmac_key = doc["sm3_hmac_key"].get_string().value.to_string();
        for (int i = 0; i < SM3_HMAC_KEY_SIZE; ++i) {
            sscanf(sm3_hmac_key.c_str() + i * 2, "%02x", &sm3_hmac_key_arr[i]);
        }
    }else{
        error("%s:Failed to find sm3_hmac_key\n",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }

    return ERROR_SUCCESS;
}

bool util::insert_public_message(mongocxx::pool *p,const std::string & database,const std::string & uuid,const std::string & message){
    auto client = p->try_acquire();
    if (!client) {
        error("%s:Failed to pop client pool\n",util::get_timestamp().c_str());
        return false;
    }
    auto public_message = (*client)->database(database).collection("public_message");
    if (!public_message){
        error("%s:Failed to get collection\n",util::get_timestamp().c_str());
        return false;
    }
    auto doc = bsoncxx::builder::stream::document{};
    doc << "uuid" << uuid;
    doc << "message" << message;
    doc << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::now()};
    try {
        public_message.insert_one(doc.view());
    } catch (mongocxx::exception &e) {
        error("%s:Failed to insert public message:%s\n",util::get_timestamp().c_str(),e.what());
        return false;
    }
    return true;
}

bool util::insert_p2p_message(mongocxx::pool *p,const std::string& database,const std::string& sender,const std::string& receiver,const std::string& message){
    auto client = p->try_acquire();
    if (!client) {
        error("%s:Failed to pop client pool\n",util::get_timestamp().c_str());
        return false;
    }
    auto p2p_message = (*client)->database(database).collection("p2p_message");
    if (!p2p_message){
        error("%s:Failed to get collection\n",util::get_timestamp().c_str());
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
        error("%s:Failed to insert p2p message:%s\n",util::get_timestamp().c_str(),e.what());
        return false;
    }
    return true;
}

#endif //MOSQUITTO_MESSAGE_ENCRYPT_UTIL_HPP
