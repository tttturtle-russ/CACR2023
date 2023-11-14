//
// Created by russ on 23-10-24.
//

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <bsoncxx//builder/stream/document.hpp>
#include <string>
#include <bsoncxx/types.hpp>
#include <mqtt/client.h>
uint8_t pub[1024];
uint8_t p2p[1024];
const std::string HOST("tcp://localhost:1883");
const std::string client_id("test");
mongocxx::pool *p;

int read_pem(const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm4_key_arr[16],uint8_t sm4_key_iv[16],uint8_t sm3_hmac_key_arr[16]) {
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
    if (doc["sm4_key"] && (doc["sm4_key"].type() == bsoncxx::type::k_string)){
        auto sm4_key = doc["sm4_key"].get_string().value.to_string();
        for (int i = 0; i < 16; ++i) {
            sscanf(sm4_key.c_str() + i * 2, "%02x", &sm4_key_arr[i]);
        }
    }else{
        return 1;
    }
    printf("sm4_key:");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_key_arr[i]);
    }
    printf("\n");
    if (doc["sm4_iv"] && (doc["sm4_iv"].type() == bsoncxx::type::k_string)){
        auto sm4_iv = doc["sm4_iv"].get_string().value.to_string();
        for (int i = 0; i < 16; ++i) {
            sscanf(sm4_iv.c_str() + i * 2, "%02x", &sm4_key_iv[i]);
        }
    }else{
        return 1;
    }
    printf("sm4_iv:");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_key_iv[i]);
    }
    printf("\n");
    printf("sm3 key:");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm3_hmac_key_arr[i]);
    }
    printf("\n");
    return 0;
}

uint32_t generate_public(const char * msg,const char* uuid){
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    unsigned char *sm4_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm4_iv = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm3_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    read_pem(uuid,&sm2Key,sm4_key,sm4_iv,sm3_key);
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    sm3_hmac(sm3_key,16, (const uint8_t*)(msg), strlen(msg),sm3_hash);
    uint8_t *sig = (uint8_t*)malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
    sm2_sign(&sm2Key,sm3_hash,sig,&siglen);
    std::cout << "siglen:" << siglen << std::endl;
    uint8_t* needsm4 = (uint8_t*)realloc(sig,siglen + strlen(msg));
    memcpy(sig + siglen,msg,strlen(msg));
    sm4_set_encrypt_key(&sm4Key,sm4_key);
    uint8_t *y2 = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t y2_len;
    sm4_cbc_padding_encrypt(&sm4Key,sm4_iv,needsm4,siglen + strlen(msg),y2,&y2_len);
    uint8_t *y1 = (uint8_t *)malloc(512 * sizeof (uint8_t));
    size_t y1_len;
    uint8_t *needy1 = (uint8_t *)malloc(32 * sizeof (uint8_t));
    memcpy(needy1,sm4_key,16);
    memcpy(needy1 + 16,sm4_iv,16);
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    std::cout << "y1_len:" << y1_len << std::endl;
    for (int i = 0; i < y1_len; ++i) {
        printf("%02x",y1[i]);
    }
    printf("\n");
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result, uuid);
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    memset(pub,0,1024);
    for (int i = 0; i < y1_len + y2_len + 32; ++i) {
        printf("%02x",result[i]);
        pub[i] = result[i];
    }
    printf("\n");
    for (int i = 0; i < y1_len + y2_len + 32; ++i) {
        printf("%02x",pub[i]);
    }
    printf("\n");
    return y1_len + y2_len + 32;
}

uint32_t generate_p2p(const char* msg,const char* sender,const char* receiver){
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    auto sender_uuid = sender;
    auto receiver_uuid = receiver;
    unsigned char *sm4_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm4_iv = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm3_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    read_pem(sender_uuid, &sm2Key, sm4_key, sm4_iv, sm3_key);
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    sm3_hmac(sm3_key,16, (const uint8_t*)(msg), strlen(msg),sm3_hash);
    uint8_t *sig = (uint8_t*)malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
    sm2_sign(&sm2Key,sm3_hash,sig,&siglen);
    std::cout << "siglen:" << siglen << std::endl;
    uint8_t* needsm4 = (uint8_t*)realloc(sig,siglen + strlen(msg));
    memcpy(sig + siglen,msg,strlen(msg));
    sm4_set_encrypt_key(&sm4Key,sm4_key);
    uint8_t *y2 = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t y2_len;
    sm4_cbc_padding_encrypt(&sm4Key,sm4_iv,needsm4,siglen + strlen(msg),y2,&y2_len);
    uint8_t *y1 = (uint8_t *)malloc(512 * sizeof (uint8_t));
    size_t y1_len;
    uint8_t *needy1 = (uint8_t *)malloc(32 * sizeof (uint8_t));
    memcpy(needy1,sm4_key,16);
    memcpy(needy1 + 16,sm4_iv,16);
    read_pem(receiver_uuid, &sm2Key, sm4_key, sm4_iv, sm3_key);
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    std::cout << "y1_len:" << y1_len << std::endl;
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result, sender_uuid);
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    memset(p2p,0,1024);
    for (int i = 0; i < y1_len + y2_len + 32; ++i) {
        printf("%02x",result[i]);
        p2p[i] = result[i];
    }
    printf("\n");
    for (int i = 0; i < y1_len + y2_len + 32; ++i) {
        printf("%02x",p2p[i]);
    }
    printf("\n");
    return y1_len + y2_len + 32;
}

void usage() {
    std::cout << "1.generate p2p message" << std::endl;
    std::cout << "2.generate public message" << std::endl;
    std::cout << "3.generate checkpoint message" << std::endl;
    std::cout << "4.generate accident message" << std::endl;
}

int main() {
    int choice;
    std::string msg;
    std::string sender;
    std::string receiver;
    mongocxx::instance inst{};
    p = new mongocxx::pool(mongocxx::uri("mongodb://localhost:27017"));
    mqtt::client client(HOST,client_id);
    uint32_t len;
    mqtt::connect_options connOpts;
    mqtt::message_ptr pubmsg = nullptr;
    mqtt::message_ptr p2pmsg = nullptr;
    connOpts.set_keep_alive_interval(20);
    connOpts.set_clean_session(true);
    try {
        client.connect(connOpts);
        while (true) {
            usage();
            std::cin >> choice;
            std::cin.get();
            switch (choice) {
                case 1:
                    std::cout << "input message:" << std::endl;
                    std::getline(std::cin,msg);
                    std::cout << "input sender:" << std::endl;
                    std::getline(std::cin,sender);
                    std::cout << "input receiver:" << std::endl;
                    std::getline(std::cin,receiver);
                    len = generate_p2p(msg.c_str(),sender.c_str(),receiver.c_str());
                    p2pmsg = mqtt::make_message("/p2p/"+std::string(receiver),(const void *)p2p,len,1,false);
                    client.publish(p2pmsg);
                    break;
                case 2:
                    std::cout << "input message" << std::endl;
                    std::getline(std::cin,msg);
                    std::cout << "input sender" << std::endl;
                    std::getline(std::cin,sender);
                    len = generate_public(msg.c_str(),sender.c_str());
                    pubmsg = mqtt::make_message("/public", (const void *) pub,len, 1, false);
                    client.publish(pubmsg);
                    break;
                case 3:
                    std::cout << "input message" << std::endl;
                    std::getline(std::cin,msg);
                    std::cout << "input sender" << std::endl;
                    std::getline(std::cin,sender);
                    len = generate_public(msg.c_str(),sender.c_str());
                    pubmsg = mqtt::make_message("/checkpoint", (const void *) pub,len, 1, false);
                    client.publish(pubmsg);
                case 4:
                    std::cout << "input message" << std::endl;
                    std::getline(std::cin,msg);
                    std::cout << "input sender" << std::endl;
                    std::getline(std::cin,sender);
                    len = generate_public(msg.c_str(),sender.c_str());
                    pubmsg = mqtt::make_message("/accident", (const void *) pub,len, 1, false);
                    client.publish(pubmsg);
                default:
                    usage();
                    break;
            }
        }
    } catch (const mqtt::exception &exc) {
        std::cerr << exc.what() << std::endl;
        return 1;
    }

    delete p;
    return 0;
}
