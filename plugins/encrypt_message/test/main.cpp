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
#include "util.hpp"



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
            printf("%02x",sm4_key_arr[i]);
        }
    } else {
        return 1;
    }
    printf("\n");
    if (doc["sm4_iv"] && (doc["sm4_iv"].type() == bsoncxx::type::k_string)) {
        auto sm4_iv = doc["sm4_iv"].get_string().value.to_string();
        for (int i = 0; i < 16; ++i) {
            sscanf(sm4_iv.c_str() + i * 2, "%02x", &sm4_iv_arr[i]);
            printf("%02x",sm4_iv_arr[i]);
        }
    } else {
        return 1;
    }
    printf("\n");
    return 0;
}

std::string generate_public(const char* msg){
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    auto uuid = get_uuid();
    unsigned char sm4_key[16];
    unsigned char sm4_iv[16];
    unsigned char sm3_key[16];
    read_pem(uuid,&sm2Key,sm4_key,sm4_iv,sm3_key);
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    sm2_key_print(stdout,0,0,"", &sm2Key);
    sm3_hmac(sm3_key,16, (const uint8_t*)(msg), strlen(msg),sm3_hash);
    printf("hmac:");
    uint8_t *sig = (uint8_t*)malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
    sm2_sign(&sm2Key,sm3_hash,sig,&siglen);
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
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result,uuid.c_str());
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    return std::string((char *)result,y1_len + y2_len + 32);
}

std::pair<std::string,std::string> generate_p2p(const char * msg){
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    auto sender_uuid = get_uuid();
    auto receiver_uuid = get_uuid();
    unsigned char *sm4_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm4_iv = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm3_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    read_pem(sender_uuid, &sm2Key, sm4_key, sm4_iv, sm3_key);
    printf("sm4_key:\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_key[i]);
    }
    printf("\n");
    printf("sm4_iv:\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_iv[i]);
    }
    printf("\n");
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    printf("sm3_key:\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm3_key[i]);
    }
    printf("\n");
    sm3_hmac(sm3_key,16, (const uint8_t*)(msg), strlen(msg),sm3_hash);
    printf("hmac:");
    for (int i = 0; i < SM3_HMAC_SIZE; ++i)
        printf("%02x",sm3_hash[i]);
    printf("\n");
    uint8_t *sig = (uint8_t*)malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
    sm2_key_print(stdout,0,0,"",&sm2Key);
    sm2_sign(&sm2Key,sm3_hash,sig,&siglen);
    printf("siglen:%zu\n",siglen);
    printf("sig:");
    for (int i = 0; i < siglen; ++i)
        printf("%02x",sig[i]);
    printf("\n");
    uint8_t* needsm4 = (uint8_t*)realloc(sig,siglen + strlen(msg));
    memcpy(sig + siglen,msg,strlen(msg));
    sm4_set_encrypt_key(&sm4Key,sm4_key);
    uint8_t *y2 = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t y2_len;
    sm4_cbc_padding_encrypt(&sm4Key,sm4_iv,needsm4,siglen + strlen(msg),y2,&y2_len);
    printf("y2_len:%zu\n",y2_len);
    printf("y2:");
    for (int i = 0; i < y2_len; ++i)
        printf("%02x",y2[i]);
    printf("\n");
    uint8_t *y1 = (uint8_t *)malloc(512 * sizeof (uint8_t));
    size_t y1_len;
    uint8_t *needy1 = (uint8_t *)malloc(32 * sizeof (uint8_t));
    memcpy(needy1,sm4_key,16);
    memcpy(needy1 + 16,sm4_iv,16);
    read_pem(receiver_uuid, &sm2Key, sm4_key, sm4_iv, sm3_key);
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    printf("y1_len:%zu\n",y1_len);
    printf("y1:");
    for (int i = 0; i < y1_len; ++i)
        printf("%02x",y1[i]);
    printf("\n");
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result, sender_uuid.c_str());
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    printf("result:");
    for (int i = 0; i < y1_len + y2_len + 32; ++i)
        printf("%02x",result[i]);
    printf("\n");
    sm2_key_print(stdout,0,0,"",&sm2Key);
    std::string ans;
    std::vector<uint8_t> dataVector(result, result + y1_len + y2_len + 32 / sizeof(uint8_t));
    std::stringstream ss;
    for (const uint8_t& value : dataVector) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(value);
    }
    return {ss.str(),receiver_uuid};
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
        printf("%s:decrypt_sig_and_msg failed", util::get_timestamp().c_str());
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
        printf("%s:sm2_verify failed",util::get_timestamp().c_str());
        return "";
    }
    printf("%s:sm2_verify success",util::get_timestamp().c_str());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';

    auto str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    free(decrypted_sig_and_msg);
    return str;
}

int public_handler(std::string p){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];

    printf("%s:receive payload:%s",util::get_timestamp().c_str(),p.c_str());
    auto payload = (uint8_t *) p.c_str();
    auto payload_len = p.length();
    // 从payload中解析出uuid
    std::string uuid = util::get_uuid(p);
    std::cout << uuid << std::endl;
    // 从数据库中读取pem私钥
    if (util::read_pem(uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){

        return ERROR_INTERNAL;
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return ret;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {

        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg

    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                                    &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        printf("%s:decrypt_sig_and_msg failed", util::get_timestamp().c_str());
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
        printf("%s:sm2_verify failed",util::get_timestamp().c_str());
        return ERROR_VERIFY;
    }
    printf("%s:sm2_verify success",util::get_timestamp().c_str());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    free(decrypted_sig_and_msg);
    if (!util::insert_public_message(uuid,str)){
        return ERROR_INTERNAL;
    }
    return ERROR_SUCCESS;
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
    std::cout << "sender uuid:" << sender_uuid << std::endl;
    std::cout << "receiver uuid:" << receiver_uuid << std::endl;
    // 从数据库中读取pem私钥
    if (read_pem(receiver_uuid, &sm2_key,sm4_key_arr,sm4_iv_arr, sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_INTERNAL";
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "";
    }
    std::cout << "success decrypt sm4 key iv" << std::endl;
    if (read_pem(sender_uuid, &sm2_key,sm4_key_arr,sm4_iv_arr, sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "ERROR_INTERNAL";
    }
    sm2_key_print(stdout,0,0,"",&sm2_key);
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
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
        printf("%s:decrypt_sig_and_msg failed", util::get_timestamp().c_str());
        return "";
    }
    std::cout << "success decrypt sig and msg" << std::endl;
    offset = 70;
    uint8_t hmac[SM3_HMAC_SIZE];
    bool success = false;
    for (; offset <= 72; ++offset) {
        sm3_hmac(sm3_hmac_key_arr,SM3_HMAC_KEY_SIZE,decrypted_sig_and_msg + offset,decrypted_sig_and_msg_len - offset,hmac);
        printf("hmac:");
        for (int i = 0; i < SM3_HMAC_SIZE; ++i) {
            printf("%02x",hmac[i]);
        }
        printf("\n");
        printf("sig:");
        for (int i = 0; i < offset; ++i) {
            printf("%02x",decrypted_sig_and_msg[i]);
        }
        printf("\n");
        success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    std::cout << str << std::endl;
    if (!success){
        printf("%s:sm2_verify failed",util::get_timestamp().c_str());
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return "";
    }
    printf("%s:sm2_verify success",util::get_timestamp().c_str());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    free(decrypted_sig_and_msg);
    free(sm3_hmac_key_arr);
    free(sm4_key_arr);
    free(sm4_iv_arr);
    if (!util::insert_p2p_message(sender_uuid,receiver_uuid,str)){
        return "";
    }
    return str;
}

std::string decrypt(std::pair<std::string,std::string> p){
    p2p_handler(p.first,p.second);
}


TEST(DecryptTestCase,DecryptTest){
    EXPECT_EQ(decrypt(generate_p2p("i love xj")),"i love xj");
}


int main(int argc, char** argv) {
    mongocxx::instance ins{};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}