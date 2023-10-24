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

mongocxx::pool *p;

int read_pem(const std::string& uuid,SM2_KEY *sm2_key,uint8_t sm4_key_arr[SM4_KEY_SIZE],uint8_t sm4_iv_arr[SM4_BLOCK_SIZE],uint8_t sm3_hmac_key_arr[16]) {
    auto client = p->try_acquire();
    if (!client) {
        return 1;
    }
    auto pems = (*client)->database("mqtt").collection("pems");
    if (!pems){
        return 1;
    }
    auto query = bsoncxx::builder::stream::document{} << "uuid" << uuid << bsoncxx::builder::stream::finalize;
    auto cursor = pems.find_one(query.view());
    if(cursor->empty()){
        return 1;
    }
    auto doc = cursor->view();
    if (doc["private_key"] && (doc["private_key"].type() == bsoncxx::type::k_string)){
        int pass = doc["pass"].get_int32().value;
        std::string private_key = doc["private_key"].get_string().value.to_string();
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

    return 0;
}

void generate_public(){
    const char * msg = "i love xj";
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    auto uuid = "fc04472f91ff4df58567e7f205f268fa";
    unsigned char sm4_key[16];
    unsigned char sm4_iv[16];
    unsigned char sm3_key[16];
    read_pem(uuid,&sm2Key,sm4_key,sm4_iv,sm3_key);
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    sm2_key_print(stdout,0,0,"", &sm2Key);
    sm3_hmac(sm3_key,16, (const uint8_t*)(msg), strlen(msg),sm3_hash);
    printf("hmac:");
    for (int i = 0; i < SM3_HMAC_SIZE; ++i)
        printf("%02x",sm3_hash[i]);
    printf("\n");
    uint8_t *sig = (uint8_t*)malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
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
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    printf("y1_len:%zu\n",y1_len);
    printf("y1:");
    for (int i = 0; i < y1_len; ++i)
        printf("%02x",y1[i]);
    printf("\n");
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result,uuid);
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    printf("result:");
    for (int i = 0; i < y1_len + y2_len + 32; ++i)
        printf("%02x",result[i]);
    printf("\n");
}

void generate_p2p(){
    const char * msg = "i love xj";
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    auto sender_uuid = "fc04472f91ff4df58567e7f205f268fa";
    auto receiver_uuid = "a87fd0eec32a4a60a07b0103247b6a45";
    unsigned char *sm4_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm4_iv = (unsigned char *)malloc(16 * sizeof (unsigned char));
    unsigned char *sm3_key = (unsigned char *)malloc(16 * sizeof (unsigned char));
    read_pem(sender_uuid, &sm2Key, sm4_key, sm4_iv, sm3_key);
    for (int i = 0; i < 16; ++i) {
        sscanf(&"42b84d8bafdf4ff92021f70d7c1d3e84"[i*2],"%02x",&sm4_key[i]);
        sscanf(&"bc3aa81dc98fa7d479ca766d161c884c"[2*i], "%02x", &sm4_iv[i]);
    }
    sm2_key_print(stdout,0,0,"", &sm2Key);
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
    sm2_key_print(stdout,0,0,"", &sm2Key);
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
    sm2_key_print(stdout,0,0,"",&sm2Key);
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    printf("y1_len:%zu\n",y1_len);
    printf("y1:");
    for (int i = 0; i < y1_len; ++i)
        printf("%02x",y1[i]);
    printf("\n");
    auto *result = (uint8_t *)malloc(y1_len + y2_len + 32 + 1);
    strcpy((char *)result, sender_uuid);
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    printf("result:");
    for (int i = 0; i < y1_len + y2_len + 32; ++i)
        printf("%02x",result[i]);
    printf("\n");
    auto *buf = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t offset;
    bool flag = false;
    for (int i = 138; i <= 143; ++i) {
        if(sm2_decrypt(&sm2Key, result + 32, i, buf, &offset) != 1){
            continue;
        }
        flag = true;
        break;
    }
    if (!flag)
        return;
    printf("offset:%zu\n",offset);
    printf("buf:");
    for (int i = 0; i < offset; ++i)
        printf("%02x",buf[i]);
    printf("\n");
    sm4_set_decrypt_key(&sm4Key,sm4_key);
    uint8_t * result2 = (uint8_t *)malloc(1024 * sizeof (uint8_t));
    size_t result2_len;
    sm4_cbc_padding_decrypt(&sm4Key,sm4_iv,result + offset + 32,(y1_len + y2_len + 32)/2 - offset - 32,result2,&result2_len);
    printf("result2_len:%zu\n",result2_len);
    printf("result2:");
    for (int i = 0; i < result2_len; ++i)
        printf("%02x",result2[i]);
    printf("\n");
}

int main() {
    mongocxx::instance inst{};
    p = new mongocxx::pool(mongocxx::uri("mongodb://localhost:27017"));
//    generate_public();
    generate_p2p();
}