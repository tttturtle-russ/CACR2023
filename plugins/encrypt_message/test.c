//
// Created by russ on 23-10-24.
//

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

int main() {
    const char * msg = "i love xj";
    SM2_KEY sm2Key;
    SM4_KEY sm4Key;
    const int8_t * uuid = "fc04472f91ff4df58567e7f205f268fa";
    unsigned char sm4_key[16];
    unsigned char sm4_iv[16];
    const char* iv = "bc3aa81dc98fa7d479ca766d161c884c";
    const char* _key = "42b84d8bafdf4ff92021f70d7c1d3e84";
    for (int i = 0; i < 16; ++i) {
        sscanf(&_key[2 * i], "%02x", &sm4_key[i]);
        sscanf(&iv[2 * i], "%02x",&sm4_iv[i]);
    }
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_key[i]);
    }
    printf("\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm4_iv[i]);
    }
    printf("\n");
    unsigned char sm3_key[16];
    for (int i = 0; i < 16; ++i) {
        sscanf(&"e076a04d5914bb3717327afe81493601"[2 * i], "%02x", &sm3_key[i]);
    }
    printf("sm3_key:");
    for (int i = 0; i < 16; ++i) {
        printf("%02x",sm3_key[i]);
    }
    printf("\n");
    unsigned char sm3_hash[SM3_HMAC_SIZE];
    char * key = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                 "MIIBBjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQdwq5lMASuht9P8x3\n"
                 "W4ESlgIDAQAAAgEQMAsGCSqBHM9VAYMRAjAcBggqgRzPVQFoAgQQ6uWEjmb7zXem\n"
                 "RgfqAyOaTwSBoKVfPfUwqKBFsnepzfSzHojTqO10dbPQrprLM2rmtFYDmBmIK30X\n"
                 "Ls50AY/watlldKujdlVutsv0HLx/8m05xwdfIOaIJPynOqskt+qQ8iHcy57ExRF7\n"
                 "v5gqbvkLH2wEdGHT9ZtogfWWnZ5I2wNV6vVYNCW45h+GWRAG0OLL91qxIXiGflbH\n"
                 "OMAWVC/peCVm4Ly2XDZ+NDYvxj0GAnbArQM=\n"
                 "-----END ENCRYPTED PRIVATE KEY-----\n";
    FILE* p = fmemopen(key, strlen(key), "r");
    sm2_private_key_info_decrypt_from_pem(&sm2Key,"63789",p);
    sm2_key_print(stdout,0,0,"", &sm2Key);
    sm3_hmac(sm3_key,16,msg, strlen(msg),sm3_hash);
    printf("hmac:");
    for (int i = 0; i < SM3_HMAC_SIZE; ++i)
        printf("%02x",sm3_hash[i]);
    printf("\n");
    uint8_t *sig = malloc(1024 * sizeof (uint8_t));
    size_t siglen ;
    sm2_sign(&sm2Key,sm3_hash,sig,&siglen);
    printf("siglen:%zu\n",siglen);
    printf("sig:");
    for (int i = 0; i < siglen; ++i)
        printf("%02x",sig[i]);
    printf("\n");
    uint8_t *needsm4 = realloc(sig,siglen + strlen(msg));
    memcpy(sig + siglen,msg,strlen(msg));
    sm4_set_encrypt_key(&sm4Key,sm4_key);
    uint8_t *y2 = malloc(1024 * sizeof (uint8_t));
    size_t y2_len;
    sm4_cbc_padding_encrypt(&sm4Key,sm4_iv,needsm4,siglen + strlen(msg),y2,&y2_len);
    printf("y2_len:%zu\n",y2_len);
    printf("y2:");
    for (int i = 0; i < y2_len; ++i)
        printf("%02x",y2[i]);
    printf("\n");
    uint8_t *y1 = malloc(512 * sizeof (uint8_t));
    size_t y1_len;
    uint8_t *needy1 = malloc(32 * sizeof (uint8_t));
    memcpy(needy1,sm4_key,16);
    memcpy(needy1 + 16,sm4_iv,16);
    sm2_encrypt(&sm2Key,needy1,32,y1,&y1_len);
    printf("y1_len:%zu\n",y1_len);
    printf("y1:");
    for (int i = 0; i < y1_len; ++i)
        printf("%02x",y1[i]);
    printf("\n");
    uint8_t *result = malloc(y1_len + y2_len + 32);
    strcpy(result,uuid);
    memcpy(result + 32,y1,y1_len);
    memcpy(result + y1_len + 32,y2,y2_len);
    printf("result:");
    for (int i = 0; i < y1_len + y2_len + 32; ++i)
        printf("%02x",result[i]);
    printf("\n");
    getchar();
    printf("uuid:");
    for (int i = 0; i < 32; ++i)
        printf("%02x",uuid[i]);
    printf("\n");

    uint8_t *uid = malloc(16 * sizeof (uint8_t));
    for (int i = 0; i < 16; ++i) {
        sscanf(result+2*i,"%02x",&uid[i]);
    }
    printf("uid:");
    for (int i = 0; i < 16; ++i)
        printf("%02x",uid[i]);
    printf("\n");
    uint8_t * y1_ = malloc(512 * sizeof (uint8_t));
    size_t y1_len_;
    sm2_decrypt(&sm2Key,result + 32,y1_len,y1_,&y1_len_);
    printf("y1_len_:%zu\n",y1_len_);
    printf("y1_:");
    for (int i = 0; i < y1_len_; ++i)
        printf("%02x",y1_[i]);
    printf("\n");
    sm4_set_decrypt_key(&sm4Key,sm4_key);
    uint8_t *y2_ = malloc(1024 * sizeof (uint8_t));
    size_t y2_len_;
    printf("siglen:%zu\n",siglen);
    printf("sig || x:");
    for (int i = 32; i < siglen; ++i) {
        printf("%02x",result[i]);
    }
    sm4_cbc_padding_decrypt(&sm4Key,sm4_iv,result + 32,siglen,y2_,&y2_len_);

}