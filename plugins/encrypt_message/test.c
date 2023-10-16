//
// Created by russ on 23-10-16.
//
#include <gmssl/sm2.h>
#include <gmssl/sm4.h>
int main() {
//    uint8_t *data = malloc(1 * sizeof(uint8_t));
//    for (int i = 0; i < cipher2_len; ++i) {
//        scanf("%02x", data + i);
//    }
    SM2_KEY *sm2_key = calloc(1,sizeof(SM2_KEY));
    FILE * test = fopen("./pems/private.pem","r");
//    fseek(test,0,SEEK_END);
    char * pass = "123456";
//    char* data = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
//                 "MIIBBjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQAkz0ftaZVaS+P4/S\n"
//                 "dnyCegIDAQAAAgEQMAsGCSqBHM9VAYMRAjAcBggqgRzPVQFoAgQQCWwFesgJooCU\n"
//                 "YPeHGnWFQwSBoCipH6yfzGatkUkoWJfs6SEQozIHyoVr5llgVgjALkGIIydGwE/d\n"
//                 "E8Yy3PEjL8Ru5qe1H/rNB35fkIrXhSgrTQRLiW/OitA3TwOsNavt/xfZA9oe76C5\n"
//                 "jT5nDYMdv69tHbBmcRZEWrBjTZBBzP6eNn2MCcQeSep69NLwERI/cFcSX06AnuL3\n"
//                 "0mPwNYrIQzxkE7IUSI1mAFKH9gs6wMI8Pmk=\n"
//                 "-----END ENCRYPTED PRIVATE KEY-----";
//    long i = ftell(test);
//    if (strlen(data) == i){
//        printf("yes\n");
//    }
//    printf("%lu\n",strlen(data));
//    printf("%ld\n",i);
//    FILE * private = fmemopen(data,strlen(data),"r");
    sm2_key_print(stdout,0,1,"russ private key",sm2_key);
    sm2_private_key_info_decrypt_from_pem(sm2_key,pass,test);
    sm2_key_print(stdout,0,1,"russ private key",sm2_key);
    return 0;
}