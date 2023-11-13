//
// Created by russ on 23-10-13.
//
#include "config.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"

#include "graph.hpp"
#include "util.hpp"
#include <mongocxx/uri.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <bsoncxx/json.hpp>


std::string database;
static mosquitto_plugin_id_t *mosq_pid = nullptr;
FILE* log_;
mongocxx::pool *p = nullptr;
std::map<std::string,Graph::Graph> m;

std::string decrypt_message(uint8_t* payload,size_t payload_len,const std::string& uuid) {
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];
    // 从数据库中读取pem私钥
    std::cout << payload << std::endl;
    if (util::read_pem(p,database,uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        error("%s:read_pem failed",util::get_timestamp().c_str());
        return "";
    }
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return "";
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        error("%s:decrypt_message_callback: mosquitto_malloc failed", util::get_timestamp().c_str());
        return "";
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                        &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:decrypt_sig_and_msg failed", util::get_timestamp().c_str());
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
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:sm2_verify failed",util::get_timestamp().c_str());
        return "";
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:sm2_verify success",util::get_timestamp().c_str());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    info("%s:after decrypt,get msg: %s",util::get_timestamp().c_str(),decrypted_sig_and_msg + offset)
    auto str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    mosquitto_free(decrypted_sig_and_msg);
    return str;
}

int public_handler(struct mosquitto_evt_message *ed){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];

    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:receive payload:%s",util::get_timestamp().c_str(),ed->payload);
    auto payload = (uint8_t *) mosquitto_malloc(ed->payloadlen/2);
    auto payload_len = ed->payloadlen / 2;
    for (int i = 0; i < payload_len; ++i) {
        sscanf((const char*)ed->payload + i * 2, "%02x", &payload[i]);
    }
    // 从payload中解析出uuid
    std::string uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    std::cout << uuid << std::endl;
    // 从数据库中读取pem私钥
    if (util::read_pem(p,database,uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        error("%s:read_pem failed",util::get_timestamp().c_str())
        return ERROR_INTERNAL;
    }
    printf("sm3 key:");
    for (int i = 0; i < SM3_HMAC_KEY_SIZE; ++i) {
        printf("%02x",sm3_hmac_key_arr[i]);
    }
    putchar('\n');
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        return ret;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        error("%s:decrypt_message_callback: mosquitto_malloc failed", util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg

    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                              &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:decrypt_sig_and_msg failed", util::get_timestamp().c_str());
        return ret;
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:decrypt_sig_and_msg success", util::get_timestamp().c_str());
    offset = 70;
    uint8_t hmac[SM3_HMAC_SIZE];
    bool success = false;
    for (; offset <= 72; ++offset) {
        sm3_hmac(sm3_hmac_key_arr,SM3_HMAC_KEY_SIZE,decrypted_sig_and_msg + offset,decrypted_sig_and_msg_len - offset,hmac);
        printf("hmac:");
        for (int i = 0; i < SM3_HMAC_SIZE; ++i) {
            printf("%02x",hmac[i]);
        }
        putchar('\n');
        printf("sig:");
        for (int i = 0; i < offset; ++i) {
            printf("%02x",decrypted_sig_and_msg[i]);
        }
        printf("\n");
        success = sm2_verify(&sm2_key,hmac,decrypted_sig_and_msg,offset) == 1;
        if (success)
            break;
    }
    if (!success){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:sm2_verify failed",util::get_timestamp().c_str());
        return ERROR_VERIFY;
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:sm2_verify success",util::get_timestamp().c_str());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    info("%s:after decrypt,get msg: %s",util::get_timestamp().c_str(),decrypted_sig_and_msg + offset)
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    mosquitto_free(decrypted_sig_and_msg);
    if (!util::insert_public_message(p,database,uuid,str)){
        error("%s:insert_public_message failed",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    return ERROR_SUCCESS;
}

int p2p_handler(struct mosquitto_evt_message *ed){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    auto *sm3_hmac_key_arr = (uint8_t *) malloc(SM3_HMAC_KEY_SIZE * sizeof(uint8_t));
    if (!sm3_hmac_key_arr){
        error("%s:malloc failed",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    auto *sm4_key_arr = (uint8_t *) malloc(SM4_KEY_SIZE * sizeof(uint8_t));
    if (!sm4_key_arr) {
        free(sm3_hmac_key_arr);
        error("%s:malloc failed",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    auto *sm4_iv_arr = (uint8_t*) malloc(SM4_BLOCK_SIZE * sizeof(uint8_t));
    if (!sm4_iv_arr) {
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        error("%s:malloc failed",util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    std::string sender_uuid;
    std::string receiver_uuid = ed->topic + 5;
    auto payload = (uint8_t *) mosquitto_malloc(ed->payloadlen/2);
    auto payload_len = ed->payloadlen / 2;
    for (int i = 0; i < payload_len; ++i) {
        sscanf((const char*)ed->payload + i * 2, "%02x", &payload[i]);
    }
    // 从payload中解析出uuid
    sender_uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    std::cout << "sender uuid" << sender_uuid << std::endl;
    std::cout << "receiver uuid" << receiver_uuid << std::endl;
    // 从数据库中读取pem私钥
    if (util::read_pem(p,database,receiver_uuid, &sm2_key, sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        error("%s:read_pem failed",util::get_timestamp().c_str())
        return ERROR_INTERNAL;
    }
    sm2_key_print(stdout,0,0,"", &sm2_key);
    ERROR ret;
    size_t offset;
    // 从payload头部解析出sm4_key和sm4_iv
    if ((ret = util::decrypt_sm4_key_and_iv(payload + UUID_LEN,&sm2_key,sm4_key_arr,sm4_iv_arr,&offset)) != ERROR_SUCCESS){
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        return ret;
    }
    if (util::read_pem(p,database,sender_uuid, &sm2_key, sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        error("%s:read_pem failed",util::get_timestamp().c_str())
        return ERROR_INTERNAL;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        error("%s:decrypt_message_callback: mosquitto_malloc failed", util::get_timestamp().c_str());
        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    sm2_key_print(stdout,0,0,"",&sm2_key);
    // 解密sig和msg
    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                              &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:decrypt_sig_and_msg failed", util::get_timestamp().c_str());
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
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        mosquitto_log_printf(MOSQ_LOG_ERR,"%s:sm2_verify failed",util::get_timestamp().c_str());
        return ERROR_VERIFY;
    }
    mosquitto_log_printf(MOSQ_LOG_INFO,"%s:sm2_verify success",util::get_timestamp().c_str());
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    info("%s:after decrypt,get msg: %s",util::get_timestamp().c_str(),decrypted_sig_and_msg + offset)
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    mosquitto_free(decrypted_sig_and_msg);
    free(sm3_hmac_key_arr);
    free(sm4_key_arr);
    free(sm4_iv_arr);
    if (!util::insert_p2p_message(p,database,sender_uuid,receiver_uuid,str)){
        error("%s:insert_p2p_message failed",util::get_timestamp().c_str())
        return ERROR_INTERNAL;
    }
    return ERROR_SUCCESS;
}

int checkpoint_handler(struct mosquitto_evt_message *ed){
    std::string uuid;
    auto payload = (uint8_t *) mosquitto_malloc(ed->payloadlen/2);
    auto payload_len = ed->payloadlen / 2;
    for (int i = 0; i < payload_len; ++i) {
        sscanf((const char*)ed->payload + i * 2, "%02x", &payload[i]);
    }
    uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    if (m.find(uuid) == m.end()){
        m[uuid] = Graph::Graph(uuid,p);
    }
    auto& g = m[uuid];
    auto str = decrypt_message(payload,payload_len,uuid);
    if (str.empty()){
        error("%s:error decrypt",util::get_timestamp().c_str());
        mosquitto_free(payload);
        return ERROR_DECRYPT;
    }
    auto new_vertex = g.add_vertex(str);
    if (g.size() > 1){
        g.add_edge(g.size() - 2,new_vertex);
    }
    info("%s:%s checkpoint %s",util::get_timestamp().c_str(),uuid.c_str(),str.c_str());
    auto gr = g.get_graph();
    BGL_FORALL_EDGES(e,gr,Graph::graph){
        auto source = boost::source(e,gr);
        auto target = boost::target(e,gr);
        std::cout << gr[source].name << " -> " << gr[target].name << std::endl;
    }
    mosquitto_free(payload);
    return ERROR_SUCCESS;
}

static int accident_handler(mosquitto_evt_message *ed) {
    std::string uuid;
    auto payload = (uint8_t *) mosquitto_malloc(ed->payloadlen/2);
    auto payload_len = ed->payloadlen / 2;
    for (int i = 0; i < payload_len; ++i) {
        sscanf((const char*)ed->payload + i * 2, "%02x", &payload[i]);
    }
    // 从payload中解析出uuid
//    for (int i = 0; i < UUID_LEN; ++i) {
//        sscanf(static_cast<const char *>(ed->payload) + i * 2, "%02x", &id[i]);
//        uuid += id[i];
//    }
    uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    if (m.find(uuid) == m.end()){
        m[uuid] = Graph::Graph(uuid,p);
    }
    auto str = decrypt_message(payload,payload_len,uuid);
    if (str.empty()){
        mosquitto_free(payload);
        return ERROR_DECRYPT;
    }
    if (m.find(str) == m.end()){
        error("%s:accident %s not found",util::get_timestamp().c_str(),str.c_str())
        mosquitto_free(payload);
        return ERROR_INTERNAL;
    }
    auto& g2 = m[str];
    g2.visualization("./accidents/accident_" + g2.get_owner() + "_" + util::get_timestamp().substr(1,8));
    warn("%s:%s accident %s",util::get_timestamp().c_str(),uuid.c_str(),str.c_str())
    return ERROR_SUCCESS;
}

static int decrypt_message_callback(int event, void *event_data, void *userdata){
    auto *ed = static_cast<mosquitto_evt_message *>(event_data);
    if (!strcmp(ed->topic,"/public")){
        return public_handler(ed);
    }else if (!strncmp(ed->topic,"/p2p/",5)){
        return p2p_handler(ed);
    }else if (!strcmp(ed->topic,"/checkpoint")){
        return checkpoint_handler(ed);
    }else if(!strcmp(ed->topic,"/accident")){
        return accident_handler(ed);
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
        error("%s:cant open log file",util::get_timestamp().c_str())
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
    p = new mongocxx::pool(mongocxx::uri("mongodb://localhost:27017"));
    return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count){
    delete p;
    fclose(log_);
//    mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, encrypt_message_callback, NULL);
    return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL);
}
