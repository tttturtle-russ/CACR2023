//
// Created by russ on 23-10-13.
//
#include "log.hpp"
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
mongocxx::pool *p = nullptr;
std::map<std::string,Graph::Graph> m;

std::string decrypt_message(uint8_t* payload,size_t payload_len,const std::string& uuid) {
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    uint8_t sm3_hmac_key_arr[SM3_HMAC_KEY_SIZE];
    uint8_t sm4_key_arr[SM4_KEY_SIZE];
    uint8_t sm4_iv_arr[SM4_BLOCK_SIZE];
    // 从数据库中读取pem私钥
    if (util::read_pem(p,database,uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        logger::error("read_pem failed\n");
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
        logger::error("decrypt_message_callback: mosquitto_malloc failed\n");
        return "";
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                        &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        logger::error("decrypt sig and msg failed\n");
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
        logger::error("sm2 verify failed\n");
        return "";
    }
    logger::info("sm2 verify success\n");
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    logger::info("message: %s\n",decrypted_sig_and_msg + offset);
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
    auto payload = (uint8_t *)ed->payload;
    auto payload_len = ed->payloadlen;
    // 从payload中解析出uuid
    std::string uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    // 从数据库中读取pem私钥
    if (util::read_pem(p,database,uuid,&sm2_key,sm3_hmac_key_arr) != EXIT_SUCCESS){
        logger::error("read_pem failed\n");
        return ERROR_INTERNAL;
    }
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
        logger::error("decrypt_message_callback: mosquitto_malloc failed\n");
        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg

    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                              &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        logger::error("decrypt sig and msg failed\n");
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
        logger::error("sm2 verify failed\n");
        return ERROR_VERIFY;
    }
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    logger::info("message:%s\n",str.c_str());
    mosquitto_free(decrypted_sig_and_msg);
    if (!util::insert_public_message(p,database,uuid,str)){
        logger::error("insert_public_message failed\n");
        return ERROR_INTERNAL;
    }
    return ERROR_SUCCESS;
}

int p2p_handler(struct mosquitto_evt_message *ed){
    SM2_KEY sm2_key;
    SM4_KEY sm4_key;
    auto *sm3_hmac_key_arr = (uint8_t *) malloc(SM3_HMAC_KEY_SIZE * sizeof(uint8_t));
    if (!sm3_hmac_key_arr){
        logger::error("malloc failed\n");
        return ERROR_INTERNAL;
    }
    auto *sm4_key_arr = (uint8_t *) malloc(SM4_KEY_SIZE * sizeof(uint8_t));
    if (!sm4_key_arr) {
        free(sm3_hmac_key_arr);
        logger::error("malloc failed\n");
        return ERROR_INTERNAL;
    }
    auto *sm4_iv_arr = (uint8_t*) malloc(SM4_BLOCK_SIZE * sizeof(uint8_t));
    if (!sm4_iv_arr) {
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        logger::error("malloc failed\n");
        return ERROR_INTERNAL;
    }
    std::string sender_uuid;
    std::string receiver_uuid = ed->topic + 5;
    auto payload = (uint8_t *) ed->payload;
    auto payload_len = ed->payloadlen;
    // 从payload中解析出uuid
    sender_uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    logger::info("sender:%s\n",sender_uuid.c_str());
    logger::info("receiver:%s\n",receiver_uuid.c_str());
    // 从数据库中读取pem私钥
    if (util::read_pem(p,database,receiver_uuid, &sm2_key, sm3_hmac_key_arr) != EXIT_SUCCESS){
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        logger::error("read_pem failed\n");
        return ERROR_INTERNAL;
    }
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
        logger::error("read_pem failed\n");
        return ERROR_INTERNAL;
    }
    // decrypted_sig_and_msg 是sm4加密后的hmac和msg
    auto decrypted_sig_and_msg = (uint8_t *)mosquitto_malloc(1024 * sizeof (uint8_t));
    size_t decrypted_sig_and_msg_len;
    if (!decrypted_sig_and_msg) {
        free(sm3_hmac_key_arr);
        free(sm4_key_arr);
        free(sm4_iv_arr);
        logger::error("decrypt_message_callback: mosquitto_malloc failed\n");
        return ERROR_INTERNAL;
    }
    sm4_set_decrypt_key(&sm4_key,sm4_key_arr);
    // 解密sig和msg
    ret = util::decrypt_sig_and_msg(payload + offset + UUID_LEN,payload_len - offset - UUID_LEN,
                              &sm4_key,sm4_iv_arr,decrypted_sig_and_msg,&decrypted_sig_and_msg_len);
    if (ret != ERROR_SUCCESS){
        logger::error("decrypt sig and msg failed\n");
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
        logger::error("sm2 verify failed\n");
        return ERROR_VERIFY;
    }
    decrypted_sig_and_msg[decrypted_sig_and_msg_len] = '\0';
    std::string str = reinterpret_cast<const char *>(decrypted_sig_and_msg + offset);
    logger::info("message:%s\n",str.c_str());
    mosquitto_free(decrypted_sig_and_msg);
    free(sm3_hmac_key_arr);
    free(sm4_key_arr);
    free(sm4_iv_arr);
    if (!util::insert_p2p_message(p,database,sender_uuid,receiver_uuid,str)){
        logger::error("insert_p2p_message failed\n");
        return ERROR_INTERNAL;
    }
    return ERROR_SUCCESS;
}

int checkpoint_handler(struct mosquitto_evt_message *ed){
    std::string uuid;
    auto payload = (uint8_t *) ed->payload;
    auto payload_len = ed->payloadlen;
    uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    if (m.find(uuid) == m.end()){
        m[uuid] = Graph::Graph(uuid,p);
    }
    auto& g = m[uuid];
    auto str = decrypt_message(payload,payload_len,uuid);
    if (str.empty()){
        logger::error("failed to decrypt\n");
        return ERROR_DECRYPT;
    }
    auto new_vertex = g.add_vertex(str);
    if (g.size() > 1){
        g.add_edge(g.size() - 2,new_vertex);
    }
    logger::info("%s checkpoint at %s\n",uuid.c_str(),str.c_str());
    auto gr = g.get_graph();
    BGL_FORALL_EDGES(e,gr,Graph::graph){
        auto source = boost::source(e,gr);
        auto target = boost::target(e,gr);
        logger::info("%s -> %s\n",gr[source].name.c_str(),gr[target].name.c_str());
    }
    return ERROR_SUCCESS;
}

static int accident_handler(mosquitto_evt_message *ed) {
    std::string uuid;
    auto payload = (uint8_t *)ed->payload;
    auto payload_len = ed->payloadlen;
    uuid = util::get_uuid(static_cast<const char*>(ed->payload));
    if (m.find(uuid) == m.end()){
        m[uuid] = Graph::Graph(uuid,p);
    }
    auto str = decrypt_message(payload,payload_len,uuid);
    if (str.empty()){
        logger::error("failed to decrypt\n");
        return ERROR_DECRYPT;
    }
    if (m.find(str) == m.end()){
        logger::error("accident %s not found\n",str.c_str());
        return ERROR_INTERNAL;
    }
    auto& g2 = m[str];
    if (g2.visualization("./accidents/accident_" + g2.get_owner() + "_" + util::get_timestamp().substr(1,8)) != 0) {
        logger::error("failed to export picture\n");
        return ERROR_INTERNAL;
    }
    logger::warn("%s accident at %s",uuid.c_str(),str.c_str());
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
    logger::info("Starting plugin mosquitto_message_encrypt\n");
    if (fileno(stderr) == fileno(stdout)) {
        std::cerr << "stderr and stdout are associated." << std::endl;
    }else {
        int originalStderr = dup(fileno(stderr));
        // 关闭 stderr
    //    freopen("/dev/null", "w", stderr);
        logger::warn("Disable stderr to avoid insignificant info.To enable stderr,set 'stderr true' in config\n");
    }
    mosq_pid = identifier;
    std::string uri_str("mongodb://");
    bool read_addr = false;
    bool read_port = false;
    bool read_connopts = false;
    bool read_dbname = false;
    std::string addr;
    std::string port;
    std::string connopts;
    for (int i = 0; i < opt_count; ++i) {
        if (!strcmp(opts[i].key,"db_addr")){
            logger::info("Reading db address...\n");
            addr = opts[i].value;
            read_addr = true;
        }else if (!strcmp(opts[i].key,"db_port")){
            logger::info("Reading db port...\n");
            port = opts[i].value;
            read_port = true;
        }else if (!strcmp(opts[i].key,"db_connopts")){
            logger::info("Reading db connopts...\n");
            connopts = opts[i].value;
            read_connopts = true;
        }else if (!strcmp(opts[i].key,"db_name")){
            logger::info("Reading db name...\n");
            database = opts[i].value;
            read_dbname = true;
        }
    }
    if (!read_addr){
        logger::warn("db_addr not found.use 127.0.0.1 as default\n");
        addr = "127.0.0.1";
    }
    if (!read_port){
        logger::warn("db_port not found.use 27017 as default\n");
        port = "27017";
    }
    if (!read_dbname) {
        logger::warn("db_name not found.use 'mqGate' as default\n");
        database = "mqGate";
    }
    uri_str += addr + ":" + port + "/";
    if (!read_connopts){
        logger::warn("db_connopts not found.use default connopts\n");
        connopts = "";
    }else {
        uri_str += "?" + connopts;
    }
    mongocxx::instance instance{};
    p = new mongocxx::pool(mongocxx::uri(uri_str));
    logger::info("mosquitto_message_encrypt plugin initialized successfully!\n");
    return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, nullptr, nullptr);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count){
    delete p;
    return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE, decrypt_message_callback, NULL);
}
