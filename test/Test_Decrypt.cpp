/*
 * @file	Test_Decypt.cpp
 * @brief	测试解密函数
 * @compile g++ -Wall -o Test_Decrypt Test_Decrypt.cpp -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/bsoncxx/v_noabi -lmongocxx -lbsoncxx -lgmssl -lgtest
 */

#include "Decrypt.hpp"
#include "util.hpp"
#include <gtest/gtest.h>

TEST(P2PDecryptTestCase,P2PDecryptTest){
    /*
     * 生成随机字符串，长度从1到1000，每个长度生成10个随机字符串
     * 然后检测解密后的字符串是否与原字符串相等
     */
    for (int i = 1; i < 1000; ++i) {
        for (int j = 0; j < 10; ++j) {
            auto msg = generateRandomString(i);
            auto receiver = get_uuid();
            EXPECT_EQ(msg,p2p_handler(generate_p2p(msg.c_str(),get_uuid().c_str(),receiver.c_str()),
                                      receiver));
        }
    }
}

TEST(PublicDecryptTestCase,PublicDecryptTest) {
    /*
     * 生成随机字符串，长度从1到1000，每个长度生成10个随机字符串
     * 然后检测解密后的字符串是否与原字符串相等
     */
    for (int i = 1; i < 1000; ++i) {
        for (int j = 0; j < 10; ++j) {
            auto msg = generateRandomString(i);
            EXPECT_EQ(msg,public_handler(generate_public(msg.c_str(),get_uuid().c_str())));
        }
    }
}

int main(int argc, char** argv) {
    mongocxx::instance ins{};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}