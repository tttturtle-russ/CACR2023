/*
 * @file Test_Database.cpp
 * @brief 测试数据库函数
 * @compile g++ -Wall -o Test_Database Test_Database.cpp -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/bsoncxx/v_noabi -lmongocxx -lbsoncxx -lgmssl -lgtest
 */

#include <gtest/gtest.h>
#include "Decrypt.hpp"

std::vector<std::tuple<std::string,std::string>> testcases;

TEST(InsertTestCase,InsertTest){
    for (int i = 0; i < 10000; ++i) {
        auto sender = get_uuid();
        auto receiver = get_uuid();
        auto message = generateRandomString(i+1);
        testcases.emplace_back(sender,receiver);
        EXPECT_TRUE(util::insert_p2p_message(sender,receiver,message));
        EXPECT_TRUE(util::insert_public_message(sender,message));
    }
}

TEST(SelectTestCase,SelectTest){
    for (int i = 0; i < 10000; ++i) {
        EXPECT_NE(util::select_public_message(std::get<0>(testcases[i])),"");
        EXPECT_NE(util::select_p2p_message(std::get<0>(testcases[i]),std::get<1>(testcases[i])),"");
    }
}

int main(int argc, char** argv) {
    mongocxx::instance inst{};
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}