/*
 * @file Benchmark_Database.cpp
 * @brief 测试数据库函数
 * @compile g++ -Wall -o Benchmark_Database Benchmark_Database.cpp -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/bsoncxx/v_noabi -lmongocxx -lbsoncxx -lgmssl -lbenchmark
 */
#include "Decrypt.hpp"
#include <benchmark/benchmark.h>

mongocxx::instance ins{};

static void insert_benchmark(benchmark::State& state) {
    for (auto _ : state) {
        auto sender = get_uuid();
        auto receiver = get_uuid();
        auto message = generateRandomString(100);
        util::insert_p2p_message(sender,receiver,message);
        util::insert_public_message(sender,message);
    }
}

static void select_benchmark(benchmark::State& state) {
    for (auto _ : state) {
        auto sender = get_uuid();
        auto receiver = get_uuid();
        auto message = generateRandomString(100);
        util::select_p2p_message(sender,receiver);
        util::select_public_message(sender);
    }
}

BENCHMARK(insert_benchmark)->Range(1,1<<10);
BENCHMARK(select_benchmark)->Range(1,1<<10);

BENCHMARK_MAIN();