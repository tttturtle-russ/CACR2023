/*
 * @file Benchmark_Decrypt.cpp
 * @brief 测试解密函数
 * @compile g++ -Wall -o Benchmark_Public_Decrypt Benchmark_Decrypt.cpp -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/bsoncxx/v_noabi -lmongocxx -lbsoncxx -lgmssl -lbenchmark
 * @compile g++ -Wall -o Benchmark_P2P_Decrypt Benchmark_Decrypt.cpp -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/bsoncxx/v_noabi -lmongocxx -lbsoncxx -lgmssl -lbenchmark
 */
#include <benchmark/benchmark.h>
#include <vector>
#include <string>
#include "Decrypt.hpp"

mongocxx::instance inst{};

std::vector<std::tuple<std::string,std::string,size_t ,size_t>> p2p_cases = {
        ...
};

std::vector<std::tuple<std::string,std::string,size_t ,size_t>> public_cases = {
        ...
};

void p2p_handler_benchmark(benchmark::State& state) {
    for (auto _ : state) {
        for (auto & p2p_case : p2p_cases) {
            benchmark::DoNotOptimize(p2p_handler(std::get<0>(p2p_case),std::get<1>(p2p_case)));
        }
    }
}

void public_handler_benchmark(benchmark::State& state) {
    for (auto _ : state) {
        for (auto & public_case : public_cases) {
            benchmark::DoNotOptimize(public_handler(std::get<0>(public_case)));
        }
    }
}

BENCHMARK(p2p_handler_benchmark)->Range(1,1<<10);

BENCHMARK(public_handler_benchmark)->Range(1,1<<10);

BENCHMARK_MAIN();