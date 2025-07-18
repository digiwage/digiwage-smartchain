// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "../unittests/helpers.hpp"
#include <benchmark/benchmark.h>
#include <ethash/ethash-internal.hpp>
#include <ethash/global_context.hpp>
#include <ethash/keccak.hpp>
#include <ethash/primes.h>


static void calculate_light_cache_num_items(benchmark::State& state)
{
    const auto epoch_number = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        auto answer = ethash::calculate_light_cache_num_items(epoch_number);
        benchmark::DoNotOptimize(&answer);
    }
}
BENCHMARK(calculate_light_cache_num_items)
    ->Arg(ethash::max_epoch_number - 1)
    ->Arg(ethash::max_epoch_number);

static void calculate_full_dataset_num_items(benchmark::State& state)
{
    const auto epoch_number = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        auto answer = ethash::calculate_full_dataset_num_items(epoch_number);
        benchmark::DoNotOptimize(&answer);
    }
}
BENCHMARK(calculate_full_dataset_num_items)
    ->Arg(ethash::max_epoch_number - 1)
    ->Arg(ethash::max_epoch_number);


static void seed(benchmark::State& state)
{
    const int epoch_number = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        auto seed = ethash::calculate_epoch_seed(epoch_number);
        benchmark::DoNotOptimize(seed.bytes);
    }
}
BENCHMARK(seed)->Arg(1)->Arg(10)->Arg(100)->Arg(1000)->Arg(10000);


static void create_context(benchmark::State& state)
{
    const int epoch_number = static_cast<int>(state.range(0));

    for (auto _ : state)
    {
        ethash::create_epoch_context(epoch_number);
    }
}
BENCHMARK(create_context)->Arg(1)->Arg(333)->Unit(benchmark::kMillisecond);


static void ethash_calculate_dataset_item_1024(benchmark::State& state)
{
    const auto& ctx = get_ethash_epoch_context_0();

    for (auto _ : state)
    {
        auto item = ethash::calculate_dataset_item_1024(ctx, 1234);
        benchmark::DoNotOptimize(item.bytes);
    }
}
BENCHMARK(ethash_calculate_dataset_item_1024);


static void ethash_hash(benchmark::State& state)
{
    // Get block number in millions.
    const int block_number = static_cast<int>(state.range(0)) * 1000000;
    uint64_t nonce = 1;

    const auto& ctx = ethash::get_global_epoch_context(ethash::get_epoch_number(block_number));

    for (auto _ : state)
        ethash::hash(ctx, {}, nonce++);
}
BENCHMARK(ethash_hash)->Unit(benchmark::kMicrosecond)->Arg(0)->Arg(10);


static void verify(benchmark::State& state)
{
    const int block_number = 5000000;
    const ethash::hash256 header_hash =
        to_hash256("bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a");
    const ethash::hash256 mix_hash =
        to_hash256("94cd4e844619ee20989578276a0a9046877d569d37ba076bf2e8e34f76189dea");
    const uint64_t nonce = 0x4617a20003ba3f25;
    const ethash::hash256 boundary =
        to_hash256("0000000000001a5c000000000000000000000000000000000000000000000000");

    static const auto ctx = ethash::create_epoch_context(ethash::get_epoch_number(block_number));

    for (auto _ : state)
        ethash::verify_against_boundary(*ctx, header_hash, mix_hash, nonce, boundary);
}
BENCHMARK(verify);


static void verify_mt(benchmark::State& state)
{
    const int block_number = 5000000;
    const ethash::hash256 header_hash =
        to_hash256("bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a");
    const ethash::hash256 mix_hash =
        to_hash256("94cd4e844619ee20989578276a0a9046877d569d37ba076bf2e8e34f76189dea");
    const uint64_t nonce = 0x4617a20003ba3f25;
    const ethash::hash256 boundary =
        to_hash256("0000000000001a5c000000000000000000000000000000000000000000000000");

    static const auto ctx = ethash::create_epoch_context(ethash::get_epoch_number(block_number));

    for (auto _ : state)
        ethash::verify_against_boundary(*ctx, header_hash, mix_hash, nonce, boundary);
}
BENCHMARK(verify_mt)->Threads(1)->Threads(2)->Threads(4)->Threads(8);


static void verify_managed(benchmark::State& state)
{
    const int block_number = 5000000;
    const ethash::hash256 header_hash =
        to_hash256("bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a");
    const ethash::hash256 mix_hash =
        to_hash256("94cd4e844619ee20989578276a0a9046877d569d37ba076bf2e8e34f76189dea");
    const uint64_t nonce = 0x4617a20003ba3f25;
    const ethash::hash256 boundary =
        to_hash256("0000000000001a5c000000000000000000000000000000000000000000000000");

    const int epoch_number = ethash::get_epoch_number(block_number);

    // This should create the light cache.
    ethash::get_global_epoch_context(epoch_number);

    for (auto _ : state)
    {
        const auto& context = ethash::get_global_epoch_context(epoch_number);
        ethash::verify_against_boundary(context, header_hash, mix_hash, nonce, boundary);
    }
}
BENCHMARK(verify_managed)->Threads(1)->Threads(2)->Threads(4)->Threads(8);


BENCHMARK_MAIN();
