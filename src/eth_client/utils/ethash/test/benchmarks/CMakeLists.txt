# ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
# Copyright 2018-2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

hunter_add_package(benchmark)
find_package(benchmark CONFIG REQUIRED)

add_executable(ethash-bench
    ethash_benchmarks.cpp
    keccak_benchmarks.cpp
    keccak_utils.hpp
    keccak_utils.cpp
    global_context_benchmarks.cpp
    threadsync_benchmarks.cpp
    threadsync_utils.hpp
    threadsync_utils.cpp)
target_link_libraries(ethash-bench PRIVATE ethash::global-context benchmark::benchmark)
target_include_directories(ethash-bench PRIVATE ${ETHASH_PRIVATE_INCLUDE_DIR})
set_target_properties(ethash-bench PROPERTIES RUNTIME_OUTPUT_DIRECTORY ..)
