// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
///
/// API design decisions:
///
/// 1. Signed integer type is used whenever the size of the type is not
///    restricted by the Ethash specification.
///    See http://www.aristeia.com/Papers/C++ReportColumns/sep95.pdf.
///    See https://stackoverflow.com/questions/10168079/why-is-size-t-unsigned/.
///    See https://github.com/Microsoft/GSL/issues/171.

#pragma once

#include <ethash/ethash.h>
#include <ethash/hash_types.hpp>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <system_error>

namespace std
{
/// Template specialization of std::is_error_code_enum for ethash_errc.
/// This enabled implicit conversions from evmc::hex_errc to std::error_code.
template <>
struct is_error_code_enum<ethash_errc> : true_type
{
};
}  // namespace std


namespace ethash
{
constexpr auto revision = ETHASH_REVISION;

constexpr int epoch_length = ETHASH_EPOCH_LENGTH;
constexpr int light_cache_item_size = ETHASH_LIGHT_CACHE_ITEM_SIZE;
constexpr int full_dataset_item_size = ETHASH_FULL_DATASET_ITEM_SIZE;
constexpr int num_dataset_accesses = ETHASH_NUM_DATASET_ACCESSES;

constexpr int max_epoch_number = ETHASH_MAX_EPOCH_NUMBER;

using epoch_context = ethash_epoch_context;
using epoch_context_full = ethash_epoch_context_full;

using result = ethash_result;

/// Constructs a 256-bit hash from an array of bytes.
///
/// @param bytes  A pointer to array of at least 32 bytes.
/// @return       The constructed hash.
inline hash256 hash256_from_bytes(const uint8_t bytes[32]) noexcept
{
    hash256 h;
    std::memcpy(&h, bytes, sizeof(h));
    return h;
}

struct search_result
{
    bool solution_found = false;
    uint64_t nonce = 0;
    hash256 final_hash = {};
    hash256 mix_hash = {};

    search_result() noexcept = default;

    search_result(result res, uint64_t n) noexcept
      : solution_found(true), nonce(n), final_hash(res.final_hash), mix_hash(res.mix_hash)
    {}
};


/// Alias for ethash_calculate_light_cache_num_items().
static constexpr auto calculate_light_cache_num_items = ethash_calculate_light_cache_num_items;

/// Alias for ethash_calculate_full_dataset_num_items().
static constexpr auto calculate_full_dataset_num_items = ethash_calculate_full_dataset_num_items;

/// Alias for ethash_calculate_epoch_seed().
static constexpr auto calculate_epoch_seed = ethash_calculate_epoch_seed;


/// Calculates the epoch number out of the block number.
inline constexpr int get_epoch_number(int block_number) noexcept
{
    return block_number / epoch_length;
}

/**
 * Coverts the number of items of a light cache to size in bytes.
 *
 * @param num_items  The number of items in the light cache.
 * @return           The size of the light cache in bytes.
 */
inline constexpr size_t get_light_cache_size(int num_items) noexcept
{
    return static_cast<size_t>(num_items) * light_cache_item_size;
}

/**
 * Coverts the number of items of a full dataset to size in bytes.
 *
 * @param num_items  The number of items in the full dataset.
 * @return           The size of the full dataset in bytes.
 */
inline constexpr uint64_t get_full_dataset_size(int num_items) noexcept
{
    return static_cast<uint64_t>(num_items) * full_dataset_item_size;
}

/// Owned unique pointer to an epoch context.
using epoch_context_ptr = std::unique_ptr<epoch_context, decltype(&ethash_destroy_epoch_context)>;

using epoch_context_full_ptr =
    std::unique_ptr<epoch_context_full, decltype(&ethash_destroy_epoch_context_full)>;

/// Creates Ethash epoch context.
///
/// This is a wrapper for ethash_create_epoch_number C function that returns
/// the context as a smart pointer which handles the destruction of the context.
inline epoch_context_ptr create_epoch_context(int epoch_number) noexcept
{
    return {ethash_create_epoch_context(epoch_number), ethash_destroy_epoch_context};
}

inline epoch_context_full_ptr create_epoch_context_full(int epoch_number) noexcept
{
    return {ethash_create_epoch_context_full(epoch_number), ethash_destroy_epoch_context_full};
}


inline result hash(
    const epoch_context& context, const hash256& header_hash, uint64_t nonce) noexcept
{
    return ethash_hash(&context, &header_hash, nonce);
}

result hash(const epoch_context_full& context, const hash256& header_hash, uint64_t nonce) noexcept;

inline std::error_code verify_final_hash_against_difficulty(const hash256& header_hash,
    const hash256& mix_hash, uint64_t nonce, const hash256& difficulty) noexcept
{
    return ethash_verify_final_hash_against_difficulty(&header_hash, &mix_hash, nonce, &difficulty);
}

inline std::error_code verify_against_difficulty(const epoch_context& context,
    const hash256& header_hash, const hash256& mix_hash, uint64_t nonce,
    const hash256& difficulty) noexcept
{
    return ethash_verify_against_difficulty(&context, &header_hash, &mix_hash, nonce, &difficulty);
}

inline std::error_code verify_against_boundary(const epoch_context& context,
    const hash256& header_hash, const hash256& mix_hash, uint64_t nonce,
    const hash256& boundary) noexcept
{
    return ethash_verify_against_boundary(&context, &header_hash, &mix_hash, nonce, &boundary);
}

[[deprecated("use verify_against_boundary()")]] inline std::error_code verify(
    const epoch_context& context, const hash256& header_hash, const hash256& mix_hash,
    uint64_t nonce, const hash256& boundary) noexcept
{
    return ethash_verify_against_boundary(&context, &header_hash, &mix_hash, nonce, &boundary);
}

search_result search_light(const epoch_context& context, const hash256& header_hash,
    const hash256& boundary, uint64_t start_nonce, size_t iterations) noexcept;

search_result search(const epoch_context_full& context, const hash256& header_hash,
    const hash256& boundary, uint64_t start_nonce, size_t iterations) noexcept;


/// Tries to find the epoch number matching the given seed hash.
///
/// Mining pool protocols (many variants of stratum and "getwork") send out
/// seed hash instead of epoch number to workers. This function tries to recover
/// the epoch number from this seed hash.
///
/// @param seed  Ethash seed hash.
/// @return      The epoch number or -1 if not found.
int find_epoch_number(const hash256& seed) noexcept;


/// Obtains a reference to the static error category object for ethash errors.
inline const std::error_category& ethash_category() noexcept
{
    struct ethash_category_impl : std::error_category
    {
        const char* name() const noexcept final { return "ethash"; }

        std::string message(int ev) const final
        {
            switch (ev)
            {
            case ETHASH_SUCCESS:
                return "";
            case ETHASH_INVALID_FINAL_HASH:
                return "invalid final hash";
            case ETHASH_INVALID_MIX_HASH:
                return "invalid mix hash";
            default:
                return "unknown error";
            }
        }
    };

    static ethash_category_impl category_instance;
    return category_instance;
}
}  // namespace ethash


/// Creates error_code object out of an Ethash error code value.
/// This is used by std::error_code to implement implicit conversion ethash_errc -> std::error_code,
/// therefore the definition is in the global namespace to match the definition of ethash_errc.
inline std::error_code make_error_code(ethash_errc errc) noexcept
{
    return {errc, ethash::ethash_category()};
}
