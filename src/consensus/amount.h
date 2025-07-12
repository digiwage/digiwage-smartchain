// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

#include <cstdint>
#include "amount.h" // <<< ADD THIS INCLUDE

// /** Amount in satoshis (Can be negative) */
// typedef int64_t CAmount; // <<< REMOVE or COMMENT OUT (defined in amount.h)

// /** The amount of satoshis in one BTC. */
// static constexpr CAmount COIN = 100000000; // <<< REMOVE or COMMENT OUT
// static constexpr CAmount CENT = 1000000; // <<< REMOVE or COMMENT OUT

// /** No amount larger than this (in satoshi) is valid.
//  * */
// static constexpr CAmount MAX_MONEY = 107822406 * COIN + 25 * (COIN / 100); // <<< REMOVE or COMMENT OUT
// inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); } // <<< REMOVE or COMMENT OUT

#endif // BITCOIN_CONSENSUS_AMOUNT_H