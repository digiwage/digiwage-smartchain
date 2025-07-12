// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Copyright (c) 2017-2021 The Qtum Core developers // Added Qtum copyright for EVM parts
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <qtum/tokenstr.h>
#include "base58.h"
#include "checkpoints.h"
#include "clientversion.h"
#include "core_io.h" // Needed for ScriptPubKeyToJSON, TxToUniv (indirectly via TxToJSON?)
#include "kernel.h"
#include "main.h" // Includes validation.h for ChainstateActive, CBlockIndex, etc.
#include "rpc/server.h"
#include "sync.h"
#include "txdb.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h" // Needed for pwalletMain check, etc. - Include if needed, maybe not strictly for blockchain RPCs
#include "zpiv/zpivmodule.h" // If DigiWage uses zPIV
#include "chainparams.h" // Needed for Params()
#include "script/standard.h" // Needed for ScriptPubKeyToJSON
#include "script/script.h"      // For ScriptToAsmStr

// === QTUM CORE COMPONENTS INCLUDES ===
// Ensure these files exist and are correctly ported in your DigiWage project structure
#include "qtum/qtumstate.h"         // Should define GlobalState(), pstorageresult, fLogEvents, LogEntry etc.
#include "qtum/storageresults.h"    // Should define TransactionReceiptInfo, LogEntry if not in qtumstate.h
#include "rpc/contract_util.h"   // Should define CallToken, assignJSON etc.
// === END QTUM INCLUDES ===
#include "rpc/protocol.h" // <<< Make sure this is included for JSONRPCError
#include "utilstrencodings.h" // Needed for HexStr
#include "string.h" // Needed for HexStr

#include <stdint.h>
#include <fstream>
#include <iostream>
#include <univalue.h>
#include <mutex>
#include <numeric>
#include <condition_variable>
#include <chrono> // Needed for wait_for
#include <set> // Needed for std::set
#include <libdevcore/Common.h>
#include <libdevcore/CommonData.h>
#include <algorithm>
#include <unordered_map>
#include <stdint.h>
#include <vector> // Make sure vector is included
#include <ostream> // Make sure ostream is included
#include "utilstrencodings.h" // Make sure HexStr is available
inline std::ostream& operator<<(std::ostream& os, const std::vector<unsigned char>& vec) { os << HexStr(vec); return os; }
#include <condition_variable>
#include <memory>
#include <mutex>
// Forward Declarations needed by this file (Remove redundant/conflicting ones)
extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry); // Keep if defined elsewhere (e.g., rpc/misc.cpp)
extern bool GetStakeKernelHash(uint256& hashProofOfStake, const CBlock& block, const CBlockIndex* pindexPrev); // Keep if defined elsewhere (e.g., kernel.cpp)

// Forward declarations for Qtum RPC helpers (Ensure these match definitions in contract_util.cpp)
extern UniValue CallToContract(const UniValue& params, ChainstateManager& chainman); // Keep - **NOTE:** Needs adaptation if DigiWage doesn't use ChainstateManager
extern void transactionReceiptInfoToJSON(const TransactionReceiptInfo& txOptionalReceipt, UniValue& object); // Keep
extern void assignJSON(UniValue &obj, const TransactionReceiptInfo &res); // Keep overload for Receipt
extern void assignJSON(UniValue &obj, const dev::eth::LogEntry &log, bool topicsInsteadOfData); // Specify namespace if needed

extern UniValue getblockindexstats(const UniValue& params, bool fHelp);

#ifndef DEFAULT_GAS_LIMIT_OP_CALL // Define a fallback if not in headers
#define DEFAULT_GAS_LIMIT_OP_CALL 2500000
#endif


// --- Global state for waitfor* RPCs ---
struct CUpdatedBlock
{
    uint256 hash;
    int height;
};
static std::mutex cs_blockchange;
static std::condition_variable cond_blockchange;
static CUpdatedBlock latestblock;

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL) {
        if (chainActive.Tip() == NULL) // Use chainActive directly
            return 1.0;
        else
            blockindex = chainActive.Tip(); // Use chainActive directly
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}




UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex)) // Use chainActive directly
        confirmations = chainActive.Height() - blockindex->nHeight + 1; // Use chainActive directly
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", blockindex->nVersion);
    result.pushKV("merkleroot", blockindex->hashMerkleRoot.GetHex());
    result.pushKV("time", (int64_t)blockindex->nTime);
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("nonce", (uint64_t)blockindex->nNonce);
    result.pushKV("bits", strprintf("%08x", blockindex->nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());
    result.pushKV("acc_checkpoint", blockindex->nAccumulatorCheckpoint.GetHex()); // Assuming DigiWage kept this

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    CBlockIndex *pnext = chainActive.Next(blockindex); // Use chainActive directly
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", block.GetHash().GetHex()); // Use block.GetHash()
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex)) // Use chainActive directly
        confirmations = chainActive.Height() - blockindex->nHeight + 1; // Use chainActive directly
    result.pushKV("confirmations", confirmations);
    result.pushKV("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION));
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", block.nVersion);
    result.pushKV("merkleroot", block.hashMerkleRoot.GetHex());
    result.pushKV("acc_checkpoint", block.nAccumulatorCheckpoint.GetHex()); // Assuming DigiWage kept this
    UniValue txs(UniValue::VARR);
    for (const CTransaction& tx : block.vtx) {
        if (txDetails) {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, blockindex->GetBlockHash(), objTx); // Pass actual block hash
            txs.push_back(objTx);
        } else
            txs.push_back(tx.GetHash().GetHex());
    }
    result.pushKV("tx", txs);
    result.pushKV("time", block.GetBlockTime());
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("nonce", (uint64_t)block.nNonce);
    result.pushKV("bits", strprintf("%08x", block.nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    CBlockIndex* pnext = chainActive.Next(blockindex); // Use chainActive directly
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());

    result.pushKV("moneysupply",ValueFromAmount(blockindex->nMoneySupply)); // Assuming DigiWage kept nMoneySupply

    // Assuming DigiWage uses libzerocoin and kept mapZerocoinSupply
    UniValue zwageObj(UniValue::VOBJ);
    if(!blockindex->mapZerocoinSupply.empty()) { // Check if map is populated
        for (auto denom : libzerocoin::zerocoinDenomList) {
             if (blockindex->mapZerocoinSupply.count(denom)) { // Check if denom exists
                 // Original formula looked wrong (denom*COIN), should just be the count * value
                 // Assuming mapZerocoinSupply stores COUNT of coins, not total value
                 CAmount denom_value = libzerocoin::ZerocoinDenominationToAmount(denom);
                 zwageObj.pushKV(std::to_string(denom), ValueFromAmount(blockindex->mapZerocoinSupply.at(denom) * denom_value));
             } else {
                 zwageObj.pushKV(std::to_string(denom), ValueFromAmount(0)); // Show 0 if denom not present
             }
        }
        zwageObj.pushKV("total", ValueFromAmount(blockindex->GetZerocoinSupply()));
    } else {
        // Provide empty/zero values if map is empty
        for (auto denom : libzerocoin::zerocoinDenomList) {
            zwageObj.pushKV(std::to_string(denom), ValueFromAmount(0));
        }
        zwageObj.pushKV("total", ValueFromAmount(0));
    }
    result.pushKV("zerocoinsupply", zwageObj);

    // Coin stake data
    if (block.IsProofOfStake()) {
        // Ensure GetStakeModifierV1/V2 are available in DigiWage's CBlockIndex
        std::string stakeModifier = "N/A"; // Default if methods don't exist
        #if defined(QTUM_DEBUG) // Example conditional compilation if methods might not exist
        // If needed, check if these methods exist before calling
        if (Params().GetConsensus().IsStakeModifierV2(blockindex->nHeight)) {
             if(blockindex->GetStakeModifierV2() != uint256()) // Check if V2 is set
                stakeModifier = blockindex->GetStakeModifierV2().GetHex();
             else // Fallback or indicate unset V2
                stakeModifier = strprintf("V2 (unset at height %d)", blockindex->nHeight);
        } else {
            stakeModifier = strprintf("%016x", blockindex->GetStakeModifierV1());
        }
        #else // Simplified version assuming methods exist
         stakeModifier = (Params().GetConsensus().IsStakeModifierV2(blockindex->nHeight) ?
                                     strprintf("%016x", blockindex->vStakeModifier) : // Access member directly if GetStakeModifierV2 doesn't exist
                                     strprintf("%016x", blockindex->vStakeModifier)); // Access member directly if GetStakeModifierV1 doesn't exist
        #endif

        result.pushKV("stakeModifier", stakeModifier);

        // Proof of stake hash
        uint256 hashProofOfStakeRet;
        if (!GetStakeKernelHash(hashProofOfStakeRet, block, blockindex->pprev)) {
             // Log error instead of throwing, return "N/A"
             LogPrintf("ERROR: Cannot get proof of stake hash for block %s\n", block.GetHash().GetHex());
             result.pushKV("hashProofOfStake", "N/A");
        } else {
             result.pushKV("hashProofOfStake", hashProofOfStakeRet.GetHex());
        }
    }

    return result;
}

UniValue getblockcount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockcount", "") + HelpExampleRpc("getblockcount", ""));

    LOCK(cs_main); // cs_main protects chainActive
    return chainActive.Height();
}

UniValue getbestblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"
            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"
            "\nExamples\n" +
            HelpExampleCli("getbestblockhash", "") + HelpExampleRpc("getbestblockhash", ""));

    LOCK(cs_main); // cs_main protects chainActive
    return chainActive.Tip()->GetBlockHash().GetHex();
}

void RPCNotifyBlockChange(bool fInitialDownload, const CBlockIndex* pindex)
{
    if(pindex) {
        std::lock_guard<std::mutex> lock(cs_blockchange); // Use std::lock_guard
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

UniValue waitfornewblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "waitfornewblock ( timeout )\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
        );
    int timeout = 0;
    if (params.size() > 0)
        timeout = params[0].getInt<int>();
    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange); // Use std::unique_lock for condition variable
        block = latestblock;
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        else
            cond_blockchange.wait(lock, [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
}

UniValue waitforblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "waitforblock blockhash ( timeout )\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. \"blockhash\" (required, std::string) Block hash to wait for.\n"
            "2. timeout       (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
        );
    int timeout = 0;

    uint256 hash = uint256S(params[0].get_str());

    if (params.size() > 1)
        timeout = params[1].getInt<int>();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange); // Use std::unique_lock
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&hash]{return latestblock.hash == hash || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&hash]{return latestblock.hash == hash || !IsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
}

UniValue waitforblockheight(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "waitforblockheight height ( timeout )\n"
            "\nWaits for (at least) block height and returns the height and hash\n"
            "of the current tip.\n"
            "\nReturns the current block on timeout or exit.\n"
            "\nArguments:\n"
            "1. height  (required, int) Block height to wait for (int)\n"
            "2. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("waitforblockheight", "\"100\", 1000")
            + HelpExampleRpc("waitforblockheight", "\"100\", 1000")
        );
    int timeout = 0;

   int height = params[0].getInt<int>();

    if (params.size() > 1)
        timeout = params[1].getInt<int>();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange); // Use std::unique_lock
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&height]{return latestblock.height >= height || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&height]{return latestblock.height >= height || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", block.hash.GetHex());
    ret.pushKV("height", block.height);
    return ret;
}

UniValue getdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n" +
            HelpExampleCli("getdifficulty", "") + HelpExampleRpc("getdifficulty", ""));

    LOCK(cs_main); // cs_main protects chainActive needed by GetDifficulty() default arg
    return GetDifficulty();
}


UniValue mempoolToJSON(bool fVerbose = false)
{
    if (fVerbose) {
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        // Use const auto& for range loop
        for (const auto& entryPair : mempool.mapTx) { // Use different name to avoid conflict
            const uint256& hash = entryPair.first;
            const CTxMemPoolEntry& e = entryPair.second;
            UniValue info(UniValue::VOBJ);
            info.pushKV("size", (int)e.GetTxSize());
            info.pushKV("fee", ValueFromAmount(e.GetFee()));
            info.pushKV("time", e.GetTime());
            info.pushKV("height", (int)e.GetHeight());
            int currentHeight = 0; // Get current height safely
            {
                LOCK(cs_main);
                currentHeight = chainActive.Height();
            }
            info.pushKV("startingpriority", e.GetPriority(e.GetHeight())); // Requires GetPriority
            info.pushKV("currentpriority", e.GetPriority(currentHeight)); // Requires GetPriority
            const CTransaction& tx = e.GetTx();
            std::set<std::string> setDepends;
            for (const CTxIn& txin : tx.vin) {
                if (mempool.exists(txin.prevout.hash))
                    setDepends.insert(txin.prevout.hash.ToString());
            }

            UniValue depends(UniValue::VARR);
            for (const std::string& dep : setDepends) {
                depends.push_back(dep);
            }

            info.pushKV("depends", depends);
            o.pushKV(hash.ToString(), info);
        }
        return o;
    } else {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        for (const uint256& hash : vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"
            "\nResult: (for verbose = false):\n"
            "[...] (array of strings)\n"
            "\nResult: (for verbose = true):\n"
            "{...} (object with tx details)\n"
            "\nExamples\n" +
            HelpExampleCli("getrawmempool", "true") + HelpExampleRpc("getrawmempool", "true"));

    // No need for LOCK(cs_main) here, mempool has its own lock (mempool.cs) handled by mempoolToJSON

    bool fVerbose = false;
    if (params.size() > 0)
        fVerbose = params[0].get_bool();

    return mempoolToJSON(fVerbose);
}

UniValue getblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"
            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockhash", "1000") + HelpExampleRpc("getblockhash", "1000"));

    LOCK(cs_main); // cs_main protects chainActive

    int nHeight = params[0].getInt<int>();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

UniValue getblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getblock \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbose is true, returns an Object with information about block <hash>.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true): See help\n"
            "\nResult (for verbose=false): See help\n"
            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    LOCK(cs_main); // cs_main protects mapBlockIndex and potentially ReadBlockFromDisk internals

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!ReadBlockFromDisk(block, pblockindex))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex, true); // Pass true for tx details
}

UniValue getblockheader(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash' header.\n"
            "If verbose is true, returns an Object with information about block <hash> header.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true): See help\n"
            "\nResult (for verbose=false): See help\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    LOCK(cs_main); // cs_main protects mapBlockIndex

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockheaderToJSON(pblockindex);
}

UniValue gettxoutsetinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"
            "\nResult: See help\n"
            "\nExamples:\n" +
            HelpExampleCli("gettxoutsetinfo", "") + HelpExampleRpc("gettxoutsetinfo", ""));

    LOCK(cs_main); // cs_main protects pcoinsTip and FlushStateToDisk

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk(); // Ensure this function exists and is appropriate for DigiWage
    // Ensure pcoinsTip is the correct UTXO set view for DigiWage
    if (pcoinsTip && pcoinsTip->GetStats(stats)) { // Check pcoinsTip is not null
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("transactions", (int64_t)stats.nTransactions);
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("bytes_serialized", (int64_t)stats.nSerializedSize);
        ret.pushKV("hash_serialized", stats.hashSerialized.GetHex());
        ret.pushKV("total_amount", ValueFromAmount(stats.nTotalAmount));
    } else {
        // Handle case where stats couldn't be obtained
         ret.pushKV("height", (int64_t)chainActive.Height());
         ret.pushKV("bestblock", chainActive.Tip()->GetBlockHash().GetHex());
         ret.pushKV("error", "Unable to get UTXO set statistics.");
    }
    return ret;
}

UniValue gettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional, default=true) Whether to included the mem pool\n"
            "\nResult: See help\n"
            "\nExamples:\n" +
            HelpExampleCli("gettxout", "\"txid\" 1") +
            HelpExampleRpc("gettxout", "\"txid\", 1"));

    LOCK(cs_main); // cs_main protects pcoinsTip, mempool, mapBlockIndex

    UniValue ret(UniValue::VOBJ);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    int n = params[1].getInt<int>();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip, mempool); // Ensure pcoinsTip is correct
        if (!view.GetCoins(hash, coins))
            return NullUniValue;
        mempool.pruneSpent(hash, coins); // Assuming pruneSpent exists
    } else {
         if (!pcoinsTip || !pcoinsTip->GetCoins(hash, coins)) // Check pcoinsTip
            return NullUniValue;
    }
    if (n < 0 || (unsigned int)n >= coins.vout.size() || coins.vout[n].IsNull())
        return NullUniValue;

    // Use chainActive.Tip() instead of mapBlockIndex lookup
    CBlockIndex* pindex = chainActive.Tip();
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.pushKV("confirmations", 0);
    else
        ret.pushKV("confirmations", pindex->nHeight - coins.nHeight + 1);
    ret.pushKV("value", ValueFromAmount(coins.vout[n].nValue));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true); // Use locally defined version
    ret.pushKV("scriptPubKey", o);
    ret.pushKV("version", coins.nVersion); // Assuming CCoins has nVersion
    ret.pushKV("coinbase", coins.fCoinBase); // Assuming CCoins has fCoinBase

    return ret;
}

UniValue verifychain(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // Corrected check (was > 2)
        throw std::runtime_error(
            "verifychain ( checklevel numblocks )\n" // Updated help
            "\nVerifies blockchain database.\n"
            "\nArguments:\n"
            "1. checklevel (numeric, optional, default=3, range=0-4) How thorough the block verification is.\n" // Updated help
            "2. numblocks    (numeric, optional, default=6, 0=all) The number of blocks to check.\n" // Updated help
            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"
            "\nExamples:\n" +
            HelpExampleCli("verifychain", "4 100") + HelpExampleRpc("verifychain", "4, 100")); // Updated help


    int nCheckLevel = GetArg("-checklevel", 3); // Use default from GetArg
    int nCheckDepth = GetArg("-checkblocks", 6); // Use default from GetArg
    if (!params[0].isNull()) { // Check level param
        nCheckLevel = params[0].getInt<int>();
    }
    if (params.size() > 1 && !params[1].isNull()) { // Check depth param
        nCheckDepth = params[1].getInt<int>();
    }


    LOCK(cs_main); // cs_main needed for VerifyDB? Check CVerifyDB implementation
    fVerifyingBlocks = true; // Ensure this global exists
    // Ensure CVerifyDB and pcoinsTip are compatible with DigiWage
    bool fVerified = CVerifyDB().VerifyDB(pcoinsTip, nCheckLevel, nCheckDepth);
    fVerifyingBlocks = false;

    return fVerified;
}

/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int version, CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    bool activated = false;
    // Use the exact height logic from original DigiWage
    switch(version) {
    // Assuming versions 1, 2, 3 were early forks or always active from genesis/low height
    case 1:
    case 2:
    case 3:
        activated = pindex->nHeight >= 1; // Or appropriate low activation height
        break;
    case 4: // Assuming version 4 corresponds to the ZC fork feature
        activated = pindex->nHeight >= consensusParams.height_start_ZC;
        break;
    case 5: // Assuming version 5 corresponds to the RHF fork feature
        activated = pindex->nHeight >= consensusParams.height_RHF;
        break;
    // Add cases for other DigiWage specific versions if they exist
    default:
        // Handle unknown version? Or assume false?
        activated = false;
        break;
    }
    rv.pushKV("status", activated);
    return rv;
}

static UniValue SoftForkDesc(const std::string &name, int version, CBlockIndex* pindex)
{
    // Ensure Params() is accessible or pass consensus params explicitly if needed
    const Consensus::Params& consensus = Params().GetConsensus();
    UniValue rv(UniValue::VOBJ);
    rv.pushKV("id", name);
    rv.pushKV("version", version);
    rv.pushKV("reject", SoftForkMajorityDesc(version, pindex, consensus));
    return rv;
}


UniValue getblockchaininfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"
            "\nResult: See help\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockchaininfo", "") + HelpExampleRpc("getblockchaininfo", ""));

    LOCK(cs_main); // Protects chainActive, pindexBestHeader, nBurnedCoins

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", Params().NetworkIDString());
    obj.pushKV("blocks", (int)chainActive.Height());
    obj.pushKV("headers", pindexBestHeader ? pindexBestHeader->nHeight : -1); // Ensure pindexBestHeader exists
    obj.pushKV("bestblockhash", chainActive.Tip()->GetBlockHash().GetHex());
    obj.pushKV("difficulty", (double)GetDifficulty());
    // Ensure GuessVerificationProgress exists and works with chainActive.Tip()
    obj.pushKV("verificationprogress", Checkpoints::GuessVerificationProgress(chainActive.Tip())); // <<< Pass only the tip CBlockIndex*
    obj.pushKV("chainwork", chainActive.Tip()->nChainWork.GetHex());
    obj.pushKV("moneysupply", ValueFromAmount(chainActive.Tip()->nMoneySupply)); // Assuming nMoneySupply exists
    obj.pushKV("burned", ValueFromAmount(nBurnedCoins)); // Assuming nBurnedCoins exists

    CBlockIndex* tip = chainActive.Tip();
    UniValue softforks(UniValue::VARR);
    // --- Add DigiWage specific forks ---
    // Example placeholders - replace with actual fork names and versions/bits
    softforks.pushKV("bip34",    SoftForkDesc("bip34",    2, tip));
    softforks.pushKV("bip66",    SoftForkDesc("bip66",    3, tip));
    softforks.pushKV("bip65",    SoftForkDesc("bip65",    4, tip)); // Map version 4?
    softforks.pushKV("zerocoin", SoftForkDesc("zerocoin", 5, tip)); // Map version 5?
    softforks.pushKV("rhf",      SoftForkDesc("rhf",      6, tip)); // Map version 6?
    // Add any other relevant forks for DigiWage
    // --- End DigiWage forks ---
    obj.pushKV("softforks", softforks);
    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight {
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        if (a->nHeight != b->nHeight)
            return (a->nHeight > b->nHeight);
        return a < b; // Use pointer comparison for tie-breaking
    }
};

UniValue getchaintips(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"
            "\nResult: See help\n"
            "\nExamples:\n" +
            HelpExampleCli("getchaintips", "") + HelpExampleRpc("getchaintips", ""));

    LOCK(cs_main); // Protects mapBlockIndex and chainActive

    /* Build up a list of chain tips. */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    for (const auto& item : mapBlockIndex)
        setTips.insert(item.second);
    for (const auto& item : mapBlockIndex) {
        const CBlockIndex* pprev = item.second->pprev;
        if (pprev)
            setTips.erase(pprev);
    }

    // Always report the currently active tip.
    if (chainActive.Tip()) { // Ensure tip exists
        setTips.insert(chainActive.Tip());
    }

    /* Construct the output array. */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->GetBlockHash().GetHex()); // Use GetBlockHash()

        const CBlockIndex* pfork = chainActive.FindFork(block);
        const int branchLen = pfork ? (block->nHeight - pfork->nHeight) : block->nHeight + 1; // Handle case where fork is null (e.g. genesis)
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (chainActive.Contains(block)) {
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            status = "invalid";
        } else if (block->nChainTx == 0 && block->nHeight > 0) { // Add check for nHeight > 0, genesis has nChainTx=0
             status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            status = "valid-headers";
        } else {
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(obj);
    }

    return res;
}

UniValue getfeeinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getfeeinfo blocks\n"
            "\nReturns details of transaction fees over the last n blocks.\n"
            "\nArguments:\n"
            "1. blocks     (int, required) the number of blocks to get transaction data from\n"
            "\nResult: See help\n"
            "\nExamples:\n" +
            HelpExampleCli("getfeeinfo", "5") + HelpExampleRpc("getfeeinfo", "5"));

    int nBlocks = params[0].getInt<int>();
    int nBestHeight;
    {
        LOCK(cs_main);
        nBestHeight = chainActive.Height();
    }
    int nStartHeight = nBestHeight - nBlocks + 1; // Adjust to include current block
    if (nBlocks <= 0 || nStartHeight < 0 ) // Check nBlocks > 0
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count or calculated start height is negative.");

    // Cap start height at 0 (genesis)
    if (nStartHeight < 0) nStartHeight = 0;

    // Note: getblockindexstats expects height + range.
    // We want stats from [nStartHeight, nBestHeight].
    // So, height = nStartHeight, range = nBestHeight - nStartHeight + 1 = nBlocks
    UniValue newParams(UniValue::VARR);
    newParams.push_back(UniValue(nStartHeight));
    newParams.push_back(UniValue(nBlocks));
    newParams.push_back(UniValue(true));    // fFeeOnly = true

    return getblockindexstats(newParams, false); // Call the other RPC function
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("size", (int64_t) mempool.size());
    ret.pushKV("bytes", (int64_t) mempool.GetTotalTxSize());
    // mempool.DynamicMemoryUsage() might not exist in older versions. Remove if causes error.
    // ret.pushKV("usage", (int64_t) mempool.DynamicMemoryUsage());

    return ret;
}

UniValue getmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"
            "\nResult: See help\n"
            "\nExamples:\n" +
            HelpExampleCli("getmempoolinfo", "") + HelpExampleRpc("getmempoolinfo", ""));

    return mempoolInfoToJSON();
}

UniValue invalidateblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"
            "\nResult: null\n" // Added result type
            "\nExamples:\n" +
            HelpExampleCli("invalidateblock", "\"blockhash\"") + HelpExampleRpc("invalidateblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state; // Ensure this type exists

    {
        LOCK(cs_main); // Protects mapBlockIndex and chainActive modification
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        // Ensure InvalidateBlock function exists and takes these params
        InvalidateBlock(state, pblockindex); // Call with expected arguments for DigiWage
        
    }

    if (state.IsValid()) {
        // Ensure ActivateBestChain function exists and takes these params
        ActivateBestChain(state);// Pass consensus params if needed
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"
            "\nResult: null\n" // Added result type
            "\nExamples:\n" +
            HelpExampleCli("reconsiderblock", "\"blockhash\"") + HelpExampleRpc("reconsiderblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main); // Protects mapBlockIndex and chainActive modification
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        // Ensure ReconsiderBlock function exists and takes these params
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        // Ensure ActivateBestChain function exists and takes these params
        ActivateBestChain(state); // Pass consensus params if needed
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

// Helper for validaterange, avoids code duplication
static void ParseValidateRangeParams(const UniValue& params, int& heightStart, int& heightEnd, int minHeightStart)
{
     if (params.size() < 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not enough parameters for range (expected height and range)");
    }

    int nBestHeight;
    {
        LOCK(cs_main);
        nBestHeight = chainActive.Height();
    }

    heightStart = params[0].getInt<int>();
    if (heightStart < minHeightStart || heightStart > nBestHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid starting block (%d). Out of range [%d, %d].", heightStart, minHeightStart, nBestHeight));
    }

    const int range = params[1].getInt<int>();
    if (range < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range. Must be strictly positive.");
    }

    heightEnd = heightStart + range - 1;

    if (heightEnd > nBestHeight) {
        LogPrintf("WARN: %s: range extends beyond tip, adjusting end block from %d to %d\n", __func__, heightEnd, nBestHeight);
        heightEnd = nBestHeight;
    }
     // Add check: ensure start <= end after adjustment
     if (heightStart > heightEnd) {
         throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid range after adjustment: start (%d) > end (%d). Tip might be lower than start.", heightStart, heightEnd));
     }
}


// This function was defined but not used in the original snippet, keeping it static
// static void validaterange(const UniValue& params, int& heightStart, int& heightEnd, int minHeightStart)
// {
//     ParseValidateRangeParams(params, heightStart, heightEnd, minHeightStart);
// }


UniValue getblockindexstats(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
                "getblockindexstats height range ( fFeeOnly )\n"
                "\nReturns aggregated BlockIndex data for blocks "
                "\n[height, height+1, height+2, ..., height+range-1]\n"
                "\nArguments:\n"
                "1. height             (numeric, required) block height where the search starts.\n"
                "2. range              (numeric, required) number of blocks to include.\n"
                "3. fFeeOnly           (boolean, optional, default=False) return only fee info.\n"
                "\nResult: See help\n"
                "\nExamples:\n" +
                HelpExampleCli("getblockindexstats", "1200000 1000") +
                HelpExampleRpc("getblockindexstats", "1200000, 1000"));

    int heightStart, heightEnd;
    ParseValidateRangeParams(params, heightStart, heightEnd, 0); // Use helper

    // return object
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("first_block", heightStart);
    ret.pushKV("last_block", heightEnd);

    bool fFeeOnly = false;
    if (params.size() > 2) {
        fFeeOnly = params[2].get_bool();
    }

    CAmount nFees = 0;
    CAmount nFees_all = 0;
    int64_t nBytes = 0;
    int64_t nTxCount = 0;
    int64_t nTxCount_all = 0;

    std::map<libzerocoin::CoinDenomination, int64_t> mapSpendCount;
    if (!fFeeOnly) { // Only initialize if needed
        for (auto& denom : libzerocoin::zerocoinDenomList) {
            mapSpendCount.insert(std::make_pair(denom, 0));
        }
    }

    CBlockIndex* pindex = nullptr;
    {
        LOCK(cs_main); // Protects chainActive access
        if (heightStart > chainActive.Height()) // Double check start height vs current tip
             throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid starting block %d, current tip is %d", heightStart, chainActive.Height()));
        pindex = chainActive[heightStart];
    }

    if (!pindex) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Failed to find block index for starting height %d", heightStart));
    }

    // Loop from start height up to and including end height
    for (int currentHeight = heightStart; currentHeight <= heightEnd; ++currentHeight) {
         CBlock block;
         if (!ReadBlockFromDisk(block, pindex)) {
             // Maybe log an error but continue? Or throw? Throwing is safer.
             throw JSONRPCError(RPC_DATABASE_ERROR, strprintf("failed to read block %s (height %d) from disk", pindex->GetBlockHash().ToString(), currentHeight));
         }

         CAmount block_fees_all = 0; // Sum fees within this block
         int64_t block_bytes = 0; // Sum bytes within this block (excluding ZC mints/pure spends)
         int block_tx_count = 0; // Count non-coinbase/coinstake txs
         int block_tx_count_all = block.vtx.size(); // Count all txs

         // loop through each tx in block and save size and fee
         for (const CTransaction& tx : block.vtx) {
             if (tx.IsCoinBase() || tx.IsCoinStake()) // Skip coinbase/coinstake for fee/byte/txcount stats
                 continue;

             block_tx_count++; // Increment standard tx count

             // Calculate fee (ValueIn - ValueOut)
             CAmount nTxValueIn = 0;
             CAmount nTxValueOut = 0;
             bool txHasZCSpend = false;
             bool txHasZCMint = tx.HasZerocoinMintOutputs(); // Check for mints

             for (unsigned int j = 0; j < tx.vin.size(); ++j) {
                 if (tx.vin[j].IsZerocoinSpend()) {
                     txHasZCSpend = true;
                     if (!fFeeOnly) {
                         try {
                            mapSpendCount[libzerocoin::IntToZerocoinDenomination(tx.vin[j].nSequence)]++;
                         } catch (const std::out_of_range& oor) {
                             LogPrintf("ERROR: %s: Invalid sequence %u treated as denomination in tx %s, block %d\n", __func__, tx.vin[j].nSequence, tx.GetHash().ToString(), currentHeight);
                         } catch (...) { // Catch any other potential error from IntToZerocoinDenomination
                             LogPrintf("ERROR: %s: Unknown error converting sequence %u to denomination in tx %s, block %d\n", __func__, tx.vin[j].nSequence, tx.GetHash().ToString(), currentHeight);
                         }
                     }
                     continue; // Zerocoin spends don't contribute to ValueIn for fee calc here
                 }

                 const COutPoint& prevout = tx.vin[j].prevout;
                 CTransaction txPrev;
                 uint256 hashBlock; // We don't strictly need hashBlock here
                 // Use the main GetTransaction function
                 if (!GetTransaction(prevout.hash, txPrev, hashBlock, true, pindex->pprev)) { // Pass pprev as hint if available
                      LogPrintf("ERROR: %s: failed to read prev_tx %s for input %d of tx %s in block %d\n", __func__, prevout.hash.ToString(), j, tx.GetHash().ToString(), currentHeight);
                      // Treat as error or skip? Skipping might skew results. Throwing stops calculation.
                       throw JSONRPCError(RPC_DATABASE_ERROR, "failed to read previous transaction needed for fee calculation");
                 }

                 if (prevout.n >= txPrev.vout.size()) {
                     LogPrintf("ERROR: %s: invalid prevout index %d for tx %s (prev_tx %s has %u outputs) in block %d\n", __func__, prevout.n, tx.GetHash().ToString(), prevout.hash.ToString(), txPrev.vout.size(), currentHeight);
                     throw JSONRPCError(RPC_DATABASE_ERROR, "invalid previous transaction output index encountered");
                 }
                 nTxValueIn += txPrev.vout[prevout.n].nValue;
             }

             for (unsigned int j = 0; j < tx.vout.size(); ++j) {
                 nTxValueOut += tx.vout[j].nValue;
             }

             CAmount nTxFee = nTxValueIn - nTxValueOut;
             if (nTxFee < 0) {
                  LogPrintf("WARN: %s: negative fee (%s) calculated for tx %s in block %d. ValueIn=%s, ValueOut=%s. Treating as 0.\n", __func__, FormatMoney(nTxFee), tx.GetHash().ToString(), currentHeight, FormatMoney(nTxValueIn), FormatMoney(nTxValueOut));
                  nTxFee = 0;
             }

             block_fees_all += nTxFee; // Add to block's total fee

             // Add to overall fee/byte count ONLY if it's not a pure ZC mint/spend transaction
             if (!txHasZCMint && !txHasZCSpend) { // Standard tx
                  nFees += nTxFee;
                  block_bytes += ::GetSerializeSize(tx, SER_NETWORK, CLIENT_VERSION);
             } else if (!txHasZCMint && txHasZCSpend) { // Mixed spend (standard inputs + ZC spends)
                 // Fee is derived from standard inputs/outputs
                 nFees += nTxFee;
                 block_bytes += ::GetSerializeSize(tx, SER_NETWORK, CLIENT_VERSION);
             }
             // Pure ZC mints (txHasZCMint=true, txHasZCSpend=false) are excluded from nFees and block_bytes
             // Pure ZC spends (txHasZCMint=false, txHasZCSpend=true, no standard inputs) should have nTxFee=0 and are excluded from nFees/block_bytes

         } // End loop through txs in block

         // Update overall totals
         nFees_all += block_fees_all;
         nBytes += block_bytes;
         nTxCount += block_tx_count;
         nTxCount_all += block_tx_count_all;

         // Move to the next block index
         if (currentHeight < heightEnd) {
             LOCK(cs_main); // Protect chainActive access
             CBlockIndex* pnext = chainActive.Next(pindex);
             if (!pnext || pnext->nHeight != currentHeight + 1) { // Check if next block is expected one
                  LogPrintf("ERROR: %s: Chain inconsistency detected. Expected block %d, found %s\n", __func__, currentHeight+1, pnext ? std::to_string(pnext->nHeight) : "null");
                  throw JSONRPCError(RPC_INTERNAL_ERROR, "Chain inconsistency detected while iterating blocks");
             }
             pindex = pnext;
         }

    } // End loop through blocks

    // Calculate final fee rate
    CFeeRate nFeeRate = (nBytes > 0) ? CFeeRate(nFees, nBytes) : CFeeRate(0);

    // Populate return object
    ret.pushKV("txcount", nTxCount); // Use int64_t cast if needed, pushKV handles it
    ret.pushKV("txcount_all", nTxCount_all);
    if (!fFeeOnly) {
        UniValue spend_obj(UniValue::VOBJ);
        for (auto const& [denom, count] : mapSpendCount) { // C++17 structured binding
             try {
                 spend_obj.pushKV(strprintf("denom_%d", libzerocoin::ZerocoinDenominationToInt(denom)), count);
             } catch (const std::out_of_range& oor) {
                 LogPrintf("ERROR: %s: Invalid denomination value encountered when formatting output.\n", __func__);
                 spend_obj.pushKV(strprintf("denom_invalid_%d", static_cast<int>(denom)), count); // Log invalid denom explicitly
             } catch (...) {
                 LogPrintf("ERROR: %s: Unknown error converting denomination to int for output.\n", __func__);
             }
        }
        ret.pushKV("spendcount", spend_obj);
    }
    ret.pushKV("txbytes", nBytes);
    ret.pushKV("ttlfee", ValueFromAmount(nFees)); // Use ValueFromAmount for amounts
    ret.pushKV("ttlfee_all", ValueFromAmount(nFees_all));
    ret.pushKV("feeperkb", ValueFromAmount(nFeeRate.GetFeePerK()));

    return ret;
}

