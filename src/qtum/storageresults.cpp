// Copyright (c) 2017- TBD The Qtum Core developers // Modified for DigiWage Integration
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qtum/storageresults.h>
#include <util/convert.h>          // For uintToh256, h256Touint
#include <util.h>                  // For LogPrintf, GetDataDir
#include <primitives/transaction.h> // For CTransaction, GetHash
#include <uint256.h>               // For uint256 type
#include <validationinterface.h>   // Included for signals? Ensure it's needed.
#include <consensus/params.h>      // Included for consensus params? Ensure it's needed.
#include <utilstrencodings.h>      // For HexStr if needed (dev::h256.hex() is usually preferred)
#include <amount.h>                // For MAX_MONEY
#include <boost/filesystem.hpp>    // For path operations

// LevelDB includes
#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <leveldb/options.h>
#include <leveldb/env.h>
#include <leveldb/slice.h>

// Standard library includes
#include <string>
#include <vector>
#include <utility>
#include <cassert>
#include <algorithm>
#include <stdexcept>
#include <limits>                  // For numeric_limits

// EVM/RLP includes (ensure these paths are correct for your project)
#include <libdevcore/RLP.h>
#include <libdevcore/CommonData.h> // For dev::sha3


// Filesystem namespace alias
namespace fs = boost::filesystem;

// Constructor with improved path handling and error logging
StorageResults::StorageResults(std::string const& basePath){ // basePath is likely /root/.digiwage/
    fs::path resultsParentPath;
    fs::path dbPathObj;

    try {
        // Define the parent directory path first
        resultsParentPath = fs::path(basePath) / fs::path("results");

        // ---> CREATE THE PARENT DIRECTORY IF IT DOESN'T EXIST <---
        if (!fs::exists(resultsParentPath)) {
            LogPrintf("Creating parent directory for StorageResults: %s\n", resultsParentPath.string());
            if (!fs::create_directories(resultsParentPath)) {
                 // Throw an error if directory creation fails
                 throw std::runtime_error("Failed to create directory for StorageResults DB: " + resultsParentPath.string());
            }
        } else if (!fs::is_directory(resultsParentPath)) {
            // Handle case where 'results' exists but is a file
             throw std::runtime_error("Path for StorageResults parent exists but is not a directory: " + resultsParentPath.string());
        }
        // ---> END OF ADDED DIRECTORY CREATION <---


        // Now construct the final DB path inside the parent
        dbPathObj = resultsParentPath / fs::path("resultsDB");
        path = dbPathObj.string(); // Store the full path string

    } catch (const fs::filesystem_error& e) {
         throw std::runtime_error("Filesystem error constructing StorageResults path from " + basePath + ": " + e.what());
    } catch (const std::exception& e) {
         throw std::runtime_error("Error constructing StorageResults path: " + std::string(e.what()));
    }

    LogPrintf("Opening StorageResults LevelDB in %s\n", path);
    leveldb::Options options;
    options.create_if_missing = true;
    options.paranoid_checks = true;
    leveldb::Status status = leveldb::DB::Open(options, path, &db); // LevelDB should now create 'resultsDB' inside 'results'

    if(!status.ok()){
        std::string errorMsg = "ERROR: Failed to open LevelDB database at " + path + ": " + status.ToString();
        LogPrintf("%s\n", errorMsg);
        throw std::runtime_error(errorMsg);
        // db = nullptr; // Handled by exception
    } else {
        LogPrintf("Opened LevelDB successfully: %s\n", path);
    }
}

// Destructor
StorageResults::~StorageResults()
{
    // Check if db pointer is valid before deleting
    if (db) {
        delete db;
        db = NULL; // Set to NULL after deleting
    }
}

// Add result to cache
void StorageResults::addResult(dev::h256 hashTx, std::vector<TransactionReceiptInfo>& result){
    // Use emplace or insert_or_assign for potentially better efficiency
    m_cache_result.insert_or_assign(hashTx, result);
}

// Clear the cache
void StorageResults::clearCacheResult(){
    m_cache_result.clear();
}

// Wipe the entire database
void StorageResults::wipeResults(){
    LogPrintf("Wiping StorageResults LevelDB in %s\n", path);
    bool was_open = (db != NULL);
    if (was_open) {
        delete db;
        db = NULL;
    }

    leveldb::Options options; // Need options for DestroyDB
    leveldb::Status result = leveldb::DestroyDB(path, options);
    if (!result.ok()) {
         // NotFound is expected if the DB didn't exist, others might be warnings
         if (!result.IsNotFound()) {
             LogPrintf("WARNING: Failed to destroy LevelDB (may already be gone or other issue): %s : %s\n", path, result.ToString());
         }
    } else {
        LogPrintf("Successfully destroyed LevelDB: %s\n", path);
    }

    // Re-open the database after wiping
    options.create_if_missing = true;
    options.paranoid_checks = true;
    leveldb::Status status = leveldb::DB::Open(options, path, &db);

    if(!status.ok()){
        std::string errorMsg = "ERROR: Failed to re-open LevelDB after wipe: " + path + ": " + status.ToString();
        LogPrintf("%s\n", errorMsg);
        throw std::runtime_error(errorMsg); // Critical failure if re-open fails
        // db = nullptr; // Already null or will be due to exception
    } else {
        LogPrintf("Successfully re-opened LevelDB after wipe: %s\n", path);
    }
}

// Delete results for specific transactions
void StorageResults::deleteResults(const std::vector<const CTransaction*>& txs){
    if (!db) {
        LogPrintf("ERROR: StorageResults::deleteResults called but DB is not open.\n");
        return; // Cannot proceed without DB
    }

    leveldb::WriteBatch batch;
    bool items_to_delete = false; // Flag to track if we added anything

    for(const CTransaction* tx : txs){
        if (!tx) {
            LogPrintf("Warning: Null transaction pointer passed to StorageResults::deleteResults.\n");
            continue; // Skip null pointers
        }

        // Ensure uintToh256 function is available and correct
        dev::h256 hashTx = uintToh256(tx->GetHash());
        m_cache_result.erase(hashTx); // Remove from cache regardless of DB status

        std::string keyTemp = hashTx.hex(); // Use .hex() if available
        leveldb::Slice key(keyTemp);
        batch.Delete(key); // Add deletion to batch
        items_to_delete = true; // Set the flag since we added a delete operation
    }

    // Apply the batch write to the database ONLY if we added items
    // ---> REPLACED Check <---
    if(items_to_delete) {
        leveldb::WriteOptions writeOptions;
        writeOptions.sync = true; // Ensure data is written before returning (optional)
        leveldb::Status status = db->Write(writeOptions, &batch);
        if (!status.ok()) {
             std::string errorMsg = "ERROR: Failed to delete results batch from LevelDB: " + status.ToString();
             LogPrintf("%s\n", errorMsg);
             // Consider how critical this error is. Throw? Log only?
             // assert(status.ok()); // Use assert only for debug builds if it's critical
        }
    }
    // ---> END OF REPLACED Check <---
}

// Get result, checking cache first, then DB
std::vector<TransactionReceiptInfo> StorageResults::getResult(dev::h256 const& hashTx){
    std::vector<TransactionReceiptInfo> result;
    auto it = m_cache_result.find(hashTx);
    if (it == m_cache_result.end()){
        // Not in cache, try reading from DB
        if(readResult(hashTx, result)) {
            // Found in DB, add to cache
            m_cache_result.insert(std::make_pair(hashTx, result));
        }
        // If not found in DB, result remains empty
    } else {
        // Found in cache
        result = it->second;
    }
    return result;
}

// Commit cached results to DB
void StorageResults::commitResults(){
    if (!db) {
        LogPrintf("ERROR: Attempted to commit results but LevelDB is not open.\n");
        // Decide whether to clear cache here or leave it for next attempt
        // m_cache_result.clear();
        return;
    }
    if (m_cache_result.empty()) {
        return; // Nothing to commit
    }

    leveldb::WriteBatch batch;
    bool batch_has_items = false;

    for (auto const& [key_h256, value_vec] : m_cache_result){
        std::string keyTemp = key_h256.hex();
        leveldb::Slice key(keyTemp);

        // Serialize the vector of receipts into the serialized format
        TransactionReceiptInfoSerialized tris;
        size_t numEntries = value_vec.size();
        tris.blockHashes.reserve(numEntries);
        tris.blockNumbers.reserve(numEntries);
        tris.transactionHashes.reserve(numEntries);
        tris.transactionIndexes.reserve(numEntries);
        tris.senders.reserve(numEntries);
        tris.receivers.reserve(numEntries);
        tris.cumulativeGasUsed.reserve(numEntries);
        tris.gasUsed.reserve(numEntries);
        tris.contractAddresses.reserve(numEntries);
        tris.logs.reserve(numEntries);
        tris.excepted.reserve(numEntries);
        tris.exceptedMessage.reserve(numEntries);
        tris.outputIndexes.reserve(numEntries);
        tris.blooms.reserve(numEntries);
        tris.stateRoots.reserve(numEntries);
        tris.utxoRoots.reserve(numEntries);

        for(const auto& receipt : value_vec){
            tris.blockHashes.push_back(uintToh256(receipt.blockHash));
            tris.blockNumbers.push_back(receipt.blockNumber);
            tris.transactionHashes.push_back(uintToh256(receipt.transactionHash));
            tris.transactionIndexes.push_back(receipt.transactionIndex);
            tris.senders.push_back(receipt.from); // Assumes dev::Address implicitly converts to dev::h160 if needed by RLP
            tris.receivers.push_back(receipt.to);
            tris.cumulativeGasUsed.push_back(dev::u256(receipt.cumulativeGasUsed));
            tris.gasUsed.push_back(dev::u256(receipt.gasUsed));
            tris.contractAddresses.push_back(receipt.contractAddress);
            tris.logs.push_back(logEntriesSerialization(receipt.logs)); // Serialize logs
            tris.excepted.push_back(static_cast<uint32_t>(receipt.excepted));
            tris.exceptedMessage.push_back(receipt.exceptedMessage);
            tris.outputIndexes.push_back(receipt.outputIndex);
            tris.blooms.push_back(receipt.bloom); // Assumes dev::eth::LogBloom is dev::h2048
            tris.stateRoots.push_back(receipt.stateRoot);
            tris.utxoRoots.push_back(receipt.utxoRoot);
        }

        // RLP Encode the serialized data
        dev::RLPStream streamRLP;
        streamRLP.appendList(16); // List of 16 vectors
        streamRLP << tris.blockHashes << tris.blockNumbers << tris.transactionHashes << tris.transactionIndexes << tris.senders;
        streamRLP << tris.receivers << tris.cumulativeGasUsed << tris.gasUsed << tris.contractAddresses << tris.logs;
        streamRLP << tris.excepted << tris.exceptedMessage << tris.outputIndexes << tris.blooms << tris.stateRoots << tris.utxoRoots;

        dev::bytes data = streamRLP.out();
        // Use Slice directly on the RLP output bytes
        leveldb::Slice value(reinterpret_cast<const char*>(data.data()), data.size());
        batch.Put(key, value); // Add Put operation to the batch
        batch_has_items = true;
    }

    // Write the batch if it contains items
    if(batch_has_items) {
        leveldb::WriteOptions writeOptions;
        writeOptions.sync = true; // Make commit durable (optional)
        leveldb::Status write_status = db->Write(writeOptions, &batch);

        if (!write_status.ok()) {
             std::string errorMsg = "ERROR: Failed to commit results batch to LevelDB: " + write_status.ToString();
             LogPrintf("%s\n", errorMsg);
             // Decide how to handle: throw? assert? Clear cache anyway?
             // For now, log and clear cache.
             // assert(write_status.ok());
        } else {
             LogPrint("db", "Committed %d storage results to LevelDB\n", m_cache_result.size());
        }
    }

    // Clear cache after attempting commit
    m_cache_result.clear();
}

// Read result from DB
bool StorageResults::readResult(dev::h256 const& _key, std::vector<TransactionReceiptInfo>& _result){
    if (!db) {
        LogPrintf("ERROR: Attempted to read result but LevelDB is not open.\n");
        return false;
    }

    std::string value;
    std::string keyTemp = _key.hex();
    leveldb::Slice key(keyTemp);
    leveldb::Status s = db->Get(leveldb::ReadOptions(), key, &value);

    if(s.ok()){
        try {
            TransactionReceiptInfoSerialized tris;
            dev::RLP rlpData(value); // Create RLP object from retrieved string data

            // Check RLP structure before accessing elements
            if (!rlpData.isList() || rlpData.itemCount() != 16) { // Expect exactly 16 lists
                LogPrintf("Error reading result for key %s: Invalid RLP structure (isList=%d, itemCount=%zu, expected=16)\n", keyTemp, rlpData.isList(), rlpData.itemCount());
                return false;
            }

            // Deserialize vectors from RLP list
            tris.blockHashes = rlpData[0].toVector<dev::h256>();
            tris.blockNumbers = rlpData[1].toVector<uint32_t>();
            tris.transactionHashes = rlpData[2].toVector<dev::h256>();
            tris.transactionIndexes = rlpData[3].toVector<uint32_t>();
            tris.senders = rlpData[4].toVector<dev::h160>(); // Assumes Address/h160 RLP compatibility
            tris.receivers = rlpData[5].toVector<dev::h160>();
            tris.cumulativeGasUsed = rlpData[6].toVector<dev::u256>();
            tris.gasUsed = rlpData[7].toVector<dev::u256>();
            tris.contractAddresses = rlpData[8].toVector<dev::h160>();
            tris.logs = rlpData[9].toVector<logEntriesSerialize>(); // Requires RLP support for the pair structure
            tris.excepted = rlpData[10].toVector<uint32_t>();
            tris.exceptedMessage = rlpData[11].toVector<std::string>();
            tris.outputIndexes = rlpData[12].toVector<uint32_t>();
            tris.blooms = rlpData[13].toVector<dev::h2048>(); // LogBloom is h2048
            tris.stateRoots = rlpData[14].toVector<dev::h256>();
            tris.utxoRoots = rlpData[15].toVector<dev::h256>();

            // Check if all mandatory vectors have the same size and are non-empty
            size_t numEntries = tris.blockHashes.size();
            if (numEntries == 0 || // Cannot have zero entries if data exists
                tris.blockNumbers.size() != numEntries ||
                tris.transactionHashes.size() != numEntries ||
                tris.transactionIndexes.size() != numEntries ||
                tris.senders.size() != numEntries ||
                tris.receivers.size() != numEntries ||
                tris.cumulativeGasUsed.size() != numEntries ||
                tris.gasUsed.size() != numEntries ||
                tris.contractAddresses.size() != numEntries ||
                tris.logs.size() != numEntries ||
                tris.excepted.size() != numEntries || // All fields were mandatory in serialization
                tris.exceptedMessage.size() != numEntries ||
                tris.outputIndexes.size() != numEntries ||
                tris.blooms.size() != numEntries ||
                tris.stateRoots.size() != numEntries ||
                tris.utxoRoots.size() != numEntries)
             {
                LogPrintf("Error reading result for key %s: Mismatched vector sizes after RLP decoding.\n", keyTemp);
                // Log sizes for debugging:
                 LogPrintf("Sizes: BH=%zu, BN=%zu, TXH=%zu, TXI=%zu, S=%zu, R=%zu, CGU=%zu, GU=%zu, CA=%zu, L=%zu, E=%zu, EM=%zu, OI=%zu, B=%zu, SR=%zu, UR=%zu\n",
                           tris.blockHashes.size(), tris.blockNumbers.size(), tris.transactionHashes.size(), tris.transactionIndexes.size(),
                           tris.senders.size(), tris.receivers.size(), tris.cumulativeGasUsed.size(), tris.gasUsed.size(),
                           tris.contractAddresses.size(), tris.logs.size(), tris.excepted.size(), tris.exceptedMessage.size(),
                           tris.outputIndexes.size(), tris.blooms.size(), tris.stateRoots.size(), tris.utxoRoots.size());
                return false;
            }

            _result.clear(); // Clear output vector before filling
            _result.reserve(numEntries);
            for(size_t j = 0; j < numEntries; ++j){
                // Check for potential overflow converting u256 gas values back to uint64_t
                uint64_t cumulativeGasUsed_u64 = 0;
                uint64_t gasUsed_u64 = 0;
                if (tris.cumulativeGasUsed[j] <= dev::u256(std::numeric_limits<uint64_t>::max())) {
                    cumulativeGasUsed_u64 = static_cast<uint64_t>(tris.cumulativeGasUsed[j]);
                } else {
                     LogPrintf("Warning: CumulativeGasUsed overflow converting from u256 for key %s, index %zu\n", keyTemp, j);
                     cumulativeGasUsed_u64 = std::numeric_limits<uint64_t>::max(); // Assign max? Or handle differently?
                }
                 if (tris.gasUsed[j] <= dev::u256(std::numeric_limits<uint64_t>::max())) {
                     gasUsed_u64 = static_cast<uint64_t>(tris.gasUsed[j]);
                 } else {
                     LogPrintf("Warning: GasUsed overflow converting from u256 for key %s, index %zu\n", keyTemp, j);
                     gasUsed_u64 = std::numeric_limits<uint64_t>::max();
                 }

                // Construct TransactionReceiptInfo
                _result.emplace_back(TransactionReceiptInfo{
                    h256Touint(tris.blockHashes[j]),
                    tris.blockNumbers[j],
                    h256Touint(tris.transactionHashes[j]),
                    tris.transactionIndexes[j],
                    dev::Address(tris.senders[j]), // Convert h160 back to Address
                    dev::Address(tris.receivers[j]),
                    cumulativeGasUsed_u64,
                    gasUsed_u64,
                    dev::Address(tris.contractAddresses[j]),
                    logEntriesDeserialize(tris.logs[j]), // Deserialize logs
                    static_cast<dev::eth::TransactionException>(tris.excepted[j]),
                    tris.exceptedMessage[j],
                    tris.outputIndexes[j],
                    tris.blooms[j], // LogBloom is h2048
                    tris.stateRoots[j],
                    tris.utxoRoots[j]
                });
            }
            return true;

        } catch (const dev::RLPException& e) {
            LogPrintf("Error reading result for key %s: RLP decoding failed: %s\n", keyTemp, e.what());
            return false;
        } catch (const std::exception& e) {
            LogPrintf("Error reading result for key %s: Standard exception during decoding: %s\n", keyTemp, e.what());
            return false;
        } catch (...) {
            LogPrintf("Error reading result for key %s: Unknown exception during decoding.\n", keyTemp);
            return false;
        }
    }
    else if(s.IsNotFound()){
        // Key not found is not an error for readResult, just means no stored result
        return false;
    } else {
        // Other LevelDB Get error
        LogPrintf("Error reading result for key %s from LevelDB: %s\n", keyTemp, s.ToString());
        return false;
    }
}

// Log serialization helpers
logEntriesSerialize StorageResults::logEntriesSerialization(dev::eth::LogEntries const& _logs){
    logEntriesSerialize result;
    result.reserve(_logs.size());
    for(const auto& logEntry : _logs){ // Use const& and clearer variable name
        // Pair format: {Address, {TopicsVector, DataBytes}}
        result.emplace_back(logEntry.address, std::make_pair(logEntry.topics, logEntry.data));
    }
    return result;
}

dev::eth::LogEntries StorageResults::logEntriesDeserialize(logEntriesSerialize const& _logs){
    dev::eth::LogEntries result;
    result.reserve(_logs.size());
    for(const auto& serializedLog : _logs){ // Use const& and clearer variable name
        // Construct LogEntry from the pair data
        result.emplace_back(serializedLog.first, serializedLog.second.first, serializedLog.second.second);
    }
    return result;
}