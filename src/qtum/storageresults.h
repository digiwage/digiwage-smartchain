#ifndef QTUM_STORAGERESULTS_H
#define QTUM_STORAGERESULTS_H

#include <uint256.h>
#include <libethereum/State.h>          // Includes Common.h which defines Address, h256, u256, LogBloom etc.
#include <libethereum/TransactionReceipt.h> // Defines TransactionReceipt, LogEntry, LogEntries, TransactionException
#include <leveldb/db.h>                 // Forward declare leveldb::DB if possible, otherwise include
#include <vector>
#include <string>
#include <utility>
#include <unordered_map>

// Forward declare CTransaction to avoid including full primitives/transaction.h
class CTransaction;

// Type alias for serialization format
using logEntriesSerialize = std::vector<std::pair<dev::Address, std::pair<dev::h256s, dev::bytes>>>;

// TransactionReceiptInfo structure seems fine
struct TransactionReceiptInfo{
    uint256 blockHash;
    uint32_t blockNumber;
    uint256 transactionHash;
    uint32_t transactionIndex;
    dev::Address from;
    dev::Address to;
    uint64_t cumulativeGasUsed;
    uint64_t gasUsed;
    dev::Address contractAddress;
    dev::eth::LogEntries logs;
    dev::eth::TransactionException excepted;
    std::string exceptedMessage; // Store exception message
    uint32_t outputIndex = 0xffffffff; // Use a sentinel value
    dev::eth::LogBloom bloom;
    dev::h256 stateRoot;
    dev::h256 utxoRoot;
};

// TransactionReceiptInfoSerialized structure seems fine
struct TransactionReceiptInfoSerialized{
    std::vector<dev::h256> blockHashes;
    std::vector<uint32_t> blockNumbers;
    std::vector<dev::h256> transactionHashes;
    std::vector<uint32_t> transactionIndexes;
    std::vector<dev::h160> senders; // Use h160 if Address is implicitly convertible, otherwise keep Address
    std::vector<dev::h160> receivers; // Use h160 if Address is implicitly convertible
    std::vector<dev::u256> cumulativeGasUsed;
    std::vector<dev::u256> gasUsed;
    std::vector<dev::h160> contractAddresses; // Use h160 if Address is implicitly convertible
    std::vector<logEntriesSerialize> logs;
    std::vector<uint32_t> excepted;
    std::vector<std::string> exceptedMessage;
    std::vector<uint32_t> outputIndexes;
    std::vector<dev::h2048> blooms; // h2048 is LogBloom
    std::vector<dev::h256> stateRoots;
    std::vector<dev::h256> utxoRoots;
};

class StorageResults{

public:
    // Use boost::filesystem::path? Or stick to string? String is simpler for LevelDB API.
    explicit StorageResults(std::string const& dbPath); // Use explicit to prevent implicit conversions
    ~StorageResults();

    // Prevent copying/moving to avoid issues with LevelDB pointer ownership
    StorageResults(const StorageResults&) = delete;
    StorageResults& operator=(const StorageResults&) = delete;
    StorageResults(StorageResults&&) = delete;
    StorageResults& operator=(StorageResults&&) = delete;


    void addResult(dev::h256 hashTx, std::vector<TransactionReceiptInfo>& result);

    // Corrected signature using vector of const pointers
    void deleteResults(const std::vector<const CTransaction*>& txs);

    std::vector<TransactionReceiptInfo> getResult(dev::h256 const& hashTx);

    void commitResults();

    void clearCacheResult();

    void wipeResults();

private:

    bool readResult(dev::h256 const& _key, std::vector<TransactionReceiptInfo>& _result);

    logEntriesSerialize logEntriesSerialization(dev::eth::LogEntries const& _logs);

    dev::eth::LogEntries logEntriesDeserialize(logEntriesSerialize const& _logs);

    std::string path; // Full path to the LevelDB directory

    leveldb::DB* db = nullptr; // Initialize to nullptr

    // Use boost::unordered_map or ensure dev::h256 has std::hash specialization
    // Adding hash specialization for dev::h256 might be needed for std::unordered_map
    struct h256_hash { std::size_t operator()(const dev::h256& k) const { return std::hash<std::string>()(k.hex()); } }; // Example hash functor
    std::unordered_map<dev::h256, std::vector<TransactionReceiptInfo>, h256_hash> m_cache_result;
};

#endif // QTUM_STORAGERESULTS_H