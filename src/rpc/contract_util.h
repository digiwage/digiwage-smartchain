#ifndef CONTRACT_UTIL_H
#define CONTRACT_UTIL_H

#include <univalue.h>
#include <main.h>
#include <qtum/qtumtoken.h>
// <<< Needed for dev::Address, dev::bytes, dev::u256 >>>
#include <libdevcore/Common.h>
#include <libdevcore/FixedHash.h>
#include <set>      // Include for std::set
#include <vector>   // Include for std::vector
#include <boost/optional.hpp> // Include for boost::optional

class ChainstateManager;

// Forward declarations for types used below if not included via main.h/qtumtoken.h
// struct TransactionReceiptInfo; // Example if needed
// namespace dev { namespace eth { class LogEntry; } } // Example if needed

UniValue CallToContract(const UniValue& params, ChainstateManager &chainman);

UniValue SearchLogs(const UniValue& params, ChainstateManager &chainman);

void assignJSON(UniValue& entry, const TransactionReceiptInfo& resExec);

void assignJSON(UniValue& logEntry, const dev::eth::LogEntry& log,
        bool includeAddress);

void transactionReceiptInfoToJSON(const TransactionReceiptInfo& resExec, UniValue& entry);

size_t parseUInt(const UniValue& val, size_t defaultVal);

int parseBlockHeight(const UniValue& val, int defaultVal);

void parseParam(const UniValue& val, std::set<dev::h160> &h160s);

void parseParam(const UniValue& val, std::vector<boost::optional<dev::h256>> &h256s);

/**
 * @brief The CallToken class Read available token data
 */
class CallToken : public QtumTokenExec, public QtumToken
{
public: // <<< Make sure members are public if accessed directly >>>

    // === Add these missing members ===
    dev::Address contractAddress;
    dev::bytes data;
    dev::Address senderAddress;
    dev::u256 value = 0;
    dev::u256 gasLimit = 0;
    dev::u256 gasPrice = 0;
    // =================================

    CallToken();
    
    bool execValid(const int& func, const bool& sendTo) override;

    bool execEventsValid(const int &func, const int64_t &fromBlock) override;

    bool exec(const bool& sendTo, const std::map<std::string, std::string>& lstParams, std::string& result, std::string&) override;

    bool execEvents(const int64_t &fromBlock, const int64_t &toBlock, const int64_t &minconf, const std::string &eventName, const std::string &contractAddress, const std::string &senderAddress, const int &numTopics, std::vector<TokenEvent> &result) override;

    bool searchTokenTx(const int64_t &fromBlock, const int64_t &toBlock, const int64_t &minconf, const std::string &eventName, const std::string &contractAddress, const std::string &senderAddress, const int &numTopics, UniValue& resultVar);

    void setCheckGasForCall(bool value);

protected:

private:
    bool checkGasForCall = false;
};

#endif // CONTRACT_UTIL_H