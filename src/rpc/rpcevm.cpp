// ===========================================================================
// REVISED CODE FOR src/rpc/rpcevm.cpp (Addressing Compilation Errors)
// ===========================================================================

#include "rpc/server.h"
#include "base58.h"
#include "core_io.h"
#include "main.h"       // <<< Keep for pblocktree, potentially other globals if validation.h doesn't cover all
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h" // For ValueFromAmount
// #include "chainparams.h" // Included via validation.h or main.h typically, CURRENCY_UNIT removed below

// --- EVM Includes (Ensure paths are correct for DigiWage) ---
#include "qtum/qtumstate.h"
#include "qtum/storageresults.h"
#include "libdevcore/CommonData.h"
#include "libdevcore/Common.h"
// #include "qtum/qtumtransaction.h" // Keep commented until CallToContract is defined/ported

// --- Other includes ---
#include <stdint.h>
#include <sstream>
#include <univalue.h>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <algorithm>
#include <list> // For RPCTypeCheck list

// --- Forward Declarations & Globals ---
extern std::unique_ptr<QtumState> globalState;
extern std::unique_ptr<StorageResults> pstorageresult;
extern CBlockTreeDB* pblocktree;
extern bool fLogEvents;
// extern UniValue searchlogs(const UniValue& params, bool fHelp); // Moved to placeholder

// --- Globals for waitfor* ---
struct CUpdatedBlock { uint256 hash; int height; };
extern std::mutex cs_blockchange;
extern std::condition_variable cond_blockchange;
extern CUpdatedBlock latestblock;

// Forward declaration for the actual implementation function (assumed to exist elsewhere)
// *** Revised Signature: Removed ChainstateManager& parameter ***
// CallToContract needs access to cs_main and potentially globalState for simulation.
// The implementation needs to handle acquiring these resources itself.
extern UniValue CallToContract(const UniValue& params); // <<< Removed chainman parameter

// --------------------------------------------------------------------

// --- Helper Functions ---
dev::u256 pow10_u256(uint32_t n) {
    dev::u256 ret = 1; dev::u256 base = 10;
    while (n > 0) { if (n % 2 == 1) ret *= base; base *= base; n /= 2; }
    return ret;
}
inline uint160 DevH160ToUint160(const dev::h160& h160) {
    std::vector<unsigned char> dataBytes = h160.asBytes();
    // Use hardcoded size 20 instead of protected member uint160::WIDTH
    if (dataBytes.size() != 20) return uint160();
    try { return uint160(dataBytes); } catch (...) { return uint160(); }
    // Unreachable return removed
}
std::string FormatToken(const unsigned int& decimals, const dev::s256& n) { return n.str(); } // Placeholder
template <typename T> void parseParam(const UniValue& array, T& resultContainer) { /* Placeholder */ }

// --- Adapted RPC Functions ---

UniValue getaccountinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error( // Use std::runtime_error for help text throw
            "getaccountinfo \"address\"\n"
            "\nReturns balance, code and storage details for an account.\n"
            "\nArguments:\n"
            "1. \"address\"      (string, required) The account address (40-char hex string).\n"
            "\nResult:\n"
            "{\n"
            "  \"address\": \"hex\",       (string) The address of the account (same as input).\n"
            // --- Replaced CURRENCY_UNIT with hardcoded "DWG" ---
            "  \"balance\": amount,      (numeric) The balance of the account in DWG.\n"
            "  \"code\": \"hex\",          (string) The contract bytecode, if any.\n"
            "  \"storage\": {            (object) The account's storage map.\n"
            "    \"slot_hash\": {        (object) Storage entry.\n"
            "      \"internal_key?\": \"value_hash\"  (string) Key-value pair representing the storage data.\n"
            "     }, ...\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccountinfo", "\"eb23c0b3e6042821da281a2e2364feb22dd543e3\"")
            + HelpExampleRpc("getaccountinfo", "\"eb23c0b3e6042821da281a2e2364feb22dd543e3\"")
        );

    // Check parameter types
    RPCTypeCheck(params, {UniValue::VSTR});

    std::string strAddr = params[0].get_str();
    // Validate address format (40 hex characters)
    if (strAddr.size() != 40 || !IsHex(strAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address format: Must be a 40-character hexadecimal string.");

    dev::Address addrAccount;
    try {
        // Convert hex string to EVM address type
        addrAccount = dev::Address(strAddr);
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid address format: ") + e.what());
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", strAddr);

    LOCK(cs_main); // Lock critical section for accessing chain state
    {
        // Ensure globalState is initialized
        if (!globalState) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "EVM state database is not available.");
        }
        // Check if the address exists in the state
        if (!globalState->addressInUse(addrAccount)) {
             result.pushKV("balance", ValueFromAmount(0));
             result.pushKV("code", "");
             result.pushKV("storage", UniValue(UniValue::VOBJ));
             return result; // Return early if address not found
        }

        // Retrieve balance
        try {
            result.pushKV("balance", ValueFromAmount(CAmount(globalState->balance(addrAccount))));
        } catch (const std::exception& e) {
             LogPrintf("Error getting balance for %s: %s\n", strAddr, e.what());
             result.pushKV("balance", ValueFromAmount(0)); // Default to 0 on error
        }

        // Retrieve code
        try {
            result.pushKV("code", HexStr(globalState->code(addrAccount)));
        } catch (const std::exception& e) {
            LogPrintf("Error getting code for %s: %s\n", strAddr, e.what());
            result.pushKV("code", ""); // Default to empty string on error
        }

        // Retrieve storage
        UniValue storageUV(UniValue::VOBJ);
        try {
            auto storage = globalState->storage(addrAccount);
            for (const auto& entry : storage) {
                UniValue storageEntry(UniValue::VOBJ);
                storageEntry.pushKV(dev::toHex(dev::h256(entry.second.first)), dev::toHex(dev::h256(entry.second.second)));
                storageUV.pushKV(entry.first.hex(), storageEntry); // Use entry.first (slot hash) as key
            }
        } catch (const std::exception& e) {
            LogPrintf("Error getting storage for %s: %s\n", strAddr, e.what());
            // Leave storageUV as an empty object on error
        }
        result.pushKV("storage", storageUV);
    } // End LOCK(cs_main)
    return result;
}


UniValue getstorage(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error( // Use std::runtime_error for help text throw
            "getstorage \"address\" ( index )\n"
            "\nReturns storage data for a contract address.\n"
            "\nArguments:\n"
            "1. \"address\"      (string, required) The contract address (40-char hex string).\n"
            "2. index          (numeric, optional) The zero-based index of the storage entry (slot) to retrieve. If omitted, returns all storage slots.\n"
            "\nResult:\n"
             "{                         (object) Storage object\n"
             "  \"slot_hash\": {        (object) Storage entry.\n"
             "    \"internal_key?\": \"value_hash\"  (string) Key-value pair representing the storage data.\n"
             "   }, ...\n"
             "}\n"
             "If 'index' is specified, returns only the storage entry at that index.\n"
             "\nExamples:\n"
            + HelpExampleCli("getstorage", "\"eb23c0b3e6042821da281a2e2364feb22dd543e3\"")
            + HelpExampleCli("getstorage", "\"eb23c0b3e6042821da281a2e2364feb22dd543e3\" 0")
            + HelpExampleRpc("getstorage", "[\"eb23c0b3e6042821da281a2e2364feb22dd543e3\"]")
            + HelpExampleRpc("getstorage", "[\"eb23c0b3e6042821da281a2e2364feb22dd543e3\", 0]")
        );

    // Check parameter types, index is optional
    RPCTypeCheck(params, {UniValue::VSTR, UniValue::VNUM}, true);

    std::string strAddr = params[0].get_str();
    if (strAddr.size() != 40 || !IsHex(strAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address format: Must be a 40-character hexadecimal string.");

    dev::Address addrAccount;
     try {
         addrAccount = dev::Address(strAddr);
     } catch (const std::exception& e) {
         throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid address format: ") + e.what());
     }

    bool onlyIndex = false;
    unsigned index = 0;
    if (params.size() > 1 && !params[1].isNull()) {
         if (!params[1].isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, "index must be a number");
         // --- Use getInt<int64_t>() instead of get_int64() ---
         int64_t indexTmp = params[1].getInt<int64_t>();
         if (indexTmp < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Storage index cannot be negative");
         onlyIndex = true;
         index = static_cast<unsigned>(indexTmp);
    }

    UniValue result(UniValue::VOBJ);
    std::map<dev::h256, std::pair<dev::u256, dev::u256>> storage;

    LOCK(cs_main);
    {
        if (!globalState) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "EVM state database is not available.");
        }
        if (!globalState->addressInUse(addrAccount)) {
            return result; // Return empty object if address not found
        }

        QtumState* stateToUse = globalState.get();

        try {
            storage = stateToUse->storage(addrAccount);
        } catch (const std::exception& e) {
            LogPrintf("Error getting storage for %s: %s\n", strAddr, e.what());
            return result; // Return empty object on error retrieving storage
        }
    } // End LOCK(cs_main)

    if (storage.empty()) {
        return result; // Return empty object if storage map is empty
    }

    if (onlyIndex) {
        if (index >= storage.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Storage index %u is out of bounds (size: %d)", index, storage.size()));
        }
        auto it = std::next(storage.begin(), index);
        UniValue e(UniValue::VOBJ);
        e.pushKV(dev::toHex(dev::h256(it->second.first)), dev::toHex(dev::h256(it->second.second)));
        result.pushKV(it->first.hex(), e);
    } else {
        for (const auto& entry : storage) {
            UniValue e(UniValue::VOBJ);
            e.pushKV(dev::toHex(dev::h256(entry.second.first)), dev::toHex(dev::h256(entry.second.second)));
            result.pushKV(entry.first.hex(), e);
        }
    }
    return result;
}

// --- Replaced Placeholder Function ---

UniValue callcontract(const UniValue& params, bool fHelp) {
     if (fHelp || params.size() < 2 || params.size() > 5)
        throw std::runtime_error(
            "callcontract \"address\" \"data\" ( senderaddress gaslimit amount )\n"
            "\nCall contract methods offline, or test contract deployment offline.\n"
            "\nArguments:\n"
            "1. \"address\"        (string, required) The contract address (40-char hex), or empty string \"\" for creation.\n"
            "2. \"data\"           (string, required) The data hex string (bytecode for creation, encoded method call for execution).\n"
            "3. senderaddress    (string, optional) The sender address string (standard DigiWage address or 40-char hex). If omitted, a default or dummy address may be used.\n"
            "4. gaslimit         (numeric, optional) The gas limit for executing the contract. Default depends on implementation.\n"
            // --- Replaced CURRENCY_UNIT with hardcoded "DWG" ---
            "5. amount           (numeric or string, optional) The amount in DWG to send (e.g., 0.1). Default: 0.\n"
            "\nResult:\n"
            "{\n"
            "  \"address\": \"hex\",                 (string) The address of the contract (returned from execution, relevant for creation).\n"
            "  \"executionResult\": {              (object) The result of the execution.\n"
            "    \"gasUsed\": n,                   (numeric) Gas consumed.\n"
            "    \"excepted\": \"...\".             (string) Type of exception if thrown (e.g., 'OutOfGas', 'BadInstruction').\n"
            "    \"newAddress\": \"hex\",            (string) Address of newly created contract, if applicable.\n"
            "    \"output\": \"hex\",                (string) Return data from the contract call.\n"
            "    \"codeDeposit\": n,               (numeric) Code deposit cost (Qtum specific?).\n"
            "    \"gasRefunded\": n,               (numeric) Gas refunded.\n"
            "    \"depositSize\": n,               (numeric) Deposit size (Qtum specific?).\n"
            "    \"gasForDeposit\": n,             (numeric) Gas for deposit (Qtum specific?).\n"
            "    \"exceptedMessage\": \"...\"      (string) Additional message for the exception.\n"
            "  },\n"
            "  \"transactionReceipt\": {           (object) Simulated transaction receipt.\n"
            "    \"stateRoot\": \"hex\",             (string) State root hash after execution.\n"
            "    \"utxoRoot\": \"hex\",              (string) UTXO root hash (if applicable).\n"
            "    \"gasUsed\": n,                   (numeric) Total gas used for the simulated transaction.\n"
            "    \"bloom\": \"hex\",                 (string) Log bloom filter.\n"
            "    \"log\": [                        (array) Array of log entries.\n"
            "      {\n"
            "        \"address\": \"hex\",           (string) Contract address that emitted the log.\n"
            "        \"topics\": [\"hex\", ...],    (array) Indexed log topics.\n"
            "        \"data\": \"hex\"             (string) Non-indexed log data.\n"
            "      }, ...\n"
            "    ]\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("callcontract", "\"eb23c0b3e6042821da281a2e2364feb22dd543e3\" \"06fdde03\"") + "\n"
            + HelpExampleCli("callcontract", "\"\" \"60606040...5b600256\" \"DGYOURSENDERADDRESS\" 250000 0.5") + "\n"
            + HelpExampleRpc("callcontract", "[\"eb23c0b3e6042821da281a2e2364feb22dd543e3\", \"06fdde03\"]") + "\n"
            + HelpExampleRpc("callcontract", "[\"\", \"60606040...5b600256\", \"DGYOURSENDERADDRESS\", 250000, \"0.5\"]")
        );

    // Basic type checks for required params
    RPCTypeCheck(params, {UniValue::VSTR, UniValue::VSTR}, true); // Check first two, allow nulls for optionals

    // Manual type checks for optional parameters
    if (params.size() > 2 && !params[2].isNull() && !params[2].isStr()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "senderaddress must be a string");
    }
    if (params.size() > 3 && !params[3].isNull() && !params[3].isNum()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "gaslimit must be a number");
    }
    if (params.size() > 4 && !params[4].isNull() && !params[4].isNum() && !params[4].isStr()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "amount must be a number or string");
    }

    // --- Removed g_chainman/ChainstateManager logic ---
    // The CallToContract function is now responsible for accessing necessary state
    // (likely via cs_main lock and globalState)

    // Call the implementation function (needs porting/defining elsewhere)
    return CallToContract(params); // <<< Pass only params
}


// --- Placeholder Functions (With fixed help throws) ---
UniValue waitforlogs(const UniValue& params, bool fHelp) {
    if (fHelp) throw std::runtime_error(
        "waitforlogs ( fromBlock toBlock filter minconf )\n"
        "\nWait for logs matching a filter, then return matching logs.\n"
        "\nArguments:\n"
        "1. fromBlock      (numeric or string, optional, default=0) The block number to start searching from.\n"
        "2. toBlock        (numeric or string, optional, default=\"latest\") The block number to stop searching at.\n"
        "3. filter         (object, optional) Filter criteria for logs.\n"
        "    {\n"
        "      \"addresses\": [\"address\",...], (array, optional) Contracts to look for logs from.\n"
        "      \"topics\": [\"topic\",...]      (array, optional) Topics to filter by.\n"
        "    }\n"
        "4. minconf        (numeric, optional, default=1) Minimum confirmations the logs must have.\n"
        "\nResult:\n"
        "[ ... ]           (array) Array of log objects matching the filter (see searchlogs result format).\n"
        "\nExamples:\n"
        + HelpExampleCli("waitforlogs", "1000 \"latest\" '{\"addresses\":[\"aabbcc...\"]}' 6")
        + HelpExampleRpc("waitforlogs", "[1000, \"latest\", {\"addresses\":[\"aabbcc...\"]}, 6]")
        );
    if (params.size() > 4) throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters");
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "waitforlogs requires porting.");
}

// Forward declare searchlogs as it's used internally by waitforlogs (if implemented)
UniValue searchlogs(const UniValue& params, bool fHelp);

UniValue searchlogs(const UniValue& params, bool fHelp) {
    if (fHelp) throw std::runtime_error(
        "searchlogs fromBlock toBlock (addressFilter) (topicFilter) (minconf)\n"
        "\nSearch for logs matching criteria within a block range.\n"
        "\nArguments:\n"
        "1. fromBlock      (numeric or string, required) The block number or hash to start searching from.\n"
        "2. toBlock        (numeric or string, required) The block number or hash to stop searching at (e.g., \"latest\").\n"
        "3. addressFilter  (string or array, optional) A single contract address (hex) or an array of addresses to filter by.\n"
        "4. topicFilter    (array, optional) An array of topics to filter by. Topics are order-dependent.\n"
        "5. minconf        (numeric, optional, default=1) Minimum confirmations the logs must have.\n"
        "\nResult:\n"
        "[                 (array) Array of log objects.\n"
        "  {\n"
        "    \"blockNumber\": n,          (numeric) Block number containing the log.\n"
        "    \"blockHash\": \"hex\",      (string) Hash of the block.\n"
        "    \"transactionHash\": \"hex\",(string) Hash of the transaction that created the log.\n"
        "    \"transactionIndex\": n,   (numeric) Index of the transaction within the block.\n"
        "    \"logIndex\": n,           (numeric) Index of the log within the transaction receipt.\n"
        "    \"address\": \"hex\",        (string) Address of the contract that emitted the log.\n"
        "    \"topics\": [\"hex\", ...], (array) Array of log topics.\n"
        "    \"data\": \"hex\",           (string) Log data.\n"
        "    \"removed\": bool          (boolean) True if log was removed due to reorg, false otherwise.\n"
        "  }, ...\n"
        "]\n"
        "\nExamples:\n"
        + HelpExampleCli("searchlogs", "1000 1100 '[\"aabbcc...\"]' '[\"topic0hex\", null, \"topic2hex\"]'")
        + HelpExampleRpc("searchlogs", "[1000, \"latest\", \"aabbcc...\", [\"topic0hex\"]], 6")
        );
    if (params.size() < 2 || params.size() > 5) throw JSONRPCError(RPC_INVALID_PARAMETER, "Incorrect number of parameters (expected 2 to 5)");
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "searchlogs requires porting.");
}

UniValue gettransactionreceipt(const UniValue& params, bool fHelp) {
    if (fHelp) throw std::runtime_error(
        "gettransactionreceipt \"txid\"\n"
        "\nGet the transaction receipt for a given transaction ID.\n"
        "Note: This only works for transactions that involve EVM execution (contract calls, creations, or sends to contracts).\n"
        "\nArguments:\n"
        "1. \"txid\"         (string, required) The hash of the transaction.\n"
        "\nResult:\n"
        "[\n"
        "  {\n"
        "    \"transactionHash\": \"hex\", (string) Hash of the transaction.\n"
        "    \"transactionIndex\": n,    (numeric) Integer of the transactions index position in the block.\n"
        "    \"blockHash\": \"hex\",       (string) Hash of the block where this transaction was in.\n"
        "    \"blockNumber\": n,         (numeric) Block number where this transaction was in.\n"
        "    \"from\": \"hex\",            (string) Address of the sender.\n"
        "    \"to\": \"hex\",              (string) Address of the receiver. Null when its a contract creation transaction.\n"
        "    \"cumulativeGasUsed\": n,   (numeric) The total amount of gas used when this transaction was executed in the block.\n"
        "    \"gasUsed\": n,             (numeric) The amount of gas used by this specific transaction alone.\n"
        "    \"contractAddress\": \"hex\", (string) The contract address created, if the transaction was a contract creation, otherwise null.\n"
        "    \"logsBloom\": \"hex\",       (string) Bloom filter for light clients to quickly retrieve related logs.\n"
        "    \"logs\": [ ... ],          (array) Array of log objects, which were created during the execution of the transaction. (See searchlogs format).\n"
        "    \"excepted\": \"...\",        (string) Exception status, if any (e.g., 'None', 'OutOfGas').\n"
        "    \"output\": \"hex\"           (string) EVM execution output (Qtum specific extension?).\n"
        "  }\n"
        "]\n"
        "\nExamples:\n"
        + HelpExampleCli("gettransactionreceipt", "\"txhashhex...\"")
        + HelpExampleRpc("gettransactionreceipt", "[\"txhashhex...\"]")
        );
    if (params.size() != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected 1 parameter: transaction hash");
    RPCTypeCheck(params, {UniValue::VSTR});
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "gettransactionreceipt requires porting.");
}

UniValue listcontracts(const UniValue& params, bool fHelp) {
    if (fHelp) throw std::runtime_error(
        "listcontracts ( start maxDisplay )\n"
        "\nList contracts recorded in the state database.\n"
        "\nArguments:\n"
        "1. start        (numeric, optional, default=1) The starting index (1-based) of contracts to display.\n"
        "2. maxDisplay   (numeric, optional, default=20) The maximum number of contracts to display.\n"
        "\nResult:\n"
        "{\n"
        // --- Replaced CURRENCY_UNIT with hardcoded "DWG" ---
        "  \"address_hex\": balance_DWG, ...\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("listcontracts", "")
        + HelpExampleCli("listcontracts", "101 50")
        + HelpExampleRpc("listcontracts", "[101, 50]")
        );
    if (params.size() > 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters (expected 0 to 2)");
    RPCTypeCheck(params, {UniValue::VNUM, UniValue::VNUM}, true); // Check types if present
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "listcontracts requires porting.");
}

// --- Placeholder QRC20 Functions ---

UniValue qrc20name(const UniValue& params, bool fHelp) {
     if (fHelp) throw std::runtime_error(
        "qrc20name \"contractaddress\"\n"
        "\nGet the name of a QRC20 token.\n"
        "\nArguments:\n"
        "1. \"contractaddress\" (string, required) The QRC20 contract address (40-char hex).\n"
        "\nResult:\n"
        "\"name\"            (string) The token name.\n"
        "\nExamples:\n"
        + HelpExampleCli("qrc20name", "\"aabbcc...\"")
        + HelpExampleRpc("qrc20name", "[\"aabbcc...\"]")
        );
     if (params.size() != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected 1 parameter: contract address");
     RPCTypeCheck(params, {UniValue::VSTR});
     throw JSONRPCError(RPC_METHOD_NOT_FOUND, "qrc20name requires porting.");
}
UniValue qrc20symbol(const UniValue& params, bool fHelp) {
     if (fHelp) throw std::runtime_error(
        "qrc20symbol \"contractaddress\"\n"
        "\nGet the symbol of a QRC20 token.\n"
        "\nArguments:\n"
        "1. \"contractaddress\" (string, required) The QRC20 contract address (40-char hex).\n"
        "\nResult:\n"
        "\"symbol\"          (string) The token symbol.\n"
        "\nExamples:\n"
        + HelpExampleCli("qrc20symbol", "\"aabbcc...\"")
        + HelpExampleRpc("qrc20symbol", "[\"aabbcc...\"]")
        );
      if (params.size() != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected 1 parameter: contract address");
      RPCTypeCheck(params, {UniValue::VSTR});
     throw JSONRPCError(RPC_METHOD_NOT_FOUND, "qrc20symbol requires porting.");
}
UniValue qrc20decimals(const UniValue& params, bool fHelp) {
     if (fHelp) throw std::runtime_error(
        "qrc20decimals \"contractaddress\"\n"
        "\nGet the number of decimals a QRC20 token uses.\n"
        "\nArguments:\n"
        "1. \"contractaddress\" (string, required) The QRC20 contract address (40-char hex).\n"
        "\nResult:\n"
        "n                 (numeric) The number of decimals.\n"
        "\nExamples:\n"
        + HelpExampleCli("qrc20decimals", "\"aabbcc...\"")
        + HelpExampleRpc("qrc20decimals", "[\"aabbcc...\"]")
        );
      if (params.size() != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected 1 parameter: contract address");
      RPCTypeCheck(params, {UniValue::VSTR});
     throw JSONRPCError(RPC_METHOD_NOT_FOUND, "qrc20decimals requires porting.");
}
UniValue qrc20totalsupply(const UniValue& params, bool fHelp) {
     if (fHelp) throw std::runtime_error(
        "qrc20totalsupply \"contractaddress\"\n"
        "\nGet the total supply of a QRC20 token.\n"
        "\nArguments:\n"
        "1. \"contractaddress\" (string, required) The QRC20 contract address (40-char hex).\n"
        "\nResult:\n"
        "\"supply\"          (string) The total supply as a string (to handle large numbers).\n"
        "\nExamples:\n"
        + HelpExampleCli("qrc20totalsupply", "\"aabbcc...\"")
        + HelpExampleRpc("qrc20totalsupply", "[\"aabbcc...\"]")
        );
      if (params.size() != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected 1 parameter: contract address");
      RPCTypeCheck(params, {UniValue::VSTR});
     throw JSONRPCError(RPC_METHOD_NOT_FOUND, "qrc20totalsupply requires porting.");
}
UniValue qrc20balanceof(const UniValue& params, bool fHelp) {
     if (fHelp) throw std::runtime_error(
        "qrc20balanceof \"contractaddress\" \"owneraddress\"\n"
        "\nGet the QRC20 token balance of a specific address.\n"
        "\nArguments:\n"
        "1. \"contractaddress\" (string, required) The QRC20 contract address (40-char hex).\n"
        "2. \"owneraddress\"    (string, required) The address to check the balance of (40-char hex).\n"
        "\nResult:\n"
        "\"balance\"         (string) The token balance as a string (to handle large numbers).\n"
        "\nExamples:\n"
        + HelpExampleCli("qrc20balanceof", "\"aabbcc...\" \"112233...\"")
        + HelpExampleRpc("qrc20balanceof", "[\"aabbcc...\", \"112233...\"]")
        );
      if (params.size() != 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected 2 parameters: contract address, owner address");
      RPCTypeCheck(params, {UniValue::VSTR, UniValue::VSTR});
     throw JSONRPCError(RPC_METHOD_NOT_FOUND, "qrc20balanceof requires porting.");
}
UniValue qrc20allowance(const UniValue& params, bool fHelp) {
     if (fHelp) throw std::runtime_error(
        "qrc20allowance \"contractaddress\" \"owneraddress\" \"spenderaddress\"\n"
        "\nGet the amount of QRC20 tokens an owner has allowed a spender to withdraw.\n"
        "\nArguments:\n"
        "1. \"contractaddress\" (string, required) The QRC20 contract address (40-char hex).\n"
        "2. \"owneraddress\"    (string, required) The address of the token owner (40-char hex).\n"
        "3. \"spenderaddress\"  (string, required) The address of the spender (40-char hex).\n"
        "\nResult:\n"
        "\"allowance\"       (string) The allowed amount as a string (to handle large numbers).\n"
        "\nExamples:\n"
        + HelpExampleCli("qrc20allowance", "\"aabbcc...\" \"ownerhex...\" \"spenderhex...\"")
        + HelpExampleRpc("qrc20allowance", "[\"aabbcc...\", \"ownerhex...\", \"spenderhex...\"]")
        );
      if (params.size() != 3) throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected 3 parameters: contract address, owner address, spender address");
      RPCTypeCheck(params, {UniValue::VSTR, UniValue::VSTR, UniValue::VSTR});
     throw JSONRPCError(RPC_METHOD_NOT_FOUND, "qrc20allowance requires porting.");
}
UniValue qrc20listtransactions(const UniValue& params, bool fHelp) {
     if (fHelp) throw std::runtime_error(
        "qrc20listtransactions \"contractaddress\" \"targetaddress\" (fromBlock) (minconf)\n"
        "\nList QRC20 'Transfer' event logs related to a specific address.\n"
        "\nArguments:\n"
        "1. \"contractaddress\" (string, required) The QRC20 contract address (40-char hex).\n"
        "2. \"targetaddress\"   (string, required) The address to search for transfers involving (as sender or receiver) (40-char hex).\n"
        "3. fromBlock         (numeric or string, optional, default=0) Block height or hash to start search from.\n"
        "4. minconf           (numeric, optional, default=1) Minimum confirmations required for the logs.\n"
        "\nResult:\n"
        "[ ... ]              (array) Array of log objects matching the Transfer event signature and target address (see searchlogs result format).\n"
        "\nExamples:\n"
        + HelpExampleCli("qrc20listtransactions", "\"aabbcc...\" \"112233...\" 10000 6")
        + HelpExampleRpc("qrc20listtransactions", "[\"aabbcc...\", \"112233...\", 10000, 6]")
        );
      if (params.size() < 2 || params.size() > 4) throw JSONRPCError(RPC_INVALID_PARAMETER, "Incorrect number of parameters (expected 2 to 4)");
      // --- Corrected RPCTypeCheck and added manual checks ---
      RPCTypeCheck(params, {UniValue::VSTR, UniValue::VSTR}, true); // Check required params, allow null for optionals
      if (params.size() > 2 && !params[2].isNull()) { // Check optional fromBlock
          if (!params[2].isNum() && !params[2].isStr()) {
              throw JSONRPCError(RPC_TYPE_ERROR, "fromBlock must be a number or string");
          }
      }
      if (params.size() > 3 && !params[3].isNull()) { // Check optional minconf
           if (!params[3].isNum()) {
               throw JSONRPCError(RPC_TYPE_ERROR, "minconf must be a number");
           }
      }
     throw JSONRPCError(RPC_METHOD_NOT_FOUND, "qrc20listtransactions requires porting.");
}

