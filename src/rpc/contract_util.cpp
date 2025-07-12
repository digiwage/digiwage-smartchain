// Copyright (c) 2017-2021 The Qtum Core developers
// Copyright (c) 2023-2024 The DigiWage developers (Adaptation for older base)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/contract_util.h>

// Core Bitcoin / DigiWage headers
#include <util.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h> // For CheckHex, ParseHex, HexStr
#include <rpc/server.h>      // For AmountFromValue, ValueFromAmount etc.
#include <rpc/protocol.h>    // <<< Explicitly include for JSONRPCError definition >>>
#include <txdb.h>            // For CBlockTreeDB, pblocktree
#include <main.h>      // For chainActive, cs_main, pcoinsTip, CallContract? Check specific includes.
#include <sync.h>            // For LOCK, cs_main, RecursiveMutex

// Qtum specific headers (ensure these exist and are correct)
#include <qtum/qtumstate.h>
#include <qtum/storageresults.h>
#include <qtum/qtumtransaction.h> // For QtumTransactionReceipt if needed by transactionReceiptToJSON, Constants

// Libdevcore / Libethereum headers
#include <libdevcore/Common.h>
#include <libdevcore/FixedHash.h>
#include <libethcore/LogEntry.h> // For dev::eth::LogEntry
#include <libethereum/TransactionReceipt.h> // For dev::eth::ExecutionResult ? Check includes

// Standard C++
#include <sstream>
#include <algorithm>
#include <vector>
#include <set>
#include <memory> // For std::unique_ptr if globalState uses it
#include <limits> // For numeric_limits
#include <cstring> // For memcpy/memset
#include <stdexcept> // For std::exception

// === Global variables assumed from DigiWage base (Verify these exist!) ===
// extern CChain chainActive;
// extern CCoinsViewCache* pcoinsTip;
// extern CBlockTreeDB* pblocktree;
// extern RecursiveMutex cs_main;
struct CUpdatedBlock; // Forward declaration
extern CUpdatedBlock latestblock;
extern bool fLogEvents;
extern std::unique_ptr<QtumState> globalState;
extern std::unique_ptr<StorageResults> pstorageresult;
extern bool fRecordLogOpcodes;
// =======================================================================

// === Helper function declarations assumed to exist (Verify!) ===
extern void writeVMlog(const std::vector<ResultExecute>&, const CTransaction&, const CBlock&);
extern std::vector<ResultExecute> CallContract(const dev::Address& addrContract, std::vector<unsigned char> opcode, const dev::Address& sender, uint64_t gasLimit, CAmount nAmount);
extern std::string exceptedMessage(const dev::eth::TransactionException&, const dev::bytes&);
extern void ToQtumAddress(const std::string& hexAddr, std::string& qtumAddr);
extern dev::u256 ToUint256(const std::string&);
extern bool ParseFixedPoint(const std::string& val, int decimals, int64_t* amount_out);
// ==============================================================


UniValue executionResultToJSON(const dev::eth::ExecutionResult& exRes)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("gasUsed", ValueFromAmount(CAmount(exRes.gasUsed)));
    std::stringstream ss;
    ss << exRes.excepted;
    result.pushKV("excepted", ss.str());
    result.pushKV("newAddress", exRes.newAddress.hex());
    result.pushKV("output", HexStr(exRes.output));
    result.pushKV("codeDeposit", static_cast<int32_t>(exRes.codeDeposit));
    result.pushKV("gasRefunded", ValueFromAmount(CAmount(exRes.gasRefunded)));
    result.pushKV("depositSize", static_cast<int32_t>(exRes.depositSize));
    result.pushKV("gasForDeposit", ValueFromAmount(CAmount(exRes.gasForDeposit)));
    result.pushKV("exceptedMessage", exceptedMessage(exRes.excepted, exRes.output));
    return result;
}

UniValue transactionReceiptToJSON(const QtumTransactionReceipt& txRec)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("stateRoot", txRec.stateRoot().hex());
    //result.pushKV("utxoRoot", txRec.utxoRoot().hex());
    result.pushKV("gasUsed", ValueFromAmount(CAmount(txRec.cumulativeGasUsed())));
    result.pushKV("bloom", txRec.bloom().hex());
    UniValue logEntries(UniValue::VARR);
    for(const dev::eth::LogEntry& log : txRec.log()){
        UniValue logEntrie(UniValue::VOBJ);
        logEntrie.pushKV("address", log.address.hex());
        UniValue topics(UniValue::VARR);
        for(const dev::h256& l : log.topics){
            topics.push_back(l.hex());
        }
        logEntrie.pushKV("topics", topics);
        logEntrie.pushKV("data", HexStr(log.data));
        logEntries.push_back(logEntrie);
    }
    result.pushKV("log", logEntries);
    return result;
}

UniValue CallToContract(const UniValue& params)
{
    LOCK(cs_main);

    if (params.size() < 2)
         throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing parameters: address and data required");

    std::string strAddr = params[0].get_str();
    std::string data = params[1].get_str();

    if(data.size() % 2 != 0 || !IsHex(data))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid data (data not hex)");

    dev::Address addrAccount;
    if(strAddr.size() > 0)
    {
        if(strAddr.size() != 40 || !IsHex(strAddr))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect address format");

        addrAccount = dev::Address(ParseHex(strAddr));
        if(!globalState || !globalState->addressInUse(addrAccount))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not exist");
    } else {
         throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing contract address");
    }

    dev::Address senderAddress;
    if (params.size() > 2 && !params[2].isNull()){
        std::string senderStr = params[2].get_str();
         if(senderStr.size() != 40 || !IsHex(senderStr))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect sender address format");
        senderAddress = dev::Address(ParseHex(senderStr));
    }

    uint64_t gasLimit = DEFAULT_GAS_LIMIT_OP_SEND;
    if(params.size() > 3 && !params[3].isNull()){
        int64_t gl = params[3].getInt<int64_t>();
        if (gl < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Gas limit cannot be negative");
        gasLimit = (uint64_t)gl;
    }

    CAmount nAmount = 0;
    if (params.size() > 4 && !params[4].isNull()){
        nAmount = AmountFromValue(params[4]);
        if (nAmount < 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send (must be non-negative)");
    }

    if (!pcoinsTip) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "UTXO set (pcoinsTip) is not available.");
    }
    std::vector<ResultExecute> execResults = CallContract(addrAccount, ParseHex(data), senderAddress, gasLimit, nAmount);

    // Commented out writeVMlog call
    // if(fRecordLogOpcodes){ ... }

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", strAddr);
    if (!execResults.empty()) {
        result.pushKV("executionResult", executionResultToJSON(execResults[0].execRes));
        result.pushKV("transactionReceipt", transactionReceiptToJSON(execResults[0].txRec));
    } else {
        result.pushKV("executionResult", NullUniValue);
        result.pushKV("transactionReceipt", NullUniValue);
        result.pushKV("error", "CallContract execution failed or returned no results.");
    }

    return result;
}

void assignJSON(UniValue& entry, const TransactionReceiptInfo& resExec) {
    entry.pushKV("blockHash", resExec.blockHash.GetHex());
    entry.pushKV("blockNumber", uint64_t(resExec.blockNumber));
    entry.pushKV("transactionHash", resExec.transactionHash.GetHex());
    entry.pushKV("transactionIndex", uint64_t(resExec.transactionIndex));
    entry.pushKV("from", resExec.from.hex());
    entry.pushKV("to", resExec.to.hex());
    entry.pushKV("cumulativeGasUsed", ValueFromAmount(CAmount(resExec.cumulativeGasUsed)));
    entry.pushKV("gasUsed", ValueFromAmount(CAmount(resExec.gasUsed)));
    entry.pushKV("contractAddress", resExec.contractAddress.hex());
    std::stringstream ss;
    ss << resExec.excepted;
    entry.pushKV("excepted",ss.str());
    entry.pushKV("bloom", resExec.bloom.hex());
    entry.pushKV("stateRoot", resExec.stateRoot.hex());
}

void assignJSON(UniValue& logEntry, const dev::eth::LogEntry& log,
        bool includeAddress) {
    if (includeAddress) {
        logEntry.pushKV("address", log.address.hex());
    }

    UniValue topics(UniValue::VARR);
    for (const dev::h256& hash : log.topics) {
        topics.push_back(hash.hex());
    }
    logEntry.pushKV("topics", topics);
    logEntry.pushKV("data", HexStr(log.data));
}

void transactionReceiptInfoToJSON(const TransactionReceiptInfo& resExec, UniValue& entry) {
    assignJSON(entry, resExec); // Assign basic receipt fields

    const auto& logs = resExec.logs;
    UniValue logEntries(UniValue::VARR);
    for(const auto& log : logs){ // log here is dev::eth::LogEntry
        UniValue logEntryJSON(UniValue::VOBJ);
        assignJSON(logEntryJSON, log, true); // Call specific overload
        logEntries.push_back(logEntryJSON);
    }
    entry.pushKV("log", logEntries);
}

size_t parseUInt(const UniValue& val, size_t defaultVal) {
    if (val.isNull()) return defaultVal;
    int64_t n = val.getInt<int64_t>();
    if (n < 0) throw JSONRPCError(RPC_INVALID_PARAMS, "Expects unsigned integer");
    if (n > (int64_t)std::numeric_limits<size_t>::max()) throw JSONRPCError(RPC_INVALID_PARAMS, "Integer is too large for size_t");
    return (size_t)n;
}

int parseBlockHeight(const UniValue& val) {
    if (val.isStr()) {
        auto blockKey = val.get_str();
        if (blockKey == "latest" || blockKey == "pending") {
             LOCK(cs_main);
             if (!chainActive.Tip()) throw JSONRPCError(RPC_INTERNAL_ERROR, "Chain tip is not available");
            return chainActive.Height();
        } else if (blockKey == "earliest") { return 0; }
        else {
             if (blockKey.substr(0, 2) == "0x" && IsHex(blockKey)) {
                 try {
                    long long llHeight = std::stoll(blockKey, nullptr, 16);
                    if (llHeight < 0 || llHeight > std::numeric_limits<int>::max()) throw JSONRPCError(RPC_INVALID_PARAMS, "Hex block number out of range");
                    return (int)llHeight;
                 } catch (const std::exception& e) { throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid hex block number: ") + e.what()); } }
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid block string specifier (use 'latest', 'earliest', 'pending', or hex '0x...')"); }}
    if (val.isNum()) {
        int64_t blockHeightLL = val.getInt<int64_t>();
        if (blockHeightLL < 0 || blockHeightLL > std::numeric_limits<int>::max()) throw JSONRPCError(RPC_INVALID_PARAMS, "Block height out of range");
        return (int)blockHeightLL; }
    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid block number type (expected string or number)");
}

int parseBlockHeight(const UniValue& val, int defaultVal) {
    if (val.isNull()) return defaultVal;
    return parseBlockHeight(val);
}

dev::h160 parseParamH160(const UniValue& val) {
    if (!val.isStr()) throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 160: not a string");
    auto addrStr = val.get_str();
    if (addrStr.length() != 40 || !IsHex(addrStr)) throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 160 string: incorrect format or length");
    try { return dev::h160(ParseHex(addrStr)); }
    catch (const std::exception& e) { throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Failed to parse hex 160 string: ") + e.what()); }
}

void parseParam(const UniValue& val, std::vector<dev::h160> &h160s) {
    if (val.isNull()) return;
    if (val.isStr()) { h160s.push_back(parseParamH160(val)); return; }
    if (!val.isArray()) throw JSONRPCError(RPC_INVALID_PARAMS, "Expected an array of hex 160 strings or a single hex 160 string");
    auto vals = val.getValues(); h160s.reserve(vals.size());
    for(const auto& item : vals) h160s.push_back(parseParamH160(item));
}

void parseParam(const UniValue& val, std::set<dev::h160> &h160s) {
    std::vector<dev::h160> v; parseParam(val, v); h160s.insert(v.begin(), v.end());
}

dev::h256 parseParamH256(const UniValue& val) {
     if (!val.isStr()) throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 256: not a string");
    auto addrStr = val.get_str();
    if (addrStr.length() != 64 || !IsHex(addrStr)) throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex 256 string: incorrect format or length");
    try { return dev::h256(ParseHex(addrStr)); }
    catch (const std::exception& e) { throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Failed to parse hex 256 string: ") + e.what()); }
}

void parseParam(const UniValue& val, std::vector<boost::optional<dev::h256>> &h256s) {
    if (val.isNull()) return;
    if (!val.isArray()) throw JSONRPCError(RPC_INVALID_PARAMS, "Expected an array of hex 256 strings (or null elements)");
    auto vals = val.getValues(); h256s.reserve(vals.size());
    for(const auto& item : vals) {
        if (item.isNull()) h256s.push_back(boost::optional<dev::h256>());
        else h256s.push_back(boost::optional<dev::h256>(parseParamH256(item)));
    }
}

class SearchLogsParams {
public:
    size_t fromBlock;
    size_t toBlock;
    size_t minconf;
    std::set<dev::h160> addresses;
    std::vector<boost::optional<dev::h256>> topics;
    SearchLogsParams(const UniValue& params);
private:
    void setFromBlock(const UniValue& val);
    void setToBlock(const UniValue& val);
};

SearchLogsParams::SearchLogsParams(const UniValue& params) {
    LOCK(cs_main);
    if (params.size() < 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing required parameters: fromBlock and toBlock");
    setFromBlock(params[0]);
    setToBlock(params[1]);
    if (params.size() > 2 && params[2].isObject() && params[2].exists("addresses")) parseParam(params[2]["addresses"], addresses);
    if (params.size() > 3 && params[3].isObject() && params[3].exists("topics")) parseParam(params[3]["topics"], topics);
    minconf = (params.size() > 4) ? parseUInt(params[4], 0) : 0;
}

void SearchLogsParams::setFromBlock(const UniValue& val) {
    int height = parseBlockHeight(val, 0);
    if (height < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "fromBlock cannot be negative");
    fromBlock = (size_t)height;
}

void SearchLogsParams::setToBlock(const UniValue& val) {
    int height = parseBlockHeight(val, -1);
    if (height < 0) {
        if (!chainActive.Tip()) throw JSONRPCError(RPC_INTERNAL_ERROR, "Chain tip not available for default toBlock");
        toBlock = (size_t)chainActive.Height();
    } else {
        toBlock = (size_t)height;
    }
}

UniValue SearchLogs(const UniValue& _params)
{
    if(!fLogEvents) throw JSONRPCError(RPC_MISC_ERROR, "Events indexing disabled (-logevents=0)");
    if (!pblocktree) throw JSONRPCError(RPC_INTERNAL_ERROR, "Block tree database (pblocktree) is not available.");
    if (!pstorageresult) throw JSONRPCError(RPC_INTERNAL_ERROR, "Log storage database (pstorageresult) is not available.");

    UniValue result(UniValue::VARR);
    LOCK(cs_main);
    SearchLogsParams params(_params);
    if (params.fromBlock > params.toBlock) return result;

    std::vector<std::vector<uint256>> hashesToBlock;
    LogPrintf("SearchLogs: Skipping CBlockTreeDB::ReadHeightIndex call - requires replacement logic.\n");
    // int highestBlockChecked = pblocktree->ReadHeightIndex(params.fromBlock, params.toBlock, params.minconf, hashesToBlock, params.addresses);
    // if (highestBlockChecked == -1) return result;

    auto filterTopics = params.topics;
    std::set<uint256> dupes;

    for(const auto& hashesTx : hashesToBlock) { // This loop won't run currently
        for(const auto& e : hashesTx) {
            if(dupes.count(e)) continue;
            dupes.insert(e);
            std::vector<TransactionReceiptInfo> receipts;
            try {
                receipts = pstorageresult->getResult(uintToh256(e));
            } catch (const std::exception& db_exc) {
                 std::string txHashStr = e.GetHex(); // <<< Convert hash to string first
                 LogPrintf("ERROR: SearchLogs - Failed to get receipt for tx %s: %s\n", txHashStr, db_exc.what()); // <<< Use string variable
                 continue;
            }
            for(const auto& receipt : receipts) {
                for (const auto& log: receipt.logs) {
                    bool topicMatch = true; // <<< Declare topicMatch HERE
                    if (!filterTopics.empty()) {
                        if (log.topics.size() < filterTopics.size()) topicMatch = false;
                        else {
                            for (size_t i = 0; i < filterTopics.size(); i++) {
                                if (filterTopics[i] && filterTopics[i].get() != log.topics[i]) {
                                    topicMatch = false;
                                    break;
                                }
                            } // End topic checking loop
                        } // End else (sizes match or log has more)
                    } // End topic filtering check

                    if (topicMatch) { // <<< USE topicMatch HERE
                        UniValue logEntry(UniValue::VOBJ);
                        assignJSON(logEntry, receipt); // Assign receipt info
                        assignJSON(logEntry, log, true); // Assign log info (address, topics, data)
                        result.push_back(logEntry);
                    } // End topicMatch block
                } // End log loop
            } // End receipt loop
        } // End tx loop
    } // End block loop

    return result;
} // <<< CORRECTED END OF SearchLogs FUNCTION >>>


CallToken::CallToken() {}

bool CallToken::execValid(const int &, const bool &sendTo) { return !sendTo; }

bool CallToken::execEventsValid(const int &func, const int64_t &fromBlock) { return func != -1 && fromBlock >= 0; }

bool CallToken::exec(const bool &sendTo, const std::map<std::string, std::string> &lstParams, std::string &result, std::string & error_msg)
{
    if(sendTo) return false;
    UniValue params(UniValue::VARR);
    std::string contractAddrStr, dataStr, senderStr, gasLimitStr;
    auto it = lstParams.find(paramAddress()); if(it != lstParams.end()) params.push_back(it->second); else { error_msg = "Missing contract address"; return false; }
    it = lstParams.find(paramDatahex()); if(it != lstParams.end()) params.push_back(it->second); else { error_msg = "Missing data hex"; return false; }
    it = lstParams.find(paramSender()); if(it != lstParams.end()) { if(params.size()!=2){error_msg="Sender address order error";return false;} params.push_back(it->second); } else { if(params.size()==2) params.push_back(NullUniValue); }
    if(checkGasForCall) { it = lstParams.find(paramGasLimit()); if(it != lstParams.end()) { if(params.size()!=3){error_msg="Gas limit order error";return false;} try { UniValue g(UniValue::VNUM); int64_t v=std::stoll(it->second); if(v<0)throw std::runtime_error("Neg gas"); g.setInt(v); params.push_back(g); } catch (const std::exception& e) { error_msg=std::string("Invalid gas: ")+e.what(); return false;} } else { if(params.size()==3) params.push_back(NullUniValue); } } else { if(params.size()==3) params.push_back(NullUniValue); }
    if(params.size()==4) params.push_back(UniValue(0.0)); // Amount 0
    try {
        UniValue response = CallToContract(params);
        if(!response.isObject() || !response.exists("executionResult")) { error_msg = "CallToContract failed"; return false; }
        const UniValue& execRes = response["executionResult"];
        if (execRes.exists("excepted") && execRes["excepted"].get_str() != "None") { error_msg = "Exec reverted: "+execRes["exceptedMessage"].get_str(); result=""; return false; }
        if(!execRes.isObject() || !execRes.exists("output")) { error_msg = "Missing output"; return false; }
        result = execRes["output"].get_str(); return true;
    // <<< CORRECTED catch blocks >>>
    } catch (const UniValue& jsonRpcError) {
        error_msg = std::string("RPC Error: ") + jsonRpcError.write();
        return false;
    } catch (const std::exception& e) {
        error_msg = std::string("Exception: ") + e.what();
        return false;
    } catch (...) {
        error_msg = "Unknown exception";
        return false;
    }
}

bool CallToken::execEvents(const int64_t &fromBlock, const int64_t &toBlock, const int64_t& minconf, const std::string &eventName, const std::string &contractAddress, const std::string &senderAddress, const int &numTopics, std::vector<TokenEvent> &result)
{
    UniValue resultVar;
    if(!searchTokenTx(fromBlock, toBlock, minconf, eventName, contractAddress, senderAddress, numTopics, resultVar)) return false;
    if (!resultVar.isArray()) { LogPrintf("CallToken::execEvents: searchTokenTx failed\n"); return false; }
    const UniValue& list = resultVar.get_array();
    for(size_t i = 0; i < list.size(); i++) {
        const UniValue& eventLog = list[i].get_obj();
        if (!eventLog.exists("topics") || !eventLog["topics"].isArray() || !eventLog.exists("data")) continue;
        const UniValue& topicsList = eventLog["topics"].get_array();
        if(topicsList.empty() || !topicsList[0].isStr() || topicsList[0].get_str() != eventName) continue;
        if(topicsList.size() < (size_t)numTopics) continue;
        TokenEvent tokenEvent;
        if (!eventLog.exists("address") || !eventLog["address"].isStr()) continue;
        tokenEvent.address = eventLog["address"].get_str();
        try {
            if(numTopics > 1 && topicsList[1].isStr()) { dev::h160 h=dev::h160(dev::h256(ParseHex(topicsList[1].get_str()))); ToQtumAddress(h.hex(), tokenEvent.sender); }
            if(numTopics > 2 && topicsList[2].isStr()) { dev::h160 h=dev::h160(dev::h256(ParseHex(topicsList[2].get_str()))); ToQtumAddress(h.hex(), tokenEvent.receiver); }
        } catch (const std::exception& e) { LogPrintf("Evt parse topic err: %s\n", e.what()); continue; }
        if (!eventLog.exists("blockHash") || !eventLog.exists("blockNumber") || !eventLog.exists("transactionHash")) continue;
        tokenEvent.blockHash = uint256S(eventLog["blockHash"].get_str());
        tokenEvent.blockNumber = eventLog["blockNumber"].getInt<int64_t>();
        tokenEvent.transactionHash = uint256S(eventLog["transactionHash"].get_str());
        if (eventLog["data"].isStr()) { try { tokenEvent.value = ToUint256(eventLog["data"].get_str()); } catch (const std::exception& e) { LogPrintf("Evt parse data err: %s\n", e.what()); continue; } }
        else continue;
        result.push_back(tokenEvent);
    }
    return true;
}

bool CallToken::searchTokenTx(const int64_t &fromBlock, const int64_t &toBlock, const int64_t &minconf, const std::string &eventName, const std::string &contractAddress, const std::string &senderAddress, const int &numTopics, UniValue &resultVar)
{
    UniValue params(UniValue::VARR);
    params.push_back(UniValue(fromBlock)); params.push_back(UniValue(toBlock));
    UniValue addrs(UniValue::VARR); if (!contractAddress.empty()) addrs.push_back(contractAddress);
    UniValue addrsObj(UniValue::VOBJ); if (!addrs.empty()) addrsObj.pushKV("addresses", addrs); params.push_back(addrs.empty() ? NullUniValue : addrsObj);
    UniValue topics(UniValue::VARR); topics.push_back(eventName.empty() ? NullUniValue : UniValue(eventName));
    auto addTopic = [&](const std::string& addrHex) {
        if (!addrHex.empty()) { try { if (addrHex.length()!=40 || !IsHex(addrHex)) throw std::runtime_error("Bad topic addr"); dev::h160 h=dev::h160(ParseHex(addrHex)); dev::h256 t; memset(t.data(),0,dev::h256::size); memcpy(t.data()+(size_t(dev::h256::size)-size_t(dev::h160::size)),h.data(),dev::h160::size); topics.push_back(t.hex()); return true; } catch (const std::exception& e) { LogPrintf("Search topic parse err: %s\n",e.what()); return false; } }
        else { topics.push_back(NullUniValue); return true; } };
    if (numTopics > 1 && !addTopic(senderAddress)) return false;
    if (numTopics > 2 && !addTopic(senderAddress)) return false; // Assuming Topic2 == sender still
    while (topics.size() < (size_t)numTopics && numTopics <= 4) topics.push_back(NullUniValue);
    UniValue topicsObj(UniValue::VOBJ); topicsObj.pushKV("topics", topics); if (params.size()==3) params.push_back(topicsObj); else return false;
    if (params.size()==4) params.push_back(UniValue(minconf)); else return false;
    try { resultVar = SearchLogs(params); return true;
    // <<< CORRECTED catch blocks >>>
    } catch (const UniValue& jsonRpcError) {
        LogPrintf("SearchLogs RPC Err: %s\n", jsonRpcError.write());
        return false;
    } catch (const std::exception& e) {
        LogPrintf("SearchLogs Exc: %s\n", e.what());
        return false;
    } catch (...) {
        LogPrintf("SearchLogs Unknown Exc\n");
        return false;
    }
}

void CallToken::setCheckGasForCall(bool value) { checkGasForCall = value; }