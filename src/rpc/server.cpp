// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The DIGIWAGE developers // Updated copyright year
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h" // Includes rpc/protocol.h, which includes univalue.h

// Base includes
#include "base58.h"
#include "init.h"
#include "main.h"
#include "random.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "chainparams.h"
#include "primitives/transaction.h" // Ensure this path is correct for DigiWage

// Optional includes based on enabled features
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
#include "guiinterface.h" // Needed for uiInterface

// Boost includes
#include <boost/bind/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp> // Needed for CRPCSignals definition
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp> // Needed for to_upper
#include <boost/foreach.hpp> // Needed for BOOST_FOREACH

// Standard includes
#include <stdint.h>
#include <vector>
#include <map>
#include <list>
#include <set> // Needed for RPCTypeCheckObj and help()
#include <memory>
#include <algorithm> // For std::sort
#include <stdexcept> // For std::runtime_error


// === Global variables ===
static bool fRPCRunning = false;
static bool fRPCInWarmup = true;
static std::string rpcWarmupStatus("RPC server started");
static RecursiveMutex cs_rpcWarmup;
static RPCTimerInterface* timerInterface = NULL;
static std::map<std::string, boost::shared_ptr<RPCTimerBase> > deadlineTimers;

// Define the signals object based on the struct in the header (rpc/server.h)
CRPCSignals g_rpcSignals;
// =======================================================================================


// === Extern Declarations for RPC Functions ===
// These declare functions defined in other rpc_*.cpp files.
// Ideally, these should be moved to specific header files (rpcwallet.h, rpcevm.h, etc.)
// and those headers included here. Adding them here directly fixes compilation
// of rpc/server.cpp but is less organized long-term.

// Control / Network / Blockchain / Mining / Raw Tx / Util / Hidden
// (Most of these are likely already declared via rpc/server.h includes)
extern UniValue getinfo(const UniValue& params, bool fHelp);
extern UniValue addnode(const UniValue& params, bool fHelp);
extern UniValue disconnectnode(const UniValue& params, bool fHelp);
extern UniValue getaddednodeinfo(const UniValue& params, bool fHelp);
extern UniValue getconnectioncount(const UniValue& params, bool fHelp);
extern UniValue getnettotals(const UniValue& params, bool fHelp);
extern UniValue getnetworkinfo(const UniValue& params, bool fHelp);
extern UniValue getpeerinfo(const UniValue& params, bool fHelp);
extern UniValue listbanned(const UniValue& params, bool fHelp);
extern UniValue ping(const UniValue& params, bool fHelp);
extern UniValue setban(const UniValue& params, bool fHelp);
extern UniValue clearbanned(const UniValue& params, bool fHelp);
extern UniValue getblock(const UniValue& params, bool fHelp);
extern UniValue getblockchaininfo(const UniValue& params, bool fHelp);
extern UniValue getblockcount(const UniValue& params, bool fHelp);
extern UniValue getblockhash(const UniValue& params, bool fHelp);
extern UniValue getblockheader(const UniValue& params, bool fHelp);
extern UniValue getchaintips(const UniValue& params, bool fHelp);
extern UniValue getdifficulty(const UniValue& params, bool fHelp);
extern UniValue getmempoolinfo(const UniValue& params, bool fHelp);
extern UniValue getrawmempool(const UniValue& params, bool fHelp);
extern UniValue gettxout(const UniValue& params, bool fHelp);
extern UniValue gettxoutsetinfo(const UniValue& params, bool fHelp);
extern UniValue invalidateblock(const UniValue& params, bool fHelp);
extern UniValue reconsiderblock(const UniValue& params, bool fHelp);
extern UniValue verifychain(const UniValue& params, bool fHelp);
extern UniValue getblocktemplate(const UniValue& params, bool fHelp);
extern UniValue getmininginfo(const UniValue& params, bool fHelp);
extern UniValue getnetworkhashps(const UniValue& params, bool fHelp);
extern UniValue prioritisetransaction(const UniValue& params, bool fHelp);
extern UniValue submitblock(const UniValue& params, bool fHelp);
extern UniValue createrawtransaction(const UniValue& params, bool fHelp);
extern UniValue decoderawtransaction(const UniValue& params, bool fHelp);
extern UniValue decodescript(const UniValue& params, bool fHelp);
extern UniValue getrawtransaction(const UniValue& params, bool fHelp);
extern UniValue sendrawtransaction(const UniValue& params, bool fHelp);
extern UniValue signrawtransaction(const UniValue& params, bool fHelp);
extern UniValue createmultisig(const UniValue& params, bool fHelp);
extern UniValue estimatefee(const UniValue& params, bool fHelp);
extern UniValue estimatepriority(const UniValue& params, bool fHelp);
extern UniValue validateaddress(const UniValue& params, bool fHelp);
extern UniValue verifymessage(const UniValue& params, bool fHelp);
extern UniValue setmocktime(const UniValue& params, bool fHelp);
extern UniValue getbestblockhash(const UniValue& params, bool fHelp);
extern UniValue waitfornewblock(const UniValue& params, bool fHelp);
extern UniValue waitforblock(const UniValue& params, bool fHelp);
extern UniValue waitforblockheight(const UniValue& params, bool fHelp);
extern UniValue getblockindexstats(const UniValue& params, bool fHelp); // Was missing? Added just in case.
extern UniValue getfeeinfo(const UniValue& params, bool fHelp); // Was missing? Added just in case.

extern UniValue createcontract(const UniValue& params, bool fHelp);


// DigiWage Features (Masternodes, Budget, Sporks, etc.)
extern UniValue listmasternodes(const UniValue& params, bool fHelp);
extern UniValue getmasternodecount(const UniValue& params, bool fHelp);
extern UniValue masternodeconnect(const UniValue& params, bool fHelp);
extern UniValue createmasternodebroadcast(const UniValue& params, bool fHelp);
extern UniValue decodemasternodebroadcast(const UniValue& params, bool fHelp);
extern UniValue relaymasternodebroadcast(const UniValue& params, bool fHelp);
extern UniValue masternodecurrent(const UniValue& params, bool fHelp);
extern UniValue startmasternode(const UniValue& params, bool fHelp);
extern UniValue createmasternodekey(const UniValue& params, bool fHelp);
extern UniValue getmasternodeoutputs(const UniValue& params, bool fHelp);
extern UniValue listmasternodeconf(const UniValue& params, bool fHelp);
extern UniValue getmasternodestatus(const UniValue& params, bool fHelp);
extern UniValue getmasternodewinners(const UniValue& params, bool fHelp);
extern UniValue getmasternodescores(const UniValue& params, bool fHelp);
extern UniValue masternodedebug(const UniValue& params, bool fHelp);
extern UniValue reloadmasternodeconfig(const UniValue& params, bool fHelp);
extern UniValue preparebudget(const UniValue& params, bool fHelp);
extern UniValue submitbudget(const UniValue& params, bool fHelp);
extern UniValue mnbudgetvote(const UniValue& params, bool fHelp);
extern UniValue getbudgetvotes(const UniValue& params, bool fHelp);
extern UniValue getnextsuperblock(const UniValue& params, bool fHelp);
extern UniValue getbudgetprojection(const UniValue& params, bool fHelp);
extern UniValue getbudgetinfo(const UniValue& params, bool fHelp);
extern UniValue mnbudgetrawvote(const UniValue& params, bool fHelp);
extern UniValue mnfinalbudget(const UniValue& params, bool fHelp);
extern UniValue checkbudgets(const UniValue& params, bool fHelp);
extern UniValue mnsync(const UniValue& params, bool fHelp);
extern UniValue spork(const UniValue& params, bool fHelp);
extern UniValue getpoolinfo(const UniValue& params, bool fHelp);

#ifdef ENABLE_WALLET
// Wallet / Generating Functions
extern UniValue getgenerate(const UniValue& params, bool fHelp);
extern UniValue setgenerate(const UniValue& params, bool fHelp);
extern UniValue generate(const UniValue& params, bool fHelp);
extern UniValue gethashespersec(const UniValue& params, bool fHelp);
extern UniValue burn(const UniValue& params, bool fHelp);
extern UniValue addmultisigaddress(const UniValue& params, bool fHelp);
extern UniValue autocombinerewards(const UniValue& params, bool fHelp);
extern UniValue backupwallet(const UniValue& params, bool fHelp);
extern UniValue delegatestake(const UniValue& params, bool fHelp);
extern UniValue dumphdinfo(const UniValue& params, bool fHelp);
extern UniValue dumpprivkey(const UniValue& params, bool fHelp);
extern UniValue dumpwallet(const UniValue& params, bool fHelp);
extern UniValue bip38encrypt(const UniValue& params, bool fHelp);
extern UniValue bip38decrypt(const UniValue& params, bool fHelp);
extern UniValue encryptwallet(const UniValue& params, bool fHelp);
extern UniValue getaccount(const UniValue& params, bool fHelp);
extern UniValue getaccountaddress(const UniValue& params, bool fHelp);
extern UniValue getaddressesbyaccount(const UniValue& params, bool fHelp);
extern UniValue getbalance(const UniValue& params, bool fHelp);
extern UniValue getcoldstakingbalance(const UniValue& params, bool fHelp);
extern UniValue getdelegatedbalance(const UniValue& params, bool fHelp);
extern UniValue getaddressinfo(const UniValue& params, bool fHelp);
extern UniValue getnewaddress(const UniValue& params, bool fHelp);
extern UniValue getnewstakingaddress(const UniValue& params, bool fHelp);
extern UniValue getrawchangeaddress(const UniValue& params, bool fHelp);
extern UniValue getreceivedbyaccount(const UniValue& params, bool fHelp);
extern UniValue getreceivedbyaddress(const UniValue& params, bool fHelp);
extern UniValue getstakingstatus(const UniValue& params, bool fHelp);
extern UniValue getstakesplitthreshold(const UniValue& params, bool fHelp);
extern UniValue gettransaction(const UniValue& params, bool fHelp);
extern UniValue abandontransaction(const UniValue& params, bool fHelp);
extern UniValue getunconfirmedbalance(const UniValue& params, bool fHelp);
extern UniValue getwalletinfo(const UniValue& params, bool fHelp);
extern UniValue importaddress(const UniValue& params, bool fHelp);
extern UniValue importprivkey(const UniValue& params, bool fHelp);
extern UniValue importwallet(const UniValue& params, bool fHelp);
extern UniValue keypoolrefill(const UniValue& params, bool fHelp);
extern UniValue listaccounts(const UniValue& params, bool fHelp);
extern UniValue listaddressgroupings(const UniValue& params, bool fHelp);
extern UniValue listcoldutxos(const UniValue& params, bool fHelp);
extern UniValue listdelegators(const UniValue& params, bool fHelp);
extern UniValue listlockunspent(const UniValue& params, bool fHelp);
extern UniValue listreceivedbyaccount(const UniValue& params, bool fHelp);
extern UniValue listreceivedbyaddress(const UniValue& params, bool fHelp);
extern UniValue listsinceblock(const UniValue& params, bool fHelp);
extern UniValue liststakingaddresses(const UniValue& params, bool fHelp);
extern UniValue listtransactions(const UniValue& params, bool fHelp);
extern UniValue listunspent(const UniValue& params, bool fHelp);
extern UniValue lockunspent(const UniValue& params, bool fHelp);
extern UniValue movecmd(const UniValue& params, bool fHelp);
extern UniValue multisend(const UniValue& params, bool fHelp);
extern UniValue rawdelegatestake(const UniValue& params, bool fHelp);
extern UniValue sendfrom(const UniValue& params, bool fHelp);
extern UniValue sendmany(const UniValue& params, bool fHelp);
extern UniValue sendtoaddress(const UniValue& params, bool fHelp);
extern UniValue sendtoaddressix(const UniValue& params, bool fHelp);
extern UniValue setaccount(const UniValue& params, bool fHelp);
extern UniValue setstakesplitthreshold(const UniValue& params, bool fHelp);
extern UniValue settxfee(const UniValue& params, bool fHelp);
extern UniValue signmessage(const UniValue& params, bool fHelp);
extern UniValue walletlock(const UniValue& params, bool fHelp);
extern UniValue upgradetohd(const UniValue& params, bool fHelp);
extern UniValue walletpassphrase(const UniValue& params, bool fHelp);
extern UniValue walletpassphrasechange(const UniValue& params, bool fHelp);
extern UniValue delegatoradd(const UniValue& params, bool fHelp);
extern UniValue delegatorremove(const UniValue& params, bool fHelp);

// Forge Feature
extern UniValue listforgeitems(const UniValue& params, bool fHelp);
#endif // ENABLE_WALLET

// EVM / QRC20 Functions
extern UniValue callcontract(const UniValue& params, bool fHelp);
extern UniValue createcontract(const UniValue& params, bool fHelp);
extern UniValue sendtocontract(const UniValue& params, bool fHelp); // Assuming you implement this
extern UniValue gettransactionreceipt(const UniValue& params, bool fHelp);
extern UniValue searchlogs(const UniValue& params, bool fHelp);
extern UniValue waitforlogs(const UniValue& params, bool fHelp);
extern UniValue getstorage(const UniValue& params, bool fHelp);
extern UniValue getaccountinfo(const UniValue& params, bool fHelp);
extern UniValue listcontracts(const UniValue& params, bool fHelp);
extern UniValue qrc20name(const UniValue& params, bool fHelp);
extern UniValue qrc20symbol(const UniValue& params, bool fHelp);
extern UniValue qrc20decimals(const UniValue& params, bool fHelp);
extern UniValue qrc20totalsupply(const UniValue& params, bool fHelp);
extern UniValue qrc20balanceof(const UniValue& params, bool fHelp);
extern UniValue qrc20allowance(const UniValue& params, bool fHelp);
extern UniValue qrc20listtransactions(const UniValue& params, bool fHelp); // Declaration in server.h is sufficient

// =======================================================================================


// === Function Definitions for functions DECLARED in rpc/server.h ===

// Helper: find_value (Using exists() and operator[] compatible with DigiWage UniValue)
const UniValue& find_value(const UniValue& obj, const std::string& name)
{
    if (!obj.isObject())
        return NullUniValue; // Return static const NullUniValue reference

    if (obj.exists(name)) {
        // obj[name] returns a const UniValue& when obj is const
        return obj[name];
    } else {
        return NullUniValue;
    }
}

// Definition for IsRPCRunning
bool IsRPCRunning()
{
    return fRPCRunning;
}

// Definition for RPCIsInWarmup
bool RPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

// Definition for SetRPCWarmupStatus
void SetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

// Definition for SetRPCWarmupFinished
void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

// --- RPCServer signal registration ---
// Assumes RPCServer namespace/class is defined as shown in the header
void RPCServer::OnStarted(boost::function<void ()> slot) { g_rpcSignals.Started.connect(slot); }
void RPCServer::OnStopped(boost::function<void ()> slot) { g_rpcSignals.Stopped.connect(slot); }
void RPCServer::OnPreCommand(boost::function<void (const CRPCCommand&)> slot) { g_rpcSignals.PreCommand.connect(boost::bind(slot, boost::placeholders::_1)); }
void RPCServer::OnPostCommand(boost::function<void (const CRPCCommand&)> slot) { g_rpcSignals.PostCommand.connect(boost::bind(slot, boost::placeholders::_1)); }

// --- RPC Type-checking functions ---
// (Assuming definitions are correct and JSONRPCError is defined via included headers)
void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    BOOST_FOREACH(UniValue::VType t, typesExpected)
    {
        if (params.size() <= i)
            break;

        const UniValue& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.isNull()))))
        {
            std::string err = strprintf("Expected type %s, got %s", uvTypeName(t), uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheckObj(const UniValue& o,
                  const std::map<std::string, UniValue::VType>& typesExpected,
                  bool fAllowNull,
                  bool fAllowMissing)
{
    if (!o.isObject())
        throw JSONRPCError(RPC_TYPE_ERROR, "Expected object");

    const std::vector<std::string>& keyVec = o.getKeys();
    std::set<std::string> keys(keyVec.begin(), keyVec.end());

    typedef std::map<std::string, UniValue::VType> MT;
    BOOST_FOREACH(const MT::value_type& t, typesExpected)
    {
        const UniValue& v = find_value(o, t.first); // Use our corrected find_value
        if (!fAllowMissing && v.isNull())
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing required field %s", t.first));

        if (!v.isNull())
        {
             if (t.second != UniValue::VNULL)
             {
                 if (v.type() != t.second) {
                    throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected type %s for %s, got %s", uvTypeName(t.second), t.first, uvTypeName(v.type())));
                 }
             }
        }
        else
        {
            if (!fAllowNull) {
                 throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Null value not allowed for %s", t.first));
            }
        }
        keys.erase(t.first);
    }
    // Extraneous key check (optional) remains commented out
}


// --- JSON Request Parsing ---
// (Assuming definition is correct)
void JSONRequest::parse(const UniValue& valRequest)
{
    if (!valRequest.isObject()) throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    id = find_value(request, "id"); // Use corrected find_value

    const UniValue& method_v = find_value(request, "method");
    if (method_v.isNull()) throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!method_v.isStr()) throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = method_v.get_str();

    const UniValue& params_v = find_value(request, "params");
    if (params_v.isArray()) {
        params = params_v.get_array();
    } else if (params_v.isNull()) {
        params = UniValue(UniValue::VARR);
        params.clear();
    } else {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or null");
    }
}

// --- Standard RPC Commands (help, stop) ---
// (Definitions rely on tableRPC being defined later)

UniValue help(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error( // Use std::runtime_error for help text errors
            "help ( \"command\" )\n"
            "\nList all commands, or get help for a specified command.\n"
            "\nArguments:\n"
            "1. \"command\"     (string, optional) The command to get help on\n"
            "\nResult:\n"
            "\"text\"     (string) The help text\n");

    std::string strCommand;
    if (params.size() > 0) {
        if (params[0].isStr()) { // Check type before getting string
           strCommand = params[0].get_str();
        } else {
            throw JSONRPCError(RPC_TYPE_ERROR, "command argument must be a string");
        }
    }

    return tableRPC.help(strCommand); // Assumes tableRPC is defined later
}


UniValue stop(const UniValue& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1)
        throw std::runtime_error( // Use std::runtime_error for help text errors
            "stop\n"
            "\nStop DIGIWAGE server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client.
    StartShutdown(); // Assumes StartShutdown() is defined in init.h or similar
    return "DIGIWAGE server stopping";
}


// --- RPC Command Table Definition ---
// Defines the actual RPC commands, their categories, function pointers,
// and flags (okSafeMode, reqWallet) based on the 5-argument constructor
// found in DigiWage's rpc/server.h.

static const CRPCCommand vRPCCommands[] =
{
    //  category              name                      actor (function)         okSafeMode reqWallet (5 arguments)
    //  --------------------- ------------------------  -----------------------  ---------- ---------
    /* Overall control/query calls */
    {"control",             "getinfo",                &getinfo,                 true,      false},
    {"control",             "help",                   &help,                    true,      false},
    {"control",             "stop",                   &stop,                    true,      false},

    /* P2P networking */
    {"network",             "getnetworkinfo",         &getnetworkinfo,          true,      false},
    {"network",             "addnode",                &addnode,                 true,      false},
    {"network",             "disconnectnode",         &disconnectnode,          true,      false},
    {"network",             "getaddednodeinfo",       &getaddednodeinfo,        true,      false},
    {"network",             "getconnectioncount",     &getconnectioncount,      true,      false},
    {"network",             "getnettotals",           &getnettotals,            true,      false},
    {"network",             "getpeerinfo",            &getpeerinfo,             true,      false},
    {"network",             "ping",                   &ping,                    true,      false},
    {"network",             "setban",                 &setban,                  true,      false},
    {"network",             "listbanned",             &listbanned,              true,      false},
    {"network",             "clearbanned",            &clearbanned,             true,      false},

    /* Block chain and UTXO */
    {"blockchain",          "getblockindexstats",     &getblockindexstats,      true,      false},
    {"blockchain",          "getblockchaininfo",      &getblockchaininfo,       true,      false},
    {"blockchain",          "getbestblockhash",       &getbestblockhash,        true,      false},
    {"blockchain",          "getblockcount",          &getblockcount,           true,      false},
    {"blockchain",          "getblock",               &getblock,                true,      false},
    {"blockchain",          "getblockhash",           &getblockhash,            true,      false},
    {"blockchain",          "getblockheader",         &getblockheader,          true,      false},
    {"blockchain",          "getchaintips",           &getchaintips,            true,      false},
    {"blockchain",          "getdifficulty",          &getdifficulty,           true,      false},
    {"blockchain",          "getfeeinfo",             &getfeeinfo,              true,      false},
    {"blockchain",          "getmempoolinfo",         &getmempoolinfo,          true,      false},
    {"blockchain",          "getrawmempool",          &getrawmempool,           true,      false},
    {"blockchain",          "gettxout",               &gettxout,                true,      false},
    {"blockchain",          "gettxoutsetinfo",        &gettxoutsetinfo,         true,      false},
    {"blockchain",          "invalidateblock",        &invalidateblock,         true,      false},
    {"blockchain",          "reconsiderblock",        &reconsiderblock,         true,      false},
    {"blockchain",          "verifychain",            &verifychain,             true,      false},

    /* Mining */
    {"mining",              "getblocktemplate",       &getblocktemplate,        true,      false},
    {"mining",              "getmininginfo",          &getmininginfo,           true,      false},
    {"mining",              "getnetworkhashps",       &getnetworkhashps,        true,      false},
    {"mining",              "prioritisetransaction",  &prioritisetransaction,   true,      false},
    {"mining",              "submitblock",            &submitblock,             true,      false},

#ifdef ENABLE_WALLET
    /* Coin generation */
    {"generating",          "getgenerate",            &getgenerate,             true,      false},
    {"generating",          "gethashespersec",        &gethashespersec,         true,      false},
    {"generating",          "setgenerate",            &setgenerate,             true,      false},
    {"generating",          "generate",               &generate,                true,      true },
#endif

    /* Raw transactions */
    {"rawtransactions",     "createrawtransaction",   &createrawtransaction,    true,      false},
    {"rawtransactions",     "decoderawtransaction",   &decoderawtransaction,    true,      false},
    {"rawtransactions",     "decodescript",           &decodescript,            true,      false},
    {"rawtransactions",     "getrawtransaction",      &getrawtransaction,       true,      false},
    {"rawtransactions",     "sendrawtransaction",     &sendrawtransaction,      false,     false},
    {"rawtransactions",     "signrawtransaction",     &signrawtransaction,      false,     true },

    /* Utility functions */
    {"util",                "createmultisig",         &createmultisig,          true,      false},
    {"util",                "validateaddress",        &validateaddress,         true,      false},
    {"util",                "verifymessage",          &verifymessage,           true,      false},
    {"util",                "estimatefee",            &estimatefee,             true,      false},
    {"util",                "estimatepriority",       &estimatepriority,        true,      false},

    /* Not shown in help */
    {"hidden",              "invalidateblock",        &invalidateblock,         true,      false},
    {"hidden",              "reconsiderblock",        &reconsiderblock,         true,      false},
    {"hidden",              "setmocktime",            &setmocktime,             true,      false},
    {"hidden",              "waitfornewblock",        &waitfornewblock,         true,      false},
    {"hidden",              "waitforblock",           &waitforblock,            true,      false},
    {"hidden",              "waitforblockheight",     &waitforblockheight,      true,      false},

    /* DIGIWAGE features */
    {"digiwage",            "listmasternodes",        &listmasternodes,         true,      false},
    {"digiwage",            "getmasternodecount",     &getmasternodecount,      true,      false},
    {"digiwage",            "masternodeconnect",      &masternodeconnect,       true,      false},
    {"digiwage",            "createmasternodebroadcast", &createmasternodebroadcast, true, true },
    {"digiwage",            "decodemasternodebroadcast", &decodemasternodebroadcast, true, false},
    {"digiwage",            "relaymasternodebroadcast", &relaymasternodebroadcast, true, false},
    {"digiwage",            "masternodecurrent",      &masternodecurrent,       true,      false},
    {"digiwage",            "masternodedebug",        &masternodedebug,         true,      false},
    {"digiwage",            "reloadmasternodeconfig", &reloadmasternodeconfig,  true,      true },
    {"digiwage",            "startmasternode",        &startmasternode,         true,      true },
    {"digiwage",            "createmasternodekey",    &createmasternodekey,     true,      false},
    {"digiwage",            "getmasternodeoutputs",   &getmasternodeoutputs,    true,      false},
    {"digiwage",            "listmasternodeconf",     &listmasternodeconf,      true,      false},
    {"digiwage",            "getmasternodestatus",    &getmasternodestatus,     true,      true },
    {"digiwage",            "getmasternodewinners",   &getmasternodewinners,    true,      false},
    {"digiwage",            "getmasternodescores",    &getmasternodescores,     true,      false},
    {"digiwage",            "preparebudget",          &preparebudget,           true,      true },
    {"digiwage",            "submitbudget",           &submitbudget,            true,      true },
    {"digiwage",            "mnbudgetvote",           &mnbudgetvote,            true,      true },
    {"digiwage",            "getbudgetvotes",         &getbudgetvotes,          true,      false},
    {"digiwage",            "getnextsuperblock",      &getnextsuperblock,       true,      false},
    {"digiwage",            "getbudgetprojection",    &getbudgetprojection,     true,      false},
    {"digiwage",            "getbudgetinfo",          &getbudgetinfo,           true,      false},
    {"digiwage",            "mnbudgetrawvote",        &mnbudgetrawvote,         true,      true },
    {"digiwage",            "mnfinalbudget",          &mnfinalbudget,           true,      false},
    {"digiwage",            "checkbudgets",           &checkbudgets,            true,      false},
    {"digiwage",            "mnsync",                 &mnsync,                  true,      false},
    {"digiwage",            "spork",                  &spork,                   true,      false},
    {"digiwage",            "getpoolinfo",            &getpoolinfo,             true,      false},

#ifdef ENABLE_WALLET
    /* Wallet */
    {"wallet",              "burn",                   &burn,                    true,      true },
    {"wallet",              "addmultisigaddress",     &addmultisigaddress,      true,      true },
    {"wallet",              "autocombinerewards",     &autocombinerewards,      false,     true },
    {"wallet",              "backupwallet",           &backupwallet,            true,      true },
    {"wallet",              "delegatestake",          &delegatestake,           false,     true },
    {"wallet",              "dumphdinfo",             &dumphdinfo,              true,      true },
    {"wallet",              "dumpprivkey",            &dumpprivkey,             true,      true },
    {"wallet",              "dumpwallet",             &dumpwallet,              true,      true },
    {"wallet",              "bip38encrypt",           &bip38encrypt,            true,      true },
    {"wallet",              "bip38decrypt",           &bip38decrypt,            true,      true },
    {"wallet",              "encryptwallet",          &encryptwallet,           true,      true },
    {"wallet",              "getaccountaddress",      &getaccountaddress,       true,      true },
    {"wallet",              "getaccount",             &getaccount,              true,      true },
    {"wallet",              "getaddressesbyaccount",  &getaddressesbyaccount,   true,      true },
    {"wallet",              "getbalance",             &getbalance,              false,     true },
    {"wallet",              "getcoldstakingbalance",  &getcoldstakingbalance,   false,     true },
    {"wallet",              "getdelegatedbalance",    &getdelegatedbalance,     false,     true },
    {"wallet",              "getaddressinfo",         &getaddressinfo,          true,      true },
    {"wallet",              "getnewaddress",          &getnewaddress,           true,      true },
    {"wallet",              "getnewstakingaddress",   &getnewstakingaddress,    true,      true },
    {"wallet",              "getrawchangeaddress",    &getrawchangeaddress,     true,      true },
    {"wallet",              "getreceivedbyaccount",   &getreceivedbyaccount,    false,     true },
    {"wallet",              "getreceivedbyaddress",   &getreceivedbyaddress,    false,     true },
    {"wallet",              "getstakingstatus",       &getstakingstatus,        false,     true },
    {"wallet",              "getstakesplitthreshold", &getstakesplitthreshold,  false,     true },
    {"wallet",              "gettransaction",         &gettransaction,          false,     true },
    {"wallet",              "abandontransaction",     &abandontransaction,      false,     true },
    {"wallet",              "getunconfirmedbalance",  &getunconfirmedbalance,   false,     true },
    {"wallet",              "getwalletinfo",          &getwalletinfo,           false,     true },
    {"wallet",              "importprivkey",          &importprivkey,           true,      true },
    {"wallet",              "importwallet",           &importwallet,            true,      true },
    {"wallet",              "importaddress",          &importaddress,           true,      true },
    {"wallet",              "keypoolrefill",          &keypoolrefill,           true,      true },
    {"wallet",              "listaccounts",           &listaccounts,            false,     true },
    {"wallet",              "listdelegators",         &listdelegators,          false,     true },
    {"wallet",              "liststakingaddresses",   &liststakingaddresses,    false,     true },
    {"wallet",              "listaddressgroupings",   &listaddressgroupings,    false,     true },
    {"wallet",              "listcoldutxos",          &listcoldutxos,           false,     true },
    {"wallet",              "listlockunspent",        &listlockunspent,         false,     true },
    {"wallet",              "listreceivedbyaccount",  &listreceivedbyaccount,   false,     true },
    {"wallet",              "listreceivedbyaddress",  &listreceivedbyaddress,   false,     true },
    {"wallet",              "listsinceblock",         &listsinceblock,          false,     true },
    {"wallet",              "listtransactions",       &listtransactions,        false,     true },
    {"wallet",              "listunspent",            &listunspent,             false,     true },
    {"wallet",              "lockunspent",            &lockunspent,             true,      true },
    {"wallet",              "move",                   &movecmd,                 false,     true },
    {"wallet",              "multisend",              &multisend,               false,     true },
    {"wallet",              "rawdelegatestake",       &rawdelegatestake,        false,     true },
    {"wallet",              "sendfrom",               &sendfrom,                false,     true },
    {"wallet",              "sendmany",               &sendmany,                false,     true },
    {"wallet",              "sendtoaddress",          &sendtoaddress,           false,     true },
    {"wallet",              "sendtoaddressix",        &sendtoaddressix,         false,     true },
    {"wallet",              "setaccount",             &setaccount,              true,      true },
    {"wallet",              "setstakesplitthreshold", &setstakesplitthreshold,  false,     true },
    {"wallet",              "settxfee",               &settxfee,                true,      true },
    {"wallet",              "signmessage",            &signmessage,             true,      true },
    {"wallet",              "walletlock",             &walletlock,              true,      true },
    {"wallet",              "upgradetohd",            &upgradetohd,             true,      true },
    {"wallet",              "walletpassphrasechange", &walletpassphrasechange,  true,      true },
    {"wallet",              "walletpassphrase",       &walletpassphrase,        true,      true },
    {"wallet",              "delegatoradd",           &delegatoradd,            true,      true },
    {"wallet",              "delegatorremove",        &delegatorremove,         true,      true },

    /* Forge - Assuming this is DigiWage specific */
    {"forge",               "listforgeitems",         &listforgeitems,          false,     true },
#endif // ENABLE_WALLET

    /* === NEW EVM/Qtum RPC Commands === */
    {"evm",                 "callcontract",           &callcontract,            true,      false},
    {"evm",                 "createcontract",         &createcontract,          false,     true},
    {"evm",                 "sendtocontract",         &sendtocontract,          false,     true},
    {"evm",                 "gettransactionreceipt",  &gettransactionreceipt,   true,      false},
    {"evm",                 "searchlogs",             &searchlogs,              true,      false},
    {"evm",                 "waitforlogs",            &waitforlogs,             true,      false},
    {"evm",                 "getstorage",             &getstorage,              true,      false},
    {"evm",                 "getaccountinfo",         &getaccountinfo,          true,      false},
    {"evm",                 "listcontracts",          &listcontracts,           true,      true }, // Needs wallet? Check impl.

    /* QRC20 Helper Commands */
    {"qrc20",               "qrc20name",              &qrc20name,               true,      false},
    {"qrc20",               "qrc20symbol",            &qrc20symbol,             true,      false},
    {"qrc20",               "qrc20decimals",          &qrc20decimals,           true,      false},
    {"qrc20",               "qrc20totalsupply",       &qrc20totalsupply,        true,      false},
    {"qrc20",               "qrc20balanceof",         &qrc20balanceof,          true,      false},
    {"qrc20",               "qrc20allowance",         &qrc20allowance,          true,      false},
    {"qrc20",               "qrc20listtransactions",  &qrc20listtransactions,   true,      false}, // Needs cs_main likely
};

// Define tableRPC instance AFTER vRPCCommands array
CRPCTable tableRPC;

// --- CRPCTable Member Definitions ---
CRPCTable::CRPCTable()
{
    // Use range-based for loop for cleaner iteration
    for (const CRPCCommand& cmd : vRPCCommands) {
        // Check for duplicate command names during registration
        if (mapCommands.count(cmd.name)) {
             // LogPrintf is better than throwing here, allows overrides if necessary
             LogPrintf("WARNING: Duplicate RPC command registered: %s\n", cmd.name);
        }
        mapCommands[cmd.name] = &cmd;
    }
}

const CRPCCommand* CRPCTable::operator[](const std::string& name) const
{
    std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return nullptr;
    return it->second;
}

// Definition for CRPCTable::execute
UniValue CRPCTable::execute(const std::string& method, const UniValue& params) const
{
    const CRPCCommand* pcmd = (*this)[method];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

#ifdef ENABLE_WALLET
    if (pcmd->reqWallet && !pwalletMain) // Assumes pwalletMain is declared/defined elsewhere
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method requires wallet, but wallet is not loaded or available");
#endif

    // Check if safe mode prohibits this command (based on okSafeMode flag)
    // You might need to adjust the condition for checking if the node is in safe mode.
    // Example: using IsInitialBlockDownload() or another specific flag.
    bool fSafeMode = GetBoolArg("-safemode", false); // Or use a proper global/chain state check
    if (!pcmd->okSafeMode && fSafeMode)
       throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, "Command is disabled in safe mode");

    // Warm-up check
    std::string warmupStatus;
    if (RPCIsInWarmup(&warmupStatus))
        throw JSONRPCError(RPC_IN_WARMUP, "RPC server started but is loading blocks..." + warmupStatus);


    try {
        g_rpcSignals.PreCommand(*pcmd); // Fire signal before execution
        UniValue result = (*pcmd->actor)(params, false); // Call the function pointer
        g_rpcSignals.PostCommand(*pcmd); // Fire signal after execution
        return result;
    } catch (const UniValue& objError) { // Catch JSONRPCError thrown as UniValue
        g_rpcSignals.PostCommand(*pcmd); // Also fire PostCommand on handled exceptions
        throw; // Re-throw UniValue error object
    } catch (const std::exception& e) {
        g_rpcSignals.PostCommand(*pcmd);
        throw JSONRPCError(RPC_MISC_ERROR, e.what()); // Convert std::exception to JSONRPCError
    } catch (...) {
        g_rpcSignals.PostCommand(*pcmd);
        throw JSONRPCError(RPC_MISC_ERROR, "Unknown exception"); // Catch-all
    }
}

std::vector<std::string> CRPCTable::listCommands() const
{
    std::vector<std::string> commandList;
    commandList.reserve(mapCommands.size());
    for(const auto& pair : mapCommands) {
        const CRPCCommand* pcmd = pair.second;
        // Optionally filter hidden commands
        if (pcmd->category == "hidden") continue;
        commandList.push_back(pair.first);
    }
    std::sort(commandList.begin(), commandList.end());
    return commandList;
}


// --- HTTP/Timer Function Definitions ---

// Forward declaration for the static helper function used by JSONRPCExecBatch
static UniValue JSONRPCExecOne(const UniValue& req);
// JSONRPCReplyObj and JSONRPCError are declared in rpc/protocol.h (included by server.h)

// Definition for JSONRPCExecBatch
std::string JSONRPCExecBatch(const UniValue& vReq)
{
    if (!vReq.isArray() || vReq.empty()) // Add check for array type and non-empty
         throw JSONRPCError(RPC_INVALID_REQUEST, "Batch request must be a non-empty array");

    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++) {
         if (!vReq[reqIdx].isObject()) { // Add check for object type within batch
              ret.push_back(JSONRPCReplyObj(NullUniValue, JSONRPCError(RPC_INVALID_REQUEST, "Request not an object"), NullUniValue));
         } else {
              ret.push_back(JSONRPCExecOne(vReq[reqIdx]));
         }
    }
    return ret.write() + "\n";
}

// Definition for JSONRPCExecOne (needed by JSONRPCExecBatch)
static UniValue JSONRPCExecOne(const UniValue& req)
{
    UniValue rpc_result(UniValue::VOBJ);
    JSONRequest jreq;
    try {
        jreq.parse(req); // Parse the request first
        // Execute the command using the table
        UniValue result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id); // Success reply
    } catch (const UniValue& objError) {
        // If execute() or parse() threw a JSONRPCError UniValue
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id); // Error reply using the thrown object
    } catch (const std::exception& e) {
        // If execute() or parse() threw a standard exception
        rpc_result = JSONRPCReplyObj(NullUniValue,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id); // Error reply
    } catch (...) {
        // Catch any other unknown errors
        rpc_result = JSONRPCReplyObj(NullUniValue,
                                     JSONRPCError(RPC_PARSE_ERROR, "unknown error processing request"), jreq.id);
    }
    return rpc_result;
}



// Define RPC Timer functions
void RPCSetTimerInterface(RPCTimerInterface *iface) { timerInterface = iface; }
void RPCSetTimerInterfaceIfUnset(RPCTimerInterface *iface) { if (!timerInterface) timerInterface = iface; }
void RPCUnsetTimerInterface(RPCTimerInterface *iface) { if (timerInterface == iface) timerInterface = nullptr; }

void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds)
{
    if (!timerInterface)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No timer handler registered for RPC");
    // Stop & erase existing timer with same name
    deadlineTimers.erase(name); // erase returns num erased, doesn't throw if not found
    LogPrint("rpc", "queue run of %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());
    // Create and insert the new timer
    deadlineTimers.insert(std::make_pair(name, boost::shared_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds*1000))));
}

// --- RPC run control functions ---
bool StartRPC()
{
    LogPrint("rpc", "Starting RPC\n");
    fRPCRunning = true;
    g_rpcSignals.Started(); // Fire signal
    return true;
}

void InterruptRPC()
{
    LogPrint("rpc", "Interrupting RPC\n");
    fRPCRunning = false;
    // Add specific interruption logic if needed (e.g., notify condition variables used by waitfor*)
    // Maybe interrupt timers?
    // deadlineTimers.clear(); // Or handle timers more gracefully
}

void StopRPC()
{
    LogPrint("rpc", "Stopping RPC\n");
    deadlineTimers.clear(); // Clear pending timers
    fRPCRunning = false;
    // Note: RPCUnsetTimerInterface should be called by the owner of the timer interface
    g_rpcSignals.Stopped(); // Fire signal
    LogPrint("rpc", "RPC stopped\n");
}

// --- CRPCTable::help() Implementation ---
// (Assumes rpcfn_type is defined in rpc/server.h)
std::string CRPCTable::help(std::string strCommand) const
{
     std::string strRet;
    std::string category;
    std::set<rpcfn_type> setDone;
    std::vector<std::pair<std::string, const CRPCCommand*> > vCommands;

    // Populate vCommands for sorting
    for (std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.begin(); it != mapCommands.end(); ++it)
    {
        const std::string& name = it->first;
        const CRPCCommand* pcmd = it->second;
        vCommands.push_back(std::make_pair(pcmd->category + name, pcmd));
    }
    std::sort(vCommands.begin(), vCommands.end());

    // Generate help string
    for (const auto& command : vCommands) {
        const CRPCCommand* pcmd = command.second;
        std::string strMethod = pcmd->name;

        if (strCommand.empty() && pcmd->category == "hidden") continue;
        if (!strCommand.empty() && strMethod != strCommand) continue;

#ifdef ENABLE_WALLET
        if (pcmd->reqWallet && !pwalletMain) continue;
#endif

        try {
            UniValue params_help(UniValue::VARR);
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params_help, true); // Call with fHelp=true, expect runtime_error
        } catch (const std::runtime_error& e) {
            std::string strHelp = std::string(e.what());
            if (strCommand.empty()) { // Format for general help listing
                if (strHelp.find('\n') != std::string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n')); // Get first line only
                if (category != pcmd->category) {
                    if (!category.empty()) strRet += "\n";
                    category = pcmd->category;
                    std::string firstLetter = category.substr(0, 1);
                    boost::to_upper(firstLetter); // Use Boost for case conversion
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
                 strRet += strprintf("  %-26s %s\n", strMethod, strHelp);
            } else { // Format for specific command help
                 strRet += strHelp + "\n";
            }
        } catch (const std::exception& e) { // Catch other potential exceptions during help generation
             std::string strHelp = "*** Error generating help for command: " + std::string(e.what()) + " ***";
             LogPrintf("ERROR: Exception generating help for RPC command %s: %s\n", strMethod, e.what());
             // Add simplified output even on error
             if (strCommand.empty()) {
                 if (category != pcmd->category) { /* ... */ } // Handle category change
                 strRet += strprintf("  %-26s %s\n", strMethod, strHelp);
             } else {
                 strRet += strHelp + "\n";
             }
        }
         catch (...) { // Catch unknown exceptions during help generation
             std::string strHelp = "*** Unknown error generating help ***";
             LogPrintf("ERROR: Unknown exception generating help for RPC command %s\n", strMethod);
             // Add simplified output even on error
             if (strCommand.empty()) {
                  if (category != pcmd->category) { /* ... */ } // Handle category change
                  strRet += strprintf("  %-26s %s\n", strMethod, strHelp);
             } else {
                  strRet += strHelp + "\n";
             }
         }
    }

    // If a specific command was requested but not found (or filtered out)
    if (strRet.empty() && !strCommand.empty())
        strRet = strprintf("help: unknown command: %s\n", strCommand);

    // Remove trailing newline if any
    if (!strRet.empty() && strRet.back() == '\n')
         strRet.pop_back();

    return strRet;
}

// Ensure necessary global objects are declared/defined if they weren't already
#ifdef ENABLE_WALLET
extern CWallet* pwalletMain; // Declaration, definition expected elsewhere (e.g., init.cpp)
#endif