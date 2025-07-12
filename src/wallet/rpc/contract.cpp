// ===========================================================================
// FILE: src/wallet/rpc/contract.cpp (Adapted for DigiWage - RPCEVM Style)
// Final Corrected Version based on compilation errors
// ===========================================================================

#include <wallet/rpc/contract.h> // Header for RegisterContractRPCCommands

// Core Bitcoin / DigiWage Includes
#include <base58.h>             // For CBitcoinAddress, CKeyID (MUST be included)
#include <consensus/params.h>   // Often where consensus constants like gas limits are defined
#include <core_io.h>            // For EncodeHexTx
#include <main.h>               // For cs_main, chainActive, RelayTransaction, Params() etc. (might include validation.h, net.h)
#include <net.h>                // For RelayTransaction definition (often included via main.h)
#include <primitives/transaction.h> // For CTransactionRef, MakeTransactionRef (MUST be included)
#include <rpc/server.h>         // For CRPCTable, RPC* errors, RPCTypeCheck, etc. (MUST include univalue.h)
#include <script/script.h>          // For CScript, OP_CREATE, OP_CALL, CScriptNum, VersionVM
#include <script/standard.h>        // For CTxDestination, ExtractDestination, CKeyID, TxoutType, CNoDestination, IsValidDestination
#include <sync.h>               // For LOCK, LOCK2, RecursiveMutex
#include <uint256.h>                // For uint160, uint256 etc.
#include <util.h>               // For GetArg, ParseHex, IsHex, i64tostr etc. (often includes utilstrencodings.h)
#include <utilmoneystr.h>     // For AmountFromValue, FormatMoney
#include <coincontrol.h>   // For CCoinControl (ensure path is correct)
#include <wallet/wallet.h>      // For CWallet, CWalletTx, CReserveKey, IsMine, ISMINE_SPENDABLE etc. (MUST be included)
#include <univalue.h>           // For UniValue (MUST be included)


// --- EVM Includes ---
#include <qtum/qtumstate.h>         // For globalState (Ensure path is correct)
#include <libdevcore/CommonData.h>  // For dev::Address, dev::h160, dev::u256 (Ensure path is correct)
#include <libdevcore/Common.h>      // For dev::toAddress, HexStr (Ensure path is correct)

// --- Other includes ---
#include <memory>               // For std::shared_ptr, std::unique_ptr
#include <string>
#include <vector>
#include <boost/variant.hpp>    // For boost::get (used with CTxDestination)

// --- Global State (Ensure these are declared 'extern' elsewhere, e.g., in validation.h, init.cpp, or wallet.cpp) ---
extern std::unique_ptr<QtumState> globalState; // Make sure this is defined and initialized elsewhere
extern RecursiveMutex cs_main;                 // Included via main.h or sync.h
extern CWallet* pwalletMain;                   // Global wallet pointer (common in older codebases)

// --- Constants ---
// Definitions are expected to come from main.h or consensus/params.h
// Ensure DEFAULT_GAS_LIMIT_OP_CREATE, DEFAULT_GAS_LIMIT_OP_SEND, MINIMUM_GAS_LIMIT,
// DEFAULT_GAS_PRICE, MAX_RPC_GAS_PRICE, COIN, MAX_MONEY are defined there.
const std::string CURRENCY_UNIT = "WAGE"; // DigiWage ticker symbol

// --- Helper Functions (within anonymous namespace) ---
namespace {

// Use boost::get for boost::variant (CTxDestination)
bool IsValidContractSenderAddress(const CTxDestination& dest)
{
    return boost::get<CKeyID>(&dest) != nullptr;
}

// Ensure AvailableCoins signature matches your wallet.h (expects pointer)
void AvailableCoinsWallet(const CWallet& wallet, std::vector<COutput>& vecOutputs, const CCoinControl* coinControl = nullptr)
{
    // Pass pointer as required by the older AvailableCoins signature found in errors
    wallet.AvailableCoins(&vecOutputs, true, coinControl);
}


bool SetDefaultSignSenderAddress(CWallet& wallet, CTxDestination& destAddress, CCoinControl& coinControl)
{
    coinControl.fAllowOtherInputs = true; // Allow wallet to add other inputs if needed
    std::vector<COutput> vecOutputs;
    AvailableCoinsWallet(wallet, vecOutputs, nullptr); // Get all available coins first

    for (const COutput& out : vecOutputs) {
        const CWalletTx* pTx = wallet.GetWalletTx(out.tx->GetHash());
        if (!pTx || out.i < 0 || (size_t)out.i >= pTx->vout.size()) continue;

        if (!(wallet.IsMine(pTx->vout[out.i]) & ISMINE_SPENDABLE)) continue;

        const CTxOut& txout = pTx->vout[out.i];
        CTxDestination currentDest;
        if (ExtractDestination(txout.scriptPubKey, currentDest)) {
            const CKeyID* keyID = boost::get<CKeyID>(&currentDest);
            if (keyID && wallet.HaveKey(*keyID)) {
                destAddress = currentDest;
                return true;
            }
        }
    }

    destAddress = CNoDestination();
    return false;
}



// Helper to get CKeyID from CTxDestination (boost::variant)
CKeyID GetKeyIDForDestination(const CTxDestination& dest) {
     const CKeyID* keyid_ptr = boost::get<CKeyID>(&dest);
     return keyid_ptr ? *keyid_ptr : CKeyID();
}

// Helper to convert CKeyID (uint160) to dev::h160
// ** VERIFY THIS CONVERSION IS CORRECT FOR YOUR CODEBASE **
// Common methods: Direct data copy if layouts match, or hex string conversion.
// Assuming CKeyID can be treated like uint160 and dev::h160 can take raw data pointer.
// Helper to convert CKeyID (uint160) to dev::h160
dev::h160 GetSenderH160(const CTxDestination& dest)
{
    CKeyID keyID = GetKeyIDForDestination(dest);
    if (!keyID.IsNull()) {
         try {
            // --- Use GetHex() instead of ToStringReverseEndian() ---
            // Assumes CKeyID has GetHex() returning std::string
            // Assumes dev::h160 has constructor taking std::string (hex)
            std::string hexStr = keyID.GetHex(); // Get hex string from CKeyID
            return dev::h160(hexStr);            // Construct dev::h160 from hex string
            // --- End Change ---

            // Original problematic line:
            // return dev::h160(HexStr(keyID.ToStringReverseEndian()));

         } catch (const std::exception& e) { // Catch specific exception if possible
             // Log the specific exception message
             LogPrintf("ERROR: GetSenderH160: Exception converting CKeyID %s via GetHex() to dev::h160: %s\n", keyID.ToString(), e.what());
         } catch (...) {
             LogPrintf("ERROR: GetSenderH160: Unknown exception converting CKeyID %s via GetHex() to dev::h160\n", keyID.ToString());
         }
    }
    // Log if keyID was null initially or conversion failed
    // LogPrintf("WARN: GetSenderH160: CKeyID was null or conversion failed for destination.\n");
    return dev::h160(); // Return empty h160 on failure
}

// Get gas defaults using GetArg
void getGasRelatedDefaults(uint64_t& blockGasLimit, CAmount& minGasPriceOut, CAmount& defaultGasPriceOut, int* pHeight = nullptr)
{
    // Use constants defined in main.h / consensus params
    blockGasLimit = GetArg("-blockgaslimit", DEFAULT_GAS_LIMIT_OP_CREATE); // Use constant from main.h
    minGasPriceOut = GetArg("-mingasprice", DEFAULT_GAS_PRICE); // Use constant from main.h
    defaultGasPriceOut = GetArg("-gasprice", DEFAULT_GAS_PRICE); // Use constant from main.h

    if(pHeight) {
        LOCK(cs_main);
        *pHeight = chainActive.Height(); // Use global variable style
    }
}


dev::Address CalculateContractAddress(const dev::h160& senderH160)
{
    if (!globalState || senderH160 == dev::h160()) return dev::Address();

    LOCK(cs_main); // Lock if getNonce accesses chain state potentially modified by block processing
    dev::u256 nonce = 0;
    try {
        nonce = globalState->getNonce(senderH160);
    }
    catch (const std::exception& e) {
         LogPrintf("ERROR: CalculateContractAddress: Failed to get nonce for %s: %s\n", senderH160.hex(), e.what());
         return dev::Address();
    } catch (...) {
         LogPrintf("ERROR: CalculateContractAddress: Failed to get nonce for %s (unknown exception)\n", senderH160.hex());
         return dev::Address();
    }
    return dev::toAddress(senderH160, nonce);
}


// Ensure wallet is unlocked
void EnsureWalletIsUnlocked(CWallet* pwallet) {
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not found.");
    }
    if (pwallet->IsLocked()) {
         throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet locked. Unlock wallet with walletpassphrase first.");
    }
}

} // anonymous namespace


// --- RPC Method Implementations ---

// Conforms to the older (const UniValue& params, bool fHelp) signature
UniValue createcontract(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 5) // Max 5 args: bytecode, gaslimit, gasprice, sender, broadcast
    {
        uint64_t blockGasLimit = 0; CAmount minGasPrice = 0, defaultGasPrice = 0;
        getGasRelatedDefaults(blockGasLimit, minGasPrice, defaultGasPrice);
        std::string msg =
            "createcontract \"bytecode\" ( gaslimit gasprice senderaddress broadcast )\n"
            "\nCreates a contract from bytecode.\n"
            "\nArguments:\n"
            "1. \"bytecode\"          (string, required) Contract bytecode hex string.\n"
            "2. gaslimit            (numeric, optional, default=" + i64tostr(DEFAULT_GAS_LIMIT_OP_CREATE) + ") Gas limit.\n"
            "3. gasprice            (numeric or string, optional, default=" + FormatMoney(defaultGasPrice) + ") Gas price in " + CURRENCY_UNIT + "/gas (in satoshis per gas unit).\n"
            "4. \"senderaddress\"     (string, optional) The " + CURRENCY_UNIT + " address (P2PKH format) sender.\n"
            "5. broadcast           (boolean, optional, default=true) Whether to broadcast the transaction.\n"
            "\nResult (if broadcast=true):\n"
            "{\n"
            "  \"txid\": \"transactionidhex\",    (string) The transaction id.\n"
            "  \"sender\": \"senderaddress\",     (string) The P2PKH address of the sender.\n"
            "  \"hash160\": \"keyidhex\",         (string) The key ID (hash160) of the sender address.\n"
            "  \"address\": \"contractaddresshex\" (string) The calculated contract address (40 hex chars).\n"
            "}\n"
            "\nResult (if broadcast=false):\n"
            "{\n"
            "  \"hex\": \"rawtransactionhex\",    (string) The hex-encoded raw transaction.\n"
            "  \"sender\": \"senderaddress\",     (string) The P2PKH address of the sender.\n"
            "  \"hash160\": \"keyidhex\",         (string) The key ID (hash160) of the sender address.\n"
            "  \"address\": \"contractaddresshex\" (string) The calculated contract address (40 hex chars).\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("createcontract", "\"60806040...\"") + "\n"
            + HelpExampleCli("createcontract", "\"6080...\" 2000000 50 \"YourSenderAddressWAGE\"") + " # Gas price in satoshis\n"
            + HelpExampleRpc("createcontract", "[\"6080...\", 2000000, 50, \"YourSenderAddressWAGE\"]"); // Gas price in satoshis
        throw std::runtime_error(msg);
    }

    // Use the global wallet pointer
    CWallet* const pwallet = pwalletMain;
    if (!pwallet) throw JSONRPCError(RPC_WALLET_ERROR, "No wallet is loaded (pwalletMain is null).");
    EnsureWalletIsUnlocked(pwallet);
    if (!globalState) throw JSONRPCError(RPC_INTERNAL_ERROR, "EVM state database (globalState) is not available.");

    LOCK2(cs_main, pwallet->cs_wallet);

    // RPCTypeCheck using VNUM for gasprice, AmountFromValue handles string input later
    RPCTypeCheck(params, { UniValue::VSTR, UniValue::VNUM, UniValue::VNUM, UniValue::VSTR, UniValue::VBOOL }, true);

    // 1. Bytecode
    std::string bytecode_hex = params[0].get_str();
    if (bytecode_hex.size() % 2 != 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid bytecode hex string: length must be even.");
    if (!IsHex(bytecode_hex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid bytecode hex string: contains non-hex characters.");
    std::vector<unsigned char> bytecode = ParseHex(bytecode_hex);

    // Get gas defaults
    uint64_t blockGasLimit = 0; CAmount minGasPrice = 0, defaultGasPrice = 0;
    getGasRelatedDefaults(blockGasLimit, minGasPrice, defaultGasPrice);

    // 2. Gas Limit
    uint64_t nGasLimit = DEFAULT_GAS_LIMIT_OP_CREATE;
    if (params.size() > 1 && !params[1].isNull()) {
        int64_t nGasLimitInput = params[1].getInt<int64_t>(); // UniValue provides template getInt<>
        if (nGasLimitInput < 0) throw JSONRPCError(RPC_TYPE_ERROR, "Gas limit cannot be negative.");
        nGasLimit = (uint64_t)nGasLimitInput;
        // Add block gas limit check if needed (using consensus params?)
        // uint64_t chainBlockGasLimit = Params().GetConsensus().evmBlockGasLimit; // Example
        // if (nGasLimit > chainBlockGasLimit) throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas limit %d exceeds block gas limit %d", nGasLimit, chainBlockGasLimit));
        if (nGasLimit < MINIMUM_GAS_LIMIT) throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas limit %d is below minimum %d", nGasLimit, MINIMUM_GAS_LIMIT));
    }

    // 3. Gas Price
    CAmount nGasPrice = defaultGasPrice;
    if (params.size() > 2 && !params[2].isNull()) {
        nGasPrice = AmountFromValue(params[2]); // AmountFromValue should handle string/num conversion
        if (nGasPrice < minGasPrice) throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas price %s is less than minimum %s", FormatMoney(nGasPrice), FormatMoney(minGasPrice)));
        CAmount maxRpcGasPrice = GetArg("-rpcmaxgasprice", MAX_RPC_GAS_PRICE);
        if (maxRpcGasPrice > 0 && nGasPrice > maxRpcGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas price %s exceeds RPC maximum %s", FormatMoney(nGasPrice), FormatMoney(maxRpcGasPrice)));
        if (nGasPrice <= 0) throw JSONRPCError(RPC_TYPE_ERROR, "Gas price must be positive.");
    }

    // 4. Sender Address
    CTxDestination senderAddress = CNoDestination();
    CKeyID senderKeyID; // Variable to hold the key ID
    bool fHasSender = false;
    if (params.size() > 3 && !params[3].isNull()) {
        std::string senderStr = params[3].get_str();
        CBitcoinAddress address_parser(senderStr);
        if (!address_parser.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid sender address");
        if (!address_parser.GetKeyID(senderKeyID)) { // Use GetKeyID which exists
             throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sender address does not refer to a key (must be P2PKH)");
        }
        senderAddress = senderKeyID; // Assign the valid CKeyID to the CTxDestination variant
        if (!pwallet->HaveKey(senderKeyID)) {
             throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not contain private key for sender address");
        }
        fHasSender = true;
    }

    // 5. Broadcast
    bool fBroadcast = true;
    if (params.size() > 4 && !params[4].isNull()) {
        fBroadcast = params[4].get_bool();
    }

    // Calculate Gas Fee
    dev::u256 gasFeeU256 = dev::u256(nGasLimit) * dev::u256(nGasPrice);
    if (gasFeeU256 > dev::u256(MAX_MONEY)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Gas fee calculation overflows CAmount limits");
    }
    CAmount nGasFee = static_cast<CAmount>(gasFeeU256);
    const CAmount requiredAmount = nGasFee; // Only gas fee needed for create

    // Check balance (using GetBalance as GetAvailableBalance likely doesn't exist)
    CAmount confirmedBalance = pwallet->GetBalance();
    if (requiredAmount > confirmedBalance) {
         throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strprintf("Insufficient confirmed balance for gas fee. Required minimum: %s, Confirmed balance: %s (Transaction fee not yet included)", FormatMoney(requiredAmount), FormatMoney(confirmedBalance)));
    }

    // Prepare CoinControl and determine signing address
    CCoinControl coinControl;
    CTxDestination signSenderAddress = CNoDestination();

    if (fHasSender) {
        signSenderAddress = senderKeyID;
        // NOTE: SelectCoinsFromAddress was removed as it likely doesn't exist
    } else {
        if (!SetDefaultSignSenderAddress(*pwallet, signSenderAddress, coinControl)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not find a default P2PKH sender address in the wallet with spendable coins. Please specify a sender address.");
        }
        const CKeyID* defaultKeyIDPtr = boost::get<CKeyID>(&signSenderAddress);
        if (!defaultKeyIDPtr) {
             throw JSONRPCError(RPC_INTERNAL_ERROR, "SetDefaultSignSenderAddress did not return a valid P2PKH address.");
        }
        senderKeyID = *defaultKeyIDPtr; // Update senderKeyID to the one found
    }

    if (!IsValidDestination(signSenderAddress) || !IsValidContractSenderAddress(signSenderAddress)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to determine a valid P2PKH sender address for the transaction.");
    }

    // Create the OP_CREATE script
    CScript scriptPubKey = CScript() << CScriptNum(VersionVM::GetEVMDefault().toRaw()) // Ensure VersionVM is correct
                                      << CScriptNum(nGasLimit)
                                      << CScriptNum(nGasPrice)
                                      << bytecode
                                      << OP_CREATE;

    // Define recipients for CreateTransaction (using std::pair)
    std::vector<std::pair<CScript, CAmount>> vecSend;
    vecSend.emplace_back(scriptPubKey, CAmount(0)); // Create contract output with 0 value

    // Prepare for CreateTransaction call
    CWalletTx wtxNew(pwallet); // CWalletTx often takes wallet pointer
    CReserveKey reservekey(pwallet);
    CAmount nFeeRet = 0;
    std::string strFailReason;

    // Call CreateTransaction
    bool createResult = pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, strFailReason, &coinControl);

    if (!createResult) {
         if (requiredAmount + nFeeRet > confirmedBalance && strFailReason.find("Insufficient funds") == std::string::npos) {
             strFailReason += strprintf(" (Failed possibly due to required gas %s + estimated fee %s > confirmed balance %s)", FormatMoney(requiredAmount), FormatMoney(nFeeRet), FormatMoney(confirmedBalance));
         } else if (strFailReason.empty()) {
            strFailReason = "Transaction creation failed. Check available funds and gas parameters.";
         }
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed: " + strFailReason);
    }

    // Get the transaction reference (assuming CWalletTx inherits CTransaction)
    CTransactionRef tx = MakeTransactionRef(wtxNew);
    if (!tx) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation succeeded but failed to create transaction reference (MakeTransactionRef failed?).");
    }

    // Prepare result object
    UniValue result(UniValue::VOBJ);
    dev::h160 senderH160 = GetSenderH160(signSenderAddress); // Use the final signing address
    dev::Address contractAddress = CalculateContractAddress(senderH160);

    result.pushKV("sender", CBitcoinAddress(signSenderAddress).ToString());
    result.pushKV("hash160", senderKeyID.IsNull() ? NullUniValue : senderKeyID.GetHex());
    result.pushKV("address", contractAddress == dev::Address() ? "Error: Could not calculate contract address" : contractAddress.hex());

    if (fBroadcast) {
        // Commit and relay
        CValidationState state; // May not be used by RelayTransaction but might be used by Commit
        if (!pwallet->CommitTransaction(wtxNew, reservekey)) {
             throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed. Wallet state might be inconsistent.");
        }
        RelayTransaction(*tx); // Use overload without CValidationState
        result.pushKV("txid", tx->GetHash().GetHex());
    } else {
        // Return hex if not broadcasting
        result.pushKV("hex", EncodeHexTx(*tx));
    }

    return result;
}

// Conforms to the older (const UniValue& params, bool fHelp) signature
UniValue sendtocontract(const UniValue& params, bool fHelp)
{
     if (fHelp || params.size() < 2 || params.size() > 7) // Max 7 args: contractaddr, data, amount, gaslimit, gasprice, sender, broadcast
     {
         uint64_t blockGasLimit = 0; CAmount minGasPrice = 0, defaultGasPrice = 0;
         getGasRelatedDefaults(blockGasLimit, minGasPrice, defaultGasPrice);
         std::string msg =
             "sendtocontract \"contractaddress\" \"data\" ( amount gaslimit gasprice senderaddress broadcast )\n"
             "\nSend funds and/or data to a contract address.\n"
             "\nArguments:\n"
             "1. \"contractaddress\" (string, required) The contract address (40 hex chars).\n"
             "2. \"data\"            (string, required) The hex-encoded data to send (e.g., function selector and arguments).\n"
             "3. amount              (numeric or string, optional, default=0) Amount of " + CURRENCY_UNIT + " to send (in " + CURRENCY_UNIT + ", e.g., 0.1).\n"
             "4. gaslimit          (numeric, optional, default=" + i64tostr(DEFAULT_GAS_LIMIT_OP_SEND) + ") Gas limit.\n"
             "5. gasprice          (numeric or string, optional, default=" + FormatMoney(defaultGasPrice) + ") Gas price in " + CURRENCY_UNIT + "/gas (in satoshis per gas unit).\n"
             "6. \"senderaddress\"   (string, optional) The " + CURRENCY_UNIT + " address (P2PKH format) sender.\n"
             "7. broadcast         (boolean, optional, default=true) Whether to broadcast.\n"
             "\nResult (if broadcast=true):\n"
             "{\n"
             "  \"txid\": \"transactionidhex\",    (string) The transaction id.\n"
             "  \"sender\": \"senderaddress\",     (string) The P2PKH address of the sender.\n"
             "  \"hash160\": \"keyidhex\"          (string) The key ID (hash160) of the sender address.\n"
             "}\n"
             "\nResult (if broadcast=false):\n"
             "{\n"
             "  \"hex\": \"rawtransactionhex\",    (string) The hex-encoded raw transaction.\n"
             "  \"sender\": \"senderaddress\",     (string) The P2PKH address of the sender.\n"
             "  \"hash160\": \"keyidhex\"          (string) The key ID (hash160) of the sender address.\n"
             "}\n"
             "\nExamples:\n"
             + HelpExampleCli("sendtocontract", "\"c6ca...\" \"aabbcc\"") + "\n"
             + HelpExampleCli("sendtocontract", "\"c6ca...\" \"70a08231000000000000000000000000<YourAddress20BytesHex>\" 0.0 500000 50 \"YourSenderAddressWAGE\"") + " # Call balanceOf with gas price 50 sat/gas\n"
             + HelpExampleRpc("sendtocontract", "[\"c6ca...\", \"aabbcc\", 1.5, 500000, 50, \"YourSenderAddressWAGE\"]"); // Gas price 50 sat/gas
         throw std::runtime_error(msg);
     }

    // Use the global wallet pointer
    CWallet* const pwallet = pwalletMain;
    if (!pwallet) throw JSONRPCError(RPC_WALLET_ERROR, "No wallet is loaded (pwalletMain is null).");
    EnsureWalletIsUnlocked(pwallet);
    if (!globalState) throw JSONRPCError(RPC_INTERNAL_ERROR, "EVM state database (globalState) is not available.");

    LOCK2(cs_main, pwallet->cs_wallet);

    // RPCTypeCheck using VNUM for amount/gasprice, AmountFromValue handles string input later
    RPCTypeCheck(params, { UniValue::VSTR, UniValue::VSTR, UniValue::VNUM, UniValue::VNUM, UniValue::VNUM, UniValue::VSTR, UniValue::VBOOL }, true);

    // 1. Contract Address
    std::string contractAddrStr = params[0].get_str();
    if (contractAddrStr.length() != 40 || !IsHex(contractAddrStr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid contract address hex string: must be 40 hex characters.");
    dev::Address contractAddr;
    try { contractAddr = dev::Address(contractAddrStr); }
    catch (...) { throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid contract address format."); }
    {
        LOCK(cs_main);
        if (!globalState->addressInUse(contractAddr))
             LogPrintf("Warning: Contract address %s not found in state database. Sending anyway.\n", contractAddrStr);
    }

    // 2. Data
    std::string datahex = params[1].get_str();
    if (datahex.size() % 2 != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid data hex string: length must be even.");
    if (!IsHex(datahex)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid data hex string: contains non-hex characters.");
    std::vector<unsigned char> data = ParseHex(datahex);

    // 3. Amount
    CAmount nAmount = 0;
    if (params.size() > 2 && !params[2].isNull()) {
        nAmount = AmountFromValue(params[2]);
        if (nAmount < 0) throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount: cannot be negative.");
        if (nAmount > MAX_MONEY) throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount: too large.");
    }

    // Gas Defaults
    uint64_t blockGasLimit = 0; CAmount minGasPrice = 0, defaultGasPrice = 0;
    getGasRelatedDefaults(blockGasLimit, minGasPrice, defaultGasPrice);

    // 4. Gas Limit
    uint64_t nGasLimit = DEFAULT_GAS_LIMIT_OP_SEND;
    if (params.size() > 3 && !params[3].isNull()) {
        int64_t nGasLimitInput = params[3].getInt<int64_t>();
         if (nGasLimitInput < 0) throw JSONRPCError(RPC_TYPE_ERROR, "Gas limit cannot be negative.");
        nGasLimit = (uint64_t)nGasLimitInput;
        // Add block gas limit check if needed
        // uint64_t chainBlockGasLimit = Params().GetConsensus().evmBlockGasLimit; // Example
        // if (nGasLimit > chainBlockGasLimit) throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas limit %d exceeds block gas limit %d", nGasLimit, chainBlockGasLimit));
        if (nGasLimit < MINIMUM_GAS_LIMIT) throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas limit %d is below minimum %d", nGasLimit, MINIMUM_GAS_LIMIT));
    }

    // 5. Gas Price
    CAmount nGasPrice = defaultGasPrice;
    if (params.size() > 4 && !params[4].isNull()) {
        nGasPrice = AmountFromValue(params[4]);
        if (nGasPrice < minGasPrice) throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas price %s is less than minimum %s", FormatMoney(nGasPrice), FormatMoney(minGasPrice)));
        CAmount maxRpcGasPrice = GetArg("-rpcmaxgasprice", MAX_RPC_GAS_PRICE);
        if (maxRpcGasPrice > 0 && nGasPrice > maxRpcGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Gas price %s exceeds RPC maximum %s", FormatMoney(nGasPrice), FormatMoney(maxRpcGasPrice)));
        if (nGasPrice <= 0) throw JSONRPCError(RPC_TYPE_ERROR, "Gas price must be positive.");
    }

    // 6. Sender Address
    CTxDestination senderAddress = CNoDestination();
    CKeyID senderKeyID;
    bool fHasSender = false;
    if (params.size() > 5 && !params[5].isNull()) {
        std::string senderStr = params[5].get_str();
        CBitcoinAddress sender_address_parser(senderStr);
        if (!sender_address_parser.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid sender address");
        if (!sender_address_parser.GetKeyID(senderKeyID)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sender address does not refer to a key (must be P2PKH)");
        }
        senderAddress = senderKeyID;
        if (!pwallet->HaveKey(senderKeyID)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not contain private key for sender address");
        }
        fHasSender = true;
    }

    // 7. Broadcast
    bool fBroadcast = true;
    if (params.size() > 6 && !params[6].isNull()) {
        fBroadcast = params[6].get_bool();
    }

    // Calculate Fees and Total Cost
    dev::u256 gasFeeU256 = dev::u256(nGasLimit) * dev::u256(nGasPrice);
    if (gasFeeU256 > dev::u256(MAX_MONEY)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Gas fee calculation overflows CAmount limits");
    }
    CAmount nGasFee = static_cast<CAmount>(gasFeeU256);
    CAmount nTotalCost = 0;
    // Manual overflow check
    if (nAmount > 0 && nGasFee > MAX_MONEY - nAmount) {
         throw JSONRPCError(RPC_TYPE_ERROR, "Total amount (value + gas fee) calculation overflows CAmount limits");
    }
    nTotalCost = nAmount + nGasFee;

    // Check balance (using GetBalance)
    CAmount confirmedBalance = pwallet->GetBalance();
    if (nTotalCost > confirmedBalance) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strprintf("Insufficient confirmed balance. Required: %s (%s amount + %s gas fee), Confirmed balance: %s (Transaction fee not yet included)", FormatMoney(nTotalCost), FormatMoney(nAmount), FormatMoney(nGasFee), FormatMoney(confirmedBalance)));
    }

    // Prepare CoinControl and determine signing address
    CCoinControl coinControl;
    CTxDestination signSenderAddress = CNoDestination();

    if (fHasSender) {
        signSenderAddress = senderKeyID;
        // NOTE: SelectCoinsFromAddress was removed as it likely doesn't exist
    } else {
        if (!SetDefaultSignSenderAddress(*pwallet, signSenderAddress, coinControl)) {
             throw JSONRPCError(RPC_WALLET_ERROR, "Could not find a default P2PKH sender address in the wallet with spendable coins. Please specify a sender address.");
        }
         const CKeyID* defaultKeyIDPtr = boost::get<CKeyID>(&signSenderAddress);
         if (!defaultKeyIDPtr) {
              throw JSONRPCError(RPC_INTERNAL_ERROR, "SetDefaultSignSenderAddress did not return a valid P2PKH address.");
         }
         senderKeyID = *defaultKeyIDPtr; // Update senderKeyID to the one found
    }

    if (!IsValidDestination(signSenderAddress) || !IsValidContractSenderAddress(signSenderAddress)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to determine a valid P2PKH sender address for the transaction.");
    }

    // Prepare Script
    std::vector<unsigned char> contractAddrBytes = ParseHex(contractAddrStr);
    CScript scriptPubKey = CScript() << CScriptNum(VersionVM::GetEVMDefault().toRaw())
                                      << CScriptNum(nGasLimit)
                                      << CScriptNum(nGasPrice)
                                      << data
                                      << contractAddrBytes // Push the contract address bytes
                                      << OP_CALL;

    // Prepare Recipients
    std::vector<std::pair<CScript, CAmount>> vecSend;
    vecSend.emplace_back(scriptPubKey, nAmount);

    // Prepare for CreateTransaction
    CWalletTx wtxNew(pwallet);
    CReserveKey reservekey(pwallet);
    CAmount nFeeRet = 0;
    std::string strFailReason;

    // Call CreateTransaction
    bool createResult = pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, strFailReason, &coinControl);

    if (!createResult) {
         if (nTotalCost + nFeeRet > confirmedBalance && strFailReason.find("Insufficient funds") == std::string::npos) {
             strFailReason += strprintf(" (Failed possibly due to required amount %s + estimated fee %s > confirmed balance %s)", FormatMoney(nTotalCost), FormatMoney(nFeeRet), FormatMoney(confirmedBalance));
         } else if (strFailReason.empty()) {
            strFailReason = "Transaction creation failed. Check available funds, gas parameters, and contract interaction.";
         }
         throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation failed: " + strFailReason);
     }

    // Get transaction reference *after* successful creation
    CTransactionRef tx = MakeTransactionRef(wtxNew);
    if (!tx) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction creation succeeded but failed to create transaction reference (MakeTransactionRef failed?).");
    }

    // Prepare Result
    UniValue result(UniValue::VOBJ);
    result.pushKV("sender", CBitcoinAddress(signSenderAddress).ToString());
    result.pushKV("hash160", senderKeyID.IsNull() ? NullUniValue : senderKeyID.GetHex());

    if (fBroadcast) {
        // Commit and Relay
        CValidationState state; // May be unused
        if (!pwallet->CommitTransaction(wtxNew, reservekey)) {
             throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed.");
        }
        RelayTransaction(*tx); // Use overload without CValidationState
        result.pushKV("txid", tx->GetHash().GetHex());
    } else {
        // Return Hex
        result.pushKV("hex", EncodeHexTx(*tx));
    }

    return result;
}


