// qtum/qtumtoken.cpp (FIXED VERSION - Option 1)

#include <qtum/qtumtoken.h>

// Standard DigiWage / Bitcoin Headers (Verify paths if needed)
#include <base58.h>           // Provides CBitcoinAddress
#include <script/standard.h>   // Provides CTxDestination, CKeyID, CScriptID
#include <utilstrencodings.h>  // Provides HexStr, ParseHex, GetHex (DigiWage native)
#include <utilmoneystr.h>      // Provides FormatMoney (DigiWage native)
#include <util.h>              // Provides LogPrintf etc.
#include <util/convert.h>      // *** MUST contain DEFINITIONS for missing conversion funcs ***
#include <uint256.h>           // Provides uint160, uint256, SetHex
#include <chainparams.h>       // For Params(), COIN
#include <pubkey.h>            // For CPubKey, CKeyID
#include <main.h>              // For globals if needed by concrete exec (e.g., pwalletMain)
#include <boost/variant.hpp>   // Needed for boost::get with CTxDestination

// Headers presumably copied/integrated from Qtum/eth (Verify paths and completeness)
#include <util/contractabi.h>  // Assumes this defines ContractABI, FunctionABI (uses std::string for type)
#include <libethcore/ABI.h>    // Assumes this defines ABIDeserialiser
#include <libdevcore/CommonData.h> // For dev::bytes, dev::fromHex etc.
#include <libdevcore/CommonIO.h> // For dev::toHex (needed by example conversion funcs)

// Standard C++
#include <vector>
#include <string>
#include <map>
#include <stdexcept>
#include <limits>
#include <cstring> // For memset/memcpy if needed by ABI code
#include <memory>  // For std::unique_ptr if used (not used here currently)

// Define defaults if not defined elsewhere - ADJUST VALUES FOR DIGIWAGE
#ifndef DEFAULT_GAS_PRICE
#define DEFAULT_GAS_PRICE 40 // Example value (in Satoshis per gas unit), adjust!
#endif
#ifndef DEFAULT_GAS_LIMIT_OP_SEND
#define DEFAULT_GAS_LIMIT_OP_SEND 250000 // Example value, adjust!
#endif

// --- Namespace for constants ---
namespace QtumToken_NS
{
// ABI String (Keep as is)
const char *TOKEN_ABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_spender\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_from\",\"type\":\"address\"},{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"burn\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_from\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"burnFrom\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_spender\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"},{\"name\":\"_extraData\",\"type\":\"bytes\"}],\"name\":\"approveAndCall\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"initialSupply\",\"type\":\"uint256\"},{\"name\":\"tokenName\",\"type\":\"string\"},{\"name\":\"decimalUnits\",\"type\":\"uint8\"},{\"name\":\"tokenSymbol\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Burn\",\"type\":\"event\"}]";
// Parameter Names (Keep as is)
const char *PARAM_ADDRESS = "address";
const char *PARAM_DATAHEX = "datahex";
const char *PARAM_AMOUNT = "amount";
const char *PARAM_GASLIMIT = "gaslimit";
const char *PARAM_GASPRICE = "gasprice";
const char *PARAM_SENDER = "sender";
const char *PARAM_BROADCAST = "broadcast";
const char *PARAM_CHANGE_TO_SENDER = "changeToSender";
const char *PARAM_PSBT = "psbt";
}

// --- Dummy implementations for the abstract base class methods ---
// You MUST provide a concrete implementation inheriting from QtumTokenExec.
bool QtumTokenExec::execValid(const int &, const bool &) { LogPrintf("QtumTokenExec::execValid - Dummy implementation called.\n"); return false; }
bool QtumTokenExec::execEventsValid(const int &, const int64_t &) { LogPrintf("QtumTokenExec::execEventsValid - Dummy implementation called.\n"); return false; }
bool QtumTokenExec::exec(const bool &, const std::map<std::string, std::string> &, std::string &, std::string &) { LogPrintf("QtumTokenExec::exec - Dummy implementation called.\n"); return false; }
bool QtumTokenExec::execEvents(const int64_t &, const int64_t &, const int64_t&, const std::string &, const std::string &, const std::string &, const int &, std::vector<TokenEvent> &) { LogPrintf("QtumTokenExec::execEvents - Dummy implementation called.\n"); return false; }
bool QtumTokenExec::privateKeysDisabled() { LogPrintf("QtumTokenExec::privateKeysDisabled - Dummy implementation called.\n"); return false; }
QtumTokenExec::~QtumTokenExec() {}

// --- Private Data Structure ---
struct QtumTokenData
{
    std::map<std::string, std::string> lstParams;
    QtumTokenExec* tokenExec; // Pointer to concrete implementation (NOT owned)
    ContractABI* ABI;         // Owned pointer to ABI processor
    // Function Indexes
    int funcName = -1;
    int funcApprove = -1;
    int funcTotalSupply = -1;
    int funcTransferFrom = -1;
    int funcDecimals = -1;
    int funcBurn = -1;
    int funcBalanceOf = -1;
    int funcBurnFrom = -1;
    int funcSymbol = -1;
    int funcTransfer = -1;
    int funcApproveAndCall = -1;
    int funcAllowance = -1;
    // Event Indexes
    int evtTransfer = -1;
    int evtBurn = -1;

    std::string txid;
    std::string psbt;
    std::string errorMessage;

    QtumTokenData(): tokenExec(nullptr), ABI(nullptr) {} // Default initialize

    ~QtumTokenData() {
         delete ABI; // Delete owned ABI object
         ABI = nullptr;
         // Do NOT delete tokenExec, it's owned externally
    }
};

// --- Static Address Conversion Methods (DigiWage compatible) ---

// Converts a DigiWage P2PKH address string to its Hash160 hex representation.
bool QtumToken::ToHash160(const std::string& strBitcoinAddress, std::string& strHash160)
{
    CBitcoinAddress address(strBitcoinAddress); // From base58.h
    if (!address.IsValid()) {
        LogPrintf("QtumToken::ToHash160 - Invalid address: %s\n", strBitcoinAddress);
        return false;
    }
    CTxDestination dest = address.Get(); // From base58.h

    // Use boost::get for boost::variant (CTxDestination in older Bitcoin forks)
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (keyID) {
        strHash160 = keyID->GetHex(); // uint160::GetHex() from utilstrencodings.h
        return true;
    }

    // Optional: Handle P2SH if needed
    // const CScriptID* scriptID = boost::get<CScriptID>(&dest);
    // if (scriptID) { strHash160 = scriptID->GetHex(); return true; }

    LogPrintf("QtumToken::ToHash160 - Address is not P2PKH: %s\n", strBitcoinAddress);
    return false; // Not a type we handle for Hash160
}

// Converts a Hash160 hex string back to a DigiWage address string.
bool QtumToken::ToQtumAddress(const std::string& strHash160, std::string& strBitcoinAddress)
{
    if (strHash160.length() != 40) { // uint160 hex length = 20 bytes * 2 chars/byte
        LogPrintf("QtumToken::ToQtumAddress - Invalid Hash160 hex length: %s\n", strHash160);
        return false;
    }

    uint160 key_data;
    // Handle void return type of SetHex (assume success if no exception)
    try {
        key_data.SetHex(strHash160); // From uint256.h / utilstrencodings.h
    } catch (const std::exception& e) {
        LogPrintf("QtumToken::ToQtumAddress - SetHex exception for %s: %s\n", strHash160, e.what());
        return false;
    } catch (...) {
        LogPrintf("QtumToken::ToQtumAddress - SetHex unknown exception for %s\n", strHash160);
        return false;
    }

    CKeyID keyid(key_data); // CKeyID is derived from uint160
    CTxDestination dest = keyid; // CTxDestination can hold a CKeyID

    CBitcoinAddress address(dest); // Create address object from the destination
    if (!address.IsValid()) { // Check if valid for the *current* network parameters
        LogPrintf("QtumToken::ToQtumAddress - Resulting CBitcoinAddress is invalid for network (Hash160: %s)\n", strHash160);
        return false;
    }

    strBitcoinAddress = address.ToString(); // Convert back to string format (base58check)
    return !strBitcoinAddress.empty(); // Ensure string conversion succeeded
}

// --- u256 Conversion (Requires u256Touint implementation from util/convert.h) ---
uint256 QtumToken::ToUint256(const std::string &data)
{
    // *** CRITICAL: Ensure u256Touint is defined and available (e.g., in util/convert.h) ***
    try {
        // Use dev::fromHex (ensure it exists and handles "0x" prefix if present)
        dev::bytes rawData = dev::fromHex(data);
        // Basic check: if input wasn't empty but output is, hex parsing likely failed
        if (rawData.empty() && !data.empty() && data != "0x" && data != "0") {
             LogPrintf("QtumToken::ToUint256 - Error parsing non-empty hex data: %s\n", data);
             return uint256();
        }
        dev::bytesConstRef o(&rawData);
        // Use ABIDeserialiser (ensure it exists)
        dev::u256 outData = dev::eth::ABIDeserialiser<dev::u256>::deserialise(o);
        // Use the necessary conversion function (ensure it exists)
        return u256Touint(outData);
    } catch (const std::exception& e) {
         LogPrintf("QtumToken::ToUint256 - Exception: %s\n", e.what());
        return uint256(); // Return zero on failure
    } catch (...) {
         LogPrintf("QtumToken::ToUint256 - Unknown exception during conversion.\n");
        return uint256(); // Return zero on failure
    }
}

// --- Constructor ---
QtumToken::QtumToken():
    d(nullptr) // Initialize pointer to null
{
    try {
        d = new QtumTokenData(); // Allocate main data structure
        d->ABI = new ContractABI(); // Allocate ABI processor (ensure ContractABI class exists)

        clear(); // Initialize parameters to defaults

        // Load ABI definition and compute function/event indexes
        if(!d->ABI || !d->ABI->loads(QtumToken_NS::TOKEN_ABI))
        {
             LogPrintf("ERROR: QtumToken - Failed to load Contract ABI definition. Token functions will not work.\n");
             if(d) d->errorMessage = "Failed to load Contract ABI";
             delete d->ABI; d->ABI = nullptr; // Clean up allocated ABI if loading failed
             // Object 'd' exists but is in an invalid state (ABI is null)
        }
        else
        {
            // ABI loaded successfully, find function/event indexes
             LogPrintf("QtumToken - Contract ABI loaded. Mapping functions/events...\n");
            for(size_t i = 0; i < d->ABI->functions.size(); ++i)
            {
                const FunctionABI& func = d->ABI->functions[i]; // Use const reference

                // Check function/event type using the string member from contractabi.h
                // *** THIS IS THE FIXED PART (Option 1) ***
                if (func.type == "function") { // <-- FIX: Compare string directly
                    if(func.name == "name") d->funcName = i;
                    else if(func.name == "approve") d->funcApprove = i;
                    else if(func.name == "totalSupply") d->funcTotalSupply = i;
                    else if(func.name == "transferFrom") d->funcTransferFrom = i;
                    else if(func.name == "decimals") d->funcDecimals = i;
                    else if(func.name == "burn") d->funcBurn = i;
                    else if(func.name == "balanceOf") d->funcBalanceOf = i;
                    else if(func.name == "burnFrom") d->funcBurnFrom = i;
                    else if(func.name == "symbol") d->funcSymbol = i;
                    else if(func.name == "transfer") d->funcTransfer = i;
                    else if(func.name == "approveAndCall") d->funcApproveAndCall = i;
                    else if(func.name == "allowance") d->funcAllowance = i;
                 } else if (func.type == "event") { // <-- FIX: Compare string directly
                    if(func.name == "Transfer") d->evtTransfer = i;
                    else if(func.name == "Burn") d->evtBurn = i;
                } else if (func.type == "constructor") {
                     // Optional: Handle constructor if needed, or ignore
                     // LogPrintf("QtumToken - Info: Found constructor ABI entry for '%s' at index %d.\n", func.name, i);
                } else if (func.type == "fallback") {
                     // Optional: Handle fallback if needed, or ignore
                     // LogPrintf("QtumToken - Info: Found fallback ABI entry at index %d.\n", i);
                } else if (func.type == "default") { // contractabi.cpp adds a "default" type
                     // Ignore the special "default" entry added by contractabi.cpp
                } else {
                    // Log if type string is unexpected
                    LogPrintf("QtumToken - Warning: Unknown ABI entry type string '%s' for '%s' at index %d.\n", func.type, func.name, i);
                }
                // *** END OF FIX ***
            }
             LogPrintf("QtumToken - Function/event mapping complete. (Name:%d, Transfer:%d, TransferEvt:%d)\n", d->funcName, d->funcTransfer, d->evtTransfer); // Example log
        }
    } catch (const std::bad_alloc& ba) {
        LogPrintf("ERROR: QtumToken Constructor - Memory allocation failed: %s\n", ba.what());
        if (d) { delete d->ABI; delete d; d = nullptr; } // Cleanup partial allocation
    } catch (const std::exception& e) {
        LogPrintf("ERROR: QtumToken Constructor - Exception: %s\n", e.what());
        if (d) { delete d->ABI; delete d; d = nullptr; } // Cleanup partial allocation
    } catch (...) {
         LogPrintf("ERROR: QtumToken Constructor - Unknown exception occurred.\n");
        if (d) { delete d->ABI; delete d; d = nullptr; } // Cleanup partial allocation
    }
}

// --- Destructor ---
QtumToken::~QtumToken()
{
    delete d; // Deletes QtumTokenData, which deletes the owned ABI object.
    d = nullptr;
}

// --- Parameter Setters ---
void QtumToken::setAddress(const std::string &address) { if (d) d->lstParams[QtumToken_NS::PARAM_ADDRESS] = address; }
void QtumToken::setDataHex(const std::string &datahex) { if (d) d->lstParams[QtumToken_NS::PARAM_DATAHEX] = datahex; }
void QtumToken::setAmount(const std::string &amount)   { if (d) d->lstParams[QtumToken_NS::PARAM_AMOUNT] = amount; }
void QtumToken::setGasLimit(const std::string &gaslimit){ if (d) d->lstParams[QtumToken_NS::PARAM_GASLIMIT] = gaslimit; }
void QtumToken::setGasPrice(const std::string &gasPrice){ if (d) d->lstParams[QtumToken_NS::PARAM_GASPRICE] = gasPrice; }
void QtumToken::setSender(const std::string &sender)   { if (d) d->lstParams[QtumToken_NS::PARAM_SENDER] = sender; }

// --- Clear State ---
void QtumToken::clear()
{
    if (!d) return; // Safety check if constructor failed
    d->lstParams.clear();
    d->txid = "";
    d->psbt = "";
    d->errorMessage = "";
    setAmount("0"); // Default amount for contract calls
    // Use FormatMoney from DigiWage's utilmoneystr.h
    CAmount default_gas_price_satoshi = DEFAULT_GAS_PRICE; // Assumes constant is in Satoshis per gas
    setGasPrice(FormatMoney(default_gas_price_satoshi)); // FormatMoney usually takes CAmount (Satoshis)
    setGasLimit(std::to_string(DEFAULT_GAS_LIMIT_OP_SEND)); // Gas limit as string
    // Default options expected by potential RPC calls
    d->lstParams[QtumToken_NS::PARAM_BROADCAST] = "true";
    d->lstParams[QtumToken_NS::PARAM_CHANGE_TO_SENDER] = "true";
}

// --- Result Getters ---
std::string QtumToken::getTxId() { return d ? d->txid : ""; }
std::string QtumToken::getPsbt() { return d ? d->psbt : ""; }
void QtumToken::setTxId(const std::string& txid) { if (d) d->txid = txid; }
std::string QtumToken::getErrorMessage() { return d ? d->errorMessage : "QtumToken object not initialized"; }

// --- Token Function Wrappers ---
// Provide implementations for all public functions defined in qtumtoken.h

bool QtumToken::name(std::string &result, bool sendTo)
{
    if (!d || d->funcName < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'name'"; return false; }
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcName, output, sendTo)) return false;
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'name' returned no data"; return false; }
        result = output[0];
    }
    return true;
}

bool QtumToken::approve(const std::string &_spender, const std::string &_value, bool &success, bool sendTo)
{
    if (!d || d->funcApprove < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'approve'"; return false; }
    std::string spenderHash160;
    if (!ToHash160(_spender, spenderHash160)) { if(d) d->errorMessage="Invalid spender address for 'approve'"; return false; }

    std::vector<std::string> input = {spenderHash160, _value};
    std::vector<std::string> output;
    if(!exec(input, d->funcApprove, output, sendTo)) return false;

    success = true; // Assume success if exec didn't fail
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'approve' returned no data (may be ok)"; success = true; } // Approve might return void on success call
        else { success = (output[0] == "true" || output[0] == "1"); }
    }
    return true;
}

bool QtumToken::totalSupply(std::string &result, bool sendTo)
{
    if (!d || d->funcTotalSupply < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'totalSupply'"; return false; }
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcTotalSupply, output, sendTo)) return false;
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'totalSupply' returned no data"; return false; }
        result = output[0];
    }
    return true;
}

bool QtumToken::transferFrom(const std::string &_from, const std::string &_to, const std::string &_value, bool &success, bool sendTo)
{
    if (!d || d->funcTransferFrom < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'transferFrom'"; return false; }
    std::string fromHash160, toHash160;
    if (!ToHash160(_from, fromHash160)) { if(d) d->errorMessage="Invalid 'from' address for 'transferFrom'"; return false; }
    if (!ToHash160(_to, toHash160)) { if(d) d->errorMessage="Invalid 'to' address for 'transferFrom'"; return false; }

    std::vector<std::string> input = {fromHash160, toHash160, _value};
    std::vector<std::string> output;
    if(!exec(input, d->funcTransferFrom, output, sendTo)) return false;

    success = true; // Assume success if exec didn't fail
    if(!sendTo) {
         if(output.empty()) { if(d) d->errorMessage="Call 'transferFrom' returned no data (may be ok)"; success = true; }
         else { success = (output[0] == "true" || output[0] == "1"); }
    }
    return true;
}

bool QtumToken::decimals(std::string &result, bool sendTo)
{
    if (!d || d->funcDecimals < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'decimals'"; return false; }
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcDecimals, output, sendTo)) return false;
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'decimals' returned no data"; return false; }
        result = output[0];
    }
    return true;
}

// Uses std::stoul for parsing, replacing missing ParseUInt32
bool QtumToken::decimals(uint32_t &result)
{
    if (!d) { return false; } // Need d for potential error message
    std::string str_decimals;
    if (!decimals(str_decimals, false)) { // Call the string version (sendTo=false)
        return false; // errorMessage should be set by the call above
    }
    try {
        unsigned long parsed_value = std::stoul(str_decimals);
        if (parsed_value > std::numeric_limits<uint32_t>::max()) {
            d->errorMessage = "Decimals value (" + str_decimals + ") out of range for uint32_t";
            return false;
        }
        result = static_cast<uint32_t>(parsed_value);
        return true;
    } catch (const std::invalid_argument& ) {
        d->errorMessage = "Invalid decimals value: not a number (" + str_decimals + ")";
        return false;
    } catch (const std::out_of_range& ) {
        d->errorMessage = "Decimals value out of range (" + str_decimals + ")";
        return false;
    } catch (...) {
        d->errorMessage = "Unknown error parsing decimals value (" + str_decimals + ")";
        return false;
    }
}

bool QtumToken::burn(const std::string &_value, bool &success, bool sendTo)
{
    if (!d || d->funcBurn < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'burn'"; return false; }
    std::vector<std::string> input = {_value};
    std::vector<std::string> output;
    if(!exec(input, d->funcBurn, output, sendTo)) return false;

    success = true; // Assume success if exec didn't fail
    if(!sendTo) {
         if(output.empty()) { if(d) d->errorMessage="Call 'burn' returned no data (may be ok)"; success = true; }
         else { success = (output[0] == "true" || output[0] == "1"); }
    }
    return true;
}

bool QtumToken::balanceOf(std::string &result, bool sendTo)
{
    if (!d) { return false; }
    std::string spender = d->lstParams[QtumToken_NS::PARAM_SENDER];
    if (spender.empty()) {
        d->errorMessage = "Sender address not set for 'balanceOf'";
        return false;
    }
    return balanceOf(spender, result, sendTo);
}

bool QtumToken::balanceOf(const std::string &_spender, std::string &result, bool sendTo)
{
    if (!d || d->funcBalanceOf < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'balanceOf'"; return false; }
    std::string spenderHash160;
    if (!ToHash160(_spender, spenderHash160)) { if(d) d->errorMessage="Invalid spender address for 'balanceOf'"; return false; }

    std::vector<std::string> input = {spenderHash160};
    std::vector<std::string> output;
    if(!exec(input, d->funcBalanceOf, output, sendTo)) return false;
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'balanceOf' returned no data"; return false; }
        result = output[0];
    }
    return true;
}

bool QtumToken::burnFrom(const std::string &_from, const std::string &_value, bool &success, bool sendTo)
{
    if (!d || d->funcBurnFrom < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'burnFrom'"; return false; }
    std::string fromHash160;
    if (!ToHash160(_from, fromHash160)) { if(d) d->errorMessage="Invalid 'from' address for 'burnFrom'"; return false; }

    std::vector<std::string> input = {fromHash160, _value};
    std::vector<std::string> output;
    if(!exec(input, d->funcBurnFrom, output, sendTo)) return false;

    success = true; // Assume success if exec didn't fail
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'burnFrom' returned no data (may be ok)"; success = true; }
        else { success = (output[0] == "true" || output[0] == "1"); }
    }
    return true;
}

bool QtumToken::symbol(std::string &result, bool sendTo)
{
     if (!d || d->funcSymbol < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'symbol'"; return false; }
    std::vector<std::string> input;
    std::vector<std::string> output;
    if(!exec(input, d->funcSymbol, output, sendTo)) return false;
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'symbol' returned no data"; return false; }
        result = output[0];
    }
    return true;
}

bool QtumToken::transfer(const std::string &_to, const std::string &_value, bool& success, bool sendTo)
{
    if (!d || d->funcTransfer < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'transfer'"; return false; }
    std::string toHash160;
    if (!ToHash160(_to, toHash160)) { if(d) d->errorMessage="Invalid 'to' address for 'transfer'"; return false; }

    std::vector<std::string> input = {toHash160, _value};
    std::vector<std::string> output;
    if(!exec(input, d->funcTransfer, output, sendTo)) return false;

    success = true; // Assume success if exec didn't fail
    if(!sendTo) {
        // Standard ERC20 transfer call might return empty on success.
        if(output.empty()) {
             success = true; // Success assumed if call didn't revert
        } else {
            // If data is returned, check if it indicates success
            success = (output[0] == "true" || output[0] == "1");
        }
    }
    return true; // Return true if exec succeeded
}

bool QtumToken::approveAndCall(const std::string &_spender, const std::string &_value, const std::string &_extraData, bool &success, bool sendTo)
{
    if (!d || d->funcApproveAndCall < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'approveAndCall'"; return false; }
    std::string spenderHash160;
    if (!ToHash160(_spender, spenderHash160)) { if(d) d->errorMessage="Invalid spender address for 'approveAndCall'"; return false; }

    // Assumes _extraData is already a hex string representation of bytes
    std::vector<std::string> input = {spenderHash160, _value, _extraData};
    std::vector<std::string> output;
    if(!exec(input, d->funcApproveAndCall, output, sendTo)) return false;

    success = true; // Assume success if exec didn't fail
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'approveAndCall' returned no data (may be ok)"; success = true; }
        else { success = (output[0] == "true" || output[0] == "1"); }
    }
    return true;
}

bool QtumToken::allowance(const std::string &_from, const std::string &_to, std::string &result, bool sendTo)
{
    if (!d || d->funcAllowance < 0 || !d->ABI) { if(d) d->errorMessage="Not initialized or ABI error for 'allowance'"; return false; }
    std::string fromHash160, toHash160;
    if (!ToHash160(_from, fromHash160)) { if(d) d->errorMessage="Invalid 'from' address for 'allowance'"; return false; }
    if (!ToHash160(_to, toHash160)) { if(d) d->errorMessage="Invalid 'to' address for 'allowance'"; return false; }

    std::vector<std::string> input = {fromHash160, toHash160};
    std::vector<std::string> output;
    if(!exec(input, d->funcAllowance, output, sendTo)) return false;
    if(!sendTo) {
        if(output.empty()) { if(d) d->errorMessage="Call 'allowance' returned no data"; return false; }
        result = output[0];
    }
    return true;
}


// --- Event Handling Wrappers ---
bool QtumToken::transferEvents(std::vector<TokenEvent> &tokenEvents, int64_t fromBlock, int64_t toBlock, int64_t minconf)
{
    tokenEvents.clear(); // Clear previous results
    if (!d || d->evtTransfer < 0 || !d->ABI) {
         LogPrintf("QtumToken::transferEvents - Not initialized or Transfer event ABI not loaded.\n");
         if(d) d->errorMessage = "Transfer event ABI not loaded or object not initialized";
         return false;
    }
    return execEvents(fromBlock, toBlock, minconf, d->evtTransfer, tokenEvents);
}

bool QtumToken::burnEvents(std::vector<TokenEvent> &tokenEvents, int64_t fromBlock, int64_t toBlock, int64_t minconf)
{
    tokenEvents.clear(); // Clear previous results
    if (!d || d->evtBurn < 0 || !d->ABI) {
        LogPrintf("QtumToken::burnEvents - Not initialized or Burn event ABI not loaded.\n");
        if(d) d->errorMessage = "Burn event ABI not loaded or object not initialized";
        return false;
    }
    return execEvents(fromBlock, toBlock, minconf, d->evtBurn, tokenEvents);
}

// --- Internal Execution Logic ---

// Executes a function call or transaction via the QtumTokenExec backend
bool QtumToken::exec(const std::vector<std::string> &input, int funcIndex, std::vector<std::string> &output, bool sendTo)
{
    // --- Pre-execution Checks ---
    if (!d || !d->ABI || !d->tokenExec) {
         // Avoid logging spam if constructor failed and logged already
         if(d && d->errorMessage.empty()) d->errorMessage = "QtumToken not properly initialized (ABI or Exec backend missing)";
         else if (!d) LogPrintf("ERROR: QtumToken::exec called on null object!\n");
        return false;
    }
     // Ensure index is valid and points to a Function type within the ABI
     // *** THIS IS THE FIXED PART (Option 1) ***
     if (funcIndex < 0 || (size_t)funcIndex >= d->ABI->functions.size() || d->ABI->functions[funcIndex].type != "function") { // <-- FIX: Compare string directly
        d->errorMessage = "Invalid function index or ABI entry is not a function";
        LogPrintf("ERROR: QtumToken::exec - %s (Index: %d, ABI size: %u)\n", d->errorMessage, funcIndex, (unsigned)d->ABI->functions.size());
        return false;
     }
     // *** END OF FIX ***

    const FunctionABI& function = d->ABI->functions[funcIndex]; // Get reference to the function definition

    // Check if the execution backend considers this specific call valid
    if (!d->tokenExec->execValid(funcIndex, sendTo)) {
        // Assuming execValid sets a more specific error message via getErrorMessage() on the backend if needed
        if(d->errorMessage.empty()) d->errorMessage = "Execution backend reported invalid operation for function: " + function.name;
        LogPrintf("ERROR: QtumToken::exec - execValid failed for function '%s' (sendTo=%d)\n", function.name, sendTo);
        return false;
    }

    // Clear previous results before execution
    d->txid = "";
    d->psbt = "";
    d->errorMessage = "";
    output.clear(); // Clear output vector for 'call' results

    // --- ABI Encoding ---
    std::string strDataHex; // ABI encoded function call data
    std::vector<std::vector<std::string>> values; // ABI library expects vector<vector<string>>
    values.resize(input.size());
    for(size_t i = 0; i < input.size(); ++i) {
        values[i].push_back(input[i]); // Each input string is a single element vector
    }

    std::vector<ParameterABI::ErrorType> encode_errors; // Assume ErrorType exists in ParameterABI
    if(!function.abiIn(values, strDataHex, encode_errors)) {
         d->errorMessage = "ABI encoding failed for function '" + function.name + "':";
         // Append specific errors if the ErrorType provides details
         for(const auto& err : encode_errors) { d->errorMessage += " encoding_error;"; } // Placeholder for error details
         LogPrintf("ERROR: QtumToken::exec - %s\n", d->errorMessage);
        return false;
    }
    setDataHex(strDataHex); // Set the generated hex data in parameters for the backend

    // --- Backend Execution ---
    std::string result_hex_or_txid_or_psbt;
    LogPrintf("QtumToken::exec - Calling backend for '%s' (sendTo=%d). Data: %s\n", function.name, sendTo, strDataHex);
    // The concrete implementation of exec() handles RPC calls / wallet interaction
    if(!(d->tokenExec->exec(sendTo, d->lstParams, result_hex_or_txid_or_psbt, d->errorMessage))) {
        // errorMessage should be set by tokenExec->exec() on failure
        if (d->errorMessage.empty()) d->errorMessage = "Execution backend failed for '" + function.name + "' without specific error";
        LogPrintf("ERROR: QtumToken::exec - Backend failed for '%s': %s\n", function.name, d->errorMessage);
        return false;
    }
    LogPrintf("QtumToken::exec - Backend successful for '%s'. Result/TxID/PSBT: %s\n", function.name, result_hex_or_txid_or_psbt);


    // --- Process Result ---
    if (!sendTo) { // This was a 'call', result should be hex data, decode it
        std::vector<std::vector<std::string>> output_values;
        std::vector<ParameterABI::ErrorType> decode_errors;
        // Use the result from the backend call
        if(!function.abiOut(result_hex_or_txid_or_psbt, output_values, decode_errors)) {
            // It's possible the contract call succeeded but returned unexpected/unparseable data.
            d->errorMessage = "ABI decoding failed for call result of '" + function.name + "':";
             for(const auto& err : decode_errors) { d->errorMessage += " decode_error;"; } // Placeholder
            LogPrintf("ERROR: QtumToken::exec - %s. Raw result: %s\n", d->errorMessage, result_hex_or_txid_or_psbt);
            // Return false as we couldn't get the expected output.
            return false;
        }
        // Flatten the decoded output_values into the output vector
        for(const auto& param_vec : output_values) {
            output.push_back(param_vec.empty() ? "" : param_vec[0]); // Handle empty results for a parameter
        }
        LogPrintf("QtumToken::exec - Call '%s' decoded output count: %u\n", function.name, (unsigned)output.size());
    } else { // This was a 'send', result is TXID or PSBT
        if (d->tokenExec->privateKeysDisabled()) {
            d->psbt = result_hex_or_txid_or_psbt; // Store PSBT
            LogPrintf("QtumToken::exec - Send '%s' generated PSBT.\n", function.name);
        } else {
            d->txid = result_hex_or_txid_or_psbt; // Store TXID
             LogPrintf("QtumToken::exec - Send '%s' generated TXID: %s\n", function.name, d->txid);
        }
        // For 'send', success is implied if exec returned true. Output vector remains empty.
    }

    return true; // Indicate overall success of the operation (call or send)
}


// --- Event Aggregation/Adding ---
void QtumToken::addTokenEvent(std::vector<TokenEvent> &tokenEvents, TokenEvent tokenEvent)
{
    // Basic approach: Add the event. Uniqueness should ideally be handled
    // by the source (searchlogs) providing distinct events based on block/tx/logIndex.
    // Avoid complex merging/duplicate checks here unless absolutely necessary.
    // **FIXED**: Removed check for logIndex as it was missing from TokenEvent struct.
    // If TokenEvent struct *should* have logIndex, add it there first.

    tokenEvents.push_back(tokenEvent);
}

// --- Internal Event Query Logic ---
bool QtumToken::execEvents(int64_t fromBlock, int64_t toBlock, int64_t minconf, int eventIndex, std::vector<TokenEvent> &tokenEvents)
{
    // --- Pre-execution Checks ---
     if (!d || !d->ABI || !d->tokenExec) {
         if(d) d->errorMessage = "QtumToken not properly initialized (ABI or Exec backend missing)";
         else LogPrintf("ERROR: QtumToken::execEvents called on null object!\n");
        return false;
    }
     // Ensure index is valid and points to an Event type within the ABI
     // *** THIS IS THE FIXED PART (Option 1) ***
    if (eventIndex < 0 || (size_t)eventIndex >= d->ABI->functions.size() || d->ABI->functions[eventIndex].type != "event") { // <-- FIX: Compare string directly
        d->errorMessage = "Invalid event index or ABI entry is not an event";
        LogPrintf("ERROR: QtumToken::execEvents - %s (Index: %d, ABI size: %u)\n", d->errorMessage, eventIndex, (unsigned)d->ABI->functions.size());
        return false;
    }
    // *** END OF FIX ***

    const FunctionABI& eventABI = d->ABI->functions[eventIndex]; // Get reference to the event definition

    // Check if the execution backend considers this specific event query valid
    if (!(d->tokenExec->execEventsValid(eventIndex, fromBlock))) { // Pass necessary validation params
        if(d->errorMessage.empty()) d->errorMessage = "Execution backend reported invalid event query operation for event: " + eventABI.name;
        LogPrintf("ERROR: QtumToken::execEvents - execEventsValid failed for event '%s'\n", eventABI.name);
        return false;
    }

    // --- Prepare Parameters for Backend ---
    tokenEvents.clear(); // Clear results from previous calls
    d->errorMessage = "";  // Clear previous error

    std::string eventSignature = eventABI.selector(); // Event signature topic[0] (e.g., sha3("Transfer(address,address,uint256)"))
    std::string contractAddress = d->lstParams[QtumToken_NS::PARAM_ADDRESS]; // Contract address filter
    if (contractAddress.empty()) {
        d->errorMessage = "Contract address not set for event query";
        LogPrintf("ERROR: QtumToken::execEvents - %s\n", d->errorMessage);
        return false;
    }

    // Placeholder for topic filtering (e.g., by sender/receiver).
    // The concrete QtumTokenExec implementation needs to construct the topic list for searchlogs.
    std::string topicFilterPlaceholder; // Example: Could be JSON array string "[null, \"0x...sender...\", null]"
                                        // This needs to be defined by how your execEvents implementation works.

    int numTopics = eventABI.numIndexed() + 1; // Total topics expected (signature + indexed params)

    // --- Backend Event Query ---
    std::vector<TokenEvent> rawEvents; // Assume backend populates this struct type directly via searchlogs parsing
    LogPrintf("QtumToken::execEvents - Calling backend for '%s' events. Contract: %s, Sig: %s\n", eventABI.name, contractAddress, eventSignature);
    // The concrete implementation of execEvents handles the searchlogs RPC call.
    if(!(d->tokenExec->execEvents(fromBlock, toBlock, minconf, eventSignature, contractAddress, topicFilterPlaceholder, numTopics, rawEvents))) {
        // errorMessage should be set by tokenExec->execEvents on failure
        if (d->errorMessage.empty()) d->errorMessage = "Event query backend failed for '" + eventABI.name + "' without specific error";
        LogPrintf("ERROR: QtumToken::execEvents - Backend failed for '%s': %s\n", eventABI.name, d->errorMessage);
        return false;
    }
    LogPrintf("QtumToken::execEvents - Backend successful for '%s'. Found %u raw events.\n", eventABI.name, (unsigned)rawEvents.size());

    // --- Process & Add Results ---
    // Assumes the backend (execEvents) returned correctly parsed TokenEvent structs.
    // If raw log data was returned, decoding using eventABI.decodeTopics/decodeData would happen here.
    for(const TokenEvent& rawEvent : rawEvents) {
        addTokenEvent(tokenEvents, rawEvent); // Use the add method (currently just pushes back)
    }
    LogPrintf("QtumToken::execEvents - Added %u events to results vector.\n", (unsigned)tokenEvents.size());

    return true; // Indicate success
}


// --- Setup & Static Accessors ---

// Sets the concrete backend implementation
void QtumToken::setQtumTokenExec(QtumTokenExec *tokenExec)
{
    if(d) {
        d->tokenExec = tokenExec;
        LogPrintf("QtumToken - Execution backend set.\n");
    } else {
        LogPrintf("ERROR: QtumToken::setQtumTokenExec called on null object!\n");
    }
}

// Static const char* accessors for parameter names (remain unchanged)
const char* QtumToken::paramAddress() { return QtumToken_NS::PARAM_ADDRESS; }
const char* QtumToken::paramDatahex() { return QtumToken_NS::PARAM_DATAHEX; }
const char* QtumToken::paramAmount() { return QtumToken_NS::PARAM_AMOUNT; }
const char* QtumToken::paramGasLimit() { return QtumToken_NS::PARAM_GASLIMIT; }
const char* QtumToken::paramGasPrice() { return QtumToken_NS::PARAM_GASPRICE; }
const char* QtumToken::paramSender() { return QtumToken_NS::PARAM_SENDER; }
const char* QtumToken::paramBroadcast() { return QtumToken_NS::PARAM_BROADCAST; }
const char* QtumToken::paramChangeToSender() { return QtumToken_NS::PARAM_CHANGE_TO_SENDER; }
const char* QtumToken::paramPsbt() { return QtumToken_NS::PARAM_PSBT; }

