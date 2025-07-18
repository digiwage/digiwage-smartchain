// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2019 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCPROTOCOL_H
#define BITCOIN_RPCPROTOCOL_H

#include "fs.h" // Consider if this include is truly needed here, or only in protocol.cpp

#include <list>
#include <map>
#include <stdint.h>
#include <string>

#include <univalue.h> // Include UniValue definition

// class UniValue; // Forward declaration - remove this if including univalue.h directly

//! HTTP status codes
enum HTTPStatusCode {
    HTTP_OK                    = 200,
    HTTP_BAD_REQUEST           = 400,
    HTTP_UNAUTHORIZED          = 401,
    HTTP_FORBIDDEN             = 403,
    HTTP_NOT_FOUND             = 404,
    HTTP_BAD_METHOD            = 405,
    HTTP_INTERNAL_SERVER_ERROR = 500,
    HTTP_SERVICE_UNAVAILABLE   = 503,
};

//! PIVX RPC error codes (Ensure these align with DigiWage needs)
enum RPCErrorCode {
    //! Standard JSON-RPC 2.0 errors
    RPC_INVALID_REQUEST     = -32600,
    RPC_METHOD_NOT_FOUND    = -32601,
    RPC_INVALID_PARAMS      = -32602,
    RPC_INTERNAL_ERROR      = -32603,
    RPC_PARSE_ERROR         = -32700,

    //! General application defined errors
    RPC_MISC_ERROR                      = -1, //! std::exception thrown in command handling
    RPC_FORBIDDEN_BY_SAFE_MODE          = -2, //! Server is in safe mode, and command is not allowed in safe mode
    RPC_TYPE_ERROR                      = -3, //! Unexpected type was passed as parameter
    RPC_INVALID_ADDRESS_OR_KEY          = -5, //! Invalid address or key
    RPC_OUT_OF_MEMORY                   = -7, //! Ran out of memory during operation
    RPC_INVALID_PARAMETER               = -8, //! Invalid, missing or duplicate parameter
    RPC_DATABASE_ERROR                  = -20, //! Database error
    RPC_DESERIALIZATION_ERROR           = -22, //! Error parsing or validating structure in raw format
    RPC_VERIFY_ERROR                    = -25, //! General error during transaction or block submission
    RPC_VERIFY_REJECTED                 = -26, //! Transaction or block was rejected by network rules
    RPC_VERIFY_ALREADY_IN_CHAIN         = -27, //! Transaction already in chain
    RPC_IN_WARMUP                       = -28, //! Client still warming up
    RPC_METHOD_DEPRECATED               = -32, //! RPC method is deprecated

    //! Aliases for backward compatibility
    RPC_TRANSACTION_ERROR               = RPC_VERIFY_ERROR,
    RPC_TRANSACTION_REJECTED            = RPC_VERIFY_REJECTED,
    RPC_TRANSACTION_ALREADY_IN_CHAIN    = RPC_VERIFY_ALREADY_IN_CHAIN,

    //! P2P client errors
    RPC_CLIENT_NOT_CONNECTED            = -9, //! DigiWage is not connected (Updated comment)
    RPC_CLIENT_IN_INITIAL_DOWNLOAD      = -10, //! Still downloading initial blocks
    RPC_CLIENT_NODE_ALREADY_ADDED       = -23, //! Node is already added
    RPC_CLIENT_NODE_NOT_ADDED           = -24, //! Node has not been added before
    RPC_CLIENT_NODE_NOT_CONNECTED       = -29, //! Node to disconnect not found in connected nodes
    RPC_CLIENT_INVALID_IP_OR_SUBNET     = -30, //! Invalid IP/Subnet
    RPC_CLIENT_P2P_DISABLED             = -31, //! No valid connection manager instance found

    //! Wallet errors
    RPC_WALLET_ERROR                    = -4, //! Unspecified problem with wallet (key not found etc.)
    RPC_WALLET_INSUFFICIENT_FUNDS       = -6, //! Not enough funds in wallet
    RPC_WALLET_INVALID_LABEL_NAME       = -11, //! Invalid label name
    RPC_WALLET_KEYPOOL_RAN_OUT          = -12, //! Keypool ran out, call keypoolrefill first
    RPC_WALLET_UNLOCK_NEEDED            = -13, //! Enter the wallet passphrase with walletpassphrase first
    RPC_WALLET_PASSPHRASE_INCORRECT     = -14, //! The wallet passphrase entered was incorrect
    RPC_WALLET_WRONG_ENC_STATE          = -15, //! Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    RPC_WALLET_ENCRYPTION_FAILED        = -16, //! Failed to encrypt the wallet
    RPC_WALLET_ALREADY_UNLOCKED         = -17, //! Wallet is already unlocked
};

// --- Function Declarations ---
// Ensure UniValue is known via <univalue.h> include above

/** Create a UniValue JSON-RPC request object */
UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id); // <<< Added semicolon

/** Create a UniValue JSON-RPC reply object */
UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id); // <<< Added semicolon

/** Create a string JSON-RPC reply */
std::string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id); // <<< Added semicolon

/** Create a UniValue JSON-RPC error object */
UniValue JSONRPCError(int code, const std::string& message); // <<< Added semicolon


// --- Cookie Authentication ---

/** Get name of RPC authentication cookie file */
fs::path GetAuthCookieFile();
/** Generate a new RPC authentication cookie and write it to disk */
bool GenerateAuthCookie(std::string *cookie_out);
/** Read the RPC authentication cookie from disk */
bool GetAuthCookie(std::string *cookie_out);
/** Delete RPC authentication cookie from disk */
void DeleteAuthCookie();

#endif // BITCOIN_RPCPROTOCOL_H