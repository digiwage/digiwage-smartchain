// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2019 The DIGIWAGE developers // Updated Copyright Year
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_STANDARD_H
#define BITCOIN_SCRIPT_STANDARD_H

#include "script/interpreter.h" // Includes script.h indirectly usually
#include "uint256.h"
#include "script/script.h" // <<< Explicitly include script.h *BEFORE* defining CTxDestination related types

#include <boost/variant.hpp>

#include <stdint.h>
#include <vector>
#include <map> // For multimap used in Solver

// --- Forward Declarations ---
class CKeyID; // Defined in pubkey.h, but forward declare if needed
class CPubKey; // Defined in pubkey.h

// --- Class Definitions ---

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    CScriptID(const CScript& in); // Definition in standard.cpp
    CScriptID(const uint160& in) : uint160(in) {}
};

// --- Constants ---
static const unsigned int MAX_OP_RETURN_RELAY = 83;      //!< bytes (+1 for OP_RETURN, +2 for the pushdata opcodes)
extern unsigned int nMaxDatacarrierBytes; // Definition likely in policy.cpp or similar

// --- Enums ---
enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA,
    TX_ZEROCOINMINT, // Keep DigiWage specific types
    TX_COLDSTAKE,    // Keep DigiWage specific types

    // QTUM / EVM Contract Types (Added)
    TX_CONTRACT_CREATE,
    TX_CONTRACT_CALL,
    TX_CONTRACT_SENDER_CREATE, // For OP_SENDER + OP_CREATE
    TX_CONTRACT_SENDER_CALL    // For OP_SENDER + OP_CALL
};

// --- Destination Types ---
class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return false; } // Make non-equal ones distinct
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * CScriptID: TX_SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in a CBitcoinAddress
 */
typedef boost::variant<CNoDestination, CKeyID, CScriptID> CTxDestination;


// --- Function Declarations ---

const char* GetTxnOutputType(txnouttype t);

/** Check whether a CTxDestination is a valid destination script type */
bool IsValidDestination(const CTxDestination& dest);

// Modified Solver to accept new parameters from Qtum's MatchContract context if needed later
// For now, keeping existing signature and handling flags internally to MatchContract
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet);
// bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet, bool contractConsensus = false, bool allowEmptySenderSig = true); // Qtum-like signature

int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions);
bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType);
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet, bool fColdStake = false);
bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet);
bool ExtractSenderData(const CScript& outputPubKey, CScript* senderPubKey, CScript* senderSig); // Declaration for function defined in standard.cpp

CScript GetScriptForDestination(const CTxDestination& dest);
CScript GetLockedScriptForDestination(const CTxDestination& dest, int nLockTime);
CScript GetScriptForRawPubKey(const CPubKey& pubKey);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);
CScript GetScriptForStakeDelegation(const CKeyID& stakingKey, const CKeyID& spendingKey); // Keep DigiWage specific

#endif // BITCOIN_SCRIPT_STANDARD_H