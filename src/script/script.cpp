// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2024 The DIGIWAGE developers // Updated year
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/script.h" // Includes opcodes.h if it's structured that way
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "pubkey.h" // For CPubKey methods like IsValid(), ValidSize()

// For GetOpName, needs script/opcodes.h to be included by script.h or here
// Or GetOpName itself is defined elsewhere (like in this file from your example)

namespace { // From your original script.cpp
inline std::string ValueString(const std::vector<unsigned char>& vch)
{
    if (vch.size() <= 4) // CScriptNum can only hold 4 bytes for getint() safely
        return strprintf("%d", CScriptNum(vch, false, 4).getint()); // Specify max size for safety
    else
        return HexStr(vch);
}
} // anon namespace

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    // OP_TRUE is an alias for OP_1
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expansion
    case OP_NOP1                   : return "OP_NOP1";
    case OP_CHECKLOCKTIMEVERIFY    : return "OP_CHECKLOCKTIMEVERIFY"; // Same as OP_NOP2
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    // zerocoin
    case OP_ZEROCOINMINT           : return "OP_ZEROCOINMINT";
    case OP_ZEROCOINSPEND          : return "OP_ZEROCOINSPEND";

    // cold staking
    case OP_CHECKCOLDSTAKEVERIFY   : return "OP_CHECKCOLDSTAKEVERIFY";

    // EVM Execution Opcodes (Your DigiWage specific values)
    case OP_CREATE                 : return "OP_CREATE";
    case OP_CALL                   : return "OP_CALL";
    case OP_SPEND                  : return "OP_SPEND"; // DigiWage specific spend
    case OP_SENDER                 : return "OP_SENDER";

    // EVM Script Structure Opcodes (for template matching, mostly not directly executable)
    case OP_VERSION                : return "OP_VERSION";
    case OP_GAS_LIMIT              : return "OP_GAS_LIMIT";
    case OP_GAS_PRICE              : return "OP_GAS_PRICE";
    case OP_DATA                   : return "OP_DATA";
    case OP_ADDRESS_TYPE           : return "OP_ADDRESS_TYPE";
    case OP_ADDRESS                : return "OP_ADDRESS";
    case OP_SCRIPT_SIG             : return "OP_SCRIPT_SIG";

    // template matching params (from your script.h)
    case OP_SMALLINTEGER : return "OP_SMALLINTEGER";
    case OP_PUBKEYS      : return "OP_PUBKEYS";
    case OP_PUBKEYHASH   : return "OP_PUBKEYHASH";
    case OP_PUBKEY       : return "OP_PUBKEY";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    default:
        return "OP_UNKNOWN";
    }
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        valtype vchData; // GetOp will fill this if it's a push
        if (!GetOp(pc, opcode, vchData)) // Use the version that extracts data
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20; // MAX_PUBKEYS_PER_MULTISIG (Bitcoin default)
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    const_iterator pc = scriptSig.begin();
    std::vector<unsigned char> data;
    opcodetype opcode; // Define opcode for GetOp
    while (pc < scriptSig.end())
    {
        // Correctly get the last PUSHED item from scriptSig
        // The original logic was to get the last item, but GetOp advances pc.
        // We need to get all pushes and then take the last one.
        // For P2SH, the redeemScript is the last item pushed.
        valtype pushed_item;
        if (!scriptSig.GetOp(pc, opcode, pushed_item)) // Use the version that extracts data
            return 0; // Malformed scriptSig
        if (opcode > OP_16 && !(opcode >= OP_1 && opcode <= OP_PUSHDATA4) ) // Not a push or OP_N
             return 0; // Malformed P2SH scriptSig (should only contain pushes)
        if (pc == scriptSig.end()) { // This was the last item pushed
            data = pushed_item;
            break;
        }
    }

    if (data.empty()) return 0; // No redeemScript pushed

    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsNormalPaymentScript() const // Kept your original logic
{
    if(this->size() != 25) return false;
    opcodetype opcode;
    const_iterator pc = begin();
    int i = 0;
    while (pc < end())
    {
        GetOp(pc, opcode); // Simple GetOp is fine if not checking pushed data

        if(     i == 0 && opcode != OP_DUP) return false;
        else if(i == 1 && opcode != OP_HASH160) return false;
        // Missing check for [2] == 0x14 (push 20 bytes)
        else if(i == 3 && opcode != OP_EQUALVERIFY) return false;
        else if(i == 4 && opcode != OP_CHECKSIG) return false;
        else if(i == 5) return false; // Should not have more than 5 ops for P2PKH
        i++;
    }
    return (i == 5); // Ensure exactly 5 ops were processed
}

bool CScript::IsPayToScriptHash() const
{
    return (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 && // Push 20 bytes
            (*this)[22] == OP_EQUAL);
}

bool CScript::IsPayToColdStaking() const
{
    return (this->size() == 51 &&
            (*this)[0]  == OP_DUP && // Added for completeness, your check started at [2]
            (*this)[1]  == OP_HASH160 &&
            (*this)[2]  == OP_ROT &&
            (*this)[3]  == OP_IF &&
            (*this)[4]  == OP_CHECKCOLDSTAKEVERIFY &&
            (*this)[5]  == 0x14 && // Push 20 bytes (staking key hash)
            (*this)[26] == OP_ELSE &&
            (*this)[27] == 0x14 && // Push 20 bytes (spending key hash)
            (*this)[48] == OP_ENDIF &&
            (*this)[49] == OP_EQUALVERIFY &&
            (*this)[50] == OP_CHECKSIG);
}

// Implementation for CScript::IsPayToPublicKeyHash
bool CScript::IsPayToPublicKeyHash() const
{
    return (this->size() == 25 &&
            (*this)[0] == OP_DUP &&
            (*this)[1] == OP_HASH160 &&
            (*this)[2] == 0x14 && // Push 20 bytes
            (*this)[23] == OP_EQUALVERIFY &&
            (*this)[24] == OP_CHECKSIG);
}

// Implementation for CScript::IsPayToPublicKey
bool CScript::IsPayToPublicKey() const
{
    if (this->size() != 35 && this->size() != 67) return false;
    if ((*this)[this->size() - 1] != OP_CHECKSIG) return false;

    unsigned int pubkey_size = (*this)[0]; // Length of the pubkey
    if (pubkey_size != 33 && pubkey_size != 65) return false;
    if (this->size() != pubkey_size + 2) return false; // 1 byte for len, pubkey_size bytes, 1 byte for OP_CHECKSIG

    // Optional: Validate that the pushed data is a valid pubkey format
    // CPubKey pubkey(this->begin() + 1, this->begin() + 1 + pubkey_size);
    // if (!pubkey.IsValid()) return false; // Requires CPubKey(const valtype&) constructor

    return true;
}


bool CScript::StartsWithOpcode(const opcodetype opcode) const
{
    return (!this->empty() && (*this)[0] == opcode);
}

bool CScript::IsZerocoinMint() const
{
    // A full check might involve looking at more than just the first opcode
    // depending on the complexity of Zerocoin mint scripts in DigiWage.
    // For now, using the simple StartsWithOpcode as per your original.
    return StartsWithOpcode(OP_ZEROCOINMINT);
}

bool CScript::IsZerocoinSpend() const
{
    // A full check might involve looking at more than just the first opcode.
    return StartsWithOpcode(OP_ZEROCOINSPEND);
}

bool CScript::IsPushOnly(const_iterator pc) const
{
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode)) // pc is advanced by GetOp
            return false;
        if (opcode > OP_16 && !(opcode >= OP_0 && opcode <= OP_PUSHDATA4) ) // Check if it's not a push op (0-75, PUSHDATA1/2/4) or OP_N
            return false;
    }
    return true;
}

bool CScript::IsPushOnly() const
{
    return this->IsPushOnly(begin());
}

// --- Implementations for Added Qtum-style helper methods ---
bool CScript::HasOpCreate() const
{
    return Find(OP_CREATE) > 0;
}

bool CScript::HasOpCall() const
{
    return Find(OP_CALL) > 0;
}

bool CScript::HasOpSpend() const // Using DigiWage's ZC Spend context
{
    return IsZerocoinSpend();
}

bool CScript::HasOpSender() const
{
    return Find(OP_SENDER) > 0;
}
// --- End Implementations for Added Qtum-style helper methods ---


std::string CScript::ToString() const
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    const_iterator pc = begin();
    while (pc < end())
    {
        if (!str.empty())
            str += " ";
        if (!GetOp(pc, opcode, vch))
        {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() > 0) { // Avoid ValueString on empty pushes like OP_0
                 str += ValueString(vch);
            } else if (opcode == OP_0) {
                 str += "0"; // Explicitly show OP_0 as "0"
            } else {
                 // Other PUSH opcodes that might push empty data (e.g. OP_PUSHDATA1 0x00)
                 // ValueString might handle this, or you might want specific output.
                 // For now, let ValueString try, or just skip adding to string if vch is empty.
            }
        } else {
            str += GetOpName(opcode);
            if (opcode == OP_ZEROCOINSPEND) { // As per your original logic
                break;
            }
        }
    }
    return str;
}