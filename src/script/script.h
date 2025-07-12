// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2016-2024 The DIGIWAGE developers // Updated year
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_H
#define BITCOIN_SCRIPT_SCRIPT_H

#include <assert.h>
#include <climits>
#include <limits>
#include "pubkey.h" // Ensure pubkey.h is available and includes CPubKey::ValidSize, SIZE, COMPRESSED_SIZE
#include <stdexcept>
#include <stdint.h>
#include <string.h> // For memcpy
#include <string>
#include <vector>
#include <algorithm>
#include "crypto/common.h" // For ReadLE16, ReadLE32, WriteLE16, WriteLE32

typedef std::vector<unsigned char> valtype;

static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520; // bytes
static const int MAX_SCRIPT_SIZE = 10000;
static const unsigned int LOCKTIME_THRESHOLD = 500000000;

template <typename T>
std::vector<unsigned char> ToByteVector(const T& in)
{
    return std::vector<unsigned char>(in.begin(), in.end());
}

/** Script opcodes */
enum opcodetype : unsigned char
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE=OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_NOP2 = 0xb1,
    OP_CHECKLOCKTIMEVERIFY = OP_NOP2,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // zerocoin (Keep DigiWage specific values)
    OP_ZEROCOINMINT = 0xc0, // Adjusted from your previous 0xc1 to avoid conflict, VERIFY THIS VALUE
    OP_ZEROCOINSPEND = 0xc1, // Adjusted from your previous 0xc2, VERIFY THIS VALUE

    // EVM opcodes (Using values from Qtum for compatibility, but adjusted to avoid direct conflict with above)
    // These are your existing DigiWage EVM opcodes:
    OP_SPEND            = 0xc3, // DigiWage specific SPEND-like op (not EVM spend precompile)
    OP_SENDER           = 0xc4, // DigiWage specific value for EVM sender opcode
    OP_CREATE           = 0xc5, // DigiWage specific value for EVM create opcode
    OP_CALL             = 0xc6, // DigiWage specific value for EVM call opcode

    // EVM script structure opcodes (for template matching in MatchContract)
    // These are *symbolic names* used in C++ to build script templates.
    // They do NOT necessarily represent opcodes executed by the VM itself in this form.
    // Assign unique values, typically in a higher, unused range.
    OP_VERSION          = 0xd2, // Example value, ensure uniqueness
    OP_GAS_LIMIT        = 0xd3, // Example value
    OP_GAS_PRICE        = 0xd4, // Example value
    OP_DATA             = 0xd5, // Example value (placeholder for bytecode/data in templates)
    OP_ADDRESS_TYPE     = 0xd6, // Example value (for OP_SENDER template)
    OP_ADDRESS          = 0xd7, // Example value (for OP_SENDER template, often P2PKH)
    OP_SCRIPT_SIG       = 0xd8, // Example value (for OP_SENDER template)

    // cold staking (Keep DigiWage specific value)
    OP_CHECKCOLDSTAKEVERIFY = 0xd1, // This was d1, OP_VERSION is now d2. Ensure no conflicts.

    // template matching params (your existing ones)
    OP_SMALLINTEGER = 0xfa,
    OP_PUBKEYS = 0xfb,
    OP_PUBKEYHASH = 0xfd, // Standard Bitcoin, also used in Qtum OP_CALL template
    OP_PUBKEY = 0xfe,

    OP_INVALIDOPCODE = 0xff,
};

const char* GetOpName(opcodetype opcode);

class scriptnum_error : public std::runtime_error
{
public:
    explicit scriptnum_error(const std::string& str) : std::runtime_error(str) {}
};

class CScriptNum
{
public:
    explicit CScriptNum(const int64_t& n)
    {
        m_value = n;
    }

    static const size_t nDefaultMaxNumSize = 4;

    explicit CScriptNum(const std::vector<unsigned char>& vch, bool fRequireMinimal,
            const size_t nMaxNumSize = nDefaultMaxNumSize)
    {
        if (vch.size() > nMaxNumSize) {
            throw scriptnum_error("script number overflow");
        }
        if (fRequireMinimal && vch.size() > 0) {
            if ((vch.back() & 0x7f) == 0) {
                if (vch.size() <= 1 || (vch[vch.size() - 2] & 0x80) == 0) {
                    throw scriptnum_error("non-minimally encoded script number");
                }
            }
        }
        m_value = set_vch(vch);
    }

    inline bool operator==(const int64_t& rhs) const    { return m_value == rhs; }
    inline bool operator!=(const int64_t& rhs) const    { return m_value != rhs; }
    inline bool operator<=(const int64_t& rhs) const    { return m_value <= rhs; }
    inline bool operator< (const int64_t& rhs) const    { return m_value <  rhs; }
    inline bool operator>=(const int64_t& rhs) const    { return m_value >= rhs; }
    inline bool operator> (const int64_t& rhs) const    { return m_value >  rhs; }

    inline bool operator==(const CScriptNum& rhs) const { return operator==(rhs.m_value); }
    inline bool operator!=(const CScriptNum& rhs) const { return operator!=(rhs.m_value); }
    inline bool operator<=(const CScriptNum& rhs) const { return operator<=(rhs.m_value); }
    inline bool operator< (const CScriptNum& rhs) const { return operator< (rhs.m_value); }
    inline bool operator>=(const CScriptNum& rhs) const { return operator>=(rhs.m_value); }
    inline bool operator> (const CScriptNum& rhs) const { return operator> (rhs.m_value); }

    inline CScriptNum operator+(   const int64_t& rhs)    const { return CScriptNum(m_value + rhs);}
    inline CScriptNum operator-(   const int64_t& rhs)    const { return CScriptNum(m_value - rhs);}
    inline CScriptNum operator+(   const CScriptNum& rhs) const { return operator+(rhs.m_value);   }
    inline CScriptNum operator-(   const CScriptNum& rhs) const { return operator-(rhs.m_value);   }

    inline CScriptNum& operator+=( const CScriptNum& rhs)       { return operator+=(rhs.m_value);  }
    inline CScriptNum& operator-=( const CScriptNum& rhs)       { return operator-=(rhs.m_value);  }

    inline CScriptNum operator-() const
    {
        if (m_value == std::numeric_limits<int64_t>::min()) {
            throw scriptnum_error("cannot negate minimum int64_t value");
        }
        return CScriptNum(-m_value);
    }

    inline CScriptNum& operator=( const int64_t& rhs)
    {
        m_value = rhs;
        return *this;
    }

    inline CScriptNum& operator+=( const int64_t& rhs)
    {
        if (rhs > 0 && m_value > std::numeric_limits<int64_t>::max() - rhs) {
            throw scriptnum_error("addition overflow");
        }
        if (rhs < 0 && m_value < std::numeric_limits<int64_t>::min() - rhs) {
            throw scriptnum_error("addition underflow");
        }
        m_value += rhs;
        return *this;
    }

    inline CScriptNum& operator-=( const int64_t& rhs)
    {
        if (rhs > 0 && m_value < std::numeric_limits<int64_t>::min() + rhs) {
            throw scriptnum_error("subtraction underflow");
        }
        if (rhs < 0 && m_value > std::numeric_limits<int64_t>::max() + rhs) {
            throw scriptnum_error("subtraction overflow");
        }
        m_value -= rhs;
        return *this;
    }

    int getint() const
    {
        if (m_value > std::numeric_limits<int>::max())
            return std::numeric_limits<int>::max();
        else if (m_value < std::numeric_limits<int>::min())
            return std::numeric_limits<int>::min();
        return static_cast<int>(m_value);
    }

    int64_t GetInt64() const { return m_value; }

    std::vector<unsigned char> getvch() const
    {
        return serialize(m_value);
    }

    static std::vector<unsigned char> serialize(const int64_t& value)
    {
        if(value == 0)
            return std::vector<unsigned char>();

        std::vector<unsigned char> result;
        const bool neg = value < 0;
        uint64_t absvalue = neg ? static_cast<uint64_t>(-(value + 1)) + 1 : static_cast<uint64_t>(value);

        while(absvalue > 0)
        {
            result.push_back(absvalue & 0xff);
            absvalue >>= 8;
        }

        if (result.empty()) { // Handle value == 0 if not caught earlier, or for specific encodings of 0
             // Bitcoin script sometimes represents 0 as an empty vector,
             // but OP_0 (0x00) is also used. push_int64 handles OP_0.
             // This serialize might be for other contexts.
             // If value was 0, result is empty.
             // If you need to represent 0 as OP_0, that's handled elsewhere.
             // This function returning empty vector for 0 is typical for CScriptNum internal serialization.
        } else if (result.back() & 0x80) {
            result.push_back(neg ? 0x80 : 0);
        } else if (neg) {
            result.back() |= 0x80;
        }
        return result;
    }

    // Added from Qtum for MatchContract
    static int64_t vch_to_int64(const std::vector<unsigned char>& vch, bool fRequireMinimal = true,
                                const size_t nMaxNumSize = nDefaultMaxNumSize) {
        if (vch.size() > nMaxNumSize) {
            throw scriptnum_error("script number overflow in vch_to_int64");
        }
        // Minimal encoding check (from CScriptNum constructor)
        if (fRequireMinimal && vch.size() > 0) {
            if ((vch.back() & 0x7f) == 0) {
                if (vch.size() <= 1 || (vch[vch.size() - 2] & 0x80) == 0) {
                    throw scriptnum_error("non-minimally encoded script number in vch_to_int64");
                }
            }
        }
        return set_vch(vch); // Use your existing private set_vch
    }

    static uint64_t vch_to_uint64(const std::vector<unsigned char>& vch, bool fRequireMinimal = false,
                                 const size_t nMaxNumSize = nDefaultMaxNumSize)
    {
         int64_t val_int64 = vch_to_int64(vch, fRequireMinimal, nMaxNumSize);
         if (val_int64 < 0) {
             throw scriptnum_error("negative value encountered where uint64_t expected");
         }
         return static_cast<uint64_t>(val_int64);
    }


private:
    static int64_t set_vch(const std::vector<unsigned char>& vch)
    {
      if (vch.empty())
          return 0;

      int64_t result = 0;
      for (size_t i = 0; i != vch.size(); ++i)
          result |= static_cast<int64_t>(vch[i]) << (8*i);

      if (vch.back() & 0x80) {
          uint64_t temp = result & ~(0x80ULL << (8 * (vch.size() - 1)));
          if (temp == 0 && vch.size() > 1 && (vch[vch.size()-2] & 0x80)) {
               return std::numeric_limits<int64_t>::min();
          }
          return -static_cast<int64_t>(temp);
      }
      return result;
    }

    int64_t m_value;
};


class CScript : public std::vector<unsigned char>
{
protected:
    CScript& push_int64(int64_t n)
    {
        if (n == -1 || (n >= 1 && n <= 16))
        {
            push_back(n + (OP_1 - 1));
        }
        else if (n == 0)
        {
            push_back(OP_0);
        }
        else
        {
            *this << CScriptNum(n).getvch();
        }
        return *this;
    }
public:
    CScript() = default;
    CScript(const CScript& b) : std::vector<unsigned char>(b.begin(), b.end()) { }
    CScript(const_iterator pbegin, const_iterator pend) : std::vector<unsigned char>(pbegin, pend) { }
    CScript(const unsigned char* pbegin, const unsigned char* pend) : std::vector<unsigned char>(pbegin, pend) { }

    CScript& operator=(const CScript& b) {
        static_cast<std::vector<unsigned char>&>(*this) = static_cast<const std::vector<unsigned char>&>(b);
        return *this;
    }
    CScript(CScript&& b) noexcept : std::vector<unsigned char>(std::move(b)) {}
    CScript& operator=(CScript&& b) noexcept {
        static_cast<std::vector<unsigned char>&>(*this) = std::move(static_cast<std::vector<unsigned char>&>(b));
        return *this;
    }

    CScript& operator+=(const CScript& b)
    {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript& a, const CScript& b)
    {
        CScript ret = a;
        ret += b;
        return ret;
    }

    explicit CScript(int64_t b)        { operator<<(b); }
    explicit CScript(opcodetype b)     { operator<<(b); }
    explicit CScript(const CScriptNum& b) { operator<<(b); }
    explicit CScript(const std::vector<unsigned char>& b) { operator<<(b); }

    CScript& operator<<(int64_t b) { return push_int64(b); }

    CScript& operator<<(opcodetype opcode)
    {
        // The warning was about "opcode < 0" and "opcode > 0xff"
        // Since opcodetype is unsigned char, opcode < 0 is always false.
        // opcode > 0xff is also always false as unsigned char max is 0xff.
        // This check is effectively redundant if opcodetype is strictly unsigned char.
        // Commenting it out to remove the warning.
        /*
        if (opcode < 0 || opcode > 0xff) // Should not happen with enum : unsigned char
            throw std::runtime_error("CScript::operator<<() : invalid opcode");
        */
        insert(end(), static_cast<unsigned char>(opcode));
        return *this;
    }

    CScript& operator<<(const CScriptNum& b)
    {
        *this << b.getvch();
        return *this;
    }

    CScript& operator<<(const std::vector<unsigned char>& b)
    {
        if (b.size() < OP_PUSHDATA1)
        {
            insert(end(), (unsigned char)b.size());
        }
        else if (b.size() <= 0xff)
        {
            insert(end(), OP_PUSHDATA1);
            insert(end(), (unsigned char)b.size());
        }
        else if (b.size() <= 0xffff)
        {
            insert(end(), OP_PUSHDATA2);
            uint16_t nSize = b.size();
            unsigned char size_bytes[2];
            WriteLE16(size_bytes, nSize);
            insert(end(), size_bytes, size_bytes + sizeof(size_bytes)); // Corrected sizeof
        }
        else
        {
            insert(end(), OP_PUSHDATA4);
            uint32_t nSize = b.size();
            unsigned char size_bytes[4];
            WriteLE32(size_bytes, nSize);
            insert(end(), size_bytes, size_bytes + sizeof(size_bytes)); // Corrected sizeof
        }
        insert(end(), b.begin(), b.end());
        return *this;
    }

    CScript& operator<<(const CPubKey& key)
    {
        if (!key.IsValid()) {
             throw std::runtime_error("CScript::operator<<: Pushing an invalid pubkey");
        }
        std::vector<unsigned char> vchKey(key.begin(), key.end());
        return (*this) << vchKey;
    }

    bool GetOp(iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet)
    {
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, &vchRet);
         pc = begin() + (pc2 - begin());
         return fRet;
    }

    bool GetOp(iterator& pc, opcodetype& opcodeRet)
    {
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, nullptr);
         pc = begin() + (pc2 - begin());
         return fRet;
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>& vchRet) const
    {
        return GetOp2(pc, opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator& pc, opcodetype& opcodeRet) const
    {
        return GetOp2(pc, opcodeRet, nullptr);
    }

    bool GetOp2(const_iterator& pc, opcodetype& opcodeRet, std::vector<unsigned char>* pvchRet) const
    {
        opcodeRet = OP_INVALIDOPCODE;
        if (pvchRet)
            pvchRet->clear();
        if (pc >= end())
            return false;

        if (end() - pc < 1)
            return false;
        unsigned int opcode = *pc++;

        if (opcode <= OP_PUSHDATA4)
        {
            unsigned int nSize = 0;
            if (opcode < OP_PUSHDATA1)
            {
                nSize = opcode;
            }
            else if (opcode == OP_PUSHDATA1)
            {
                if (end() - pc < 1)
                    return false;
                nSize = *pc++;
            }
            else if (opcode == OP_PUSHDATA2)
            {
                if (end() - pc < 2)
                    return false;
                nSize = ReadLE16(&*pc);
                pc += 2;
            }
            else if (opcode == OP_PUSHDATA4)
            {
                if (end() - pc < 4)
                    return false;
                nSize = ReadLE32(&*pc);
                pc += 4;
            }
             if (nSize > static_cast<uint32_t>(end() - pc)) {
                 return false;
             }
            if (pvchRet)
                pvchRet->assign(pc, pc + nSize);
            pc += nSize;
        }
        opcodeRet = (opcodetype)opcode;
        return true;
    }

    static int DecodeOP_N(opcodetype opcode)
    {
        if (opcode < OP_0 || opcode > OP_16) {
             throw std::runtime_error("DecodeOP_N: non-numeric opcode");
        }
        if (opcode == OP_0)
            return 0;
        return (int)opcode - (int)(OP_1 - 1);
    }
    static opcodetype EncodeOP_N(int n)
    {
        if (n < 0 || n > 16) {
            throw std::runtime_error("EncodeOP_N: out of range");
        }
        if (n == 0)
            return OP_0;
        return (opcodetype)(OP_1+n-1);
    }

    int FindAndDelete(const CScript& b)
    {
        int nFound = 0;
        if (b.empty())
            return nFound;
        CScript result;
        iterator pc = begin(), pc2 = begin();
        opcodetype opcode;
        std::vector<unsigned char> vchPushValue;
        do
        {
            result.insert(result.end(), pc2, pc);
            while (static_cast<size_t>(end() - pc) >= b.size() &&
                   std::equal(b.begin(), b.end(), pc))
            {
                pc = pc + b.size();
                ++nFound;
            }
            pc2 = pc;
        }
        while (GetOp(pc, opcode, vchPushValue));

        if (nFound > 0) {
            result.insert(result.end(), pc2, end());
            *this = result;
        }
        return nFound;
    }

    int Find(opcodetype op) const
    {
        int nFound = 0;
        opcodetype opcode_iter; // Use a different name for the loop variable
        std::vector<unsigned char> vchPushValue;
        for (const_iterator pc = begin(); pc != end() && GetOp(pc, opcode_iter, vchPushValue); ) {
            if (opcode_iter == op)
                ++nFound;
        }
        return nFound;
    }

    unsigned int GetSigOpCount(bool fAccurate) const;
    unsigned int GetSigOpCount(const CScript& scriptSig) const;

    bool IsNormalPaymentScript() const;
    bool IsPayToScriptHash() const;
    bool IsPayToColdStaking() const;
    bool IsPayToPublicKeyHash() const;
    bool IsPayToPublicKey() const;
    bool StartsWithOpcode(const opcodetype opcode) const;
    bool IsZerocoinMint() const;
    bool IsZerocoinSpend() const;

    bool IsPushOnly(const_iterator pc) const;
    bool IsPushOnly() const;

    bool IsUnspendable() const
    {
        return (size() > 0 && (*begin() == OP_RETURN || *begin() == OP_INVALIDOPCODE)) || (size() > MAX_SCRIPT_SIZE);
    }

    // Added Qtum-style helper methods
    bool HasOpCreate() const;
    bool HasOpCall() const;
    bool HasOpSpend() const; // Note: This will use DigiWage's IsZerocoinSpend
    bool HasOpSender() const;

    std::string ToString() const;

    void clear()
    {
        CScript().swap(*this);
    }
};

#endif // BITCOIN_SCRIPT_SCRIPT_H