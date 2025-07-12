// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2024 The DIGIWAGE developers // Updated year
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIGIWAGE_PUBKEY_H
#define DIGIWAGE_PUBKEY_H

#include "hash.h"
#include "serialize.h"
#include "uint256.h"

#include <stdexcept>
#include <vector>

const unsigned int BIP32_EXTKEY_SIZE = 74;

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    explicit CKeyID(const uint160& in) : uint160(in) {}
};

typedef uint256 ChainCode;

/** An encapsulated public key. */
class CPubKey
{
public:
    /**
     * secp256k1:
     */
    // Renamed to match common Bitcoin Core naming for clarity, using your values
    static const unsigned int SIZE = 65;                         // Was PUBLIC_KEY_SIZE
    static const unsigned int COMPRESSED_SIZE = 33;              // Was COMPRESSED_PUBLIC_KEY_SIZE
    // Kept your original names as well for other uses if any
    static const unsigned int PUBLIC_KEY_SIZE             = 65;
    static const unsigned int COMPRESSED_PUBLIC_KEY_SIZE  = 33;
    static const unsigned int SIGNATURE_SIZE              = 72;
    static const unsigned int COMPACT_SIGNATURE_SIZE      = 65;

    static_assert(
        PUBLIC_KEY_SIZE >= COMPRESSED_PUBLIC_KEY_SIZE,
        "COMPRESSED_PUBLIC_KEY_SIZE is larger than PUBLIC_KEY_SIZE");

private:
    unsigned char vch[PUBLIC_KEY_SIZE]; // Uses the class constant

    unsigned int static GetLen(unsigned char chHeader)
    {
        if (chHeader == 2 || chHeader == 3)
            return COMPRESSED_PUBLIC_KEY_SIZE; // Uses class constant
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return PUBLIC_KEY_SIZE; // Uses class constant
        return 0;
    }

    void Invalidate()
    {
        vch[0] = 0xFF;
    }

public:
    CPubKey()
    {
        Invalidate();
    }

    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    explicit CPubKey(const std::vector<unsigned char>& _vch)
    {
        Set(_vch.begin(), _vch.end());
    }

    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey& a, const CPubKey& b)
    {
        return !(a == b);
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return size() + 1;
    }
    template <typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char*)vch, len);
    }
    template <typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        unsigned int len = ::ReadCompactSize(s);
        if (len <= PUBLIC_KEY_SIZE) { // Uses class constant
            s.read((char*)vch, len);
        } else {
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    CKeyID GetID() const
    {
        return CKeyID(Hash160(vch, vch + size()));
    }

    uint256 GetHash() const
    {
        return Hash(vch, vch + size());
    }

    bool IsValid() const
    {
        return size() > 0;
    }

    bool IsFullyValid() const; // Declaration only, implementation in .cpp

    bool IsCompressed() const
    {
        return size() == COMPRESSED_PUBLIC_KEY_SIZE; // Uses class constant
    }

    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const; // Declaration
    static bool CheckLowS(const std::vector<unsigned char>& vchSig); // Declaration
    bool RecoverCompact(const uint256& hash, const std::vector<unsigned char>& vchSig); // Declaration
    bool Decompress(); // Declaration
    bool Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const; // Declaration

    std::vector<unsigned char> Raw() const
    {
        return std::vector<unsigned char>(vch, vch + size());
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // +++ ADDED STATIC ValidSize METHOD ++++++++++++++++++++++++
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    /**
     * Check if the given public key vector is validly sized.
     */
    static bool ValidSize(const std::vector<unsigned char>& vch_pubkey) { // Renamed param for clarity
        // Uses the class constants SIZE and COMPRESSED_SIZE defined above
        return !vch_pubkey.empty() && (vch_pubkey.size() == SIZE || vch_pubkey.size() == COMPRESSED_SIZE);
    }
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

};

// ... (rest of your pubkey.h, CExtPubKey, ECCVerifyHandle) ...

struct CExtPubKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey& a, const CExtPubKey& b)
    {
        return a.nDepth == b.nDepth &&
            memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.pubkey == b.pubkey;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    bool Derive(CExtPubKey& out, unsigned int nChild) const;

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return BIP32_EXTKEY_SIZE+1; //add one byte for the size (compact int)
    }
    template <typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        unsigned int len = BIP32_EXTKEY_SIZE;
        ::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        Encode(code);
        s.write((const char *)&code[0], len);
    }
    template <typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        unsigned int len = ::ReadCompactSize(s);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if (len != BIP32_EXTKEY_SIZE)
            throw std::runtime_error("Invalid extended key size\n");
        s.read((char *)&code[0], len);
        Decode(code);
    }

    // Added missing Serialize/Unserialize without nType, nVersion if used by your CSizeComputer or other parts
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = BIP32_EXTKEY_SIZE;
        ::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        Encode(code);
        s.write((const char *)&code[0], len);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned int len = ::ReadCompactSize(s);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if (len != BIP32_EXTKEY_SIZE)
            throw std::runtime_error("Invalid extended key size\n");
        s.read((char *)&code[0], len);
        Decode(code);
    }
    // Keep your CSizeComputer Serialize method
    void Serialize(CSizeComputer& s) const
    {
        s.seek(BIP32_EXTKEY_SIZE + 1);
    }
};

class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};

#endif // DIGIWAGE_PUBKEY_H