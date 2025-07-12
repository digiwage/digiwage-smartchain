// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013-2014 The NovaCoin Developers
// Copyright (c) 2014-2018 The BlackCoin Developers
// Copyright (c) 2015-2020 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include "primitives/block.h" // Includes CBlockHeader, CBlock, uint256.h
#include "primitives/transaction.h" // For COutPoint needed in CDiskBlockIndex serialization
#include "chainparamsbase.h"  // For CBaseChainParams::Network (used indirectly?)
#include "pow.h"             // For GetBlockProof declaration
#include "tinyformat.h"
#include "libzerocoin/Denominations.h" // Keep DigiWage specific
#include "serialize.h"       // For serialization macros
#include "uint256.h"         // Ensure uint256 is fully defined
#include "version.h"         // For CLIENT_VERSION (needed elsewhere potentially)
#include "util.h" // For LogPrintf

#include <vector>
#include <map>               // For mapZerocoinSupply
#include <string>            // For ToString
#include <stdint.h>          // For int64_t etc.
#include <stdexcept>         // For std::runtime_error
#include <cstring>           // For memcpy
#include <algorithm>         // For std::sort, std::min, std::max

// Forward declare CBlockLocator for GetLocator implementation
class CBlockLocator;

/** Stores metadata about block files and implementation of CalculateDiskSpaceUsage(). */
class CBlockFileInfo
{
public:
    unsigned int nBlocks{0};      //!< number of blocks stored in file
    unsigned int nSize{0};        //!< number of used bytes of block file
    unsigned int nUndoSize{0};    //!< number of used bytes in the undo file
    unsigned int nHeightFirst{0}; //!< lowest height of block in file
    unsigned int nHeightLast{0};  //!< highest height of block in file
    uint64_t nTimeFirst{0};       //!< earliest time of block in file
    uint64_t nTimeLast{0};        //!< latest time of block in file

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
    }

    void SetNull() {
        nBlocks = 0; nSize = 0; nUndoSize = 0; nHeightFirst = 0;
        nHeightLast = 0; nTimeFirst = 0; nTimeLast = 0;
    }

    CBlockFileInfo() { SetNull(); }

    std::string ToString() const; // Definition in chain.cpp

    void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn) {
        if (nBlocks == 0 || nHeightFirst > nHeightIn) nHeightFirst = nHeightIn;
        if (nBlocks == 0 || nTimeFirst > nTimeIn) nTimeFirst = nTimeIn;
        nBlocks++;
        if (nHeightIn > nHeightLast) nHeightLast = nHeightIn;
        if (nTimeIn > nTimeLast) nTimeLast = nTimeIn;
    }
};

/** Storage location of a block on disk */
struct CDiskBlockPos {
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() { SetNull(); }
    CDiskBlockPos(int nFileIn, unsigned int nPosIn) { nFile = nFileIn; nPos = nPosIn; }
    friend bool operator==(const CDiskBlockPos& a, const CDiskBlockPos& b) { return (a.nFile == b.nFile && a.nPos == b.nPos); }
    friend bool operator!=(const CDiskBlockPos& a, const CDiskBlockPos& b) { return !(a == b); }
    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }
};

// Block validation status flags
enum BlockStatus : unsigned int {
    BLOCK_VALID_UNKNOWN      =    0,
    BLOCK_VALID_HEADER       =    1,
    BLOCK_VALID_TREE         =    2,
    BLOCK_VALID_TRANSACTIONS =    3,
    BLOCK_VALID_CHAIN        =    4,
    BLOCK_VALID_SCRIPTS      =    5,
    BLOCK_VALID_MASK         =    BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS | BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8,
    BLOCK_HAVE_UNDO          =   16,
    BLOCK_HAVE_STATE         =  128, // Corrected flag added
    BLOCK_HAVE_MASK          =    BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO | BLOCK_HAVE_STATE, // Corrected mask

    BLOCK_FAILED_VALID       =   32,
    BLOCK_FAILED_CHILD       =   64,
    BLOCK_FAILED_MASK        =    BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
};

// BlockIndex flags related to Proof-of-Stake
enum {
    BLOCK_PROOF_OF_STAKE   = (1 << 0),
    BLOCK_STAKE_ENTROPY    = (1 << 1),
    BLOCK_STAKE_MODIFIER   = (1 << 2),
};

/** The block chain is a tree shaped structure ... */
class CBlockIndex
{
public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pskip;
    int nHeight;
    int nFile;
    unsigned int nDataPos;
    unsigned int nUndoPos;
    uint256 nChainWork;
    unsigned int nTx;
    unsigned int nChainTx;
    unsigned int nStatus;
    std::vector<unsigned char> vStakeModifier;
    int64_t nMoneySupply;
    unsigned int nFlags;
    int32_t nVersion;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 nAccumulatorCheckpoint; // v4 field
    uint256 hashStateRoot;          // v6+ field
    uint256 hashUTXORoot;           // v6+ field
    unsigned int nBlockSize;        // Persisted? Added serialization in CDiskBlockIndex
    int32_t nSequenceId;
    std::map<libzerocoin::CoinDenomination, int64_t> mapZerocoinSupply;

    // --- Constructors (Declarations ONLY) ---
    CBlockIndex();
    CBlockIndex(const CBlockHeader& block);
    CBlockIndex(const CBlock& block);

    // --- Methods ---
    uint256 GetBlockHash() const { return (phashBlock ? *phashBlock : uint256()); }
    int64_t GetBlockTime() const { return (int64_t)nTime; }
    bool IsProofOfStake() const { return (nFlags & BLOCK_PROOF_OF_STAKE); }
    bool IsProofOfWork() const { return !IsProofOfStake(); }
    void SetProofOfStake() { nFlags |= BLOCK_PROOF_OF_STAKE; }
    bool GeneratedStakeModifier() const; // Declaration only
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const;
    CDiskBlockPos GetBlockPos() const;
    CDiskBlockPos GetUndoPos() const;

    // Methods requiring implementation in chain.cpp
    void ClearMapZcSupply();
    std::string ToString() const;
    CBlockHeader GetBlockHeader() const;
    int64_t GetMedianTimePast() const;
    int64_t MaxFutureBlockTime() const;
    int64_t MinPastBlockTime() const;
    unsigned int GetStakeEntropyBit() const;
    bool SetStakeEntropyBit(unsigned int nEntropyBit);
    void SetStakeModifier(const uint64_t nStakeModifier, bool fGeneratedStakeModifier);
    void SetStakeModifier(const uint256& nStakeModifier);
    void SetNewStakeModifier(const uint256& prevoutId);
    uint64_t GetStakeModifierV1() const;
    uint256 GetStakeModifierV2() const;
    bool RaiseValidity(enum BlockStatus nUpTo);
    void BuildSkip();
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;
    int64_t GetZerocoinSupply() const;
    int64_t GetZcMints(libzerocoin::CoinDenomination denom) const;
    int64_t GetZcMintsAmount(libzerocoin::CoinDenomination denom) const;
};

/** Find the last common ancestor of two block indices */
CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb);

/** Used to marshal pointers into hashes for db storage. */
static const int DBI_OLD_SER_VERSION = 2000000;

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;
    // std::vector<unsigned char> vchBlockSig; // Uncomment if needed

    // ---> DECLARATIONS ONLY <---
    CDiskBlockIndex();
    explicit CDiskBlockIndex(const CBlockIndex* pindex);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nSerVersion_passed)
    {
        int version_to_use;
        if (ser_action.ForRead()) {
             int version_read_from_stream = 0; READWRITE(VARINT(version_read_from_stream)); version_to_use = version_read_from_stream;
        } else {
             version_to_use = nSerVersion_passed; if (!(nType & SER_GETHASH)) { READWRITE(VARINT(version_to_use)); }
        }
        READWRITE(VARINT(nHeight)); READWRITE(VARINT(nStatus)); READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) { READWRITE(VARINT(nFile)); READWRITE(VARINT(nBlockSize)); }
        else if (ser_action.ForRead()) { nBlockSize = 0; }
        if (nStatus & BLOCK_HAVE_DATA) READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO) READWRITE(VARINT(nUndoPos));
        READWRITE(this->nVersion); READWRITE(hashPrev); READWRITE(hashMerkleRoot); READWRITE(nTime); READWRITE(nBits); READWRITE(nNonce);
        READWRITE(nMoneySupply); READWRITE(nFlags); READWRITE(vStakeModifier);
        if (this->nVersion > 3) {
            READWRITE(mapZerocoinSupply);
            if (this->nVersion == CBlockHeader::VERSION_ZC) { READWRITE(nAccumulatorCheckpoint); }
        } else if (ser_action.ForRead()) { mapZerocoinSupply.clear(); nAccumulatorCheckpoint.SetNull(); }
        if (this->nVersion >= CBlockHeader::VERSION_STATEROOT) {
             READWRITE(hashStateRoot); READWRITE(hashUTXORoot);
             if (ser_action.ForRead()) {
                 if (!hashStateRoot.IsNull() && !hashUTXORoot.IsNull()) {
                      nStatus |= BLOCK_HAVE_STATE;
                 } else {
                      // ---> LogPrintf REMOVED from here <---
                      nStatus &= ~BLOCK_HAVE_STATE; // Still clear the flag if roots are null despite version
                 }
             }
        } else if (ser_action.ForRead()) {
            hashStateRoot.SetNull(); hashUTXORoot.SetNull();
            nStatus &= ~BLOCK_HAVE_STATE;
        }
        // Example PoS Sig:
        // if (nFlags & BLOCK_PROOF_OF_STAKE) { READWRITE(vchBlockSig); } else if (ser_action.ForRead()) { vchBlockSig.clear(); }
    }

    // DECLARATIONS ONLY
    uint256 GetBlockHash() const;
    CBlockHeader GetBlockHeader() const;
    std::string ToString() const;
};

/** An in-memory indexed chain of blocks. */
class CChain
{
private:
    std::vector<CBlockIndex*> vChain;

public:
    CBlockIndex* Genesis() const { return vChain.size() > 0 ? vChain[0] : nullptr; }
    CBlockIndex* Tip() const { return vChain.empty() ? nullptr : vChain.back(); }
    CBlockIndex* operator[](int nHeight) const { if (nHeight < 0 || nHeight >= (int)vChain.size()) return nullptr; return vChain[nHeight]; }
    friend bool operator==(const CChain& a, const CChain& b) { return a.Height() == b.Height() && a.Tip() == b.Tip(); }
    bool Contains(const CBlockIndex* pindex) const { if (pindex == nullptr || pindex->nHeight < 0 || pindex->nHeight >= (int)vChain.size()) return false; return (*this)[pindex->nHeight] == pindex; }
    CBlockIndex* Next(const CBlockIndex* pindex) const { if (!pindex || !Contains(pindex)) return nullptr; if (pindex->nHeight == Height()) return nullptr; return (*this)[pindex->nHeight + 1]; }
    int Height() const { return vChain.size() - 1; }
    // DECLARATIONS ONLY
    void SetTip(CBlockIndex* pindex);
    CBlockLocator GetLocator(const CBlockIndex* pindex = nullptr) const;
    const CBlockIndex* FindFork(const CBlockIndex* pindex) const;
};

#endif // BITCOIN_CHAIN_H