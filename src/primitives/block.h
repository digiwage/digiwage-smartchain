// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "keystore.h" // Needed for CKeyStore (used indirectly?) - Keep if original had it
#include "serialize.h"
#include "uint256.h"

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements. When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain. The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // Header versions
    // Note: Adjust version numbers if they differ in your original code base
    static const int32_t VERSION_PRE_ZC = 3;         // Blocks before Zerocoin activation
    static const int32_t VERSION_ZC = 4;             // Blocks with Zerocoin accumulator checkpoint
    static const int32_t VERSION_POST_RHF = 5;       // Blocks after RHF (removed accumulator, added PoS v2, etc.)
    // ---> DEFINE NEW VERSION FOR STATE ROOT ACTIVATION <---
    static const int32_t VERSION_STATEROOT = 6;      // Blocks require stateRoot and utxoRoot
    static const int32_t CURRENT_VERSION = VERSION_STATEROOT; // The latest default version

    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    // --- Version specific fields ---
    uint256 nAccumulatorCheckpoint; // Only for version 4 (VERSION_ZC)

    // ---> ADD NEW STATE ROOT FIELDS (for VERSION_STATEROOT+) <---
    uint256 hashStateRoot;
    uint256 hashUTXORoot;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nSerVersion /* protocol version */) {
        READWRITE(this->nVersion); // Read/Write the block's actual version first

        // Always serialize base fields
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        // Conditionally serialize version-specific fields based on the block's version (this->nVersion)

        // Handle Version 4 specific field
        if (this->nVersion == VERSION_ZC) { // Check if it's exactly version 4
            READWRITE(nAccumulatorCheckpoint);
        }
        // Note: If reading an old block (e.g. version 3 or 5) that doesn't have the checkpoint,
        // ensure nAccumulatorCheckpoint remains null or is ignored by validation logic.
        // If writing a version 4 block, this field must be correctly populated before serialization.

        // Handle Version 6+ specific fields (State Roots)
        if (this->nVersion >= VERSION_STATEROOT) { // Check if version is 6 or higher
            READWRITE(hashStateRoot);
            READWRITE(hashUTXORoot);
        }
        // Note: Validation logic elsewhere must ensure these fields are non-null for v6+ blocks
        // *after* the activation height (height_start_StateRoots).
        // If reading a block < v6, ensure these fields remain null or are ignored.
        // If writing a v6+ block, these fields must be correctly populated.
    }

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION; // Default to the latest version
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nAccumulatorCheckpoint.SetNull(); // Initialize all potential fields
        hashStateRoot.SetNull();          // Initialize new field
        hashUTXORoot.SetNull();           // Initialize new field
    }

    bool IsNull() const
    {
        // Original IsNull check - likely sufficient
        return (nBits == 0);
    }

    /** GetHash() needs to be updated in block.cpp to match SerializationOp */
    uint256 GetHash() const; // Implementation is in block.cpp - MUST BE UPDATED

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable CScript payee; // Should this be part of consensus/serialization? Review usage.
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header; // Copy header fields
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion /* protocol version */) {
        // Serialize the header using its own logic (handles internal versioning)
        READWRITE(*(CBlockHeader*)this);

        // Serialize transactions
        READWRITE(vtx);

        // Serialize block signature conditionally
        bool shouldHaveSig = IsProofOfStake(); // Simplified check - refine if needed
        if (shouldHaveSig) {
             READWRITE(vchBlockSig);
        } else if (ser_action.ForRead()) {
            vchBlockSig.clear();
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull(); // Initializes header members including new ones
        vtx.clear();
        vchBlockSig.clear();
        payee = CScript();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        // Copy common fields
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;

        // Conditionally copy version-specific fields based on the actual block version
        if (nVersion == VERSION_ZC) { // Version 4
            block.nAccumulatorCheckpoint = nAccumulatorCheckpoint;
        }
        if (nVersion >= VERSION_STATEROOT) { // Version 6+
            block.hashStateRoot = hashStateRoot;
            block.hashUTXORoot = hashUTXORoot;
        }
        return block;
    }

    // --- Proof type checks ---
    bool IsProofOfStake() const
    {
        // DigiWage: Second tx is coinstake
        return (vtx.size() > 1 && vtx[1].IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    bool IsZerocoinStake() const; // Implementation likely in block.cpp

    std::pair<COutPoint, unsigned int> GetProofOfStake() const
    {
        // Ensure vtx index access is safe
        return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    // --- Debug/Utility Functions ---
    std::string ToString() const; // Implementation likely in block.cpp
    void print() const;          // Implementation likely in block.cpp
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        // Protocol version determines if we read/write version field itself
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion); // Protocol version, not block version
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const // Added const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H