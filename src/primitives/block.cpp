// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h" // Make sure correct Hash function is included (Hash, HashQuark)
#include "streams.h" // For CDataStream
#include "script/standard.h"
#include "script/sign.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "util.h"

uint256 CBlockHeader::GetHash() const
{
    // ---> NEW GetHash IMPLEMENTATION <---
    // This MUST serialize exactly the same way as SerializationOp in block.h

    // Choose the correct hashing algorithm based on time or version if needed
    // Assuming Hash() is the primary algorithm for newer blocks,
    // and HashQuark for very old ones (like original DigiWage).
    // Adjust this logic if your chain uses different algos at different times.
    // For simplicity, let's assume Hash() (SHA256d) is used for v4+

    if (nVersion < VERSION_ZC) { // Versions before 4 (e.g., 1, 2, 3)
         // Assuming HashQuark was used and only hashed up to nNonce for these old versions
         return HashQuark(BEGIN(nVersion), END(nNonce));
    } else {
        // For versions 4, 5, 6+ use the standard double-SHA256 Hash()
        // but serialize fields conditionally based on version, matching SerializationOp
        CHashWriter ss(SER_GETHASH, 0); // Use 0 for protocol version, it's ignored for GetHash serialization type

        // Use the same serialization logic as in SerializationOp
        ss << nVersion;
        ss << hashPrevBlock;
        ss << hashMerkleRoot;
        ss << nTime;
        ss << nBits;
        ss << nNonce;

        // Conditionally include version-specific fields
        if (nVersion == VERSION_ZC) { // Version 4
            ss << nAccumulatorCheckpoint;
        }
        if (nVersion >= VERSION_STATEROOT) { // Version 6+
            ss << hashStateRoot;
            ss << hashUTXORoot;
        }

        return ss.GetHash();
    }
    // ---> END NEW GetHash IMPLEMENTATION <---
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, hashStateRoot=%s, hashUTXORoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        // Include state roots in ToString if version >= 6
        (nVersion >= CBlockHeader::VERSION_STATEROOT ? hashStateRoot.ToString() : "N/A"),
        (nVersion >= CBlockHeader::VERSION_STATEROOT ? hashUTXORoot.ToString() : "N/A"),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
     // Optionally include block signature if present
     if (!vchBlockSig.empty()) {
         s << "  blockSig=" << HexStr(vchBlockSig.begin(), vchBlockSig.end()) << "\n";
     }
    return s.str();
}

void CBlock::print() const
{
    LogPrintf("%s", ToString());
}

bool CBlock::IsZerocoinStake() const
{
    // Keep original DigiWage logic
    return IsProofOfStake() && vtx[1].HasZerocoinSpendInputs();
}