// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h" // Needed for Params()
#include "util.h"        // Needed for LogPrintf, GetBoolArg, DateTimeStrFormat etc.
#include "main.h"        // Needed for mapBlockIndex, chainActive, cs_main, LOCK etc.
#include "hash.h"        // Needed for CHashWriter
#include "pow.h"         // Needed for GetBlockProof definition
#include "libzerocoin/Denominations.h" // Needed for zerocoinDenomList
#include "validationinterface.h" // Needed for GetMainSignals? (If used in methods below)
#include "timedata.h" // For GetAdjustedTime()

#include <algorithm>     // Needed for std::sort, std::max
#include <vector>        // Needed for std::vector used in GetLocator
#include <map>           // Needed for std::map
#include <stdexcept>     // Needed for std::runtime_error

// --- Helper function for Skip List ---
// Determine the skip height based on the current height.
static int GetSkipHeight(int height) {
    if (height < 2) return 0;
    int log2_height_div_2 = 0; int h = height >> 1;
    while (h > 0) { h >>= 1; log2_height_div_2++; }
    return (1 << log2_height_div_2);
}

// --- CBlockFileInfo Implementation ---
std::string CBlockFileInfo::ToString() const {
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}

// --- CBlockIndex Method Implementations ---
// In src/chain.cpp

/** Find the last common ancestor block between two blocks. */
CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb)
{
    if (pa == pb) return pa;

    // Must be on the same chain if one is an ancestor of the other.

    // Use GetAncestor to efficiently find the fork point.
    CBlockIndex *pindexA = pa;
    CBlockIndex *pindexB = pb;
    while (pindexA != pindexB) {
        if (pindexA->nHeight > pindexB->nHeight) {
            pindexA = pindexA->GetAncestor(pindexB->nHeight);
        } else {
            pindexB = pindexB->GetAncestor(pindexA->nHeight);
        }
        // If heights match but pointers differ, step back one on both
        if (pindexA->nHeight == pindexB->nHeight && pindexA != pindexB) {
           if (!pindexA->pprev || !pindexB->pprev) return nullptr; // Should not happen if they have common ancestor
           pindexA = pindexA->pprev;
           pindexB = pindexB->pprev;
        }
    }
    assert(pindexA); // Should have found a common ancestor unless one was null initially
    return pindexA;
}

// Default constructor implementation
CBlockIndex::CBlockIndex() :
    phashBlock(nullptr), pprev(nullptr), pskip(nullptr), nHeight(0), nFile(0), nDataPos(0), nUndoPos(0),
    nChainWork(), nTx(0), nChainTx(0), nStatus(0), vStakeModifier(), nMoneySupply(0), nFlags(0),
    nVersion(0), hashMerkleRoot(), nTime(0), nBits(0), nNonce(0), nAccumulatorCheckpoint(),
    hashStateRoot(), hashUTXORoot(), nBlockSize(0), nSequenceId(0)
{
    ClearMapZcSupply();
}

// Constructor from CBlockHeader implementation
CBlockIndex::CBlockIndex(const CBlockHeader& block) :
    phashBlock(nullptr), pprev(nullptr), pskip(nullptr), nHeight(0), nFile(0), nDataPos(0), nUndoPos(0),
    nChainWork(), nTx(0), nChainTx(0), nStatus(0), vStakeModifier(), nMoneySupply(0), nFlags(0),
    // Copy header fields
    nVersion(block.nVersion), hashMerkleRoot(block.hashMerkleRoot), nTime(block.nTime),
    nBits(block.nBits), nNonce(block.nNonce), nAccumulatorCheckpoint(block.nAccumulatorCheckpoint),
    // Copy state roots from header
    hashStateRoot(block.hashStateRoot), hashUTXORoot(block.hashUTXORoot),
    nBlockSize(0), nSequenceId(0)
{
    ClearMapZcSupply();
}

// Constructor from CBlock implementation
CBlockIndex::CBlockIndex(const CBlock& block) :
    phashBlock(nullptr), pprev(nullptr), pskip(nullptr), nHeight(0), nFile(0), nDataPos(0), nUndoPos(0),
    nChainWork(), nTx(block.vtx.size()), nChainTx(0), nStatus(0), vStakeModifier(), nMoneySupply(0), nFlags(0),
    // Copy header fields from CBlock
    nVersion(block.nVersion), hashMerkleRoot(block.hashMerkleRoot), nTime(block.nTime),
    nBits(block.nBits), nNonce(block.nNonce), nAccumulatorCheckpoint(block.nAccumulatorCheckpoint),
    // Copy state roots from CBlock
    hashStateRoot(block.hashStateRoot), hashUTXORoot(block.hashUTXORoot),
    nBlockSize(0), nSequenceId(0)
{
    ClearMapZcSupply();
    if (block.IsProofOfStake()) { SetProofOfStake(); }
}

void CBlockIndex::ClearMapZcSupply()
{
    mapZerocoinSupply.clear();
    for (const auto& denom : libzerocoin::zerocoinDenomList)
        mapZerocoinSupply.insert(std::make_pair(denom, 0));
}

std::string CBlockIndex::ToString() const
{
    return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
        pprev, nHeight,
        hashMerkleRoot.ToString().substr(0,10),
        GetBlockHash().ToString().substr(0,10));
}

CDiskBlockPos CBlockIndex::GetBlockPos() const
{
    CDiskBlockPos ret;
    if (nStatus & BLOCK_HAVE_DATA) {
        ret.nFile = nFile;
        ret.nPos = nDataPos;
    } // Defaults to null if no data
    return ret;
}

CDiskBlockPos CBlockIndex::GetUndoPos() const
{
    CDiskBlockPos ret;
    if (nStatus & BLOCK_HAVE_UNDO) {
        ret.nFile = nFile;
        ret.nPos = nUndoPos;
    } // Defaults to null if no undo
    return ret;
}

CBlockHeader CBlockIndex::GetBlockHeader() const
{
    CBlockHeader block;
    block.nVersion        = nVersion;
    block.hashPrevBlock   = (pprev ? pprev->GetBlockHash() : uint256());
    block.hashMerkleRoot  = hashMerkleRoot;
    block.nTime           = nTime;
    block.nBits           = nBits;
    block.nNonce          = nNonce;
    // Conditionally copy version-specific fields
    if (nVersion == CBlockHeader::VERSION_ZC) {
        block.nAccumulatorCheckpoint = nAccumulatorCheckpoint;
    }
    if (nVersion >= CBlockHeader::VERSION_STATEROOT) {
        block.hashStateRoot = hashStateRoot;
        block.hashUTXORoot = hashUTXORoot;
    }
    return block;
}

int64_t CBlockIndex::GetMedianTimePast() const
{
    const int nMedianTimeSpan = 11;
    int64_t pmedian[nMedianTimeSpan];
    int64_t* pbegin = &pmedian[nMedianTimeSpan];
    int64_t* pend = &pmedian[nMedianTimeSpan];

    const CBlockIndex* pindex = this;
    for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
        *(--pbegin) = pindex->GetBlockTime();

    std::sort(pbegin, pend);
    return pbegin[(pend - pbegin) / 2];
}

int64_t CBlockIndex::MaxFutureBlockTime() const
{
    // Need access to global Params() and GetAdjustedTime()
    return GetAdjustedTime() + Params().GetConsensus().FutureBlockTimeDrift(nHeight + 1);
}

int64_t CBlockIndex::MinPastBlockTime() const
{
    const Consensus::Params& consensus = Params().GetConsensus();
    if (!consensus.IsTimeProtocolV2(nHeight + 1)) {
        return GetMedianTimePast();
    } else {
        // Time Protocol v2: Use previous block's time
        return (pprev ? pprev->GetBlockTime() : GetBlockTime()); // Fallback for genesis?
    }
}

unsigned int CBlockIndex::GetStakeEntropyBit() const
{
    if (!phashBlock) return 0;
    unsigned int nEntropyBit = ((phashBlock->GetCheapHash()) & 1);
    // Requires access to GetBoolArg from util.h
    if (GetBoolArg("-printstakemodifier", false))
        LogPrintf("GetStakeEntropyBit: nHeight=%u hashBlock=%s nEntropyBit=%u\n", nHeight, phashBlock->ToString(), nEntropyBit);
    return nEntropyBit;
}

bool CBlockIndex::SetStakeEntropyBit(unsigned int nEntropyBit)
{
    if (nEntropyBit > 1) return false;
    nFlags &= ~BLOCK_STAKE_ENTROPY;
    if (nEntropyBit) nFlags |= BLOCK_STAKE_ENTROPY;
    return true;
}

// Implementation for GeneratedStakeModifier
bool CBlockIndex::GeneratedStakeModifier() const
{
    return (nFlags & BLOCK_STAKE_MODIFIER);
}

void CBlockIndex::SetStakeModifier(const uint64_t nStakeModifier, bool fGeneratedStakeModifier)
{
    vStakeModifier.resize(sizeof(nStakeModifier));
    memcpy(vStakeModifier.data(), &nStakeModifier, sizeof(nStakeModifier));
    if (fGeneratedStakeModifier) nFlags |= BLOCK_STAKE_MODIFIER;
    else nFlags &= ~BLOCK_STAKE_MODIFIER;
}

void CBlockIndex::SetStakeModifier(const uint256& nStakeModifier) // V2 Setter
{
    vStakeModifier.assign(nStakeModifier.begin(), nStakeModifier.end());
    nFlags |= BLOCK_STAKE_MODIFIER;
}

// Requires ComputeStakeModifier definition if not already present elsewhere
void CBlockIndex::SetNewStakeModifier(const uint256& prevoutStakeHash)
{
    if (nHeight < Params().GetConsensus().height_start_StakeModifierV2) return;
    if (!pprev) throw std::runtime_error(strprintf("%s : ERROR: null pprev", __func__));

    CHashWriter ss(SER_GETHASH, 0); // Requires #include "hash.h"
    ss << prevoutStakeHash << pprev->GetStakeModifierV2();
    SetStakeModifier(ss.GetHash()); // Calls the V2 setter
}

uint64_t CBlockIndex::GetStakeModifierV1() const
{
    if (vStakeModifier.size() != sizeof(uint64_t) || Params().GetConsensus().IsStakeModifierV2(nHeight)) return 0;
    uint64_t nStakeModifier = 0;
    memcpy(&nStakeModifier, vStakeModifier.data(), sizeof(nStakeModifier));
    return nStakeModifier;
}

uint256 CBlockIndex::GetStakeModifierV2() const
{
    if (vStakeModifier.size() != sizeof(uint256) || !Params().GetConsensus().IsStakeModifierV2(nHeight)) return uint256();
    uint256 nStakeModifier;
    memcpy(nStakeModifier.begin(), vStakeModifier.data(), sizeof(nStakeModifier));
    return nStakeModifier;
}

bool CBlockIndex::IsValid(enum BlockStatus nUpTo) const
{
    assert(!(nUpTo & BLOCK_HAVE_MASK));
    assert(nUpTo != BLOCK_VALID_UNKNOWN);
    if (nStatus & BLOCK_FAILED_MASK) return false;
    return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
}

bool CBlockIndex::RaiseValidity(enum BlockStatus nUpTo)
{
    assert(!(nUpTo & BLOCK_HAVE_MASK));
    assert(nUpTo != BLOCK_VALID_UNKNOWN);
    if (nStatus & BLOCK_FAILED_MASK) return false;
    unsigned int nOldStatus = nStatus;
    if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
        nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
        // LogPrintf("RaiseValidity: %s %d -> %d\n", GetBlockHash().ToString(), nOldStatus, nStatus);
        return true;
    }
    return false;
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(nHeight - GetSkipHeight(nHeight));
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > nHeight || height < 0) return nullptr;
    if (height == nHeight) return this;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = (pskip == nullptr) ? -1 : pskip->nHeight;
        if (pskip && heightSkipPrev >= height && (heightSkipPrev - height < heightWalk - height)) {
            pindexWalk = pskip;
            heightWalk = heightSkipPrev;
        } else {
            if (!pindexWalk->pprev) return nullptr;
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

int64_t CBlockIndex::GetZerocoinSupply() const
{
    int64_t nTotal = 0;
    for (const auto& pair : mapZerocoinSupply) { nTotal += libzerocoin::ZerocoinDenominationToAmount(pair.first) * pair.second; }
    return nTotal;
}

int64_t CBlockIndex::GetZcMints(libzerocoin::CoinDenomination denom) const
{
    auto it = mapZerocoinSupply.find(denom);
    if (it != mapZerocoinSupply.end()) { return it->second; }
    return 0;
}

int64_t CBlockIndex::GetZcMintsAmount(libzerocoin::CoinDenomination denom) const
{
    return libzerocoin::ZerocoinDenominationToAmount(denom) * GetZcMints(denom);
}


// --- CDiskBlockIndex Method Implementations ---

// Default constructor implementation
CDiskBlockIndex::CDiskBlockIndex() : CBlockIndex()
{
    hashPrev.SetNull();
    // if (vchBlockSig defined in .h) vchBlockSig.clear();
}

// Constructor from CBlockIndex pointer implementation
CDiskBlockIndex::CDiskBlockIndex(const CBlockIndex* pindex) : CBlockIndex(*pindex)
{
    hashPrev = (pprev ? pprev->GetBlockHash() : uint256());
    // if (vchBlockSig defined in .h) this->vchBlockSig = pindex->vchBlockSig;
}

// GetBlockHash implementation for CDiskBlockIndex
uint256 CDiskBlockIndex::GetBlockHash() const
{
    CBlockHeader header = GetBlockHeader();
    // CBlockHeader::GetHash() in block.cpp must be correct
    return header.GetHash();
}

// GetBlockHeader implementation for CDiskBlockIndex
CBlockHeader CDiskBlockIndex::GetBlockHeader() const
{
    CBlockHeader block;
    block.nVersion        = nVersion;
    block.hashPrevBlock   = hashPrev;
    block.hashMerkleRoot  = hashMerkleRoot;
    block.nTime           = nTime;
    block.nBits           = nBits;
    block.nNonce          = nNonce;
    if (nVersion == CBlockHeader::VERSION_ZC) { block.nAccumulatorCheckpoint = nAccumulatorCheckpoint; }
    if (nVersion >= CBlockHeader::VERSION_STATEROOT) { block.hashStateRoot = hashStateRoot; block.hashUTXORoot = hashUTXORoot; }
    return block;
}

// ToString implementation for CDiskBlockIndex
std::string CDiskBlockIndex::ToString() const
{
    std::string str = "CDiskBlockIndex(";
    str += CBlockIndex::ToString();
    str += strprintf("\n                hashBlock=%s, hashPrev=%s)", GetBlockHash().ToString(), hashPrev.ToString());
    return str;
}


// --- CChain Method Implementations ---

void CChain::SetTip(CBlockIndex* pindex)
{
    if (pindex == nullptr) { vChain.clear(); return; }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex* pindex) const
{
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);
    if (!pindex) pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        if (pindex->nHeight == 0) break;
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        // Use Contains check before operator[]
        if (Contains(pindex)) {
             if(nHeight >= 0 && nHeight < (int)vChain.size()) pindex = (*this)[nHeight];
             else pindex = pindex->GetAncestor(nHeight);
        } else { pindex = pindex->GetAncestor(nHeight); }
        if (vHave.size() > 10) nStep *= 2;
    }
    return CBlockLocator(vHave);
}

const CBlockIndex* CChain::FindFork(const CBlockIndex* pindex) const
{
    if (pindex == nullptr) return nullptr;
    if (pindex->nHeight > Height()) pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex)) pindex = pindex->pprev;
    return pindex;
}