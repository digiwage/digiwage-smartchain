// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013-2014 The NovaCoin Developers
// Copyright (c) 2014-2018 The BlackCoin Developers
// Copyright (c) 2015-2020 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h" // needed in case of no ENABLE_WALLET
#include "hash.h"
#include "main.h" // For GetChainTip, cs_main, chainActive, mapBlockIndex, Params, etc.
#include "masternode-sync.h"
#include "net.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
#include "validationinterface.h"
#include "masternode-payments.h"
#include "blocksignature.h"
#include "spork.h"


#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>


//////////////////////////////////////////////////////////////////////////////
//
// DIGIWAGEMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    std::set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;

    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) {}

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee) {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        } else {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

void UpdateTime(CBlockHeader* pblock, const CBlockIndex* pindexPrev)
{
    pblock->nTime = std::max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    if (Params().GetConsensus().fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
}

CBlockIndex* GetChainTip()
{
    LOCK(cs_main);
    CBlockIndex* p = chainActive.Tip();
    if (!p)
        return nullptr;

    // Ensure the CBlockIndex pointer is from mapBlockIndex for stability
    BlockMap::iterator mi = mapBlockIndex.find(p->GetBlockHash());
    if (mi != mapBlockIndex.end()) {
        return mi->second;
    }
    // Fallback if tip isn't in mapBlockIndex (should be rare after init)
    LogPrintf("GetChainTip(): Warning - chainActive.Tip() not found in mapBlockIndex. Returning pointer from chainActive.\n");
    return p;
}

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn, CWallet* pwallet, bool fProofOfStake)
{
    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if (!pblocktemplate.get()) return nullptr;
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Tip
    CBlockIndex* pindexPrev = GetChainTip();
    if (!pindexPrev) {
        LogPrintf("%s: Error: GetChainTip() returned null. Cannot create new block.\n", __func__);
        return nullptr;
    }
    const int nHeight = pindexPrev->nHeight + 1;
    const Consensus::Params& consensus = Params().GetConsensus();

    // Defense-in-depth: Ensure PoW blocks are not created after PoW phase.
    if (!fProofOfStake && nHeight > consensus.height_last_PoW) {
        LogPrintf("%s: Attempted to create a PoW block (height %d) after PoW phase ended (last PoW: %d). Aborting.\n",
                  __func__, nHeight, consensus.height_last_PoW);
        return nullptr;
    }

    // Make sure to create the correct block version
    bool isAfterRHF = consensus.IsPastRHFBlock(nHeight);
    if (nHeight < consensus.height_start_ZC)
        pblock->nVersion = 3;
    else if (!isAfterRHF)
        pblock->nVersion = 4;
    else
        pblock->nVersion = 5;

    if (Params().IsRegTestNet()) {
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);
    }

    // Create coinbase tx
    CMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1);
    pblocktemplate->vTxSigOps.push_back(-1);

    if (fProofOfStake) {
        boost::this_thread::interruption_point();
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
        CMutableTransaction txCoinStake;
        int64_t nTxNewTime = 0;
        if (!pwallet->CreateCoinStake(*pwallet, pindexPrev, pblock->nBits, txCoinStake, nTxNewTime)) {
            LogPrint("staking", "%s : stake not found for pindexPrev %s, height %d\n", __func__, pindexPrev->GetBlockHash().ToString(), pindexPrev->nHeight);
            return nullptr;
        }
        pblock->nTime = nTxNewTime;
        pblock->vtx[0].vout[0].SetEmpty();
        pblock->vtx.push_back(CTransaction(txCoinStake));
    }

    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    unsigned int nBlockMaxSizeNetwork = MAX_BLOCK_SIZE_CURRENT;
    nBlockMaxSize = std::max((unsigned int)1000, std::min((nBlockMaxSizeNetwork - 1000), nBlockMaxSize));

    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    CAmount nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache view(pcoinsTip);

        std::list<COrphan> vOrphan;
        std::map<uint256, std::vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        std::vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (std::map<uint256, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi) {
            const CTransaction& tx = mi->second.GetTx();
            if (tx.IsCoinBase() || tx.IsCoinStake() || !IsFinalTx(tx, nHeight)){
                continue;
            }

            COrphan* porphan = NULL;
            double dPriority = 0;
            CAmount nTotalIn = 0;
            bool fMissingInputs = false;

            for (const CTxIn& txin : tx.vin) {
                 if (txin.IsZerocoinSpend()){
                    // Zerocoin is disabled, so this should ideally not happen in mempool.
                    // If it does, skip this tx for block inclusion.
                    LogPrint("miner", "Skipping transaction %s with Zerocoin spend for block creation.\n", tx.GetHash().ToString());
                    fMissingInputs = true; // Treat as missing to skip
                    break;
                }
                if (!view.HaveCoins(txin.prevout.hash)) {
                    if (!mempool.mapTx.count(txin.prevout.hash)) {
                        LogPrintf("ERROR: mempool transaction %s missing input %s\n", tx.GetHash().ToString(), txin.prevout.hash.ToString());
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }
                    if (!porphan) {
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].GetTx().vout[txin.prevout.n].nValue;
                    continue;
                }
                const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                assert(coins);
                CAmount nValueIn = coins->vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;
                int nConf = nHeight - coins->nHeight;
                dPriority = double_safe_addition(dPriority, ((double)nValueIn * nConf));
            }
            if (fMissingInputs) continue;

            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);
            uint256 hash = tx.GetHash();
            mempool.ApplyDeltas(hash, dPriority, nTotalIn);
            CFeeRate feeRate(nTotalIn - tx.GetValueOut(), nTxSize);

            if (porphan) {
                porphan->dPriority = dPriority;
                porphan->feeRate = feeRate;
            } else
                vecPriority.push_back(TxPriority(dPriority, feeRate, &mi->second.GetTx()));
        }

        uint64_t nBlockSize = fProofOfStake ? pblock->GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION) : 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = GetLegacySigOpCount(pblock->vtx[0]); // Coinbase sigops
        if (fProofOfStake && pblock->vtx.size() > 1) { // If coinstake is added
             nBlockSigOps += GetLegacySigOpCount(pblock->vtx[1]);
        }

        bool fSortedByFee = (nBlockPrioritySize <= 0);
        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty()) {
            double dPriority = vecPriority.front().get<0>();
            CFeeRate feeRate = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            unsigned int nMaxBlockSigOps = MAX_BLOCK_SIGOPS_CURRENT;
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= nMaxBlockSigOps)
                continue;

            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < ::minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority))) {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!view.HaveInputs(tx))
                continue;

            CAmount nTxFees = view.GetValueIn(tx) - tx.GetValueOut();
            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= nMaxBlockSigOps)
                continue;

            CValidationState local_tx_state; // Use a local CValidationState
            if (!CheckInputs(tx, local_tx_state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true))
                continue;

            CTxUndo txundo;
            UpdateCoins(tx, local_tx_state, view, txundo, nHeight);

            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority) {
                LogPrintf("priority %.1f fee %s txid %s\n",
                    dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }

            if (mapDependers.count(hash)) {
                for (COrphan* porphan : mapDependers[hash]) {
                    if (!porphan->setDependsOn.empty()) {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty()) {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        if (!fProofOfStake) {
            FillBlockPayee(txNew, nFees, fProofOfStake);
            if (txNew.vout.size() > 1) {
                pblock->payee = txNew.vout[1].scriptPubKey;
            } else {
                CAmount blockValue = nFees + GetBlockValue(pindexPrev->nHeight);
                txNew.vout[0].nValue = blockValue;
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("%s : created new block with %u transactions, total size %u\n", __func__, nBlockTx, nBlockSize);

        pblock->vtx[0].vin[0].scriptSig = CScript() << nHeight << OP_0;
        if (!fProofOfStake) {
            pblock->vtx[0] = txNew;
            pblocktemplate->vTxFees[0] = -nFees;
        }

        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        if (!fProofOfStake) {
            UpdateTime(pblock, pindexPrev);
            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
        }
        // For PoS, nTime and nBits are already set from CreateCoinStake.
        pblock->nNonce = 0; // Initial nonce for PoW search

        if (pblock->nVersion == 4 && consensus.height_last_ZC_AccumCheckpoint != INT_MAX && nHeight > consensus.height_start_ZC) {
             if (pindexPrev->nAccumulatorCheckpoint.IsNull())
                 LogPrintf("WARNING: %s: pindexPrev->nAccumulatorCheckpoint is null at height %d\n", __func__, pindexPrev->nHeight);
             pblock->nAccumulatorCheckpoint = pindexPrev->nAccumulatorCheckpoint;
        }

        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);
        if (fProofOfStake && pblock->vtx.size() > 1) {
            pblocktemplate->vTxSigOps[0] += GetLegacySigOpCount(pblock->vtx[1]);
        }
        
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock); // Compute Merkle Root after all transactions are set

        if (fProofOfStake) {
            // IncrementExtraNonce called here for PoS mainly to recompute Merkle root if coinbase scriptSig changes.
            // The block is effectively "solved" by CreateCoinStake and needs signing.
            // unsigned int nExtraNonce = 0; // Not directly used for PoS nonce search
            // IncrementExtraNonce(pblock, pindexPrev, nExtraNonce); // Updates Merkle root if coinbase changed

            LogPrintf("%s: PoS block template created %s, attempting to sign.\n", __func__, pblock->GetHash().ToString());
            if (!SignBlock(*pblock, *pwallet)) {
                LogPrintf("%s: Signing new PoS block with UTXO key failed \n", __func__);
                return nullptr;
            }
            // After signing, the PoS block is ready. Validate it before returning.
            CValidationState pos_validation_state;
            if (!TestBlockValidity(pos_validation_state, *pblock, pindexPrev, false, false)) { // fCheckPOW is false for PoS
                LogPrintf("CreateNewBlock() : PoS TestBlockValidity failed: %s\n", pos_validation_state.GetRejectReason());
                return nullptr;
            }
        } else {
            // For PoW, the block is a template. Nonce search happens in BitcoinMiner.
            // TestBlockValidity is NOT called here for PoW.
            LogPrintf("%s : PoW block template created for height %d, nBits %08x\n", __func__, nHeight, pblock->nBits);
        }
    }

    return pblocktemplate.release();
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    static uint256 hashPrevBlock_static_extranonce; // Use a distinct name for static variable
    if (hashPrevBlock_static_extranonce != pblock->hashPrevBlock) {
        nExtraNonce = 0;
        hashPrevBlock_static_extranonce = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight + 1;
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//
double dHashesPerSec = 0.0;
int64_t nHPSTimerStart = 0;

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, CWallet* pwallet)
{
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey, false))
        return nullptr;

    CBlockIndex* pindexPrev = nullptr;
    {
        LOCK(cs_main);
        if (chainActive.Tip()) {
             pindexPrev = chainActive.Tip(); // Get current tip
        }
    }

    if (!pindexPrev) {
        LogPrintf("%s: Error: chainActive.Tip() is null. Cannot create new PoW block.\n", __func__);
        MilliSleep(1000); // Prevent tight loop if this state persists during startup
        return nullptr;
    }

    const int nHeightNext = pindexPrev->nHeight + 1;
    const Consensus::Params& consensusParams = Params().GetConsensus();

    LogPrintf("%s: Attempting PoW block creation for height %d. Last PoW height is %d.\n",
              __func__, nHeightNext, consensusParams.height_last_PoW);

    if (nHeightNext > consensusParams.height_last_PoW) {
        LogPrintf("%s: Aborting PoW block creation for height %d. PoS phase active (last PoW: %d).\n",
                  __func__, nHeightNext, consensusParams.height_last_PoW);
        MilliSleep((consensusParams.nTargetSpacing * 1000) / 2); // Sleep for half a block time
        return nullptr;
    }

    LogPrintf("%s: Proceeding with PoW block creation for height %d.\n", __func__, nHeightNext);
    CScript scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
    return CreateNewBlock(scriptPubKey, pwallet, false); // fProofOfStake is false for PoW
}

bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    if (pblock->vtx.empty() || pblock->vtx[0].vout.empty()){
        LogPrintf("%s: ERROR - Mined block has no coinbase or no coinbase outputs.\n", __func__);
        return false;
    }
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));


    {
        WAIT_LOCK(g_best_block_mutex, lock);
        if (pblock->hashPrevBlock != g_best_block)
            return error("DIGIWAGEMiner : generated block is stale");
    }

    if (!pblock->IsProofOfStake()) { // Only PoW blocks use reservekey this way
        reservekey.KeepKey();
    }

    GetMainSignals().BlockFound(pblock->GetHash());

    CValidationState state;
    if (!ProcessNewBlock(state, NULL, pblock, nullptr)) { // Pass nullptr for CDiskBlockPos*
        return error("DIGIWAGEMiner : ProcessNewBlock, block not accepted: %s", state.GetRejectReason());
    }

    return true;
}

bool fGenerateBitcoins = false; // Controls PoW mining
bool fStakeableCoins = false;
int nMintableLastCheck = 0;

void CheckForCoins(CWallet* pwallet, const int minutes)
{
    int nTimeNow = GetTime();
    if ((nTimeNow - nMintableLastCheck > minutes * 60)) {
        nMintableLastCheck = nTimeNow;
        if(pwallet) fStakeableCoins = pwallet->StakeableCoins();
        else fStakeableCoins = false; // Should not happen if pwallet is valid
    }
}

void BitcoinMiner(CWallet* pwallet, bool fProofOfStake)
{
    LogPrintf("DIGIWAGEMiner started (fProofOfStake = %s)\n", fProofOfStake ? "true" : "false");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    util::ThreadRename(fProofOfStake ? "digiwage-staker" : "digiwage-miner");
    const int64_t nSpacingMillis = Params().GetConsensus().nTargetSpacing * 1000;
    const int last_pow_block = Params().GetConsensus().height_last_PoW;

    CReserveKey reservekey(pwallet); // For PoW
    unsigned int nExtraNonce = 0;

    while (fProofOfStake || fGenerateBitcoins) { // Loop continues if either staking is enabled for this thread OR PoW generation is globally enabled
        boost::this_thread::interruption_point();

        CBlockIndex* pindexPrev = GetChainTip();
        if (!pindexPrev) {
            MilliSleep(nSpacingMillis);
            continue;
        }

        if (fProofOfStake) { // Staking Logic
            if (pindexPrev->nHeight < last_pow_block) {
                LogPrint("staking", "PoS miner waiting: Current height %d, PoS starts after %d\n", pindexPrev->nHeight, last_pow_block);
                MilliSleep(nSpacingMillis);
                continue;
            }

            CheckForCoins(pwallet, 5);

            while (pwallet->IsLocked() || !fStakeableCoins || masternodeSync.NotCompleted() || (vNodes.empty() && Params().MiningRequiresPeers() && !Params().IsRegTestNet()) ) {
                nMintableLastCheck = 0; // force check in CheckForCoins on next iteration
                MilliSleep(5000);
                boost::this_thread::interruption_point();
                if (!fStakeableCoins) CheckForCoins(pwallet, 1); // Check more often if this is the blocker
                if (!fProofOfStake) { // If staking was disabled externally while waiting
                     LogPrintf("%s (PoS): Staking flag turned off, exiting staker part of BitcoinMiner.\n", __func__);
                     return; // Exit this instance of BitcoinMiner (the staker thread)
                }
            }

            if (pwallet->pStakerStatus &&
                pwallet->pStakerStatus->GetLastHash() == pindexPrev->GetBlockHash() &&
                pwallet->pStakerStatus->GetLastTime() >= GetCurrentTimeSlot()) {
                MilliSleep(2000);
                continue;
            }
        } else { // PoW Logic (fProofOfStake is false)
            if (pindexPrev->nHeight >= last_pow_block) {
                LogPrintf("%s (PoW): PoW phase ended. Current height %d, last PoW height %d. PoW Miner stopping.\n",
                          __func__, pindexPrev->nHeight, last_pow_block);
                // fGenerateBitcoins should be set to false by GenerateBitcoins to stop all PoW threads
                // This return will exit this specific PoW thread.
                return;
            }
            // The (pindexPrev->nHeight - 6) > last_pow_block condition is a softer exit for PoW.
            // The stricter check above is preferred for a clean cut-off.
        }

        unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        std::unique_ptr<CBlockTemplate> pblocktemplate(
            fProofOfStake ? CreateNewBlock(CScript(), pwallet, true)
                          : CreateNewBlockWithKey(reservekey, pwallet)
        );

        if (!pblocktemplate.get()) {
            LogPrint(fProofOfStake ? "staking" : "miner", "%s: CreateNewBlock%s returned nullptr. Sleeping.\n", __func__, fProofOfStake ? "" : "WithKey");
            MilliSleep(nSpacingMillis / 2);
            continue;
        }
        CBlock* pblock = &pblocktemplate->block;

        if (fProofOfStake) {
            LogPrintf("%s (PoS): Proof-of-stake block created/signed: %s \n", __func__, pblock->GetHash().ToString());
            SetThreadPriority(THREAD_PRIORITY_NORMAL);
            CReserveKey dummyReserveKey(pwallet); // ProcessBlockFound expects a reservekey
            if (!ProcessBlockFound(pblock, *pwallet, dummyReserveKey)) {
                LogPrintf("%s (PoS): New PoS block orphaned\n", __func__);
            }
            SetThreadPriority(THREAD_PRIORITY_LOWEST);
            MilliSleep(nSpacingMillis / 2); // Wait a bit after staking
            continue;
        }

        // ----- PoW Mining Search -----
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
        LogPrintf("Running DIGIWAGEMiner (PoW) with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
            ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        int64_t nStart = GetTime();
        uint256 hashTarget = uint256().SetCompact(pblock->nBits);
        while (true) { // PoW search loop
            boost::this_thread::interruption_point();
            if (!fGenerateBitcoins) break; // Check if PoW mining was disabled globally

            unsigned int nHashesDone = 0;
            uint256 hash;

            // Inner hashing loop - iterate a small chunk of nonces
            for (unsigned int i = 0; i <= 0xFFF; ++i) { // Iterate more nonces before checking external conditions
                pblock->nNonce++;
                hash = pblock->GetHash();
                nHashesDone++;
                if (hash <= hashTarget) {
                    break; // Found solution
                }
            }

            if (hash <= hashTarget) { // Check if solution found
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                LogPrintf("%s (PoW):\n", __func__);
                LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex());
                ProcessBlockFound(pblock, *pwallet, reservekey); // Pass the actual reservekey for PoW
                SetThreadPriority(THREAD_PRIORITY_LOWEST);

                if (Params().IsRegTestNet())
                    throw boost::thread_interrupted(); // Stop after 1 block in regtest
                break; // Break PoW search loop (goes to top of main while loop)
            }

            // Meter hashes/sec
            static int64_t nHashCounter_static; // Ensure static for accumulation across calls within this thread if outer loop continues
            static RecursiveMutex cs_hashmeter_static; // Protect shared dHashesPerSec
            
            if (nHPSTimerStart == 0) {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter_static = 0;
            } else {
                nHashCounter_static += nHashesDone;
            }

            if (GetTimeMillis() - nHPSTimerStart > 4000) {
                LOCK(cs_hashmeter_static);
                if (GetTimeMillis() - nHPSTimerStart > 4000) { // Double check after lock
                    dHashesPerSec = 1000.0 * nHashCounter_static / (GetTimeMillis() - nHPSTimerStart);
                    nHPSTimerStart = GetTimeMillis();
                    nHashCounter_static = 0;
                    static int64_t nLogTime;
                    if (GetTime() - nLogTime > 30 * 60) {
                        nLogTime = GetTime();
                        LogPrintf("hashmeter %6.0f khash/s\n", dHashesPerSec / 1000.0);
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            if ((vNodes.empty() && Params().MiningRequiresPeers() && !Params().IsRegTestNet()) ||
                (pblock->nNonce >= 0xffffffff) || // Exhausted nonce range for this extranonce
                (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60) ||
                (pindexPrev != GetChainTip()) // Chain tip changed, rebuild template
            ) {
                break; // Break PoW search loop, will go to top of main while loop to rebuild
            }
            
            // Update nTime periodically for PoW block template
            if ((pblock->nNonce & 0x3FFFFF) == 0) { // Update time less frequently
                 UpdateTime(pblock, pindexPrev);
                 if (Params().GetConsensus().fPowAllowMinDifficultyBlocks) {
                     hashTarget.SetCompact(pblock->nBits); // Target can change on testnet with time
                 }
            }
        } // End of PoW search loop
        if (!fGenerateBitcoins) break; // If PoW mining was disabled globally, exit outer loop
    } // End of while (fProofOfStake || fGenerateBitcoins)
    LogPrintf("%s: %s thread exiting.\n", __func__, fProofOfStake ? "Staker" : "PoW Miner");
}


void static ThreadBitcoinMiner(void* parg)
{
    boost::this_thread::interruption_point();
    CWallet* pwallet = (CWallet*)parg;
    try {
        BitcoinMiner(pwallet, false); // This thread is for PoW mining
        boost::this_thread::interruption_point();
    } catch (const boost::thread_interrupted&) {
        LogPrintf("DIGIWAGEMiner (PoW) thread interrupted\n");
        // Allow thread to exit cleanly
    } catch (const std::exception& e) {
        LogPrintf("DIGIWAGEMiner (PoW) exception: %s\n", e.what());
    } catch (...) {
        LogPrintf("DIGIWAGEMiner (PoW) unknown exception\n");
    }

    LogPrintf("DIGIWAGEMiner (PoW) thread exiting\n");
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
{
    static boost::thread_group* minerThreads = NULL;
    fGenerateBitcoins = fGenerate; // This global flag controls PoW mining

    if (minerThreads != NULL) {
        minerThreads->interrupt_all();
        try {
            minerThreads->join_all(); // Wait for threads to finish
        } catch (const std::exception& e) {
            LogPrintf("Error joining PoW miner threads: %s\n", e.what());
        }
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate) // If nThreads is 0 or fGenerate is false, don't start PoW mining.
        return;

    if (nThreads < 0) {
        nThreads = boost::thread::hardware_concurrency();
        if (nThreads <= 0) nThreads = 1; // Fallback if detection fails
    }


    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&ThreadBitcoinMiner, pwallet));
}

// ppcoin: stake minter thread
void ThreadStakeMinter()
{
    boost::this_thread::interruption_point();
    LogPrintf("ThreadStakeMinter started\n");
    CWallet* pwallet = pwalletMain;
    if (!pwallet) {
        LogPrintf("ThreadStakeMinter: pwalletMain is null, exiting.\n");
        return;
    }
    try {
        BitcoinMiner(pwallet, true); // Call BitcoinMiner with fProofOfStake = true
        boost::this_thread::interruption_point();
    } catch (const boost::thread_interrupted&) {
        LogPrintf("ThreadStakeMinter interrupted\n");
        // Allow thread to exit cleanly
    } catch (const std::exception& e) {
        LogPrintf("ThreadStakeMinter() exception: %s\n", e.what());
    } catch (...) {
        LogPrintf("ThreadStakeMinter() unknown error\n");
    }
    LogPrintf("ThreadStakeMinter exiting.\n");
}

#endif // ENABLE_WALLET