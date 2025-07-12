// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2016-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "swifttx.h"

#include "activemasternode.h"
#include "base58.h"
#include "consensus/validation.h" // For CValidationState
#include "hash.h"                 // Needed for CHash256
#include "init.h"                 // For GetMainSignals
#include "key.h"
#include "keystore.h"             // Needed for CBasicKeyStore (used in CMessageSigner potentially)
#include "main.h"                 // For cs_main, chainActive, mempool, AcceptToMemoryPool, GetTransaction, ReprocessBlocks etc.
#include "masternodeman.h"
#include "masternode-sync.h"      // For masternodeSync
#include "messagesigner.h"        // Needed for Sign/Verify V1/V2
#include "net.h"                  // For CNode, RelayInv, etc.
#include "obfuscation.h"          // May not be strictly needed here, but often related
#include "protocol.h"             // For CInv, MSG_TXLOCK_REQUEST, etc.
#include "spork.h"                // For sporkManager
#include "sync.h"                 // For LOCK
#include "timedata.h"             // For GetTime(), GetAdjustedTime()
#include "util.h"                 // For LogPrintf, GetArg, etc.
#include "utilmoneystr.h"         // For FormatMoney
#include "validationinterface.h"  // For GetMainSignals()
#include <boost/foreach.hpp>

// Define missing constants if they weren't picked up from elsewhere (unlikely but possible)
#ifndef SWIFTTX_SIGNATURES_REQUIRED
#define SWIFTTX_SIGNATURES_REQUIRED 6
#endif
#ifndef SWIFTTX_SIGNATURES_TOTAL
#define SWIFTTX_SIGNATURES_TOTAL 10
#endif
#ifndef MIN_SWIFTTX_PROTO_VERSION
// Use a reasonable default if not defined, check your consensus params/chainparams
#define MIN_SWIFTTX_PROTO_VERSION 70210 // Example: Adjust if necessary
#endif

// Global maps defined in swifttx.h
std::map<uint256, CTransaction> mapTxLockReq;
std::map<uint256, CTransaction> mapTxLockReqRejected;
std::map<uint256, CConsensusVote> mapTxLockVote;
std::map<uint256, CTransactionLock> mapTxLocks;
std::map<COutPoint, uint256> mapLockedInputs;
std::map<uint256, int64_t> mapUnknownVotes; //track votes with no tx for DOS
int nCompleteTXLocks = 0; // Initialize global counter

// Forward declaration just in case, though definition is below
void DoConsensusVote(CTransaction& tx, int64_t nBlockHeight);

// Process incoming SwiftTX messages
void ProcessMessageSwiftTX(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (fLiteMode) return; //disable all obfuscation/masternode related functionality
    if (!sporkManager.IsSporkActive(SPORK_2_SWIFTTX)) return;
    if (!masternodeSync.IsBlockchainSynced()) return;

    if (strCommand == "ix") { // InstantSend Transaction Lock Request
        //LogPrintf("ProcessMessageSwiftTX::ix\n");
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TXLOCK_REQUEST, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        if (mapTxLockReq.count(tx.GetHash()) || mapTxLockReqRejected.count(tx.GetHash())) {
             // Already known, ignore
            return;
        }

        if (!IsIXTXValid(tx)) {
            // Transaction is invalid for SwiftTX rules (too high value, invalid scripts, etc.)
            LogPrintf("%s: Received invalid SwiftTX request %s from peer %s\n", __func__, tx.GetHash().ToString(), pfrom->addr.ToString());
            // Potentially penalize peer? For now, just ignore.
            return;
        }

        // Check inputs, calculate required block height for voting
        int64_t nBlockHeight = CreateNewLock(tx);
        if (nBlockHeight == 0) {
             // Could not create lock (e.g., inputs too new)
             LogPrintf("%s: Could not create lock for SwiftTX request %s from peer %s\n", __func__, tx.GetHash().ToString(), pfrom->addr.ToString());
            return;
        }

        bool fMissingInputs = false;
        CValidationState state;
        bool fAccepted = false;
        {
            LOCK(cs_main);
            // Use standard mempool acceptance rules
            fAccepted = AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true); // last true bypasses fees for IX
        }

        if (fAccepted) {
            // Accepted to mempool, relay inventory and process voting
            RelayInv(inv);

            DoConsensusVote(tx, nBlockHeight); // Masternodes vote if they are in the quorum

            mapTxLockReq.insert(std::make_pair(tx.GetHash(), tx)); // Track the request

            LogPrint("swiftx", "%s : Transaction Lock Request: peer=%s %s txid=%s accepted\n", __func__,
                    pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str(),
                    tx.GetHash().ToString().c_str());

            // Check if we just completed the lock (can happen if votes arrived before the request)
            if (GetTransactionLockSignatures(tx.GetHash()) >= SWIFTTX_SIGNATURES_REQUIRED) {
                GetMainSignals().NotifyTransactionLock(tx); // Notify UI/Wallet
            }

        } else {
            // Rejected from mempool (conflict, double spend, invalid, etc.)
            mapTxLockReqRejected.insert(std::make_pair(tx.GetHash(), tx)); // Track rejection

            LogPrint("swiftx", "%s : Transaction Lock Request: peer=%s %s txid=%s rejected (%s)\n", __func__,
                pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str(),
                tx.GetHash().ToString().c_str(), state.GetRejectReason());

            // Add inputs to mapLockedInputs to detect conflicts with *other* IX requests
            // This doesn't lock them in the chain context, just for IX conflict resolution
            for (const CTxIn& in : tx.vin) {
                if (!mapLockedInputs.count(in.prevout)) {
                    mapLockedInputs.insert(std::make_pair(in.prevout, tx.GetHash()));
                }
            }

            // Check if this rejection conflicts with an *existing* completed lock
            std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(tx.GetHash());
            if (i != mapTxLocks.end()) {
                // Only care if the existing lock is complete
                if (i->second.CountSignatures() >= SWIFTTX_SIGNATURES_REQUIRED) {
                    // If the rejection doesn't conflict with another lock, something is wrong.
                    // Maybe this node previously accepted it? Re-process blocks to potentially resolve.
                    if (!CheckForConflictingLocks(tx)) {
                        LogPrintf("%s : Found Existing Complete IX Lock for a rejected tx %s - Reprocessing blocks\n", __func__, tx.GetHash().ToString());
                        // Reprocess recent blocks might resolve state inconsistencies
                        // Be cautious with this, could be resource intensive
                        LOCK(cs_main);
                        ReprocessBlocks(15); // Reprocess last 15 blocks
                        // If reprocessing helps, maybe it gets accepted now?
                        // We might need to remove it from rejected and re-add to requests?
                        // For now, just log and rely on reprocessing.
                        // mapTxLockReq.insert(std::make_pair(tx.GetHash(), tx)); // Maybe re-add? Risky.
                    }
                }
            }
        }
        return; // Handled ix message

    } else if (strCommand == "txlvote") { // SwiftX Lock Consensus Vote
        CConsensusVote ctxVote;
        vRecv >> ctxVote;

        CInv inv(MSG_TXLOCK_VOTE, ctxVote.GetHash());
        pfrom->AddInventoryKnown(inv);

        if (mapTxLockVote.count(ctxVote.GetHash())) {
            // Already have this vote, ignore
            return;
        }

        mapTxLockVote.insert(std::make_pair(ctxVote.GetHash(), ctxVote)); // Track the vote itself

        // Process the vote (check signature, masternode rank, add to lock)
        if (ProcessConsensusVote(pfrom, ctxVote)) {
            // Vote was valid and processed, relay it
            RelayInv(inv);

            // Anti-spam: Track votes received before the transaction request itself
            if (!mapTxLockReq.count(ctxVote.txHash) && !mapTxLockReqRejected.count(ctxVote.txHash)) {
                uint256 masternodeBlockHash = ctxVote.vinMasternode.prevout.hash; // Use MN outpoint hash for tracking
                if (!mapUnknownVotes.count(masternodeBlockHash)) {
                    mapUnknownVotes[masternodeBlockHash] = GetTime() + (60 * 10); // Allow 10 minutes grace
                }

                // Check if this MN is sending votes too frequently without corresponding TXs
                int64_t nAverageVoteTime = GetAverageVoteTime(); // Calculate average across all unknown votes
                // Allow some burst, but penalize if consistently too fast
                if (mapUnknownVotes[masternodeBlockHash] > GetTime() &&
                    (mapUnknownVotes[masternodeBlockHash] - nAverageVoteTime) > (60 * 10)) { // 10 min threshold over avg
                    LogPrintf("%s : masternode %s is spamming transaction votes for unknown tx %s\n", __func__,
                        ctxVote.vinMasternode.prevout.ToStringShort(),
                        ctxVote.txHash.ToString());
                    // Maybe penalize peer? For now, just ignore subsequent votes within the window.
                    // Note: This simple check might not be robust enough.
                    return; // Ignore vote if considered spam
                } else {
                    // Reset the timer for this MN
                    mapUnknownVotes[masternodeBlockHash] = GetTime() + (60 * 10);
                }
            }

            // Check if this vote completes the transaction lock
            if (mapTxLockReq.count(ctxVote.txHash) && GetTransactionLockSignatures(ctxVote.txHash) >= SWIFTTX_SIGNATURES_REQUIRED) {
                 // Ensure the transaction exists in our request map before notifying
                 GetMainSignals().NotifyTransactionLock(mapTxLockReq[ctxVote.txHash]);
            }

        } else {
             // Vote was invalid (bad signature, wrong rank, etc.)
             LogPrint("swiftx", "%s: Invalid consensus vote %s from peer %s\n", __func__, ctxVote.GetHash().ToString(), pfrom->addr.ToString());
             // No relay needed for invalid votes
        }
        return; // Handled txlvote message
    }
}


// Check if a transaction is valid according to SwiftTX rules
bool IsIXTXValid(const CTransaction& tx)
{
    // Basic checks
    if (tx.vout.empty()) {
        LogPrint("swiftx", "%s: Transaction %s has no outputs\n", __func__, tx.GetHash().ToString());
        return false;
    }
    if (tx.IsCoinBase() || tx.IsCoinStake()) {
        LogPrint("swiftx", "%s: Transaction %s is coinbase/coinstake\n", __func__, tx.GetHash().ToString());
        return false; // IX doesn't apply to generation transactions
    }
    // SwiftTX specific locktime (must be 0)
    // Note: Some protocols might use locktime for other purposes, ensure this is correct for DIGIWAGE
    if (tx.nLockTime != 0) {
         LogPrint("swiftx", "%s: Transaction %s has non-zero locktime %u\n", __func__, tx.GetHash().ToString(), tx.nLockTime);
        return false;
    }

    // Check output value limits using Spork 5
    CAmount nValueOut = tx.GetValueOut();
    CAmount maxTxValue = sporkManager.GetSporkValue(SPORK_5_MAX_VALUE) * COIN;
    if (maxTxValue > 0 && nValueOut > maxTxValue) { // Check if spork is enabled (>0)
        LogPrint("swiftx", "%s: Transaction %s value %s exceeds max allowed %s\n", __func__,
                 tx.GetHash().ToString(), FormatMoney(nValueOut), FormatMoney(maxTxValue));
        return false;
    }

    // Check transaction fee
    CAmount nValueIn = 0;
    bool fMissingInputs = false;
    {
        LOCK(cs_main); // Needed for GetTransaction/Accessing block index
        for (const CTxIn& txin : tx.vin) {
            CTransaction prevTx;
            uint256 hashBlock; // Not used here but required by GetTransaction
            // Look up the previous transaction output
            if (GetTransaction(txin.prevout.hash, prevTx, hashBlock, true)) {
                if (txin.prevout.n < prevTx.vout.size()) {
                    nValueIn += prevTx.vout[txin.prevout.n].nValue;
                } else {
                    // Output index out of bounds - should not happen for valid txs
                    LogPrintf("%s: Error - Input %s references invalid output index %u in tx %s\n", __func__,
                              txin.prevout.ToStringShort(), txin.prevout.n, txin.prevout.hash.ToString());
                    fMissingInputs = true; // Treat as missing input for fee calc
                    break;
                }
            } else {
                // Previous transaction not found in index/mempool
                fMissingInputs = true;
                break; // Cannot calculate fee if any input is missing
            }
        }
    } // End LOCK(cs_main)

    if (fMissingInputs) {
        // This can happen if the tx depends on other unconfirmed txs not yet seen by this node.
        // SwiftTX aims to lock quickly, so relying on unconfirmed chains is risky.
        // The original code returned true here, acknowledging this might happen. Let's stick with that,
        // but log it clearly. If it's invalid later, standard consensus will reject it.
        LogPrint("swiftx", "%s : Could not find all inputs for IX transaction %s - allowing IX request for now\n", __func__, tx.GetHash().ToString());
        return true;
    }

    // Check if fee meets the minimum required for SwiftTX (e.g., 0.01 DIGI)
    // This fee requirement might be different from standard relay fees.
    CAmount nFee = nValueIn - nValueOut;
    CAmount minSwiftTXFee = 0.01 * COIN; // Example: 0.01 DIGI - adjust if needed
    if (nFee < minSwiftTXFee) {
        LogPrint("swiftx", "%s: Transaction %s fee %s is less than SwiftTX minimum %s\n", __func__,
                 tx.GetHash().ToString(), FormatMoney(nFee), FormatMoney(minSwiftTXFee));
        return false;
    }

    // Check output script types (allow standard and unspendable)
    for (const CTxOut &o : tx.vout) {
        CTxDestination dest;
        bool fStandard = ExtractDestination(o.scriptPubKey, dest);
        if (!fStandard && !o.scriptPubKey.IsUnspendable()) {
            LogPrint("swiftx", "%s : Transaction %s has non-standard/non-unspendable output script: %s\n", __func__,
                     tx.GetHash().ToString(), o.scriptPubKey.ToString().substr(0, 40));
            return false;
        }
    }

    return true; // Passed all checks
}


// Create a new CTransactionLock object or update existing one for a TX request
// Returns the calculated block height for voting, or 0 if inputs are too new.
int64_t CreateNewLock(CTransaction tx) // Pass tx by value as it was in original code
{
    // Determine the age of the youngest input. SwiftTX requires inputs to be confirmed.
    int64_t nYoungestInputAge = -1; // Use -1 to indicate not found or unconfirmed
    {
        LOCK(cs_main); // Needed for GetInputAge
        // *** FIX 1: Change loop variable to be a copy, not const ref ***
        for (CTxIn txin : tx.vin) {
            int64_t nInputAge = GetInputAge(txin); // GetInputAge returns confirmations, or 0 if unconfirmed/not found
            if (nInputAge == 0) {
                // Input is unconfirmed or not found
                nYoungestInputAge = 0;
                break; // No need to check others if one is too new
            }
            if (nYoungestInputAge == -1 || nInputAge < nYoungestInputAge) {
                nYoungestInputAge = nInputAge;
            }
        }
    } // End LOCK(cs_main)

    // Define the minimum required confirmations for SwiftTX inputs
    const int nRequiredConfirmations = 6; // Example: PIVX/Dash used 6, adjust if needed for DIGIWAGE

    if (nYoungestInputAge < nRequiredConfirmations) {
        LogPrint("swiftx", "%s : Transaction %s inputs too new (%lld/%d confirmations)\n", __func__,
                 tx.GetHash().ToString(), nYoungestInputAge, nRequiredConfirmations);
        return 0; // Signal failure: Inputs not sufficiently confirmed
    }

    // Calculate the block height for the masternode quorum.
    // This should be a height *in the past* based on the input age,
    // making the quorum deterministic and harder to game.
    int nCurrentHeight = 0;
    {
        LOCK(cs_main);
        nCurrentHeight = chainActive.Height();
    }
    // Use a height slightly older than the youngest input's confirmation block.
    // Adding 4 blocks as in original code provides some buffer.
    int nVotingBlockHeight = (nCurrentHeight - nYoungestInputAge) + 4;
    // Ensure the calculated height is not in the future (can happen with clock drift or reorgs)
    nVotingBlockHeight = std::min(nVotingBlockHeight, nCurrentHeight);
    // Ensure it's not negative or zero (genesis block issues)
    nVotingBlockHeight = std::max(1, nVotingBlockHeight);


    // Create or update the lock entry
    if (!mapTxLocks.count(tx.GetHash())) {
        LogPrint("swiftx", "%s : New Transaction Lock %s at block height %d\n", __func__,
                 tx.GetHash().ToString(), nVotingBlockHeight);

        CTransactionLock newLock;
        newLock.nBlockHeight = nVotingBlockHeight;
        newLock.txHash = tx.GetHash();
        // Set reasonable expiration and timeout values
        newLock.nExpiration = GetTime() + (60 * 60); // Locks expire after 60 minutes
        newLock.nTimeout = GetTime() + (60 * 5);    // Voting timeout after 5 minutes
        mapTxLocks.insert(std::make_pair(tx.GetHash(), newLock));
    } else {
        // Lock already exists, update the block height if necessary (e.g., if inputs changed due to malleability?)
        // Usually, this shouldn't happen for the same tx hash, but handle defensively.
        mapTxLocks[tx.GetHash()].nBlockHeight = nVotingBlockHeight;
        // Maybe update expiration/timeout? Let's keep them from the first creation time.
        LogPrint("swiftx", "%s : Transaction Lock Exists %s, updated block height to %d\n", __func__,
                 tx.GetHash().ToString(), nVotingBlockHeight);
    }

    return nVotingBlockHeight; // Return the calculated height for voting
}

// Called when a valid SwiftTX request is received or generated locally
void DoConsensusVote(CTransaction& tx, int64_t nBlockHeight)
{
    if (!fMasterNode) return; // Only masternodes vote

    // Check if this masternode is in the quorum for the given block height
    int nRank = mnodeman.GetMasternodeRank(activeMasternode.vin, nBlockHeight, MIN_SWIFTTX_PROTO_VERSION);

    if (nRank == -1) {
        LogPrint("swiftx", "%s : Masternode %s not found for block height %d\n", __func__,
                 activeMasternode.vin.prevout.ToStringShort(), nBlockHeight);
        return;
    }

    if (nRank > SWIFTTX_SIGNATURES_TOTAL) {
        LogPrint("swiftx", "%s : Masternode %s rank %d is not in the top %d for block height %d\n", __func__,
                 activeMasternode.vin.prevout.ToStringShort(), nRank, SWIFTTX_SIGNATURES_TOTAL, nBlockHeight);
        return;
    }

    LogPrint("swiftx", "%s : Masternode %s rank %d in the top %d for block height %d - Voting for tx %s\n", __func__,
             activeMasternode.vin.prevout.ToStringShort(), nRank, SWIFTTX_SIGNATURES_TOTAL, nBlockHeight, tx.GetHash().ToString());

    // Create the consensus vote
    CConsensusVote ctxVote(activeMasternode.vin, tx.GetHash(), nBlockHeight);

    // Determine signature version based on current chain state (use feature flag/height)
    bool fNewSigs = false;
    {
        LOCK(cs_main); // Access chainActive/Params safely
        // Example: Check if a specific consensus parameter or block height activates new signatures
        // Replace with actual DIGIWAGE logic if available
        // *** FIX 2: Remove unused variable ***
        // int nCurrentHeight = chainActive.Height();
        // fNewSigs = Params().GetConsensus().IsV2SignaturesActive(nCurrentHeight); // Hypothetical check
        // If no specific V2 activation, assume V1 for now:
        fNewSigs = false; // <<< ADJUST THIS if V2 signatures are used
    }

    // Sign the vote
    if (!ctxVote.Sign(strMasterNodePrivKey, fNewSigs)) {
        LogPrintf("%s : Failed to sign consensus vote for tx %s\n", __func__, tx.GetHash().ToString());
        return;
    }

    // Double-check the signature immediately after signing
    if (!ctxVote.CheckSignature()) {
        LogPrintf("%s : Signature invalid immediately after signing vote for tx %s (BUG?)\n", __func__, tx.GetHash().ToString());
        return; // Should not happen
    }

    // Store the vote locally
    uint256 voteHash = ctxVote.GetHash();
    if (mapTxLockVote.find(voteHash) == mapTxLockVote.end()) {
         mapTxLockVote[voteHash] = ctxVote;
         // Relay the vote to the network
         ctxVote.Relay();
    } else {
         LogPrint("swiftx", "%s: Vote %s already exists locally.\n", __func__, voteHash.ToString());
    }
}


// Process a received consensus vote
bool ProcessConsensusVote(CNode* pnode, CConsensusVote& ctxVote)
{
    // Find the masternode that sent the vote
    CMasternode* pmn = mnodeman.Find(ctxVote.vinMasternode);
    if (pmn == NULL) {
        LogPrint("swiftx", "%s : Unknown Masternode %s sending vote %s - requesting MN data\n", __func__,
                 ctxVote.vinMasternode.prevout.ToStringShort(), ctxVote.GetHash().ToString());
        // Ask the peer for masternode data for this MN
        mnodeman.AskForMN(pnode, ctxVote.vinMasternode);
        return false; // Cannot process vote without MN details (pubkey)
    }

    // Check masternode rank for the vote's specified block height
    int nRank = mnodeman.GetMasternodeRank(ctxVote.vinMasternode, ctxVote.nBlockHeight, MIN_SWIFTTX_PROTO_VERSION);

    if (nRank == -1) {
        // Should not happen if pmn was found, but check defensively
        LogPrint("swiftx", "%s : Masternode %s not found for block height %d (inconsistency?)\n", __func__,
                 ctxVote.vinMasternode.prevout.ToStringShort(), ctxVote.nBlockHeight);
        return false;
    }

    if (nRank > SWIFTTX_SIGNATURES_TOTAL) {
        LogPrint("swiftx", "%s : Masternode %s rank %d is not in the top %d for block height %d - rejecting vote %s\n", __func__,
                 ctxVote.vinMasternode.prevout.ToStringShort(), nRank, SWIFTTX_SIGNATURES_TOTAL, ctxVote.nBlockHeight, ctxVote.GetHash().ToString());
        return false; // Vote is from a MN outside the valid quorum
    }

    // Check the signature using the masternode's public key
    if (!ctxVote.CheckSignature(pmn->pubKeyMasternode)) {
         LogPrintf("%s : Signature invalid for vote %s from masternode %s\n", __func__,
                   ctxVote.GetHash().ToString(), ctxVote.vinMasternode.prevout.ToStringShort());
         // Don't ban, could be sync issues or old protocol version.
         // Maybe increase DoS score? For now, just reject the vote.
         return false;
    }

    // Ensure a lock object exists for this transaction hash
    if (!mapTxLocks.count(ctxVote.txHash)) {
        // Vote arrived before the 'ix' request. Create a placeholder lock.
        LogPrint("swiftx", "%s : Received vote %s for unknown tx lock %s - Creating placeholder lock\n", __func__,
                 ctxVote.GetHash().ToString(), ctxVote.txHash.ToString());

        CTransactionLock newLock;
        // We don't know the correct block height yet, set to 0 initially.
        // It should be updated when the 'ix' message arrives via CreateNewLock.
        newLock.nBlockHeight = 0;
        newLock.txHash = ctxVote.txHash;
        newLock.nExpiration = GetTime() + (60 * 60); // Standard expiration
        newLock.nTimeout = GetTime() + (60 * 5);    // Standard timeout
        mapTxLocks.insert(std::make_pair(ctxVote.txHash, newLock));
    } else {
        // Lock exists, log for debugging if needed
        // LogPrint("swiftx", "%s : Transaction Lock Exists %s !\n", __func__, ctxVote.txHash.ToString());
    }

    // Add the valid signature to the corresponding transaction lock
    std::map<uint256, CTransactionLock>::iterator it = mapTxLocks.find(ctxVote.txHash);
    if (it != mapTxLocks.end()) {
        // Prevent duplicate votes from the same masternode for the same tx
        for (const CConsensusVote& existingVote : it->second.vecConsensusVotes) {
            if (existingVote.vinMasternode == ctxVote.vinMasternode) {
                LogPrint("swiftx", "%s: Masternode %s already voted for tx %s. Ignoring duplicate vote %s.\n", __func__,
                         ctxVote.vinMasternode.prevout.ToStringShort(), ctxVote.txHash.ToString(), ctxVote.GetHash().ToString());
                return false; // Don't add duplicate vote, but don't treat as error either
            }
        }

        // *** FIX 6 applied implicitly by calling AddSignature below ***
        // Definition of AddSignature is changed later to match header
        it->second.AddSignature(ctxVote); // Add the new valid vote

        // *** FIX 7 applied implicitly by calling CountSignatures below ***
        // Definition of CountSignatures is changed later to match header
        int sigCount = it->second.CountSignatures();
        LogPrint("swiftx", "%s : Added vote %s from MN %s for tx %s. Total sigs: %d/%d\n", __func__,
                 ctxVote.GetHash().ToString(), ctxVote.vinMasternode.prevout.ToStringShort(),
                 ctxVote.txHash.ToString(), sigCount, SWIFTTX_SIGNATURES_REQUIRED);


        // If enough signatures are gathered, mark the transaction lock as complete
        if (sigCount >= SWIFTTX_SIGNATURES_REQUIRED) {
            LogPrint("swiftx", "%s : Transaction Lock Is Complete %s !\n", __func__, it->second.GetHash().ToString());

            // Only proceed if we have the actual transaction request
            if (mapTxLockReq.count(ctxVote.txHash)) {
                CTransaction& tx = mapTxLockReq[ctxVote.txHash];

                // Critical: Check for conflicts *after* the lock is complete
                if (!CheckForConflictingLocks(tx)) {
                    // Lock is complete and not conflicting

                    // Update wallet transaction state if applicable (triggers UI updates)
#ifdef ENABLE_WALLET
                    if (pwalletMain && pwalletMain->UpdatedTransaction(it->second.txHash)) {
                            LogPrint("swiftx", "Updated wallet tx %s for completed lock.\n", it->second.txHash.ToString());
                            nCompleteTXLocks++; // Increment counter for RPC info
                    }
#endif

                    // Add the inputs to the map of globally locked inputs (for IX conflict detection)
                    for (const CTxIn& in : tx.vin) {
                        if (!mapLockedInputs.count(in.prevout)) {
                            mapLockedInputs.insert(std::make_pair(in.prevout, ctxVote.txHash));
                            LogPrint("swiftx", "Added input %s to mapLockedInputs for tx %s\n", in.prevout.ToStringShort(), ctxVote.txHash.ToString());
                        } else {
                            // This input was already locked by another *completed* TX. This indicates a conflict!
                            // CheckForConflictingLocks should ideally catch this earlier, but double-check.
                            if(mapLockedInputs[in.prevout] != ctxVote.txHash) {
                                LogPrintf("%s: CONFLICT DETECTED *after* lock completion! Input %s locked by %s, now attempted by %s\n", __func__,
                                          in.prevout.ToStringShort(), mapLockedInputs[in.prevout].ToString(), ctxVote.txHash.ToString());
                                // Mark both locks as expired to resolve conflict
                                it->second.nExpiration = GetTime();
                                if(mapTxLocks.count(mapLockedInputs[in.prevout])) {
                                     mapTxLocks[mapLockedInputs[in.prevout]].nExpiration = GetTime();
                                }
                                // Do not proceed with other actions for this lock
                                return false; // Vote added, but lock invalidated due to conflict
                            }
                        }
                    }

                    // If this transaction was previously rejected, completing the lock overrides the rejection.
                    // This might happen if votes arrived late. Reprocessing blocks can help ensure consistency.
                    if (mapTxLockReqRejected.count(it->second.txHash)) {
                        LogPrintf("%s: Completed lock %s overrides previous rejection. Reprocessing blocks.\n", __func__, it->second.txHash.ToString());
                        mapTxLockReqRejected.erase(it->second.txHash); // Remove from rejected list
                        LOCK(cs_main);
                        ReprocessBlocks(15); // Reprocess recent blocks
                    }

                     // Notify that the transaction is locked (important for UI/wallet)
                     GetMainSignals().NotifyTransactionLock(tx);

                } else {
                     // Lock is complete BUT conflicts with another existing lock.
                     // CheckForConflictingLocks already marked them for expiration.
                     LogPrintf("%s: Completed lock %s conflicts with another lock. Both invalidated.\n", __func__, it->second.txHash.ToString());
                     return false; // Vote processed, but lock invalidated
                }
            } else {
                 LogPrint("swiftx", "%s: Lock %s complete, but original tx request not found locally yet.\n", __func__, it->second.txHash.ToString());
                 // Lock is complete based on votes, but we need the 'ix' to fully process/notify.
                 // It should arrive soon.
            }
        }
        return true; // Vote was valid and added
    } else {
        // Should not happen if we created the placeholder lock earlier
        LogPrintf("%s : Error - Transaction lock %s not found even after trying to create placeholder.\n", __func__, ctxVote.txHash.ToString());
        return false;
    }
}


// Check if a new transaction conflicts with existing *completed* transaction locks
bool CheckForConflictingLocks(CTransaction& tx)
{
    // Iterate through the inputs of the transaction being checked
    for (const CTxIn& txin : tx.vin) {
        // Check if this input is already present in the map of locked inputs
        if (mapLockedInputs.count(txin.prevout)) {
            uint256 lockingTxHash = mapLockedInputs[txin.prevout];
            // Ensure the input is locked by a *different* transaction hash
            if (lockingTxHash != tx.GetHash()) {
                 // Check if the locking transaction still has a valid, non-expired lock
                 if (mapTxLocks.count(lockingTxHash) && mapTxLocks[lockingTxHash].nExpiration > GetTime()) {
                      // Make sure the existing lock has enough signatures (is truly complete)
                      if (mapTxLocks[lockingTxHash].CountSignatures() >= SWIFTTX_SIGNATURES_REQUIRED) {
                            LogPrintf("%s : CONFLICT FOUND - Input %s used by transaction %s conflicts with existing completed lock %s\n", __func__,
                                    txin.prevout.ToStringShort(), tx.GetHash().ToString(), lockingTxHash.ToString());

                            // Invalidate *both* conflicting locks by setting their expiration to now
                            if (mapTxLocks.count(tx.GetHash())) {
                                mapTxLocks[tx.GetHash()].nExpiration = GetTime();
                                LogPrintf("%s : Invalidating new lock %s\n", __func__, tx.GetHash().ToString());
                            }
                            mapTxLocks[lockingTxHash].nExpiration = GetTime();
                             LogPrintf("%s : Invalidating conflicting lock %s\n", __func__, lockingTxHash.ToString());

                            // It's crucial to remove the input from mapLockedInputs so it doesn't cause further issues
                            mapLockedInputs.erase(txin.prevout);

                            return true; // Conflict detected and handled
                      }
                 } else {
                     // The input was in mapLockedInputs, but the corresponding lock is expired or missing.
                     // Clean up the stale entry.
                     LogPrint("swiftx", "%s: Removing stale entry for input %s from mapLockedInputs (locked by %s)\n", __func__,
                              txin.prevout.ToStringShort(), lockingTxHash.ToString());
                     mapLockedInputs.erase(txin.prevout);
                 }
            }
        }
    }

    return false; // No conflicts found
}


// Calculate the average time of votes for unknown transactions (used for spam detection)
int64_t GetAverageVoteTime()
{
    int64_t total = 0;
    int64_t count = 0;

    std::map<uint256, int64_t>::iterator it = mapUnknownVotes.begin();
    while (it != mapUnknownVotes.end()) {
        // Consider only non-expired entries for average calculation
        if (it->second > GetTime()) {
             // Use the expiration time for calculation (approximates arrival time + grace period)
             total += it->second;
             count++;
        }
        it++;
    }

    if (count == 0) {
        return 0; // Avoid division by zero
    }

    return total / count;
}


// Clean up expired transaction locks and associated data
void CleanTransactionLocksList()
{
    if (chainActive.Tip() == NULL) return; // Need chain context

    int64_t nNow = GetTime();
    std::map<uint256, CTransactionLock>::iterator itLock = mapTxLocks.begin();

    while (itLock != mapTxLocks.end()) {
        if (nNow > itLock->second.nExpiration) {
            uint256 txHash = itLock->second.txHash;
            LogPrint("swiftx", "%s : Removing expired transaction lock %s\n", __func__, txHash.ToString());

            // If we have the corresponding transaction request, remove its inputs from mapLockedInputs
            if (mapTxLockReq.count(txHash)) {
                CTransaction& tx = mapTxLockReq[txHash];
                for (const CTxIn& in : tx.vin) {
                    // Only erase if it was locked by *this* transaction
                    if (mapLockedInputs.count(in.prevout) && mapLockedInputs[in.prevout] == txHash) {
                         mapLockedInputs.erase(in.prevout);
                         LogPrint("swiftx", "Removed input %s from mapLockedInputs for expired tx %s\n", in.prevout.ToStringShort(), txHash.ToString());
                    }
                }
                // Remove the transaction request itself
                mapTxLockReq.erase(txHash);
            }
             // Remove from rejected list as well
             mapTxLockReqRejected.erase(txHash);

             // Remove associated votes
             for (const CConsensusVote& vote : itLock->second.vecConsensusVotes) {
                 mapTxLockVote.erase(vote.GetHash());
             }

             // Finally, remove the lock object itself
             mapTxLocks.erase(itLock++); // Erase and increment iterator safely
        } else {
            itLock++; // Move to the next lock
        }
    }

    // Clean up expired unknown vote entries
    std::map<uint256, int64_t>::iterator itVote = mapUnknownVotes.begin();
    while(itVote != mapUnknownVotes.end()) {
        if(nNow > itVote->second) {
            mapUnknownVotes.erase(itVote++);
        } else {
            itVote++;
        }
    }
}


// Get the number of valid signatures for a transaction lock
int GetTransactionLockSignatures(uint256 txHash)
{
    // SwiftTX relies on Spork 2
    if (!sporkManager.IsSporkActive(SPORK_2_SWIFTTX)) return -1;

    // Check if there are issues with chain state (e.g., large reorgs) - PIVX specific check
    // Adapt or remove if not applicable to DIGIWAGE
    // if(fLargeWorkForkFound || fLargeWorkInvalidChainFound) return -2;

    std::map<uint256, CTransactionLock>::iterator it = mapTxLocks.find(txHash);
    if (it != mapTxLocks.end()) {
        // *** FIX 7 applied implicitly by calling CountSignatures below ***
        return it->second.CountSignatures(); // Use the method in CTransactionLock
    }

    return 0; // No lock found, so 0 signatures
}


// Check transaction locks periodically (e.g., on new block arrival)
// Not explicitly called in the provided snippet, but likely needed in main loop/ConnectBlock
void CheckTransactionLocks(int nHeight) {
     // Placeholder: Logic to re-evaluate locks based on new block height might go here
     // For example, checking if a locked tx got included in a block.
     // Or potentially re-evaluating conflicts if a block contains a conflicting tx.
     // This might be handled sufficiently by standard mempool conflict detection + CleanTransactionLocksList
}


// --------- CConsensusVote Implementation ---------

uint256 CConsensusVote::GetHash() const
{
    // Simple hash combining masternode outpoint and tx hash
    // Note: This doesn't include block height or time, meaning a MN can only vote once per tx.
    // If needing re-votes on height changes, the hash needs more components.
    return Hash(vinMasternode.prevout.hash.begin(), vinMasternode.prevout.hash.end(),
                BEGIN(vinMasternode.prevout.n), END(vinMasternode.prevout.n),
                txHash.begin(), txHash.end());
}

// Get the hash of the data that is actually signed
uint256 CConsensusVote::GetSignatureHash() const
{
    // Version 2 signatures (if used) typically sign a more comprehensive hash
    if (nMessVersion == 2) {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << nMessVersion; // Include version in the signed hash
        ss << vinMasternode;
        ss << txHash;
        ss << nBlockHeight;
        // nTime is usually *not* included in the signature hash itself,
        // as it's set *after* signing or can vary slightly between nodes.
        return ss.GetHash();
    } else {
        // Version 1 signatures typically sign a string message
        // *** FIX 3: Use CHash256 to get a uint256 from the string ***
        CHash256 hasher;
        std::string msg = GetStrMessage();
        // Hash the string message data
        hasher.Write((const unsigned char*)msg.data(), msg.size());
        uint256 hashResult;
        // Finalize into the uint256 object
        hasher.Finalize(hashResult.begin());
        return hashResult;
    }
}

// Get the string message used for Version 1 signatures
std::string CConsensusVote::GetStrMessage() const
{
     // Simple format: txhash followed by block height
     return txHash.ToString() + std::to_string(nBlockHeight);
}


// Sign the vote using the provided private key
bool CConsensusVote::Sign(std::string strPrivateKey, bool fNewSignatures) // Corresponds to fNewSigs in DoConsensusVote
{
    CKey key;
    CPubKey pubkey;

    // Use CMessageSigner utility to derive keys from the secret string
    if (!CMessageSigner::GetKeysFromSecret(strPrivateKey, key, pubkey)) {
        LogPrintf("%s: ERROR - Invalid masternode private key provided for signing.\n", __func__);
        return false;
    }

    // Set the message version based on the flag
    nMessVersion = fNewSignatures ? 2 : 1;

    // Sign the appropriate data based on the version
    if (nMessVersion == 2) {
        uint256 hashToSign = GetSignatureHash();
        if (!CHashSigner::SignHash(hashToSign, key, vchMasterNodeSignature)) {
            LogPrintf("%s: ERROR - Failed to sign hash (V2) for vote %s\n", __func__, GetHash().ToString());
            vchMasterNodeSignature.clear(); // Ensure signature is cleared on failure
            return false;
        }
    } else { // Version 1
        std::string messageToSign = GetStrMessage();
        if (!CMessageSigner::SignMessage(messageToSign, vchMasterNodeSignature, key)) {
            LogPrintf("%s: ERROR - Failed to sign message (V1) for vote %s\n", __func__, GetHash().ToString());
            vchMasterNodeSignature.clear(); // Ensure signature is cleared on failure
            return false;
        }
    }

    nTime = GetAdjustedTime(); // Record the time of signing
    LogPrint("swiftx", "%s: Successfully signed vote %s (Version %d)\n", __func__, GetHash().ToString(), nMessVersion);
    return true;
}


// Check the signature using the public key derived from the masternode list
bool CConsensusVote::CheckSignature() const
{
    CMasternode* pmn = mnodeman.Find(vinMasternode);
    if (pmn == NULL) {
        // Masternode not found locally, cannot verify signature without its public key
        // This is expected during sync or if the MN list is outdated. Don't log excessively.
        // LogPrint("swiftx", "%s: Masternode %s not found, cannot verify vote %s\n", __func__, vinMasternode.prevout.ToStringShort(), GetHash().ToString());
        return false;
    }
    // Call the overload that takes the public key
    return CheckSignature(pmn->pubKeyMasternode);
}

// Check the signature against a provided public key
bool CConsensusVote::CheckSignature(CPubKey& pubKeyMasternode) const
{
    if (!pubKeyMasternode.IsValid()) {
        LogPrintf("%s: ERROR - Invalid public key provided for verifying vote %s\n", __func__, GetHash().ToString());
        return false;
    }
    if (vchMasterNodeSignature.empty()) {
        LogPrint("swiftx", "%s: Vote %s has no signature.\n", __func__, GetHash().ToString());
        return false;
    }

    // *** FIX 4 & 5: Add dummy strError variable ***
    std::string strError;

    // Verify based on the message version stored in the vote
    if (nMessVersion == 2) {
        uint256 hashToVerify = GetSignatureHash();
        if (!CHashSigner::VerifyHash(hashToVerify, pubKeyMasternode, vchMasterNodeSignature, strError)) {
            // Failed verification is somewhat expected for invalid votes, log as debug/swiftx
             LogPrint("swiftx", "%s: Failed to verify hash (V2) for vote %s using pubkey %s. Error: %s\n", __func__,
                      GetHash().ToString(), pubKeyMasternode.GetID().ToString(), strError);
            return false;
        }
    } else { // Version 1
        std::string messageToVerify = GetStrMessage();
        if (!CMessageSigner::VerifyMessage(pubKeyMasternode.GetID(), vchMasterNodeSignature, messageToVerify, strError)) {
             // Failed verification is somewhat expected for invalid votes, log as debug/swiftx
             LogPrint("swiftx", "%s: Failed to verify message (V1) for vote %s using pubkey %s. Error: %s\n", __func__,
                      GetHash().ToString(), pubKeyMasternode.GetID().ToString(), strError);
            return false;
        }
    }

    // If verification passed
    return true;
}

// Relay the vote inventory to peers
bool CConsensusVote::Relay() const
{
    CInv inv(MSG_TXLOCK_VOTE, GetHash());
    RelayInv(inv);
    // LogPrint("swiftx", "Relayed vote inventory %s\n", inv.ToString());
    return true;
}


// --------- CTransactionLock Implementation ---------

// Check if all signatures in the lock are valid according to the masternode list and ranks
bool CTransactionLock::SignaturesValid()
{
     // Note: This checks *all* signatures, even if count < required.
     // It's mostly useful for sanity checks or debugging.
     // The core logic relies on ProcessConsensusVote checking individual votes as they arrive.
    for (const CConsensusVote& vote : vecConsensusVotes) {
        // Find the masternode
        CMasternode* pmn = mnodeman.Find(vote.vinMasternode);
        if (pmn == NULL) {
            LogPrintf("%s : Unknown Masternode %s found in transaction lock %s\n", __func__,
                      vote.vinMasternode.prevout.ToStringShort(), txHash.ToString());
            return false; // Cannot validate without MN data
        }

        // Check rank (ensure it matches the stored block height)
        int nRank = mnodeman.GetMasternodeRank(vote.vinMasternode, vote.nBlockHeight, MIN_SWIFTTX_PROTO_VERSION);
        if (nRank == -1 || nRank > SWIFTTX_SIGNATURES_TOTAL) {
             LogPrintf("%s : Masternode %s rank %d out of bounds for block height %d in lock %s\n", __func__,
                       vote.vinMasternode.prevout.ToStringShort(), nRank, vote.nBlockHeight, txHash.ToString());
            return false; // Invalid rank
        }

        // Check signature using the MN's public key
        if (!vote.CheckSignature(pmn->pubKeyMasternode)) {
             LogPrintf("%s : Invalid signature found for vote %s (MN %s) in lock %s\n", __func__,
                       vote.GetHash().ToString(), vote.vinMasternode.prevout.ToStringShort(), txHash.ToString());
            return false; // Invalid signature
        }
    }

    // All signatures checked (if any exist) are valid
    return true;
}

// Add a signature (vote) to the lock
// *** FIX 6: Remove const from parameter to match header ***
void CTransactionLock::AddSignature(CConsensusVote& cv)
{
    // Basic check to prevent duplicates, though ProcessConsensusVote should handle this too
    for (const CConsensusVote& existingVote : vecConsensusVotes) {
        if (existingVote.vinMasternode == cv.vinMasternode) {
            return; // Already have a vote from this masternode
        }
    }
    vecConsensusVotes.push_back(cv);
}

// Count the number of valid signatures that match the lock's target block height
// *** FIX 7: Remove const from function definition to match header ***
int CTransactionLock::CountSignatures()
{
    // SwiftTX requires votes to be for the specific block height calculated for the lock.
    if (nBlockHeight == 0) {
        // Block height not set yet (e.g., placeholder lock before 'ix' arrives)
        return 0;
    }

    int count = 0;
    for (const CConsensusVote& vote : vecConsensusVotes) {
        // Only count votes that match the authoritative block height of this lock
        if (vote.nBlockHeight == nBlockHeight) {
            count++;
        }
    }
    return count;
}

// uint256 CTransactionLock::GetHash() const is implicitly defined by returning txHash