
// Copyright (c) 2017-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tx_verify.h"
#include "consensus/consensus.h"

#include "consensus/consensus.h"
#include "consensus/zerocoin_verify.h"
#include "main.h"
#include "script/interpreter.h"
#include "timedata.h" // For GetAdjustedTime()

bool IsFinalTx(const CTransaction& tx, int nBlockHeight, int64_t nBlockTime)
{
    AssertLockHeld(cs_main);
    // Time based nLockTime implemented in 0.1.6
    if (tx.nLockTime == 0)
        return true;
    if (nBlockHeight == 0)
        nBlockHeight = chainActive.Height();
    if (nBlockTime == 0)
        nBlockTime = GetAdjustedTime();
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const CTxIn& txin : tx.vin)
        if (!txin.IsFinal())
            return false;
    return true;
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const CTxIn& txin : tx.vin) {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const CTxOut& txout : tx.vout) {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase() || tx.HasZerocoinSpendInputs())
        // a tx containing a zc spend can have only zc inputs
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prevout = inputs.GetOutputFor(tx.vin[i]);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

bool CheckTransaction(const CTransaction& tx, bool fZerocoinActive, CValidationState& state, bool fColdStakingActive)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, error("CheckTransaction() : vin empty"),
            REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, error("CheckTransaction() : vout empty"),
            REJECT_INVALID, "bad-txns-vout-empty");

    // Size limits
    unsigned int nMaxSize = MAX_ZEROCOIN_TX_SIZE;

    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > nMaxSize)
        return state.DoS(100, error("CheckTransaction() : size limits failed"),
            REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    const Consensus::Params& consensus = Params().GetConsensus();
    CAmount nValueOut = 0;
    for (const CTxOut& txout : tx.vout) {
        if (txout.IsEmpty() && !tx.IsCoinBase() && !tx.IsCoinStake())
            return state.DoS(100, error("CheckTransaction(): txout empty for user transaction"));
        if (txout.nValue < 0)
            return state.DoS(100, error("CheckTransaction() : txout.nValue negative"),
                REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > consensus.nMaxMoneyOut)
            return state.DoS(100, error("CheckTransaction() : txout.nValue too high"),
                REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!consensus.MoneyRange(nValueOut))
            return state.DoS(100, error("CheckTransaction() : txout total out of range"),
                REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        // check cold staking enforcement (for delegations) and value out
        if (txout.scriptPubKey.IsPayToColdStaking()) {
            if (!fColdStakingActive)
                return state.DoS(10, error("%s: cold staking not active", __func__), REJECT_INVALID, "bad-txns-cold-stake");
            if (txout.nValue < MIN_COLDSTAKING_AMOUNT)
                return state.DoS(100, error("%s: dust amount (%d) not allowed for cold staking. Min amount: %d",
                        __func__, txout.nValue, MIN_COLDSTAKING_AMOUNT), REJECT_INVALID, "bad-txns-cold-stake");
        }
    }

    std::set<COutPoint> vInOutPoints;

    for (const CTxIn& txin : tx.vin) {
        // Check for duplicate inputs
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, error("CheckTransaction() : duplicate inputs"), REJECT_INVALID, "bad-txns-inputs-duplicate");

        // Ignore Zerocoin spends as they can share the same prevout if they came from the same mint TX
        if (!txin.IsZerocoinSpend())
            vInOutPoints.insert(txin.prevout);
    }

    if (tx.IsCoinBase()) {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 150)
            return state.DoS(100, error("CheckTransaction() : coinbase script size=%d", tx.vin[0].scriptSig.size()),
                REJECT_INVALID, "bad-cb-length");
    } else {
        for (const CTxIn& txin : tx.vin)
            if (txin.prevout.IsNull() && (fZerocoinActive && !txin.IsZerocoinSpend()))
                return state.DoS(10, error("CheckTransaction() : prevout is null"),
                    REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}
