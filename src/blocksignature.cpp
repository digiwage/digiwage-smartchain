// Copyright (c) 2017-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blocksignature.h"
#include "main.h"

bool SignBlockWithKey(CBlock& block, const CKey& key)
{
    if (!key.Sign(block.GetHash(), block.vchBlockSig))
        return error("%s: failed to sign block hash with key", __func__);

    return true;
}

bool GetKeyIDFromUTXO(const CTxOut& txout, CKeyID& keyID)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(txout.scriptPubKey, whichType, vSolutions))
        return false;
    if (whichType == TX_PUBKEY) {
        keyID = CPubKey(vSolutions[0]).GetID();
    } else if (whichType == TX_PUBKEYHASH || whichType == TX_COLDSTAKE) {
        keyID = CKeyID(uint160(vSolutions[0]));
    } else {
        return false;
    }

    return true;
}

bool SignBlock(CBlock& block, const CKeyStore& keystore)
{
    CKeyID keyID;
    if (block.IsProofOfWork()) {
        bool fFoundID = false;
        for (const CTxOut& txout :block.vtx[0].vout) {
            if (!GetKeyIDFromUTXO(txout, keyID))
                continue;
            fFoundID = true;
            break;
        }
        if (!fFoundID)
            return error("%s: failed to find key for PoW", __func__);
    } else {
        if (!GetKeyIDFromUTXO(block.vtx[1].vout[1], keyID))
            return error("%s: failed to find key for PoS", __func__);
    }

    CKey key;
    if (!keystore.GetKey(keyID, key))
        return error("%s: failed to get key from keystore", __func__);

    return SignBlockWithKey(block, key);
}

bool CheckBlockSignature(const CBlock& block)
{
    if (block.IsProofOfWork())
        return block.vchBlockSig.empty();

    if (block.vchBlockSig.empty())
        return error("%s: vchBlockSig is empty!", __func__);

    /** Each block is signed by the private key of the input that is staked.
     * The public key that signs must match the public key associated with the first utxo of the coinstake tx.
     */
    CPubKey pubkey;
    txnouttype whichType;
        std::vector<valtype> vSolutions;
        const CTxOut& txout = block.vtx[1].vout[1];
        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;
        if (whichType == TX_PUBKEY || whichType == TX_PUBKEYHASH) {
            valtype& vchPubKey = vSolutions[0];
            pubkey = CPubKey(vchPubKey);
        } else if (whichType == TX_COLDSTAKE) {
            // pick the public key from the P2CS input
            const CTxIn& txin = block.vtx[1].vin[0];
            int start = 1 + (int) *txin.scriptSig.begin(); // skip sig
            start += 1 + (int) *(txin.scriptSig.begin()+start); // skip flag
            pubkey = CPubKey(txin.scriptSig.begin()+start+1, txin.scriptSig.end());
        }

    if (!pubkey.IsValid())
        return error("%s: invalid pubkey %s", __func__, HexStr(pubkey));

    return pubkey.Verify(block.GetHash(), block.vchBlockSig);
}
