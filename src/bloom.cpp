// Copyright (c) 2012-2014 The Bitcoin developers
// Copyright (c) 2017-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bloom.h"


#include "chainparams.h"
#include "hash.h"
#include "libzerocoin/bignum.h"
#include "libzerocoin/CoinSpend.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "streams.h"

#include <math.h>
#include <stdlib.h>


#define LN2SQUARED 0.4804530139182014246671025263266649717305529515945455
#define LN2 0.6931471805599453094172321214581765680755001343602552


CBloomFilter::CBloomFilter(unsigned int nElements, double nFPRate, unsigned int nTweakIn, unsigned char nFlagsIn) :
 /**
 * The ideal size for a bloom filter with a given number of elements and false positive rate is:
 * - nElements * log(fp rate) / ln(2)^2
 * We ignore filter parameters which will create a bloom filter larger than the protocol limits
 */
    vData(std::min((unsigned int)(-1 / LN2SQUARED * nElements * log(nFPRate)), MAX_BLOOM_FILTER_SIZE * 8) / 8),
 /**
 * The ideal number of hash functions is filter size * ln(2) / number of elements
 * Again, we ignore filter parameters which will create a bloom filter with more hash functions than the protocol limits
 * See https://en.wikipedia.org/wiki/Bloom_filter for an explanation of these formulas
 */
    isFull(false),
    isEmpty(false),
  nHashFuncs(std::min((unsigned int)(vData.size() * 8 / nElements * LN2), MAX_HASH_FUNCS)),
  nTweak(nTweakIn),
  nFlags(nFlagsIn)
{
}

inline unsigned int CBloomFilter::Hash(unsigned int nHashNum, const std::vector<unsigned char>& vDataToHash) const
{
    // 0xFBA4C795 chosen as it guarantees a reasonable bit difference between nHashNum values.
    return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8);
}

void CBloomFilter::setNotFull()
{
    isFull = false;
}

void CBloomFilter::insert(const std::vector<unsigned char>& vKey)
{
    if (isFull)
        return;
    for (unsigned int i = 0; i < nHashFuncs; i++) {
        unsigned int nIndex = Hash(i, vKey);
        // Sets bit nIndex of vData
        vData[nIndex >> 3] |= (1 << (7 & nIndex));
    }
    isEmpty = false;
}

void CBloomFilter::insert(const COutPoint& outpoint)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << outpoint;
    std::vector<unsigned char> data(stream.begin(), stream.end());
    insert(data);
}

void CBloomFilter::insert(const uint256& hash)
{
    std::vector<unsigned char> data(hash.begin(), hash.end());
    insert(data);
}

bool CBloomFilter::contains(const std::vector<unsigned char>& vKey) const
{
    if (isFull) {
        return true;
    }
    if (isEmpty) {
        return false;
    }
    for (unsigned int i = 0; i < nHashFuncs; i++) {
        unsigned int nIndex = Hash(i, vKey);
        // Checks bit nIndex of vData
        if (!(vData[nIndex >> 3] & (1 << (7 & nIndex))))
            return false;
    }
    return true;
}

bool CBloomFilter::contains(const COutPoint& outpoint) const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << outpoint;
    std::vector<unsigned char> data(stream.begin(), stream.end());
    return contains(data);
}

bool CBloomFilter::contains(const uint256& hash) const
{
    std::vector<unsigned char> data(hash.begin(), hash.end());
    return contains(data);
}

void CBloomFilter::clear()
{
    vData.assign(vData.size(), 0);
    isFull = false;
    isEmpty = true;
}

bool CBloomFilter::IsWithinSizeConstraints() const
{
    return vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS;
}

/**
 * Returns true if this filter will match anything. See {@link org.digiwagej.core.BloomFilter#setMatchAll()}
 * for when this can be a useful thing to do.
 */
bool CBloomFilter::MatchesAll() const {
    for (unsigned char b : vData)
        if (b !=  0xff)
            return false;
    return true;
}

/**
 * Copies filter into this. Filter must have the same size, hash function count and nTweak or an
 * IllegalArgumentException will be thrown.
 */
bool CBloomFilter::Merge(const CBloomFilter& filter) {
    if (!this->MatchesAll() && !filter.MatchesAll()) {
        if(! (filter.vData.size() == this->vData.size() &&
                filter.nHashFuncs == this->nHashFuncs &&
                filter.nTweak == this->nTweak)){
            return false;
        }
        for (unsigned int i = 0; i < vData.size(); i++)
            this->vData[i] |= filter.vData[i];
    } else {
        // TODO: Check this.
        this->vData.clear();
        this->vData[0] = 0xff;
    }
    return true;
}

bool CBloomFilter::IsRelevantAndUpdate(const CTransaction& tx)
{
    bool fFound = false;
    // Match if the filter contains the hash of tx
    //  for finding tx when they appear in a block
    if (isFull)
        return true;
    if (isEmpty)
        return false;
    const uint256& hash = tx.GetHash();
    if (contains(hash))
        fFound = true;

    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        // Match if the filter contains any arbitrary script data element in any scriptPubKey in tx
        // If this matches, also add the specific output that was matched.
        // This means clients don't have to update the filter themselves when a new relevant tx
        // is discovered in order to find spending transactions, which avoids round-tripping and race conditions.
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        std::vector<unsigned char> data;
        while (pc < txout.scriptPubKey.end()) {
            opcodetype opcode;
            if (!txout.scriptPubKey.GetOp(pc, opcode, data)){
                break;
            }

            if (txout.IsZerocoinMint()){
                data = std::vector<unsigned char>(txout.scriptPubKey.begin() + 6, txout.scriptPubKey.begin() + txout.scriptPubKey.size());
            }

            if (data.size() != 0 && contains(data)) {
                fFound = true;
                if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
                    insert(COutPoint(hash, i));
                else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY) {
                    txnouttype type;
                    std::vector<std::vector<unsigned char> > vSolutions;
                    if (Solver(txout.scriptPubKey, type, vSolutions) &&
                        (type == TX_PUBKEY || type == TX_MULTISIG))
                        insert(COutPoint(hash, i));
                }
                break;
            }
        }
    }

    if (fFound)
        return true;

    for (const CTxIn& txin : tx.vin) {
        // Match if the filter contains an outpoint tx spends
        if (contains(txin.prevout))
            return true;

        // Match if the filter contains any arbitrary script data element in any scriptSig in tx
        CScript::const_iterator pc = txin.scriptSig.begin();
        std::vector<unsigned char> data;
        while (pc < txin.scriptSig.end()) {
            opcodetype opcode;
            if (!txin.scriptSig.GetOp(pc, opcode, data))
                break;
            if (txin.IsZerocoinSpend()) {
                CDataStream s(std::vector<unsigned char>(txin.scriptSig.begin() + 44, txin.scriptSig.end()),
                        SER_NETWORK, PROTOCOL_VERSION);

                data = libzerocoin::CoinSpend::ParseSerial(s);
            }
            if (data.size() != 0 && contains(data)) {
                return true;
            }
        }
    }

    return false;
}

void CBloomFilter::UpdateEmptyFull()
{
    bool full = true;
    bool empty = true;
    for (unsigned int i = 0; i < vData.size(); i++) {
        full &= vData[i] == 0xff;
        empty &= vData[i] == 0;
    }
    isFull = full;
    isEmpty = empty;
}
