// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include "key.h"
#include "pubkey.h"
#include "sync.h"
#include "wallet/hdchain.h"

#include <boost/signals2/signal.hpp>

class CScript;
class CScriptID;

/** A virtual base class for key stores */
class CKeyStore
{

public:
    // todo: Make it protected again once we are more advanced in the wallet/spkm decoupling.
    mutable RecursiveMutex cs_KeyStore;

    virtual ~CKeyStore() {}

    //! Add a key to the store.
    virtual bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey) = 0;
    virtual bool AddKey(const CKey& key);

    //! Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID& address) const = 0;
    virtual bool GetKey(const CKeyID& address, CKey& keyOut) const = 0;
    virtual void GetKeys(std::set<CKeyID>& setAddress) const = 0;
    virtual bool GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const;

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript& redeemScript) = 0;
    virtual bool HaveCScript(const CScriptID& hash) const = 0;
    virtual bool GetCScript(const CScriptID& hash, CScript& redeemScriptOut) const = 0;

    //! Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript& dest) = 0;
    virtual bool RemoveWatchOnly(const CScript& dest) = 0;
    virtual bool HaveWatchOnly(const CScript& dest) const = 0;
    virtual bool HaveWatchOnly() const = 0;

    //! Support for MultiSig addresses
    virtual bool AddMultiSig(const CScript& dest) = 0;
    virtual bool RemoveMultiSig(const CScript& dest) = 0;
    virtual bool HaveMultiSig(const CScript& dest) const = 0;
    virtual bool HaveMultiSig() const = 0;
};

typedef std::map<CKeyID, CKey> KeyMap;
typedef std::map<CScriptID, CScript> ScriptMap;
typedef std::set<CScript> WatchOnlySet;
typedef std::set<CScript> MultiSigScriptSet;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;
    ScriptMap mapScripts;
    WatchOnlySet setWatchOnly;
    CHDChain hdChain; /* the HD chain data model*/
    MultiSigScriptSet setMultiSig;

public:
    bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey);
    bool HaveKey(const CKeyID& address) const;
    void GetKeys(std::set<CKeyID>& setAddress) const;
    bool GetKey(const CKeyID& address, CKey& keyOut) const;

    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID& hash) const;
    virtual bool GetCScript(const CScriptID& hash, CScript& redeemScriptOut) const;

    virtual bool AddWatchOnly(const CScript& dest);
    virtual bool RemoveWatchOnly(const CScript& dest);
    virtual bool HaveWatchOnly(const CScript& dest) const;
    virtual bool HaveWatchOnly() const;
    bool GetHDChain(CHDChain& hdChainRet) const;

    virtual bool AddMultiSig(const CScript& dest);
    virtual bool RemoveMultiSig(const CScript& dest);
    virtual bool HaveMultiSig(const CScript& dest) const;
    virtual bool HaveMultiSig() const;
};

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;

/** Checks if a CKey is in the given CKeyStore compressed or otherwise*/
bool HaveKey(const CKeyStore& store, const CKey& key);

#endif // BITCOIN_KEYSTORE_H
