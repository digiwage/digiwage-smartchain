// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"

#include "crypter.h"
#include "key.h"
#include "script/script.h"
#include "script/standard.h"
#include "util.h"


bool CKeyStore::GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key))
        return false;
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CKeyStore::AddKey(const CKey& key)
{
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey& pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript() : redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID& hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end()) {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

bool CBasicKeyStore::AddWatchOnly(const CScript& dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript& dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript& dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

bool CBasicKeyStore::GetHDChain(CHDChain& hdChainRet) const
{
    hdChainRet = hdChain;
    return !hdChain.IsNull();
}

bool CBasicKeyStore::AddMultiSig(const CScript& dest)
{
    LOCK(cs_KeyStore);
    setMultiSig.insert(dest);
    return true;
}

bool CBasicKeyStore::RemoveMultiSig(const CScript& dest)
{
    LOCK(cs_KeyStore);
    setMultiSig.erase(dest);
    return true;
}

bool CBasicKeyStore::HaveMultiSig(const CScript& dest) const
{
    LOCK(cs_KeyStore);
    return setMultiSig.count(dest) > 0;
}

bool CBasicKeyStore::HaveMultiSig() const
{
    LOCK(cs_KeyStore);
    return (!setMultiSig.empty());
}

bool CBasicKeyStore::HaveKey(const CKeyID& address) const
{
    bool result;
    {
        LOCK(cs_KeyStore);
        result = (mapKeys.count(address) > 0);
    }
    return result;
}

void CBasicKeyStore::GetKeys(std::set<CKeyID>& setAddress) const
{
    setAddress.clear();
    {
        LOCK(cs_KeyStore);
        KeyMap::const_iterator mi = mapKeys.begin();
        while (mi != mapKeys.end()) {
            setAddress.insert((*mi).first);
            mi++;
        }
    }
}

bool CBasicKeyStore::GetKey(const CKeyID& address, CKey& keyOut) const
{
    {
        LOCK(cs_KeyStore);
        KeyMap::const_iterator mi = mapKeys.find(address);
        if (mi != mapKeys.end()) {
            keyOut = mi->second;
            return true;
        }
    }
    return false;
}

bool HaveKey(const CKeyStore& store, const CKey& key)
{
    CKey key2;
    key2.Set(key.begin(), key.end(), !key.IsCompressed());
    return store.HaveKey(key.GetPubKey().GetID()) || store.HaveKey(key2.GetPubKey().GetID());
}