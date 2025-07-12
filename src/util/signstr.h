/**
 * Sign verify message utilities.
 */
 #ifndef UTIL_SIGNSTR_H
 #define UTIL_SIGNSTR_H
 
 #include <string>
 #include <vector>       // <<< Added include
 #include "key.h"
 #include "hash.h"       // <<< Added include for CHashWriter
 #include "pubkey.h"     // <<< Added include for CPubKey
 #include "keystore.h"   // <<< Added include for CKeyID
 
 namespace SignStr
 {
 // <<< Ensure strMessageMagic is defined globally or pass it in >>>
 // It's often defined in main.cpp or util.cpp
 extern const std::string strMessageMagic; // Declare it as extern
 
 inline bool SignMessage(const CKey& key, const std::string& strMessage, std::vector<unsigned char>& vchSig)
 {
     // === FIX: Use CHashWriter ===
     CHashWriter ss(SER_GETHASH, 0); // Initialize CHashWriter correctly
     // === END FIX ===
     ss << strMessageMagic;
     ss << strMessage;
 
     return key.SignCompact(ss.GetHash(), vchSig);
 }
 
 inline bool VerifyMessage(const CKeyID& keyID, const std::string& strMessage, const std::vector<unsigned char>& vchSig)
 {
     // === FIX: Use CHashWriter ===
     CHashWriter ss(SER_GETHASH, 0); // Initialize CHashWriter correctly
     // === END FIX ===
     ss << strMessageMagic;
     ss << strMessage;
 
     CPubKey pubkey;
     if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
         return false;
 
     return (pubkey.GetID() == keyID);
 }
 
 inline bool GetKeyIdMessage(const std::string& strMessage, const std::vector<unsigned char>& vchSig, CKeyID& keyID)
 {
     // === FIX: Use CHashWriter ===
     CHashWriter ss(SER_GETHASH, 0); // Initialize CHashWriter correctly
     // === END FIX ===
     ss << strMessageMagic;
     ss << strMessage;
 
     CPubKey pubkey;
     if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
         return false;
 
     keyID = pubkey.GetID();
     return true;
 }
 } // namespace SignStr
 
 #endif // UTIL_SIGNSTR_H