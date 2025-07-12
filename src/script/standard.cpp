// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2024 The DIGIWAGE developers // Updated Copyright Year
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/standard.h"

#include "pubkey.h"
#include "script/script.h" // CScript methods like IsPayToScriptHash, IsZerocoinMint etc. are here
#include "util.h"
#include "utilstrencodings.h"
#include "streams.h"      // For DataStream (used in ported ExtractSenderData from Qtum if not already included)
#include "chainparams.h"  // For Params() -> GetConsensus() -> Contract related constants
#include "consensus/params.h" // For specific consensus parameters
#include "script/interpreter.h" // For IsPushdataOp if needed, CScriptNum

// For VersionVM (you need to port or define this from Qtum)
// Example: #include "qtum/qtumtransaction.h" or a local "versionvm.h"
// For now, we'll assume a placeholder VersionVM struct/class exists.
// You MUST provide a real implementation for VersionVM.
// Placeholder for VersionVM struct (MUST BE REPLACED WITH ACTUAL IMPLEMENTATION)
struct VersionVM {
    uint32_t vmVersion = 0;
    uint32_t flagOptions = 0;
    uint32_t rootVM = 0;

    static VersionVM GetEVMDefault() {
        VersionVM version;
        // ***** MODIFICATION 1 START *****
        // Define that DigiWage's standard EVM transaction uses vmVersion 4 and rootVM 2
        version.vmVersion = 4;   // Standard vmVersion for EVM as per transaction log
        version.flagOptions = 0; // Default flags
        version.rootVM = 2;    // Standard EVM rootVM identifier (e.g., from Qtum)
        // ***** MODIFICATION 1 END *****
        return version;
    }
    static VersionVM GetNoExec() {
        VersionVM version;
        version.rootVM = 0; // No execution
        // vmVersion and flagOptions default to 0
        return version;
    }
    uint32_t toRaw() const {
        return vmVersion | (flagOptions << 8) | (rootVM << 16) ;
    }
    static VersionVM fromRaw(uint32_t raw) {
        VersionVM version;
        version.vmVersion = raw & 0xFF;
        version.flagOptions = (raw >> 8) & 0xFF;
        version.rootVM = (raw >> 16) & 0xFF;
        return version;
    }
};
// End Placeholder VersionVM


#include <typeinfo>
#include <vector>
#include <map>

typedef std::vector<unsigned char> valtype;

// --- Global Variable Definitions ---
unsigned int nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

// --- Class Method Definitions ---
CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

// --- Helper function: IsSmallInteger ---
#ifndef HAVE_ISSMALLINTEGER
#define HAVE_ISSMALLINTEGER
bool IsSmallInteger(opcodetype opcode)
{
    return opcode == OP_0 || (opcode >= OP_1 && opcode <= OP_16);
}
#endif


// --- Ported `MatchContract` function from Qtum's solver.cpp ---
// Adapted for DigiWage.
static bool MatchContract(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet,
                          bool contractConsensus, bool allowEmptySenderSig, txnouttype& typeRet)
{
    static std::multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // These templates use the symbolic opcodes defined in script.h (OP_VERSION, OP_GAS_LIMIT, etc.)
        mTemplates.insert(std::make_pair(TX_CONTRACT_SENDER_CREATE, CScript() << OP_ADDRESS_TYPE << OP_ADDRESS << OP_SCRIPT_SIG << OP_SENDER << OP_VERSION << OP_GAS_LIMIT << OP_GAS_PRICE << OP_DATA << OP_CREATE));
        mTemplates.insert(std::make_pair(TX_CONTRACT_SENDER_CALL, CScript() << OP_ADDRESS_TYPE << OP_ADDRESS << OP_SCRIPT_SIG << OP_SENDER << OP_VERSION << OP_GAS_LIMIT << OP_GAS_PRICE << OP_DATA << OP_PUBKEYHASH << OP_CALL));
        mTemplates.insert(std::make_pair(TX_CONTRACT_CREATE, CScript() << OP_VERSION << OP_GAS_LIMIT << OP_GAS_PRICE << OP_DATA << OP_CREATE));
        mTemplates.insert(std::make_pair(TX_CONTRACT_CALL, CScript() << OP_VERSION << OP_GAS_LIMIT << OP_GAS_PRICE << OP_DATA << OP_PUBKEYHASH << OP_CALL));
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;

    for (const auto& tplatePair : mTemplates) // Renamed tplate to tplatePair for clarity
    {
        const txnouttype currentTemplateType = tplatePair.first; // Use your enum
        const CScript& scriptTemplate = tplatePair.second;

        CScript::const_iterator pcScript = scriptPubKey.begin();
        CScript::const_iterator pcTemplate = scriptTemplate.begin();
        opcodetype opcodeScript, opcodeTemplateValue; // Renamed opcodeTemplate to avoid conflict
        valtype vchScript, vchTemplate;

        uint64_t parsedAddressType = 0;
        VersionVM parsedVersion;
        // parsedVersion.rootVM = 20; // Invalid default (no longer needed with new parsing logic)

        std::vector<valtype> currentSolutions;

        while (true)
        {
            bool scriptHasOp = scriptPubKey.GetOp(pcScript, opcodeScript, vchScript);
            bool templateHasOp = scriptTemplate.GetOp(pcTemplate, opcodeTemplateValue, vchTemplate);

            if (!scriptHasOp && !templateHasOp)
            {
                typeRet = currentTemplateType;
                vSolutionsRet = currentSolutions;
                return true;
            }
            if (scriptHasOp != templateHasOp) break;

            switch (opcodeTemplateValue) // Use opcodeTemplateValue from the template script
            {
                case OP_PUBKEY: // From template
                    if (!CPubKey::ValidSize(vchScript)) goto next_template_loop; // Check CPubKey::ValidSize exists
                    currentSolutions.push_back(vchScript);
                    break;
                case OP_PUBKEYHASH: // From template (also used for contract address in OP_CALL template)
                    if (vchScript.size() != sizeof(uint160)) goto next_template_loop;
                    currentSolutions.push_back(vchScript);
                    break;
                case OP_SMALLINTEGER: // From template
                    if (!IsSmallInteger(opcodeScript)) goto next_template_loop;
                    currentSolutions.push_back(valtype(1, (unsigned char)CScript::DecodeOP_N(opcodeScript)));
                    break;
                case OP_VERSION: // From template
                    if (!(opcodeScript <= OP_PUSHDATA4) || vchScript.empty() || vchScript.size() > 4 || (vchScript.back() & 0x80))
                        goto next_template_loop;
                    try {
                        uint64_t val_from_script = CScriptNum::vch_to_uint64(vchScript, true);

                        // ***** MODIFICATION 2 START *****
                        // If the value from script is small (like 4, from OP_PUSHBYTES_1 0x04),
                        // assume it's primarily the vmVersion component.
                        // Construct the full VersionVM with default EVM rootVM and flagOptions.
                        if (val_from_script == 4 && vchScript.size() == 1) {
                            parsedVersion.vmVersion = (uint32_t)val_from_script;
                            parsedVersion.flagOptions = 0; // Default for standard EVM
                            parsedVersion.rootVM = 2;      // Default EVM root (same as GetEVMDefault().rootVM)
                        } else {
                            // Otherwise, assume val_from_script is the full raw encoded VersionVM
                            // (e.g., from a more complex client or a future version scheme)
                            parsedVersion = VersionVM::fromRaw((uint32_t)val_from_script);
                        }
                        // ***** MODIFICATION 2 END *****

                    } catch (const scriptnum_error&) { goto next_template_loop; }

                    // Check if the parsed version matches either the standard EVM default or the NoExec version.
                    // With Modification 1 & 2:
                    // - If script pushes '4' (as {0x04}):
                    //   parsedVersion becomes {vmVersion=4, flagOptions=0, rootVM=2}. toRaw() -> 0x020004
                    // - GetEVMDefault() now also returns {vmVersion=4, flagOptions=0, rootVM=2}. toRaw() -> 0x020004
                    // - So, parsedVersion.toRaw() == GetEVMDefault().toRaw() will be true.
                    if(!(parsedVersion.toRaw() == VersionVM::GetEVMDefault().toRaw() || parsedVersion.toRaw() == VersionVM::GetNoExec().toRaw())){
                         goto next_template_loop;
                    }
                    break;
                case OP_GAS_LIMIT: // From template
                case OP_GAS_PRICE: // From template
                    if (!(opcodeScript <= OP_PUSHDATA4)) goto next_template_loop;
                    try {
                        uint64_t val = CScriptNum::vch_to_uint64(vchScript, true);
                        // --- DIGIWAGE: YOU MUST ADAPT THESE CONSTANT CHECKS ---
                        // Ensure parsedVersion.rootVM is correctly set by the OP_VERSION case above
                        // if these checks are to be applied. With the fix, it should be 2 for EVM.
                        if (parsedVersion.rootVM != 0) { // This check now relies on OP_VERSION correctly setting rootVM
                            const Consensus::Params& consensus = Params().GetConsensus();
                            // If you enable these, ensure your consensus params are set correctly.
                            // For example, with GasLimit = 2500000 and GasPrice = 40:
                            if(contractConsensus){
                                // Example: if (val < consensus.nMinConsensusGasLimitContract && opcodeTemplateValue == OP_GAS_LIMIT) goto next_template_loop;
                                // Example: if (val < consensus.nMinConsensusGasPriceContract && opcodeTemplateValue == OP_GAS_PRICE) goto next_template_loop;
                                // Example: if (val > consensus.nMaxBlockGasLimitContract && opcodeTemplateValue == OP_GAS_LIMIT) goto next_template_loop;
                            } else { // Mempool policy
                                // Example: if (val < consensus.nStandardMinGasLimitContract && opcodeTemplateValue == OP_GAS_LIMIT) goto next_template_loop;
                                // Example: if (val < consensus.nStandardMinGasPriceContract && opcodeTemplateValue == OP_GAS_PRICE) goto next_template_loop;
                                // Example: if (val > consensus.nDefaultBlockGasLimitContract / 2 && opcodeTemplateValue == OP_GAS_LIMIT) goto next_template_loop;
                            }
                        }
                        // --- END ADAPTATION ---
                    } catch (const scriptnum_error&) { goto next_template_loop; }
                    break;
                case OP_DATA: // From template (Bytecode for CREATE, data for CALL)
                    if (!(opcodeScript <= OP_PUSHDATA4)) goto next_template_loop;
                    // if (vchScript.empty() && opcodeTemplateValue == OP_DATA && currentTemplateType == TX_CONTRACT_CALL) goto next_template_loop;
                    break;
                case OP_ADDRESS_TYPE: // From template (For OP_SENDER)
                    if (!(opcodeScript <= OP_PUSHDATA4)) goto next_template_loop;
                    try {
                        parsedAddressType = CScriptNum::vch_to_uint64(vchScript, true);
                        // DIGIWAGE: Implement addresstype enum and validation if needed.
                        // Example: if(parsedAddressType != YOUR_P2PKH_TYPE_ENUM) goto next_template_loop;
                    } catch (const scriptnum_error&) { goto next_template_loop; }
                    break;
                case OP_ADDRESS: // From template (For OP_SENDER)
                    if (!(opcodeScript <= OP_PUSHDATA4)) goto next_template_loop;
                    // DIGIWAGE: Validate vchScript size based on parsedAddressType
                    // if (parsedAddressType == YOUR_P2PKH_TYPE_ENUM && vchScript.size() != sizeof(CKeyID)) goto next_template_loop;
                    if (vchScript.size() != sizeof(uint160)) goto next_template_loop; // Assuming P2PKH for now
                    // CScript senderPKScript = GetScriptForDestination(CKeyID(uint160(vchScript))); // If using CTxDestination
                    // currentSolutions.push_back(std::vector<unsigned char>(senderPKScript.begin(), senderPKScript.end()));
                    break;
                case OP_SCRIPT_SIG: // From template (For OP_SENDER)
                    if (!(opcodeScript <= OP_PUSHDATA4)) goto next_template_loop;
                    if (!allowEmptySenderSig && vchScript.empty()) goto next_template_loop;
                    if (vchScript.size() > MAX_SCRIPT_SIZE) goto next_template_loop;
                    currentSolutions.push_back(vchScript);
                    break;
                default: // All other opcodes from template must match exactly in scriptPubKey
                    if (opcodeScript != opcodeTemplateValue || vchScript != vchTemplate)
                        goto next_template_loop;
                    break;
            }
        }
        next_template_loop:;
    }
    return false;
}


const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_COLDSTAKE: return "coldstake";
    case TX_NULL_DATA: return "nulldata";
    case TX_ZEROCOINMINT: return "zerocoinmint";
    case TX_CONTRACT_CREATE: return "contract_create";
    case TX_CONTRACT_CALL: return "contract_call";
    case TX_CONTRACT_SENDER_CREATE: return "contract_sender_create";
    case TX_CONTRACT_SENDER_CALL: return "contract_sender_call";
    }
    return nullptr;
}

bool IsValidDestination(const CTxDestination& dest)
{
    return dest.type() != typeid(CNoDestination);
}

bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    vSolutionsRet.clear();

    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        if (scriptPubKey.size() != 23 || scriptPubKey[0] != OP_HASH160 || scriptPubKey[1] != 0x14 || scriptPubKey[22] != OP_EQUAL)
            return false;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    if (scriptPubKey.IsZerocoinMint()) {
        typeRet = TX_ZEROCOINMINT;
        CScript::const_iterator pc = scriptPubKey.begin();
        opcodetype opcode;
        valtype vch;
        if (!scriptPubKey.GetOp(pc, opcode, vch) || opcode != OP_ZEROCOINMINT)
            return false;
        return true;
    }

    if (scriptPubKey.IsPayToColdStaking())
    {
        typeRet = TX_COLDSTAKE;
        if (scriptPubKey.size() != 51 ||
            scriptPubKey[0] != OP_DUP || scriptPubKey[1] != OP_HASH160 || scriptPubKey[2] != OP_ROT ||
            scriptPubKey[3] != OP_IF || scriptPubKey[4] != OP_CHECKCOLDSTAKEVERIFY || scriptPubKey[5] != 0x14 ||
            scriptPubKey[26] != OP_ELSE || scriptPubKey[27] != 0x14 ||
            scriptPubKey[48] != OP_ENDIF || scriptPubKey[49] != OP_EQUALVERIFY || scriptPubKey[50] != OP_CHECKSIG)
        {
            return false;
        }
        std::vector<unsigned char> spendingHashBytes(scriptPubKey.begin()+28, scriptPubKey.begin()+48);
        std::vector<unsigned char> stakingHashBytes(scriptPubKey.begin()+6, scriptPubKey.begin()+26);
        vSolutionsRet.push_back(spendingHashBytes);
        vSolutionsRet.push_back(stakingHashBytes);
        return true;
    }

    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_NULL_DATA;
        return true;
    }

    if (scriptPubKey.IsPayToPublicKey()) { // Assumes CPubKey::ValidSize is fixed in pubkey.h
        typeRet = TX_PUBKEY;
        CScript::const_iterator pc = scriptPubKey.begin();
        opcodetype opcode;
        valtype vch;
        scriptPubKey.GetOp(pc, opcode, vch);
        vSolutionsRet.push_back(vch);
        return true;
    }
    if (scriptPubKey.IsPayToPublicKeyHash()) {
        typeRet = TX_PUBKEYHASH;
        if (scriptPubKey.size() != 25 || scriptPubKey[0] != OP_DUP || scriptPubKey[1] != OP_HASH160 ||
            scriptPubKey[2] != 0x14 || scriptPubKey[23] != OP_EQUALVERIFY || scriptPubKey[24] != OP_CHECKSIG) {
            return false;
        }
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+3, scriptPubKey.begin()+23);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    txnouttype contractMatchedType = TX_NONSTANDARD;
    if (MatchContract(scriptPubKey, vSolutionsRet, /*contractConsensus=*/false, /*allowEmptySenderSig=*/true, contractMatchedType))
    {
        typeRet = contractMatchedType;
        return true;
    }

    CScript::const_iterator pc = scriptPubKey.begin();
    opcodetype opcode;
    valtype data;
    int m = 0;
    std::vector<valtype> keys;
    int n = 0;

    if (!scriptPubKey.GetOp(pc, opcode, data) || !IsSmallInteger(opcode))
        goto nonstandard_solver_fallback_label; // Changed label name
    m = CScript::DecodeOP_N(opcode);
    if (m < 1) goto nonstandard_solver_fallback_label;

    while (true) {
        if (!scriptPubKey.GetOp(pc, opcode, data)) goto nonstandard_solver_fallback_label;
        if (IsSmallInteger(opcode)) break;
        if (opcode < OP_1 || opcode > OP_PUSHDATA4 || data.empty()) goto nonstandard_solver_fallback_label;
        if (data.size() != 33 && data.size() != 65) goto nonstandard_solver_fallback_label;
        keys.push_back(data);
    }
    n = CScript::DecodeOP_N(opcode);
    if (n < m || (int)keys.size() != n) goto nonstandard_solver_fallback_label;
    if (!scriptPubKey.GetOp(pc, opcode, data) || opcode != OP_CHECKMULTISIG || pc != scriptPubKey.end()) {
        goto nonstandard_solver_fallback_label;
    }
    typeRet = TX_MULTISIG;
    vSolutionsRet.push_back(valtype(1, (unsigned char)m));
    for(const auto& key_item : keys) {
        vSolutionsRet.push_back(key_item);
    }
    vSolutionsRet.push_back(valtype(1, (unsigned char)n));
    return true;

nonstandard_solver_fallback_label: // Renamed label
    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}


int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions)
{
    switch (t)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
    case TX_ZEROCOINMINT:
        return -1;
    case TX_PUBKEY:
        return 1;
    case TX_PUBKEYHASH:
        return 2;
    case TX_COLDSTAKE:
        return 3;
    case TX_MULTISIG:
        if (vSolutions.empty() || vSolutions.front().empty())
            return -1;
        return vSolutions.front()[0] + 1;
    case TX_SCRIPTHASH:
        return 1;
    case TX_CONTRACT_CREATE:
    case TX_CONTRACT_CALL:
    case TX_CONTRACT_SENDER_CREATE:
    case TX_CONTRACT_SENDER_CALL:
        return 0;
    }
    return -1;
}

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType)
{
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_CONTRACT_CREATE || whichType == TX_CONTRACT_CALL ||
        whichType == TX_CONTRACT_SENDER_CREATE || whichType == TX_CONTRACT_SENDER_CALL) {
        return true;
    }

    if (whichType == TX_MULTISIG)
    {
        if (vSolutions.empty() || vSolutions.front().empty() || vSolutions.back().empty()) return false;
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        if (n < 1 || n > 3) return false;
        if (m < 1 || m > n) return false;
        if (vSolutions.size() != (size_t)n + 2) return false;
    } else if (whichType == TX_NULL_DATA) {
         if (scriptPubKey.size() > 1) {
             CScript::const_iterator pc = scriptPubKey.begin();
             opcodetype opcode;
             valtype data;
             scriptPubKey.GetOp(pc, opcode, data); // Get OP_RETURN
             if (pc < scriptPubKey.end()) { // Check if there's data after OP_RETURN
                 scriptPubKey.GetOp(pc, opcode, data); // Get the PUSHDATA
                 // The actual data pushed is in 'data'. Check its size.
                 // If there are multiple pushes, this logic might need adjustment,
                 // but typically OP_RETURN is OP_RETURN <optional_pushdata>.
                 if (data.size() > nMaxDatacarrierBytes) return false;
             }
         }
    }
    return whichType != TX_NONSTANDARD;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet, bool fColdStake)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY) {
        if (vSolutions.empty() || vSolutions[0].empty()) return false;
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid()) return false;
        addressRet = pubKey.GetID();
        return true;
    } else if (whichType == TX_PUBKEYHASH) {
        if (vSolutions.empty() || vSolutions[0].size() != 20) return false;
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    } else if (whichType == TX_SCRIPTHASH) {
         if (vSolutions.empty() || vSolutions[0].size() != 20) return false;
        addressRet = CScriptID(uint160(vSolutions[0])); // This was CScriptID(CScript(vSolutions[0])); fixed to CScriptID(uint160(vSolutions[0])) assuming vSolutions[0] is the hash.
        return true;
    } else if (whichType == TX_COLDSTAKE) {
        if (vSolutions.size() < 2 || vSolutions[0].size() != 20 || vSolutions[1].size() != 20) return false;
        addressRet = CKeyID(uint160(vSolutions[fColdStake ? 1 : 0]));
        return true;
    }
    return false;
}

bool ExtractSenderData(const CScript& outputPubKey, CScript* senderPubKey, CScript* senderSig)
{
    if (!outputPubKey.HasOpSender()) {
        return false;
    }
    // For a full implementation, this function would typically rely on vSolutions
    // populated by a more detailed MatchContract or a dedicated sender script parser.
    // The simplified MatchContract above doesn't fully populate vSolutions for sender scripts yet.
    // This is a placeholder and will likely need to be expanded based on how MatchContract
    // is fully ported or how sender data is extracted from vSolutions.
    LogPrint("script", "ExtractSenderData: Full parsing for OP_SENDER data needs a robust MatchContract to populate vSolutions or direct detailed parsing.\n");
    // Placeholder: Attempt to parse based on the known template structure if vSolutions is not used/populated for this.
    // Example for TX_CONTRACT_SENDER_CALL: << OP_ADDRESS_TYPE << OP_ADDRESS << OP_SCRIPT_SIG << OP_SENDER << ...
    // This would involve iterating through outputPubKey to find the pushes before OP_SENDER.
    // This function is complex to implement correctly without the full context of how sender scripts are built and parsed.
    // For now, returning false as per the placeholder.
    return false; // Placeholder until MatchContract robustly provides solutions for sender scripts or direct parsing is implemented
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    nRequiredRet = 0;
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, typeRet, vSolutions))
        return false;

    if (typeRet == TX_NULL_DATA || typeRet == TX_ZEROCOINMINT){
        return false;
    }
    if (typeRet == TX_CONTRACT_CREATE || typeRet == TX_CONTRACT_CALL ||
        typeRet == TX_CONTRACT_SENDER_CREATE || typeRet == TX_CONTRACT_SENDER_CALL) {
        // For contract calls, the destination is the contract address,
        // which is part of vSolutions if MatchContract populates it.
        // For creates, there isn't a pre-existing destination in the same way.
        // Qtum's ExtractDestinations often returns false for contract types or extracts the contract address.
        // Let's try to extract contract address for call types if available in vSolutions.
        if (typeRet == TX_CONTRACT_CALL || typeRet == TX_CONTRACT_SENDER_CALL) {
            // Assuming the contract address (hash160) is the Nth element in vSolutions
            // for OP_CALL templates (e.g., after version, gaslimit, gasprice, data).
            // This depends on how MatchContract populates vSolutions.
            // The current MatchContract pushes OP_PUBKEYHASH (contract addr) for OP_CALL templates.
            // For TX_CONTRACT_SENDER_CALL, elements are: sender_script_sig, version_vch, gas_limit_vch, gas_price_vch, data_vch, contract_addr_vch
            // For TX_CONTRACT_CALL, elements are: version_vch, gas_limit_vch, gas_price_vch, data_vch, contract_addr_vch
            int contractAddrSolIndex = -1;
            if (typeRet == TX_CONTRACT_SENDER_CALL && vSolutions.size() >= 6) contractAddrSolIndex = 5;
            if (typeRet == TX_CONTRACT_CALL && vSolutions.size() >= 5) contractAddrSolIndex = 4;

            if (contractAddrSolIndex != -1 && vSolutions[contractAddrSolIndex].size() == 20) {
                 addressRet.push_back(CScriptID(uint160(vSolutions[contractAddrSolIndex])));
                 nRequiredRet = 1;
                 return true;
            }
        }
        return false; // Generally no standard "destinations" for wallet display for creates
    }

    if (typeRet == TX_MULTISIG)
    {
        if (vSolutions.size() < 3 || vSolutions.front().empty() || vSolutions.back().empty()) return false;
        nRequiredRet = vSolutions.front()[0];
        // int n = vSolutions.back()[0]; // 'n' (total keys) isn't directly used here for extracting destinations.
                                       // The loop iterates over the pubkeys stored in vSolutions.
        // The check 'if (n < 1 || (size_t)n != vSolutions.size() - 2)' is a validity check on 'n' itself.

        for (unsigned int i = 1; i < vSolutions.size()-1; i++) // Iterate from first pubkey to last pubkey
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid()) continue; // Skip invalid pubkeys
            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }
        // The original check `if (addressRet.empty()) return false;` is correct.
        // The check `if (n < 1 || (size_t)n != vSolutions.size() - 2) return false;` should remain for validating the multisig structure.
        // However, for ExtractDestinations, we only care if we successfully extracted *any* valid pubkey destinations.
        return !addressRet.empty();


    } else if (typeRet == TX_COLDSTAKE)
    {
        if (vSolutions.size() < 2 || vSolutions[0].size() != 20 || vSolutions[1].size() != 20) return false;
        nRequiredRet = 1; // For cold staking, either key can spend, but typically one is "active"
        addressRet.push_back(CKeyID(uint160(vSolutions[0]))); // spending key hash
        addressRet.push_back(CKeyID(uint160(vSolutions[1]))); // staking key hash
        return true;

    } else
    {
        // Handles TX_PUBKEY, TX_PUBKEYHASH, TX_SCRIPTHASH (if not TX_COLDSTAKE)
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address, false)) { // fColdStake = false for standard P2PKH/P2PK etc.
           return false;
        }
        addressRet.push_back(address);
        return true;
    }
}

namespace
{
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }
    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }
    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }
};

class CLockedScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
    int nLockTime;
public:
    CLockedScriptVisitor(CScript *scriptin, int nLockTimeIn) : script(scriptin), nLockTime(nLockTimeIn) { }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }
    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << nLockTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }
    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << nLockTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }
};
}

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;
    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript GetLockedScriptForDestination(const CTxDestination& dest, int nLockTime)
{
    CScript script;
    boost::apply_visitor(CLockedScriptVisitor(&script, nLockTime), dest);
    return script;
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << ToByteVector(pubKey) << OP_CHECKSIG;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;
    script << CScript::EncodeOP_N(nRequired);
    for (const CPubKey& key : keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

CScript GetScriptForStakeDelegation(const CKeyID& stakingKey, const CKeyID& spendingKey)
{
    CScript script;
    script << OP_DUP << OP_HASH160 << OP_ROT <<
            OP_IF << OP_CHECKCOLDSTAKEVERIFY << ToByteVector(stakingKey) <<
            OP_ELSE << ToByteVector(spendingKey) << OP_ENDIF <<
            OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}