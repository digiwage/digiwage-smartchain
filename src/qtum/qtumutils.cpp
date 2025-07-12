// qtum/qtumutils.cpp (FIXED VERSION - Using std::mutex)

#include "qtumutils.h"

#include <pubkey.h>      // For CPubKey
#include <uint256.h>     // For uint256, uint256S
#include <chainparams.h> // For CChainParams, Params(), CBaseChainParams
#include <util.h>     // For LogPrintf
#include <util/chaintype.h> // For ChainType enum
// #include <sync.h>     // <<< REMOVE this include
#include <mutex>       // <<< ADD this include for std::mutex and std::lock_guard
#include <stdexcept>     // For std::runtime_error
#include <vector>        // For std::vector
#include <cstring>       // For memcpy
#include <algorithm>     // For std::min

// Make sure dev::* types are available if not included via other headers
#include <libdevcore/Common.h>
#include <libdevcore/FixedHash.h>


namespace qtumutils
{

// Implementation for btc_ecrecover (assuming previous fixes are okay)
bool btc_ecrecover(dev::h256 const& hash, dev::u256 const& v, dev::h256 const& r, dev::h256 const& s, dev::h256 & key)
{
    std::vector<unsigned char> vchSig(1 + 32 + 32); // 65 bytes total: [recid][r][s]

    unsigned int recid = v.convert_to<unsigned int>();
    if (recid > 3) {
        LogPrintf("ERROR: btc_ecrecover - Invalid recovery ID (v=%s)\n", v.str());
        return false;
    }
    vchSig[0] = (unsigned char)recid;

    dev::FixedHash<32> r_h256(r);
    memcpy(vchSig.data() + 1, r_h256.data(), 32);

    dev::FixedHash<32> s_h256(s);
    memcpy(vchSig.data() + 1 + 32, s_h256.data(), 32);

    CPubKey pubkey;
    uint256 sighash = uint256S(hash.hex());
    if (!pubkey.RecoverCompact(sighash, vchSig)) {
        return false;
    }

    if (pubkey.IsFullyValid()) {
        std::vector<unsigned char> pubkeyBytes = pubkey.Raw();

        if (pubkeyBytes.size() == 33) { // Compressed
             dev::bytes keyBytes(dev::h256::size, 0);
             memcpy(keyBytes.data(), pubkeyBytes.data(), 33);
             key = dev::h256(keyBytes);
             return true;
        } else if (pubkeyBytes.size() == 65) { // Uncompressed
             LogPrintf("Warning: btc_ecrecover - Recovered uncompressed key, specific handling might be needed.\n");
             // Returning false as padded key is ambiguous for EVM. Hash if needed.
             return false;
        }
    }
    return false;
}

// Implementation for the base eth_getChainId function
int eth_getChainId(int blockHeight, int shanghaiHeight, const ChainType& chain)
{
    switch(chain) {
        case ChainType::MAIN:
            return ChainIdType::MAIN;
        case ChainType::TESTNET:
            return ChainIdType::TESTNET;
        case ChainType::REGTEST:
            return ChainIdType::REGTEST;
        default:
             LogPrintf("ERROR: Unknown ChainType (%d) in eth_getChainId\n", static_cast<int>(chain));
             return -1;
    }
}

// --- Caching implementation for eth_getChainId(int) ---
// <<< USE std::mutex instead of CCriticalSection >>>
static std::mutex cs_chainIdCache;
static int cachedChainId = -1;
static int cachedBlockHeight = -1;
static ChainType cachedChainType = ChainType::MAIN; // Still initialize with a valid type
static int cachedShanghaiHeight = -1;

// Function using the cache
int eth_getChainId(int blockHeight)
{
    // <<< USE std::lock_guard instead of LOCKGUARD >>>
    std::lock_guard<std::mutex> lock(cs_chainIdCache);

    const CChainParams& params = Params();
    const Consensus::Params& consensusParams = params.GetConsensus();

    ChainType currentChainType;
    std::string networkID = params.NetworkIDString();

    if (networkID == CBaseChainParams::MAIN) {
        currentChainType = ChainType::MAIN;
    } else if (networkID == CBaseChainParams::TESTNET) {
        currentChainType = ChainType::TESTNET;
    } else if (networkID == CBaseChainParams::REGTEST) {
        currentChainType = ChainType::REGTEST;
    } else {
        LogPrintf("ERROR: Unknown network ID string '%s' in eth_getChainId\n", networkID);
         return -1; // Return error code instead of throwing from cache function? Consider implications.
         // throw std::runtime_error("Unknown network ID string in eth_getChainId"); // Alternative
    }

    // *** ADJUST THE MEMBER NAME if needed ***
    int currentShanghaiHeight = consensusParams.QIP7Height; // Assuming QIP7Height

    // Check cache validity
    if (cachedChainId != -1 &&
        blockHeight == cachedBlockHeight &&
        currentChainType == cachedChainType &&
        currentShanghaiHeight == cachedShanghaiHeight) {
        return cachedChainId;
    }

    // Cache is invalid or not initialized, recalculate
    int chainId = eth_getChainId(blockHeight, currentShanghaiHeight, currentChainType);

    // Update cache only if calculation was successful
    if (chainId != -1) {
        cachedChainId = chainId;
        cachedBlockHeight = blockHeight;
        cachedChainType = currentChainType;
        cachedShanghaiHeight = currentShanghaiHeight;
    }

    return chainId;
}

} // namespace qtumutils