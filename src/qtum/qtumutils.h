#ifndef QTUMUTILS_H
#define QTUMUTILS_H

#include <libdevcore/Common.h>
#include <libdevcore/FixedHash.h>
#include <util/chaintype.h> // Assumes this defines enum ChainType { MAIN, TESTNET, REGTEST, ... };

/**
 * qtumutils Provides utility functions to EVM for functionalities that already exist in qtum/digiwage
 */
namespace qtumutils
{
/**
 * @brief btc_ecrecover Wrapper to CPubKey::RecoverCompact
 * @param hash Message hash that was signed
 * @param v Recovery id (usually 27 or 28, sometimes higher with chain id)
 * @param r R value of the signature
 * @param s S value of the signature
 * @param key Output public key hash (h256 format)
 * @return true if recovery was successful
 */
bool btc_ecrecover(dev::h256 const& hash, dev::u256 const& v, dev::h256 const& r, dev::h256 const& s, dev::h256 & key);


/**
 * @brief The ChainIdType enum EIP-155 Chain Id values for the networks
 * !!! ACTION REQUIRED: Replace these placeholder values with your actual DigiWage Chain IDs !!!
 */
enum ChainIdType
{
    MAIN = 81,      // <<< REPLACE WITH ACTUAL DIGIWAGE MAINNET CHAIN ID
    TESTNET = 8889, // <<< REPLACE WITH ACTUAL DIGIWAGE TESTNET CHAIN ID
    REGTEST = 8890, // <<< REPLACE WITH ACTUAL DIGIWAGE REGTEST CHAIN ID
};

/**
 * @brief eth_getChainId Get eth chain id based on network and potentially fork status.
 * @param blockHeight Block height (may influence chain ID if non-standard forks are used)
 * @param chain Network type (MAIN, TESTNET, REGTEST)
 * @return chain id (value from ChainIdType enum) or -1 on error/unknown network
 *
 * Note: Standard EIP-155 IDs are usually fixed per network. Depending on blockHeight
 *       is non-standard but included for flexibility if needed. The implementation
 *       in qtumutils.cpp should reflect the actual logic for DigiWage.
 */
int eth_getChainId(int blockHeight, const ChainType& chain);

/**
 * @brief eth_getChainId Get eth chain id using global Params() and current chain height, possibly caching.
 * @return chain id (value from ChainIdType enum) or -1 on error/unknown network
 */
int eth_getChainId(); // Simpler version using global context

} // namespace qtumutils

#endif // QTUMUTILS_H