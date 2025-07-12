#pragma once

#ifndef QTUMSTATE_H // Added include guard
#define QTUMSTATE_H

#include <libdevcore/UndefMacros.h>
#include <libethereum/State.h>
#include <libevm/ExtVMFace.h>
#include <crypto/sha256.h>
#include <crypto/ripemd160.h>
#include <uint256.h>
#include <util/convert.h>          // Make sure this declares h256Touint
#include <primitives/transaction.h>
#include <qtum/qtumtransaction.h> // Include definition of QtumTransaction

#include <libethereum/Executive.h>
#include <libethcore/SealEngine.h>

#include <functional> // Include for std::function
#include <utility> // Include for std::pair
#include <vector> // Include for std::vector
#include <map> // Include for std::map
#include <unordered_map> // Include for std::unordered_map
#include <set> // Include for std::set
#include <memory> // Include for std::unique_ptr
#include <cstring> // Include for memcpy
#include <cassert> // Include for static_assert

class CChain; // Forward declaration

// Type aliases
using OnOpFunc = std::function<void(uint64_t, uint64_t, dev::eth::Instruction, dev::bigint, dev::bigint,
    dev::bigint, dev::eth::VMFace const*, dev::eth::ExtVMFace const*)>;
using plusAndMinus = std::pair<dev::u256, dev::u256>;
using valtype = std::vector<unsigned char>;

// Struct definitions
struct TransferInfo{
    dev::Address from;
    dev::Address to;
    dev::u256 value;
};

struct Vin{
    dev::h256 hash;
    uint32_t nVout;
    dev::u256 value;
    uint8_t alive;

    // Default constructor (Keep this)
    Vin() : hash(), nVout(0), value(0), alive(0) {}

    // --- ADD THIS CONSTRUCTOR BELOW ---
    Vin(dev::h256 _hash, uint32_t _nVout, dev::u256 _value, uint8_t _alive) :
        hash(_hash), nVout(_nVout), value(_value), alive(_alive) {}
    // --- END OF ADDED CONSTRUCTOR ---

}; // End of Vin struct definition

// --- QtumTransactionReceipt ---
class QtumTransactionReceipt: public dev::eth::TransactionReceipt {
public:
    // Constructor with parameters is necessary as base lacks default constructor
    QtumTransactionReceipt(dev::h256 const& state_root, dev::h256 const& utxo_root, dev::u256 const& gas_used, dev::eth::LogEntries const& log) :
        dev::eth::TransactionReceipt(state_root, gas_used, log), m_utxoRoot(utxo_root) {}

    // Provide a constructor that initializes the base class with default/null values
    // This allows ResultExecute to have a working default constructor.
    QtumTransactionReceipt() :
        dev::eth::TransactionReceipt(dev::h256(), 0, dev::eth::LogEntries()), m_utxoRoot() {}


    dev::h256 const& utxoRoot() const {
        return m_utxoRoot;
    }
private:
    dev::h256 m_utxoRoot;
};

// --- ResultExecute ---
struct ResultExecute{
    dev::eth::ExecutionResult execRes;
    QtumTransactionReceipt txRec;
    CTransaction tx; // CTransaction has a default constructor

    // Check this default constructor
    ResultExecute() :
        execRes(), // Default construct ExecutionResult
        // CORRECT WAY: Call the QtumTransactionReceipt constructor that works
        txRec(dev::h256(), dev::h256(), 0, dev::eth::LogEntries()),
        tx()       // Default construct CTransaction
    {}

    // Optional: Keep other constructors if needed, e.g., a constructor taking arguments
    // Use const references and move semantics for efficiency
     ResultExecute(const dev::eth::ExecutionResult& _execRes, const QtumTransactionReceipt& _txRec, const CTransaction& _tx) :
          execRes(_execRes), txRec(_txRec), tx(_tx) {}

     ResultExecute(dev::eth::ExecutionResult&& _execRes, QtumTransactionReceipt&& _txRec, CTransaction&& _tx) :
          execRes(std::move(_execRes)), txRec(std::move(_txRec)), tx(std::move(_tx)) {}
};

// --- qtum namespace ---
namespace qtum{
    template <class DB>
    dev::AddressHash commit(std::unordered_map<dev::Address, Vin> const& _cache, dev::eth::SecureTrieDB<dev::Address, DB>& _state, std::unordered_map<dev::Address, dev::eth::Account> const& /*_cacheAcc*/) // _cacheAcc seems unused
    {
        dev::AddressHash ret;
        for (auto const& i: _cache){
            if(i.second.alive == 0){
                 _state.remove(i.first);
            } else {
                dev::RLPStream s; // RLPStream doesn't strictly need size hint, it grows
                s.appendList(4); // Indicate list of 4 items
                s << i.second.hash << i.second.nVout << i.second.value << i.second.alive;
                _state.insert(i.first, dev::bytesConstRef(s.out().data(), s.out().size())); // Pass data pointer and size
            }
            ret.insert(i.first);
        }
        return ret;
    }
}

// Forward declaration
class CondensingTX;

// --- QtumState ---
class QtumState : public dev::eth::State {

public:
    // Provide definitions or ensure they exist elsewhere
    QtumState();
    QtumState(dev::u256 const& _accountStartNonce, dev::OverlayDB const& _db, const std::string& _path, dev::eth::BaseState _bs = dev::eth::BaseState::PreExisting);

    // Ensure QtumTransaction is fully defined before use here
    ResultExecute execute(dev::eth::EnvInfo const& _envInfo, dev::eth::SealEngineFace const& _sealEngine, QtumTransaction const& _t, CChain& _chain, dev::eth::Permanence _p = dev::eth::Permanence::Committed, dev::eth::OnOpFunc const& _onOp = OnOpFunc());

    void setRootUTXO(dev::h256 const& _r) { cacheUTXO.clear(); stateUTXO.setRoot(_r); }

    void setCacheUTXO(dev::Address const& address, Vin const& vin) { cacheUTXO.insert(std::make_pair(address, vin)); }

    dev::h256 rootHashUTXO() const { return stateUTXO.root(); }

    std::unordered_map<dev::Address, Vin> vins() const; // temp - provide definition

    dev::OverlayDB const& dbUtxo() const { return dbUTXO; }

    dev::OverlayDB& dbUtxo() { return dbUTXO; }

    static dev::Address createQtumAddress(dev::h256 hashTx, uint32_t voutNumber){ // Removed const from return type
        uint256 hashTXid = h256Touint(hashTx); // Ensure h256Touint is available and included
        std::vector<unsigned char> txIdAndVout(hashTXid.begin(), hashTXid.end());
        std::vector<unsigned char> voutNumberChrs(sizeof(voutNumber)); // Allocate directly
        // Ensure safe memory copy
        static_assert(sizeof(voutNumber) == 4, "Assuming uint32_t is 4 bytes");
        std::memcpy(voutNumberChrs.data(), &voutNumber, sizeof(voutNumber));
        txIdAndVout.insert(txIdAndVout.end(),voutNumberChrs.begin(),voutNumberChrs.end());

        // Use C++ classes for crypto if available and preferred
        unsigned char sha256Result[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(txIdAndVout.data(), txIdAndVout.size()).Finalize(sha256Result);

        unsigned char ripemd160Result[CRIPEMD160::OUTPUT_SIZE];
        CRIPEMD160().Write(sha256Result, CSHA256::OUTPUT_SIZE).Finalize(ripemd160Result);

        return dev::Address(std::vector<unsigned char>(ripemd160Result, ripemd160Result + CRIPEMD160::OUTPUT_SIZE));
    }

    // Provide definition or ensure it exists elsewhere
    void deployDelegationsContract();

    virtual ~QtumState(){}

    friend CondensingTX;

private:

    // Ensure overrides match base class signature exactly
    void transferBalance(dev::Address const& _from, dev::Address const& _to, dev::u256 const& _value) override;

    Vin const* vin(dev::Address const& _a) const;

    Vin* vin(dev::Address const& _addr);

    // void commit(CommitBehaviour _commitBehaviour) override; // Add override if this overrides a virtual function in dev::eth::State

    void kill(dev::Address _addr) override;

    void addBalance(dev::Address const& _id, dev::u256 const& _amount) override;

    void deleteAccounts(std::set<dev::Address>& addrs);

    void updateUTXO(const std::unordered_map<dev::Address, Vin>& vins);

    void printfErrorLog(const dev::eth::TransactionException er); // Consider using std::string for error message

    dev::Address newAddress; // Potential place for contract address

    std::vector<TransferInfo> transfers; // Tracks balance transfers during execution

    dev::OverlayDB dbUTXO; // Database for UTXO-like state

	dev::eth::SecureTrieDB<dev::Address, dev::OverlayDB> stateUTXO; // Merkle Trie for UTXO state

	std::unordered_map<dev::Address, Vin> cacheUTXO; // Cache for UTXO state

	void validateTransfersWithChangeLog(); // Ensure definition exists
};


// --- TemporaryState ---
struct TemporaryState{
    std::unique_ptr<QtumState>& globalStateRef;
    dev::h256 oldHashStateRoot;
    dev::h256 oldHashUTXORoot;

    TemporaryState(std::unique_ptr<QtumState>& _globalStateRef) :
        globalStateRef(_globalStateRef),
        // Check for null before dereferencing, although reference shouldn't be null
        oldHashStateRoot(_globalStateRef ? _globalStateRef->rootHash() : dev::h256()),
        oldHashUTXORoot(_globalStateRef ? _globalStateRef->rootHashUTXO() : dev::h256()) {}

    void SetRoot(dev::h256 newHashStateRoot, dev::h256 newHashUTXORoot)
    {
        if(globalStateRef) // Check if reference is valid
        {
            globalStateRef->setRoot(newHashStateRoot);
            globalStateRef->setRootUTXO(newHashUTXORoot);
        }
    }

    ~TemporaryState(){
         if(globalStateRef) // Check if reference is valid
         {
             globalStateRef->setRoot(oldHashStateRoot);
             globalStateRef->setRootUTXO(oldHashUTXORoot);
         }
    }
    // Deleted constructors/assignments prevent copying/moving
    TemporaryState() = delete;
    TemporaryState(const TemporaryState&) = delete;
    TemporaryState& operator=(const TemporaryState&) = delete;
    TemporaryState(TemporaryState&&) = delete;
    TemporaryState& operator=(TemporaryState&&) = delete;
};


// --- CondensingTX ---
class CondensingTX{

public:
    // Ensure QtumState is defined before use here
    CondensingTX(QtumState* _state, const std::vector<TransferInfo>& _transfers, const QtumTransaction& _transaction, std::set<dev::Address> _deleteAddresses = {}) :
        transfers(_transfers),
        deleteAddresses(std::move(_deleteAddresses)), // Move set if possible
        transaction(_transaction),
        state(_state){}

    CTransaction createCondensingTX(); // Ensure definition exists

    std::unordered_map<dev::Address, Vin> createVin(const CTransaction& tx); // Ensure definition exists

    bool reachedVoutLimit() const { return voutOverflow; }

private:

    void selectionVin(); // Ensure definition exists
    void calculatePlusAndMinus(); // Ensure definition exists
    bool createNewBalances(); // Ensure definition exists
    std::vector<CTxIn> createVins(); // Ensure definition exists
    std::vector<CTxOut> createVout(); // Ensure definition exists
    bool checkDeleteAddress(dev::Address addr); // Ensure definition exists

    std::map<dev::Address, plusAndMinus> plusMinusInfo;
    std::map<dev::Address, dev::u256> balances;
    std::map<dev::Address, uint32_t> nVouts;
    std::map<dev::Address, Vin> vins;

    const std::vector<TransferInfo>& transfers;
    const std::set<dev::Address> deleteAddresses;
    const QtumTransaction& transaction;
    QtumState* state;
    bool voutOverflow = false;

};

#endif // QTUMSTATE_H // Corrected include guard matching the #ifndef