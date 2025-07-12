#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <utility> // For std::pair, std::move
#include <memory>  // For std::shared_ptr, std::make_shared
#include <stdexcept> // For exceptions if needed
#include <cstring> // For memcpy

// --- Assumed Project Headers ---
#include <common/system.h>
#include <utilstrencodings.h>
#include <chainparams.h>
#include <main.h>
#include <script/script.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <amount.h>
#include <consensus/params.h>
#include <validationinterface.h> // For GetMainSignals
#include <main.h> // For GetMainSignals
#include <script/script.h>

#include <util/convert.h> // Include the header with the original h256/uint256 converters

// --- EVM/Qtum Specific Headers ---
#include <qtum/qtumstate.h>
#include <libevm/VMFace.h>
#include <libdevcore/Common.h>
#include <libdevcore/Log.h>
#include <libethcore/SealEngine.h>
#include <libethcore/TransactionBase.h>
#include <libethereum/State.h>
#include <libethereum/Executive.h>
#include <libethereum/Transaction.h> // May not be needed if QtumTransaction is self-contained

// --- Boost Exception ---
#include <boost/throw_exception.hpp>
// Use the exception from the library header, remove local definition
// struct CreateWithValue : virtual dev::eth::Exception {}; // REMOVED

using namespace std;
using namespace dev;
using namespace dev::eth;

// --- Placeholder Definitions (Replace with actual values/definitions) ---
#define MAX_CONTRACT_VOUTS 500 // Example value, use the actual limit

// --- Helper Function Placeholders REMOVED - Use definitions from ./util/convert.h ---
// inline uint256 h256Touint(const dev::h256& h) { ... } // REMOVED
// inline dev::h256 uintToh256(const uint256& u) { ... } // REMOVED

// Helper to convert address bytes to vector (if needed by CScript)
// Make sure this is consistent with how CScript takes byte vectors in Digiwage
inline std::vector<unsigned char> ToByteVector(const dev::Address& addr) {
    return addr.asBytes();
}

// --- QtumState Implementation ---

QtumState::QtumState(u256 const& _accountStartNonce, OverlayDB const& _db, const string& _path, BaseState _bs) :
    State(_accountStartNonce, _db, _bs) {
        // TODO: Ensure directory exists before opening DB if using filesystem
        dbUTXO = QtumState::openDB(_path + "/qtumDB", sha3(rlp("")), WithExisting::Trust);
        stateUTXO = SecureTrieDB<Address, OverlayDB>(&dbUTXO);
}

QtumState::QtumState() : dev::eth::State(dev::Invalid256, dev::OverlayDB(), dev::eth::BaseState::PreExisting) {
    dbUTXO = OverlayDB();
    stateUTXO = SecureTrieDB<Address, OverlayDB>(&dbUTXO);
}


ResultExecute QtumState::execute(EnvInfo const& _envInfo, SealEngineFace const& _sealEngine, QtumTransaction const& _t, CChain& _chain, Permanence _p, OnOpFunc const& _onOp){

    assert(_t.getVersion().toRaw() == VersionVM::GetEVMDefault().toRaw());

    addBalance(_t.sender(), _t.value() + (_t.gas() * _t.gasPrice()));
    newAddress = _t.isCreation() ? createQtumAddress(_t.getHashWith(), _t.getNVout()) : dev::Address();

    const_cast<SealEngineFace&>(_sealEngine).deleteAddresses.insert(_t.sender());
    const_cast<SealEngineFace&>(_sealEngine).deleteAddresses.insert(_envInfo.author());

    h256 oldStateRoot = rootHash();
    h256 oldUTXORoot = rootHashUTXO();
    bool voutLimit = false;

    auto onOp = _onOp;
#if ETH_VMTRACE
    //if (isChannelVisible<VMTraceChannel>())
    //    onOp = Executive::simpleTrace();
#endif

    Executive e(*this, _envInfo, _sealEngine);
    ExecutionResult res;
    e.setResultRecipient(res);

    // Use shared_ptr directly, not the CTransactionRef alias
    std::shared_ptr<const CTransaction> txRef = nullptr;
    u256 startGasUsed = _envInfo.gasUsed();
    const Consensus::Params& consensusParams = Params().GetConsensus();

    try {
        if (_t.isCreation() && _t.value())
            BOOST_THROW_EXCEPTION(dev::eth::CreateWithValue()); // Use the one from the library header

        e.initialize(_t);
        startGasUsed = _envInfo.gasUsed();
        if (!e.execute()){
            e.go(onOp);
            // QIP7 check removed as parameter doesn't exist
            // if(_chain.Height() >= consensusParams.QIP7Height){ // QTUM specific
            //     validateTransfersWithChangeLog();
            // }
        } else {
            e.revert();
            throw Exception();
        }
        e.finalize();

        if (_p == Permanence::Reverted){
            m_cache.clear();
            cacheUTXO.clear();
            m_changeLog.clear();
            m_unchangedCacheEntries.clear();
        } else {
            deleteAccounts(const_cast<SealEngineFace&>(_sealEngine).deleteAddresses);
            if(res.excepted == TransactionException::None){
                CondensingTX ctx(this, transfers, _t, const_cast<SealEngineFace&>(_sealEngine).deleteAddresses);
                CTransaction condensingTx = ctx.createCondensingTX();

                if(ctx.reachedVoutLimit()){
                    voutLimit = true;
                    e.revert();
                    throw Exception();
                }

                if(!condensingTx.IsNull()) {
                    txRef = std::make_shared<const CTransaction>(std::move(condensingTx));
                    std::unordered_map<dev::Address, Vin> vins = ctx.createVin(*txRef);
                    updateUTXO(vins);
                }

            } else {
                printfErrorLog(res.excepted);
            }

            qtum::commit(cacheUTXO, stateUTXO, m_cache);
            cacheUTXO.clear();
            bool removeEmptyAccounts = _envInfo.number() >= _sealEngine.chainParams().EIP158ForkBlock;
            commit(removeEmptyAccounts ? State::CommitBehaviour::RemoveEmptyAccounts : State::CommitBehaviour::KeepEmptyAccounts);
        }
    }
    catch(Exception const& _e){
        if (!voutLimit) {
             printfErrorLog(dev::eth::toTransactionException(_e));
        }
        res.excepted = dev::eth::toTransactionException(_e);
        res.gasUsed = _t.gas();

        // nFixUTXOCacheHFHeight check removed, always clear cache on exception
        m_cache.clear();
        cacheUTXO.clear();
        m_changeLog.clear();
        m_unchangedCacheEntries.clear();

        txRef = nullptr; // Ensure txRef is null on exception
    }

    // Clean up state for next transaction
    if(!_t.isCreation())
        res.newAddress = _t.receiveAddress();
    newAddress = dev::Address();
    transfers.clear();

    if(voutLimit){
        LogEntries logs;
        ExecutionResult ex;
        ex.gasRefunded = 0;
        ex.gasUsed = _t.gas();
        ex.excepted = TransactionException::OutOfGas;

        CMutableTransaction refundTxMut;
        if(_t.value() > 0) {
            dev::h256 txInputHash_h256 = _t.getHashWith(); // Keep as h256 first
            uint32_t nVout = _t.getNVout();
            uint256 txInputHash_u256 = h256Touint(txInputHash_h256); // Convert for COutPoint
            refundTxMut.vin.push_back(CTxIn(COutPoint(txInputHash_u256, nVout), CScript() << OP_SPEND));
            CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(_t.sender()) << OP_EQUALVERIFY << OP_CHECKSIG;
            refundTxMut.vout.push_back(CTxOut(CAmount(_t.value().convert_to<uint64_t>()), scriptPubKey));
        }
        CTransaction finalRefundTx = refundTxMut.vin.empty() ? CTransaction() : CTransaction(refundTxMut);

        // Return CTransaction object, not shared_ptr
        return ResultExecute{ex, QtumTransactionReceipt(oldStateRoot, oldUTXORoot, _t.gas(), logs), finalRefundTx};

    } else {
        u256 gasUsed = startGasUsed + res.gasUsed;
        // Dereference txRef or return empty CTransaction
        CTransaction resultTx = txRef ? *txRef : CTransaction();
        return ResultExecute{res, QtumTransactionReceipt(rootHash(), rootHashUTXO(), gasUsed, e.logs()), resultTx};
    }
}

std::unordered_map<dev::Address, Vin> QtumState::vins() const
{
    std::unordered_map<dev::Address, Vin> ret;
    for (auto const& [addr, vinInfo] : cacheUTXO)
        if (vinInfo.alive)
            ret[addr] = vinInfo;

    auto stateAddresses = addresses();
    for (auto const& [addr, accountInfo] : stateAddresses) {
        if (cacheUTXO.find(addr) == cacheUTXO.end()) {
            if (const Vin* v = vin(addr)) {
                 if(v->alive) {
                    ret[addr] = *v;
                 }
            }
        }
    }
    return ret;
}

void QtumState::transferBalance(dev::Address const& _from, dev::Address const& _to, dev::u256 const& _value) {
    subBalance(_from, _value);
    addBalance(_to, _value);
    if (_value > 0)
        transfers.push_back({_from, _to, _value});
}

Vin const* QtumState::vin(dev::Address const& _a) const
{
    return const_cast<QtumState*>(this)->vin(_a);
}

Vin* QtumState::vin(dev::Address const& _addr)
{
    auto it = cacheUTXO.find(_addr);
    if (it == cacheUTXO.end()){
        std::string stateBack = stateUTXO.at(_addr);
        if (stateBack.empty())
            return nullptr;

        try {
            dev::RLP state(stateBack);
            auto i = cacheUTXO.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(_addr),
                std::forward_as_tuple(Vin{state[0].toHash<dev::h256>(), state[1].toInt<uint32_t>(), state[2].toInt<dev::u256>(), state[3].toInt<uint8_t>()})
            );
            return &i.first->second;
        } catch (const dev::RLPException& e) {
            cwarn << "RLP decoding failed for Vin at address " << _addr.hex() << ": " << e.what();
            return nullptr;
        } catch (...) {
             cwarn << "Unknown error decoding Vin for address " << _addr.hex();
             return nullptr;
        }
    }
    if (!it->second.alive) return nullptr;
    return &it->second;
}

void QtumState::kill(dev::Address _addr)
{
    if (dev::eth::Account* a = account(_addr))
        a->kill();
    Vin* v = vin(_addr);
    if (v)
        v->alive = 0;
}

void QtumState::addBalance(dev::Address const& _idIn, dev::u256 const& _amount)
{
    dev::Address _id = _idIn;
    if (!addressInUse(newAddress) && newAddress != dev::Address() && _id == newAddress) {
         newAddress = dev::Address();
    }

    if (dev::eth::Account* a = account(_id))
    {
        if (!a->isDirty() && a->isEmpty())
            m_changeLog.emplace_back(dev::eth::Change::Touch, _id);
        a->addBalance(_amount);
    }
    else
    {
        createAccount(_id, {requireAccountStartNonce(), _amount});
    }

    if (_amount > 0 || (account(_id) && account(_id)->isDirty()))
        m_changeLog.emplace_back(dev::eth::Change::Balance, _id, _amount);
}

void QtumState::deleteAccounts(std::set<dev::Address>& addrs){
    for(dev::Address addr : addrs){
        kill(addr);
    }
}

void QtumState::updateUTXO(const std::unordered_map<dev::Address, Vin>& vins){
    for(auto const& [addr, vinInfo] : vins){
        Vin* vi = vin(addr);

        if(vi){
            vi->hash = vinInfo.hash;
            vi->nVout = vinInfo.nVout;
            vi->value = vinInfo.value;
            vi->alive = vinInfo.alive;
        } else if(vinInfo.alive > 0) {
            cacheUTXO[addr] = vinInfo;
        }
    }
}

void QtumState::printfErrorLog(const dev::eth::TransactionException er){
    std::stringstream ss;
    ss << er;
    clog(dev::VerbosityWarning, "exec") << "VM exception:" << ss.str();
}

void QtumState::validateTransfersWithChangeLog(){
    ChangeLog tmpChangeLog = m_changeLog;
    std::vector<TransferInfo> validatedTransfers;

    for(const TransferInfo& ti : transfers){
        bool foundCredit = false;
        int creditIndex = -1;
        bool foundDebit = false;
        int debitIndex = -1;

        for (std::size_t i = 0; i < tmpChangeLog.size(); ++i) {
            if (tmpChangeLog[i].kind == Change::Balance && tmpChangeLog[i].address == ti.to && tmpChangeLog[i].value == ti.value) {
                 if (tmpChangeLog[i].address != dev::Address(0)) {
                     foundCredit = true;
                     creditIndex = i;
                     break;
                 }
            }
        }

        if (foundCredit) {
            for (std::size_t j = 0; j < tmpChangeLog.size(); ++j) {
                 u256 negValue = u256(0) - ti.value;
                 if (tmpChangeLog[j].kind == Change::Balance && tmpChangeLog[j].address == ti.from && tmpChangeLog[j].value == negValue) {
                     if (tmpChangeLog[j].address != dev::Address(0)) {
                         foundDebit = true;
                         debitIndex = j;
                         break;
                     }
                 }
            }
        }

        if(foundCredit && foundDebit){
            validatedTransfers.push_back(ti);
            tmpChangeLog[creditIndex].address = dev::Address(0);
            tmpChangeLog[debitIndex].address = dev::Address(0);
        }
    }
    transfers = validatedTransfers;
}

// --- Removed as it relies on consensus params not present ---
/*
void QtumState::deployDelegationsContract(){
    // ... implementation removed ...
}
*/

///////////////////////////////////////////////////////////////////////////////////////////
// --- CondensingTX Class Implementation ---
///////////////////////////////////////////////////////////////////////////////////////////

// Constructor Definition REMOVED - Use the one in qtumstate.h
// CondensingTX::CondensingTX(...) { ... } // REMOVED

CTransaction CondensingTX::createCondensingTX(){
    selectionVin();
    calculatePlusAndMinus();
    if(!createNewBalances())
        return CTransaction();

    CMutableTransaction mutableTx;
    mutableTx.vin = createVins();
    mutableTx.vout = createVout();

    if (voutOverflow) {
        return CTransaction();
    }

    if (mutableTx.vin.empty() || mutableTx.vout.empty()) {
        return CTransaction();
    }

    return CTransaction(mutableTx);
}

std::unordered_map<dev::Address, Vin> CondensingTX::createVin(const CTransaction& tx){
    std::unordered_map<dev::Address, Vin> createdVins;
    uint256 txHash = tx.GetHash();

    for (auto const& [addr, balance] : balances){
        if(balance > 0){
            if (nVouts.count(addr)) {
                createdVins[addr] = Vin{uintToh256(txHash), nVouts[addr], balance, 1};
            } else {
                cwarn << "CondensingTX Error: No nVout index found for address " << addr.hex() << " with balance " << balance.str(); // Use .str()
                createdVins[addr] = Vin{uintToh256(txHash), 0, 0, 0};
            }
        }
    }

    for(const auto& addr : deleteAddresses) {
         if(balances.find(addr) == balances.end() || balances.at(addr) == 0) {
             createdVins[addr] = Vin{uintToh256(txHash), 0, 0, 0};
         }
    }

    std::set<dev::Address> involvedAddresses;
    for(auto const& [addr, vinInfo] : vins) { involvedAddresses.insert(addr); }
    for(auto const& [addr, pmInfo] : plusMinusInfo) { involvedAddresses.insert(addr); }

    for(const auto& addr : involvedAddresses) {
        if (balances.find(addr) == balances.end() && !deleteAddresses.count(addr)) {
             createdVins[addr] = Vin{uintToh256(txHash), 0, 0, 0};
        }
    }

    return createdVins;
}

void CondensingTX::selectionVin(){
    vins.clear();

    for(const TransferInfo& ti : transfers){
        if(!vins.count(ti.from)){
            const Vin* existingVin = state->vin(ti.from);
            vins[ti.from] = existingVin ? *existingVin : Vin{dev::h256(), 0, 0, 0};
        }
        if(!vins.count(ti.to)){
            const Vin* existingVin = state->vin(ti.to);
            vins[ti.to] = existingVin ? *existingVin : Vin{dev::h256(), 0, 0, 0};
        }
    }

    dev::Address sender = transaction.sender();
    const Vin* senderVinFromState = state->vin(sender);
    dev::u256 valueToUse = senderVinFromState ? senderVinFromState->value : transaction.value();
    vins[sender] = Vin{transaction.getHashWith(), transaction.getNVout(), valueToUse, 1};

}

void CondensingTX::calculatePlusAndMinus(){
    plusMinusInfo.clear();

    for(const TransferInfo& ti : transfers){
        plusMinusInfo[ti.from].second += ti.value; // Minus
        plusMinusInfo[ti.to].first += ti.value;   // Plus
    }
}

bool CondensingTX::createNewBalances(){
    balances.clear();

    std::set<dev::Address> involvedAddresses;
    for(auto const& [addr, vinInfo] : vins) { involvedAddresses.insert(addr); }
    for(auto const& [addr, pmInfo] : plusMinusInfo) { involvedAddresses.insert(addr); }

    for(const auto& addr : involvedAddresses) {
        if (checkDeleteAddress(addr)) {
            continue;
        }

        dev::u256 currentBalance = 0;
        if (vins.count(addr) && vins[addr].alive) {
            currentBalance = vins[addr].value;
        }

        if (plusMinusInfo.count(addr)) {
            const auto& pm = plusMinusInfo[addr];
            currentBalance += pm.first;

            if (currentBalance < pm.second) {
                cwarn << "CondensingTX Error: Insufficient funds for address " << addr.hex() << ". Has " << currentBalance.str() << ", needs " << pm.second.str(); // Use .str()
                return false;
            }
            currentBalance -= pm.second;
        }

        if (currentBalance > 0) {
            balances[addr] = currentBalance;
        }
    }
    return true;
}

std::vector<CTxIn> CondensingTX::createVins(){
    std::vector<CTxIn> ins;
    for(auto const& [addr, vinInfo] : vins){
        if(vinInfo.value > 0 && vinInfo.alive && !checkDeleteAddress(addr)) {
             uint256 txHash = h256Touint(vinInfo.hash);
             COutPoint outpoint(txHash, vinInfo.nVout);
             ins.push_back(CTxIn(outpoint, CScript() << OP_SPEND));
        }
    }
    return ins;
}

std::vector<CTxOut> CondensingTX::createVout(){
    size_t count = 0;
    std::vector<CTxOut> outs;
    nVouts.clear();
    voutOverflow = false; // Reset flag

    for(auto const& [addr, balance] : balances){
        if(balance > 0){
            if(count >= MAX_CONTRACT_VOUTS){
                voutOverflow = true;
                cwarn << "CondensingTX Error: Reached maximum number of VOUTS (" << MAX_CONTRACT_VOUTS << ")";
                return outs;
            }

            CScript scriptPubKey;
            const dev::eth::Account* acc = state->account(addr);

            if(acc && acc->isAlive() && acc->hasNewCode()){ // Use hasNewCode
                uint32_t gasLimit = DEFAULT_GAS_LIMIT_OP_SEND;
                uint64_t gasPrice = DEFAULT_GAS_PRICE;
                std::vector<unsigned char> addrBytes = addr.asBytes();
                scriptPubKey = CScript() << OP_4
                                      << CScriptNum(VersionVM::GetEVMDefault().toRaw())
                                      << CScriptNum(gasLimit)
                                      << CScriptNum(gasPrice)
                                      << addrBytes
                                      << OP_CALL;
            } else {
                std::vector<unsigned char> addrBytes = addr.asBytes();
                scriptPubKey = CScript() << OP_DUP << OP_HASH160 << addrBytes << OP_EQUALVERIFY << OP_CHECKSIG;
            }

            CAmount amount = 0;
            try {
                  if (balance > dev::u256(MAX_MONEY)) {
                       cwarn << "CondensingTX Error: Balance " << balance.str() << " exceeds MAX_MONEY for address " << addr.hex();
                       voutOverflow = true;
                       return outs;
                  }
                  amount = static_cast<CAmount>(balance.convert_to<uint64_t>());
            } catch (const boost::numeric::bad_numeric_cast& e) {
                  cwarn << "CondensingTX Error: Cannot convert balance " << balance.str() << " to CAmount for address " << addr.hex();
                  voutOverflow = true;
                  return outs;
            } catch(...) {
                 cwarn << "CondensingTX Error: Conversion failed for balance " << balance.str() << " for address " << addr.hex();
                 voutOverflow = true;
                 return outs;
            }

            outs.push_back(CTxOut(amount, scriptPubKey));
            nVouts[addr] = count;
            count++;
        }
    }
    return outs;
}

bool CondensingTX::checkDeleteAddress(dev::Address addr){
    return deleteAddresses.count(addr);
}

// Definition removed - rely on inline definition in qtumstate.h
// bool CondensingTX::reachedVoutLimit() const { ... } // REMOVED