// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2014-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#pragma once

#include <libethcore/Common.h>
#include <libdevcrypto/Common.h>
#include <libdevcore/RLP.h>
#include <libdevcore/SHA3.h>

#include <boost/optional.hpp>

namespace dev
{
namespace eth
{

struct EVMSchedule;

/// Named-boolean type to encode whether a signature be included in the serialisation process.
enum IncludeSignature
{
    WithoutSignature = 0,	///< Do not include a signature.
    WithSignature = 1,		///< Do include a signature.
};

enum class CheckTransaction
{
    None,
    Cheap,
    Everything
};

#define o_has_value(o) (o.get_ptr() != 0)

/// Encodes a transaction, ready to be exported to or freshly imported from RLP.
class TransactionBase
{
public:
    /// Constructs a null transaction.
    TransactionBase() {}

    /// Constructs a transaction from a transaction skeleton & optional secret.
    TransactionBase(TransactionSkeleton const& _ts, Secret const& _s = Secret());

    /// Constructs a signed message-call transaction.
    TransactionBase(u256 const& _value, u256 const& _gasPrice, u256 const& _gas, Address const& _dest, bytes const& _data, u256 const& _nonce, Secret const& _secret): m_type(MessageCall), m_nonce(_nonce), m_value(_value), m_receiveAddress(_dest), m_gasPrice(_gasPrice), m_gas(_gas), m_data(_data) { sign(_secret); }

    /// Constructs a signed contract-creation transaction.
    TransactionBase(u256 const& _value, u256 const& _gasPrice, u256 const& _gas, bytes const& _data, u256 const& _nonce, Secret const& _secret): m_type(ContractCreation), m_nonce(_nonce), m_value(_value), m_gasPrice(_gasPrice), m_gas(_gas), m_data(_data) { sign(_secret); }

    /// Constructs an unsigned message-call transaction.
    TransactionBase(u256 const& _value, u256 const& _gasPrice, u256 const& _gas, Address const& _dest, bytes const& _data, u256 const& _nonce = 0): m_type(MessageCall), m_nonce(_nonce), m_value(_value), m_receiveAddress(_dest), m_gasPrice(_gasPrice), m_gas(_gas), m_data(_data) {}

    /// Constructs an unsigned contract-creation transaction.
    TransactionBase(u256 const& _value, u256 const& _gasPrice, u256 const& _gas, bytes const& _data, u256 const& _nonce = 0): m_type(ContractCreation), m_nonce(_nonce), m_value(_value), m_gasPrice(_gasPrice), m_gas(_gas), m_data(_data) {}

    /// Constructs a transaction from the given RLP.
    explicit TransactionBase(bytesConstRef _rlp, CheckTransaction _checkSig);

    /// Constructs a transaction from the given RLP.
    explicit TransactionBase(bytes const& _rlp, CheckTransaction _checkSig): TransactionBase(&_rlp, _checkSig) {}

    /// Checks equality of transactions.
    bool operator==(TransactionBase const& _c) const { return m_type == _c.m_type && (m_type == ContractCreation || m_receiveAddress == _c.m_receiveAddress) && m_value == _c.m_value && m_data == _c.m_data; }
    /// Checks inequality of transactions.
    bool operator!=(TransactionBase const& _c) const { return !operator==(_c); }

    /// @returns sender of the transaction from the signature (and hash).
    /// @throws TransactionIsUnsigned if signature was not initialized
    Address const& sender() const;
    /// Like sender() but will never throw. @returns a null Address if the signature is invalid.
    Address const& safeSender() const noexcept;
    /// Force the sender to a particular value. This will result in an invalid transaction RLP.
    void forceSender(Address const& _a) { m_sender = _a; }

    /// @throws TransactionIsUnsigned if signature was not initialized
    /// @throws InvalidSValue if the signature has an invalid S value.
    void checkLowS() const;

    /// @throws InvalidSignature if the transaction is replay protected
    /// and chain id is not equal to @a _chainId
    void checkChainId(uint64_t _chainId) const;

    /// @returns true if transaction is non-null.
    explicit operator bool() const { return m_type != NullTransaction; }

    /// @returns true if transaction is contract-creation.
    bool isCreation() const { return m_type == ContractCreation; }

    /// Serialises this transaction to an RLPStream.
    /// @throws TransactionIsUnsigned if including signature was requested but it was not initialized
    void streamRLP(RLPStream& _s, IncludeSignature _sig = WithSignature, bool _forEip155hash = false) const;

    /// @returns the RLP serialisation of this transaction.
    bytes rlp(IncludeSignature _sig = WithSignature) const { RLPStream s; streamRLP(s, _sig); return s.out(); }

    /// @returns the SHA3 hash of the RLP serialisation of this transaction.
    h256 sha3(IncludeSignature _sig = WithSignature) const;

    /// @returns the amount of ETH to be transferred by this (message-call) transaction, in Wei. Synonym for endowment().
    u256 value() const { return m_value; }

    /// @returns the base fee and thus the implied exchange rate of ETH to GAS.
    u256 gasPrice() const { return m_gasPrice; }

    /// @returns the total gas to convert, paid for from sender's account. Any unused gas gets refunded once the contract is ended.
    u256 gas() const { return m_gas; }

    /// @returns the receiving address of the message-call transaction (undefined for contract-creation transactions).
    Address receiveAddress() const { return m_receiveAddress; }

    /// Synonym for receiveAddress().
    Address to() const { return m_receiveAddress; }

    /// Synonym for safeSender().
    Address from() const { return safeSender(); }

    /// @returns the data associated with this (message-call) transaction. Synonym for initCode().
    bytes const& data() const { return m_data; }

    /// @returns the transaction-count of the sender.
    u256 nonce() const { return m_nonce; }

    /// Sets the nonce to the given value. Clears any signature.
    void setNonce(u256 const& _n) { clearSignature(); m_nonce = _n; }

    /// @returns true if the transaction was signed
    bool hasSignature() const { return o_has_value(m_vrs); }

    /// @returns true if the transaction was signed with zero signature
    bool hasZeroSignature() const { return m_vrs && isZeroSignature(m_vrs->r, m_vrs->s); }

    /// @returns true if the transaction uses EIP155 replay protection
    bool isReplayProtected() const { return o_has_value(m_chainId); }

    /// @returns the signature of the transaction (the signature has the sender encoded in it)
    /// @throws TransactionIsUnsigned if signature was not initialized
    SignatureStruct const& signature() const;

    /// @returns v value of the transaction (has chainID and recoveryID encoded in it)
    /// @throws TransactionIsUnsigned if signature was not initialized
    u256 rawV() const;

    void sign(Secret const& _priv);			///< Sign the transaction.

    /// @returns amount of gas required for the basic payment.
    int64_t baseGasRequired(EVMSchedule const& _es) const { return baseGasRequired(isCreation(), &m_data, _es); }

    /// Get the fee associated for a transaction with the given data.
    static int64_t baseGasRequired(bool _contractCreation, bytesConstRef _data, EVMSchedule const& _es);

protected:
    /// Type of transaction.
    enum Type
    {
        NullTransaction,				///< Null transaction.
        ContractCreation,				///< Transaction to create contracts - receiveAddress() is ignored.
        MessageCall						///< Transaction to invoke a message call - receiveAddress() is used.
    };

    static bool isZeroSignature(u256 const& _r, u256 const& _s) { return !_r && !_s; }

    /// Clears the signature.
    void clearSignature() { m_vrs = SignatureStruct(); }

    Type m_type = NullTransaction;		///< Is this a contract-creation transaction or a message-call transaction?
    u256 m_nonce;						///< The transaction-count of the sender.
    u256 m_value;						///< The amount of ETH to be transferred by this transaction. Called 'endowment' for contract-creation transactions.
    Address m_receiveAddress;			///< The receiving address of the transaction.
    u256 m_gasPrice;					///< The base fee and thus the implied exchange rate of ETH to GAS.
    u256 m_gas;							///< The total gas to convert, paid for from sender's account. Any unused gas gets refunded once the contract is ended.
    bytes m_data;						///< The data associated with the transaction, or the initialiser if it's a creation transaction.
    boost::optional<SignatureStruct> m_vrs;	///< The signature of the transaction. Encodes the sender.
    /// EIP155 value for calculating transaction hash
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    boost::optional<uint64_t> m_chainId;

    mutable h256 m_hashWith;			///< Cached hash of transaction with signature.
    mutable boost::optional<Address> m_sender;  ///< Cached sender, determined from signature.
};

/// Nice name for vector of Transaction.
using TransactionBases = std::vector<TransactionBase>;

/// Simple human-readable stream-shift operator.
inline std::ostream& operator<<(std::ostream& _out, TransactionBase const& _t)
{
    _out << _t.sha3().abridged() << "{";
    if (_t.receiveAddress())
        _out << _t.receiveAddress().abridged();
    else
        _out << "[CREATE]";

    _out << "/" << _t.data().size() << "$" << _t.value() << "+" << _t.gas() << "@" << _t.gasPrice();
    _out << "<-" << _t.safeSender().abridged() << " #" << _t.nonce() << "}";
    return _out;
}

}
}
