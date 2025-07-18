// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2017-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ADDRESSTABLEMODEL_H
#define BITCOIN_QT_ADDRESSTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class AddressTablePriv;
class WalletModel;

class CWallet;

/**
   Qt model of the address book in the core. This allows views to access and modify the address book.
 */
class AddressTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit AddressTableModel(CWallet* wallet, WalletModel* parent = 0);
    ~AddressTableModel();

    enum ColumnIndex {
        Label = 0,  /**< User specified label */
        Address = 1, /**< Bitcoin address */
        Date = 2, /**< Address creation date */
        Type = 3 /**< Address Type */
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of address (#Send, #Receive, #ColdStaking, #ColdStakingSend, #Delegators) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                    /**< Everything ok */
        NO_CHANGES,            /**< No changes were made during edit operation */
        INVALID_ADDRESS,       /**< Unparseable address */
        DUPLICATE_ADDRESS,     /**< Address already in address book */
        WALLET_UNLOCK_FAILURE, /**< Wallet could not be unlocked to create new receiving address */
        KEY_GENERATION_FAILURE /**< Generating a new public key for a receiving address failed */
    };

    static const QString Send;    /**< Specifies send address */
    static const QString Receive; /**< Specifies receive address */
    static const QString Delegators; /**< Specifies cold staking addresses which delegated tokens to this wallet */
    static const QString ColdStaking; /**< Specifies cold staking own addresses */
    static const QString ColdStakingSend; /**< Specifies send cold staking addresses (simil 'contacts')*/

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex& parent) const;
    int columnCount(const QModelIndex& parent) const;
    int sizeSend() const;
    int sizeRecv() const;
    int sizeDell() const;
    int sizeColdSend() const;
    void notifyChange(const QModelIndex &index);
    QVariant data(const QModelIndex& index, int role) const;
    bool setData(const QModelIndex& index, const QVariant& value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex& parent) const;
    bool removeRows(int row, int count, const QModelIndex& parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex& index) const;
    /*@}*/

    /* Add an address to the model.
       Returns the added address on success, and an empty string otherwise.
     */
    QString addRow(const QString& type, const QString& label, const QString& address);

    /* Look up label for address in address book, if not found return empty string.
     */
    QString labelForAddress(const QString& address) const;

    /* Look up row index of an address in the model.
       Return -1 if not found.
     */
    int lookupAddress(const QString& address) const;

    /*
     * Look up purpose for address in address book, if not found return empty string
     */
    std::string purposeForAddress(const std::string& address) const;

    /**
     * Checks if the address is whitelisted
     */
    bool isWhitelisted(const std::string& address) const;

    /**
     * Return last unused address
     */
    QString getAddressToShow() const;

    EditStatus getEditStatus() const { return editStatus; }

private:
    WalletModel* walletModel;
    CWallet* wallet;
    AddressTablePriv* priv;
    QStringList columns;
    EditStatus editStatus;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public Q_SLOTS:
    /* Update address list from core.
     */
    void updateEntry(const QString& address, const QString& label, bool isMine, const QString& purpose, int status);
    friend class AddressTablePriv;
};

#endif // BITCOIN_QT_ADDRESSTABLEMODEL_H
