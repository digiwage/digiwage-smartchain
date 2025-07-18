// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2017-2018 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_RPCCONSOLE_H
#define BITCOIN_QT_RPCCONSOLE_H

#include "guiutil.h"
#include "peertablemodel.h"

#include "net.h"

#include <QDialog>
#include <QCompleter>

class ClientModel;
class WalletModel;
class RPCTimerInterface;

namespace Ui
{
class RPCConsole;
}

QT_BEGIN_NAMESPACE
class QMenu;
class QItemSelection;
QT_END_NAMESPACE

/** Local Bitcoin RPC console. */
class RPCConsole : public QDialog
{
    Q_OBJECT

public:
    explicit RPCConsole(QWidget* parent);
    ~RPCConsole();

    void setClientModel(ClientModel* model);
    void setWalletModel(WalletModel* walletModel);

    enum MessageClass {
        MC_ERROR,
        MC_DEBUG,
        CMD_REQUEST,
        CMD_REPLY,
        CMD_ERROR
    };

protected:
    virtual bool eventFilter(QObject* obj, QEvent* event);

private Q_SLOTS:
    void on_lineEdit_returnPressed();
    void on_tabWidget_currentChanged(int index);
    /** open the debug.log from the current datadir */
    void on_openDebugLogfileButton_clicked();
    /** change the time range of the network traffic graph */
    void on_sldGraphRange_valueChanged(int value);
    /** update traffic statistics */
    void updateTrafficStats(quint64 totalBytesIn, quint64 totalBytesOut);
    void resizeEvent(QResizeEvent* event);
    void showEvent(QShowEvent* event);
    void hideEvent(QHideEvent* event);
    /** Show custom context menu on Peers tab */
    void showPeersTableContextMenu(const QPoint& point);
    /** Show custom context menu on Bans tab */
    void showBanTableContextMenu(const QPoint& point);
    /** Hides ban table if no bans are present */
    void showOrHideBanTableIfRequired();
    /** clear the selected node */
    void clearSelectedNode();

public Q_SLOTS:
    void clear();

    /** Wallet repair options */
    void walletSalvage();
    void walletRescan();
    void walletZaptxes1();
    void walletZaptxes2();
    void walletUpgrade();
    void walletReindex();
    void walletResync();
    void walletUpgradeToHd();

    void reject();
    void message(int category, const QString& message, bool html = false);
    /** Set number of connections shown in the UI */
    void setNumConnections(int count);
    /** Set number of blocks shown in the UI */
    void setNumBlocks(int count);
    /** Set number of masternodes shown in the UI */
    void setMasternodeCount(const QString& strMasternodes);
    /** Go forward or back in history */
    void browseHistory(int offset);
    /** Scroll console view to end */
    void scrollToEnd();
    /** Switch to info tab and show */
    void showInfo();
    /** Switch to console tab and show */
    void showConsole();
    /** Switch to network tab and show */
    void showNetwork();
    /** Switch to peers tab and show */
    void showPeers();
    /** Switch to wallet-repair tab and show */
    void showRepair();
    /** Open external (default) editor with digiwage.conf */
    void showConfEditor();
    /** Open external (default) editor with masternode.conf */
    void showMNConfEditor();
    /** Handle selection of peer in peers list */
    void peerSelected(const QItemSelection& selected, const QItemSelection& deselected);
    /** Handle updated peer information */
    void peerLayoutChanged();
    /** Disconnect a selected node on the Peers tab */
    void disconnectSelectedNode();
    /** Ban a selected node on the Peers tab */
    void banSelectedNode(int bantime);
    /** Unban a selected node on the Bans tab */
    void unbanSelectedNode();
    /** Show folder with wallet backups in default browser */
    void showBackups();

Q_SIGNALS:
    // For RPC command executor
    void stopExecutor();
    void cmdRequest(const QString& command);
    /** Get restart command-line parameters and handle restart */
    void handleRestart(QStringList args);

private:
    static QString FormatBytes(quint64 bytes);
    void startExecutor();
    void setTrafficGraphRange(int mins);
    /** Build parameter list for restart */
    void buildParameterlist(QString arg);
    /** show detailed information on ui about selected node */
    void updateNodeDetail(const CNodeCombinedStats* stats);

    enum ColumnWidths {
        ADDRESS_COLUMN_WIDTH = 170,
        SUBVERSION_COLUMN_WIDTH = 140,
        PING_COLUMN_WIDTH = 80,
        BANSUBNET_COLUMN_WIDTH = 200,
        BANTIME_COLUMN_WIDTH = 250
    };

    Ui::RPCConsole* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
    QStringList history;
    int historyPtr;
    NodeId cachedNodeid;
    QCompleter *autoCompleter;
    QMenu *peersTableContextMenu;
    QMenu *banTableContextMenu;
    RPCTimerInterface *rpcTimerInterface;
};

#endif // BITCOIN_QT_RPCCONSOLE_H
