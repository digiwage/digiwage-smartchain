// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcconsole.h"
#include "ui_rpcconsole.h"

#include "bantablemodel.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "guiutil.h"
#include "peertablemodel.h"

#include "chainparams.h"
#include "main.h"
#include "rpc/client.h"
#include "rpc/server.h"
#include "util.h"

#include "init.h"
#include <startoptionsmain.h>
#include "askpassphrasedialog.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif // ENABLE_WALLET

#include <univalue.h>

#ifdef ENABLE_WALLET
#include <db_cxx.h>
#endif

#include <QDir>
#include <QKeyEvent>
#include <QMenu>
#include <QScrollBar>
#include <QSignalMapper>
#include <QThread>
#include <QTime>
#include <QTimer>
#include <QStringList>

// TODO: add a scrollback limit, as there is currently none
// TODO: make it possible to filter out categories (esp debug messages when implemented)
// TODO: receive errors and debug messages through ClientModel

const int CONSOLE_HISTORY = 50;
const QSize ICON_SIZE(24, 24);

const int INITIAL_TRAFFIC_GRAPH_MINS = 30;

// Repair parameters
const QString SALVAGEWALLET("-salvagewallet");
const QString RESCAN("-rescan");
const QString ZAPTXES1("-zapwallettxes=1");
const QString ZAPTXES2("-zapwallettxes=2");
const QString UPGRADEWALLET("-upgradewallet");
const QString REINDEX("-reindex");
const QString RESYNC("-resync");

const struct {
    const char* url;
    const char* source;
} ICON_MAPPING[] = {
    {"cmd-request", ":/icons/tx_input"},
    {"cmd-reply", ":/icons/tx_output"},
    {"cmd-error", ":/icons/tx_output"},
    {"misc", ":/icons/tx_inout"},
    {NULL, NULL}};

/* Object for executing console RPC commands in a separate thread.
*/
class RPCExecutor : public QObject
{
    Q_OBJECT

public Q_SLOTS:
    void request(const QString& command);

Q_SIGNALS:
    void reply(int category, const QString& command);
};

/** Class for handling RPC timers
 * (used for e.g. re-locking the wallet after a timeout)
 */
class QtRPCTimerBase: public QObject, public RPCTimerBase
{
    Q_OBJECT
public:
    QtRPCTimerBase(boost::function<void(void)>& func, int64_t millis):
        func(func)
    {
        timer.setSingleShot(true);
        connect(&timer, SIGNAL(timeout()), this, SLOT(timeout()));
        timer.start(millis);
    }
    ~QtRPCTimerBase() {}
private Q_SLOTS:
    void timeout() { func(); }
private:
    QTimer timer;
    boost::function<void(void)> func;
};

class QtRPCTimerInterface: public RPCTimerInterface
{
public:
    ~QtRPCTimerInterface() {}
    const char *Name() { return "Qt"; }
    RPCTimerBase* NewTimer(boost::function<void(void)>& func, int64_t millis)
    {
        return new QtRPCTimerBase(func, millis);
    }
};

#include "rpcconsole.moc"

/**
 * Split shell command line into a list of arguments. Aims to emulate \c bash and friends.
 *
 * - Arguments are delimited with whitespace
 * - Extra whitespace at the beginning and end and between arguments will be ignored
 * - Text can be "double" or 'single' quoted
 * - The backslash \c \ is used as escape character
 *   - Outside quotes, any character can be escaped
 *   - Within double quotes, only escape \c " and backslashes before a \c " or another backslash
 *   - Within single quotes, no escaping is possible and no special interpretation takes place
 *
 * @param[out]   args        Parsed arguments will be appended to this list
 * @param[in]    strCommand  Command line to split
 */
bool parseCommandLine(std::vector<std::string>& args, const std::string& strCommand)
{
    enum CmdParseState {
        STATE_EATING_SPACES,
        STATE_ARGUMENT,
        STATE_SINGLEQUOTED,
        STATE_DOUBLEQUOTED,
        STATE_ESCAPE_OUTER,
        STATE_ESCAPE_DOUBLEQUOTED
    } state = STATE_EATING_SPACES;
    std::string curarg;
    Q_FOREACH (char ch, strCommand) {
        switch (state) {
        case STATE_ARGUMENT:      // In or after argument
        case STATE_EATING_SPACES: // Handle runs of whitespace
            switch (ch) {
            case '"':
                state = STATE_DOUBLEQUOTED;
                break;
            case '\'':
                state = STATE_SINGLEQUOTED;
                break;
            case '\\':
                state = STATE_ESCAPE_OUTER;
                break;
            case ' ':
            case '\n':
            case '\t':
                if (state == STATE_ARGUMENT) // Space ends argument
                {
                    args.push_back(curarg);
                    curarg.clear();
                }
                state = STATE_EATING_SPACES;
                break;
            default:
                curarg += ch;
                state = STATE_ARGUMENT;
            }
            break;
        case STATE_SINGLEQUOTED: // Single-quoted string
            switch (ch) {
            case '\'':
                state = STATE_ARGUMENT;
                break;
            default:
                curarg += ch;
            }
            break;
        case STATE_DOUBLEQUOTED: // Double-quoted string
            switch (ch) {
            case '"':
                state = STATE_ARGUMENT;
                break;
            case '\\':
                state = STATE_ESCAPE_DOUBLEQUOTED;
                break;
            default:
                curarg += ch;
            }
            break;
        case STATE_ESCAPE_OUTER: // '\' outside quotes
            curarg += ch;
            state = STATE_ARGUMENT;
            break;
        case STATE_ESCAPE_DOUBLEQUOTED:                  // '\' in double-quoted text
            if (ch != '"' && ch != '\\') curarg += '\\'; // keep '\' for everything but the quote and '\' itself
            curarg += ch;
            state = STATE_DOUBLEQUOTED;
            break;
        }
    }
    switch (state) // final state
    {
    case STATE_EATING_SPACES:
        return true;
    case STATE_ARGUMENT:
        args.push_back(curarg);
        return true;
    default: // ERROR to end in one of the other states
        return false;
    }
}

void RPCExecutor::request(const QString& command)
{
    std::vector<std::string> args;
    if (!parseCommandLine(args, command.toStdString())) {
        Q_EMIT reply(RPCConsole::CMD_ERROR, QString("Parse error: unbalanced ' or \""));
        return;
    }
    if (args.empty())
        return; // Nothing to do
    try {
        std::string strPrint;
        // Convert argument list to JSON objects in method-dependent way,
        // and pass it along with the method name to the dispatcher.
        UniValue result = tableRPC.execute(
            args[0],
            RPCConvertValues(args[0], std::vector<std::string>(args.begin() + 1, args.end())));

        // Format result reply
        if (result.isNull())
            strPrint = "";
        else if (result.isStr())
            strPrint = result.get_str();
        else
            strPrint = result.write(2);

        Q_EMIT reply(RPCConsole::CMD_REPLY, QString::fromStdString(strPrint));
    } catch (const UniValue& objError) {
        try // Nice formatting for standard-format error
        {
            int code = find_value(objError, "code").getInt<int>();
            std::string message = find_value(objError, "message").get_str();
            Q_EMIT reply(RPCConsole::CMD_ERROR, QString::fromStdString(message) + " (code " + QString::number(code) + ")");
        } catch (const std::runtime_error&) // raised when converting to invalid type, i.e. missing code or message
        {                             // Show raw JSON object
            Q_EMIT reply(RPCConsole::CMD_ERROR, QString::fromStdString(objError.write()));
        }
    } catch (const std::exception& e) {
        Q_EMIT reply(RPCConsole::CMD_ERROR, QString("Error: ") + QString::fromStdString(e.what()));
    }
}

RPCConsole::RPCConsole(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                          ui(new Ui::RPCConsole),
                                          clientModel(0),
                                          walletModel(0),
                                          historyPtr(0),
                                          cachedNodeid(-1),
                                          peersTableContextMenu(0),
                                          banTableContextMenu(0)
{
    ui->setupUi(this);
    GUIUtil::restoreWindowGeometry("nRPCConsoleWindow", this->size(), this);

#ifndef Q_OS_MAC
    ui->openDebugLogfileButton->setIcon(QIcon(":/icons/export"));
#endif

    // Install event filter for up and down arrow
    ui->lineEdit->installEventFilter(this);
    ui->messagesWidget->installEventFilter(this);

    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));
    connect(ui->btnClearTrafficGraph, SIGNAL(clicked()), ui->trafficGraph, SLOT(clear()));

    // Wallet Repair Buttons
    connect(ui->btn_salvagewallet, SIGNAL(clicked()), this, SLOT(walletSalvage()));
    connect(ui->btn_rescan, SIGNAL(clicked()), this, SLOT(walletRescan()));
    connect(ui->btn_zapwallettxes1, SIGNAL(clicked()), this, SLOT(walletZaptxes1()));
    connect(ui->btn_zapwallettxes2, SIGNAL(clicked()), this, SLOT(walletZaptxes2()));
    connect(ui->btn_upgradewallet, SIGNAL(clicked()), this, SLOT(walletUpgrade()));
    connect(ui->btn_reindex, SIGNAL(clicked()), this, SLOT(walletReindex()));
    connect(ui->btn_resync, SIGNAL(clicked()), this, SLOT(walletResync()));
    connect(ui->btn_convert_to_hd_Wallet, SIGNAL(clicked()), this, SLOT(walletUpgradeToHd()));

    // set library version labels
#ifdef ENABLE_WALLET
    std::string strPathCustom = GetArg("-backuppath", "");
    int nCustomBackupThreshold = GetArg("-custombackupthreshold", DEFAULT_CUSTOMBACKUPTHRESHOLD);

    if(!strPathCustom.empty()) {
        ui->wallet_custombackuppath->setText(QString::fromStdString(strPathCustom));
        ui->wallet_custombackuppath_label->show();
        ui->wallet_custombackuppath->show();
        if (nCustomBackupThreshold > 0) {
            ui->wallet_custombackupthreshold->setText(QString::fromStdString(std::to_string(nCustomBackupThreshold)));
            ui->wallet_custombackupthreshold_label->setVisible(true);
            ui->wallet_custombackupthreshold->setVisible(true);
        }
    }

    ui->berkeleyDBVersion->setText(DbEnv::version(0, 0, 0));
    ui->wallet_path->setText(QString::fromStdString(GetDataDir().string() + QDir::separator().toLatin1() + GetArg("-wallet", "wallet.dat")));
#else

    ui->label_berkeleyDBVersion->hide();
    ui->berkeleyDBVersion->hide();
#endif
    // Register RPC timer interface
    rpcTimerInterface = new QtRPCTimerInterface();
    // avoid accidentally overwriting an existing, non QTThread
    // based timer interface
    RPCSetTimerInterfaceIfUnset(rpcTimerInterface);

    startExecutor();
    setTrafficGraphRange(INITIAL_TRAFFIC_GRAPH_MINS);

    ui->peerHeading->setText(tr("Select a peer to view detailed information."));

    clear();
}

RPCConsole::~RPCConsole()
{
    GUIUtil::saveWindowGeometry("nRPCConsoleWindow", this);
    Q_EMIT stopExecutor();
    RPCUnsetTimerInterface(rpcTimerInterface);
    delete rpcTimerInterface;
    delete ui;
}

bool RPCConsole::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::KeyPress) // Special key handling
    {
        QKeyEvent* keyevt = static_cast<QKeyEvent*>(event);
        int key = keyevt->key();
        Qt::KeyboardModifiers mod = keyevt->modifiers();
        switch (key) {
        case Qt::Key_Up:
            if (obj == ui->lineEdit) {
                browseHistory(-1);
                return true;
            }
            break;
        case Qt::Key_Down:
            if (obj == ui->lineEdit) {
                browseHistory(1);
                return true;
            }
            break;
        case Qt::Key_PageUp: /* pass paging keys to messages widget */
        case Qt::Key_PageDown:
            if (obj == ui->lineEdit) {
                QApplication::postEvent(ui->messagesWidget, new QKeyEvent(*keyevt));
                return true;
            }
            break;
        case Qt::Key_Return:
        case Qt::Key_Enter:
            // forward these events to lineEdit
            if(obj == autoCompleter->popup()) {
                QApplication::postEvent(ui->lineEdit, new QKeyEvent(*keyevt));
                return true;
            }
            break;
        default:
            // Typing in messages widget brings focus to line edit, and redirects key there
            // Exclude most combinations and keys that emit no text, except paste shortcuts
            if (obj == ui->messagesWidget && ((!mod && !keyevt->text().isEmpty() && key != Qt::Key_Tab) ||
                                                 ((mod & Qt::ControlModifier) && key == Qt::Key_V) ||
                                                 ((mod & Qt::ShiftModifier) && key == Qt::Key_Insert))) {
                ui->lineEdit->setFocus();
                QApplication::postEvent(ui->lineEdit, new QKeyEvent(*keyevt));
                return true;
            }
        }
    }
    return QDialog::eventFilter(obj, event);
}

void RPCConsole::setClientModel(ClientModel* model)
{
    clientModel = model;
    ui->trafficGraph->setClientModel(model);
    if (model && clientModel->getPeerTableModel() && clientModel->getBanTableModel()) {
        // Keep up to date with client
        setNumConnections(model->getNumConnections());
        connect(model, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

        setNumBlocks(model->getNumBlocks());
        connect(model, SIGNAL(numBlocksChanged(int)), this, SLOT(setNumBlocks(int)));

        setMasternodeCount(model->getMasternodeCountString());
        connect(model, SIGNAL(strMasternodesChanged(QString)), this, SLOT(setMasternodeCount(QString)));

        updateTrafficStats(model->getTotalBytesRecv(), model->getTotalBytesSent());
        connect(model, SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(updateTrafficStats(quint64, quint64)));

        // set up peer table
        ui->peerWidget->setModel(model->getPeerTableModel());
        ui->peerWidget->verticalHeader()->hide();
        ui->peerWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        ui->peerWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        ui->peerWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        ui->peerWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        ui->peerWidget->setColumnWidth(PeerTableModel::Address, ADDRESS_COLUMN_WIDTH);
        ui->peerWidget->setColumnWidth(PeerTableModel::Subversion, SUBVERSION_COLUMN_WIDTH);
        ui->peerWidget->setColumnWidth(PeerTableModel::Ping, PING_COLUMN_WIDTH);
        ui->peerWidget->horizontalHeader()->setStretchLastSection(true);

        // create peer table context menu actions
        QAction* disconnectAction = new QAction(tr("&Disconnect Node"), this);
        QAction* banAction1h      = new QAction(tr("Ban Node for") + " " + tr("1 &hour"), this);
        QAction* banAction24h     = new QAction(tr("Ban Node for") + " " + tr("1 &day"), this);
        QAction* banAction7d      = new QAction(tr("Ban Node for") + " " + tr("1 &week"), this);
        QAction* banAction365d    = new QAction(tr("Ban Node for") + " " + tr("1 &year"), this);

        // create peer table context menu
        peersTableContextMenu = new QMenu();
        peersTableContextMenu->addAction(disconnectAction);
        peersTableContextMenu->addAction(banAction1h);
        peersTableContextMenu->addAction(banAction24h);
        peersTableContextMenu->addAction(banAction7d);
        peersTableContextMenu->addAction(banAction365d);

        // Add a signal mapping to allow dynamic context menu arguments.
        // We need to use int (instead of int64_t), because signal mapper only supports
        // int or objects, which is okay because max bantime (1 year) is < int_max.
        QSignalMapper* signalMapper = new QSignalMapper(this);
        signalMapper->setMapping(banAction1h, 60*60);
        signalMapper->setMapping(banAction24h, 60*60*24);
        signalMapper->setMapping(banAction7d, 60*60*24*7);
        signalMapper->setMapping(banAction365d, 60*60*24*365);
        connect(banAction1h, SIGNAL(triggered()), signalMapper, SLOT(map()));
        connect(banAction24h, SIGNAL(triggered()), signalMapper, SLOT(map()));
        connect(banAction7d, SIGNAL(triggered()), signalMapper, SLOT(map()));
        connect(banAction365d, SIGNAL(triggered()), signalMapper, SLOT(map()));
        connect(signalMapper, SIGNAL(mapped(int)), this, SLOT(banSelectedNode(int)));

        // peer table context menu signals
        connect(ui->peerWidget, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showPeersTableContextMenu(const QPoint&)));
        connect(disconnectAction, SIGNAL(triggered()), this, SLOT(disconnectSelectedNode()));

        // peer table signal handling - update peer details when selecting new node
        connect(ui->peerWidget->selectionModel(), SIGNAL(selectionChanged(const QItemSelection&, const QItemSelection&)),
            this, SLOT(peerSelected(const QItemSelection &, const QItemSelection &)));
        // peer table signal handling - update peer details when new nodes are added to the model
        connect(model->getPeerTableModel(), SIGNAL(layoutChanged()), this, SLOT(peerLayoutChanged()));

        // set up ban table
        ui->banlistWidget->setModel(model->getBanTableModel());
        ui->banlistWidget->verticalHeader()->hide();
        ui->banlistWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        ui->banlistWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        ui->banlistWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        ui->banlistWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        ui->banlistWidget->setColumnWidth(BanTableModel::Address, BANSUBNET_COLUMN_WIDTH);
        ui->banlistWidget->setColumnWidth(BanTableModel::Bantime, BANTIME_COLUMN_WIDTH);
        ui->banlistWidget->horizontalHeader()->setStretchLastSection(true);

        // create ban table context menu action
        QAction* unbanAction = new QAction(tr("&Unban Node"), this);

        // create ban table context menu
        banTableContextMenu = new QMenu();
        banTableContextMenu->addAction(unbanAction);

        // ban table context menu signals
        connect(ui->banlistWidget, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showBanTableContextMenu(const QPoint&)));
        connect(unbanAction, SIGNAL(triggered()), this, SLOT(unbanSelectedNode()));

        // ban table signal handling - clear peer details when clicking a peer in the ban table
        connect(ui->banlistWidget, SIGNAL(clicked(const QModelIndex&)), this, SLOT(clearSelectedNode()));
        // ban table signal handling - ensure ban table is shown or hidden (if empty)
        connect(model->getBanTableModel(), SIGNAL(layoutChanged()), this, SLOT(showOrHideBanTableIfRequired()));
        showOrHideBanTableIfRequired();

        // Provide initial values
        ui->clientVersion->setText(model->formatFullVersionWithCodename());
        ui->clientName->setText(model->clientName());
        ui->buildDate->setText(model->formatBuildDate());
        ui->dataDir->setText(model->dataDir());
        ui->startupTime->setText(model->formatClientStartupTime());
        ui->networkName->setText(QString::fromStdString(Params().NetworkIDString()));

        //Setup autocomplete and attach it
        QStringList wordList;
        std::vector<std::string> commandList = tableRPC.listCommands();
        for (size_t i = 0; i < commandList.size(); ++i)
        {
            wordList << commandList[i].c_str();
            wordList << ("help " + commandList[i]).c_str();
        }

        wordList.sort();
        autoCompleter = new QCompleter(wordList, this);
        autoCompleter->setModelSorting(QCompleter::CaseSensitivelySortedModel);
        ui->lineEdit->setCompleter(autoCompleter);

        // clear the lineEdit after activating from QCompleter
        autoCompleter->popup()->installEventFilter(this);
    }
}

void RPCConsole::setWalletModel(WalletModel* walletModel)
{
    this->walletModel = walletModel;
}


static QString categoryClass(int category)
{
    switch (category) {
    case RPCConsole::CMD_REQUEST:
        return "cmd-request";
        break;
    case RPCConsole::CMD_REPLY:
        return "cmd-reply";
        break;
    case RPCConsole::CMD_ERROR:
        return "cmd-error";
        break;
    default:
        return "misc";
    }
}

/** Restart wallet with "-salvagewallet" */
void RPCConsole::walletSalvage()
{
    buildParameterlist(SALVAGEWALLET);
}

/** Restart wallet with "-rescan" */
void RPCConsole::walletRescan()
{
    buildParameterlist(RESCAN);
}

/** Restart wallet with "-zapwallettxes=1" */
void RPCConsole::walletZaptxes1()
{
    buildParameterlist(ZAPTXES1);
}

/** Restart wallet with "-zapwallettxes=2" */
void RPCConsole::walletZaptxes2()
{
    buildParameterlist(ZAPTXES2);
}

/** Restart wallet with "-upgradewallet" */
void RPCConsole::walletUpgrade()
{
    buildParameterlist(UPGRADEWALLET);
}

/** Restart wallet with "-reindex" */
void RPCConsole::walletReindex()
{
    buildParameterlist(REINDEX);
}

/** Restart wallet with "-resync" */
void RPCConsole::walletResync()
{
    QString resyncWarning = tr("This will delete your local blockchain folders and the wallet will synchronize the complete Blockchain from scratch.<br /><br />");
        resyncWarning +=   tr("This needs quite some time and downloads a lot of data.<br /><br />");
        resyncWarning +=   tr("Your transactions and funds will be visible again after the download has completed.<br /><br />");
        resyncWarning +=   tr("Do you want to continue?.<br />");
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm resync Blockchain"),
        resyncWarning,
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if (retval != QMessageBox::Yes) {
        // Resync canceled
        return;
    }

    // Restart and resync
    buildParameterlist(RESYNC);
}

/** Restart wallet with "-resync" and upgrade to a HD wallet*/
void RPCConsole::walletUpgradeToHd()
{
    QString upgradeWarning = tr("This will convert you non-HD wallet to a HD wallet<br /><br />");
    upgradeWarning +=   tr("Make sure to make a backup of your wallet ahead of time<br /><br />");
    upgradeWarning +=   tr("You shouldn't force close the wallet while this is running<br /><br />");
    upgradeWarning +=   tr("Do you want to continue?.<br />");
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm upgrade to HD wallet"),
                                                               upgradeWarning,
                                                               QMessageBox::Yes | QMessageBox::Cancel,
                                                               QMessageBox::Cancel);

    if (retval != QMessageBox::Yes) {
        // Resync canceled
        return;
    }

    if (IsInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Cannot set a new HD seed while still in Initial Block Download");
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Do not do anything to HD wallets
    if (pwalletMain->IsHDEnabled()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot upgrade a wallet to hd if It is already upgraded to hd.");
    }

    std::vector<std::string> words;
    SecureString strWalletPass;
    strWalletPass.reserve(100);

    int prev_version = pwalletMain->GetVersion();

    int nMaxVersion = GetArg("-upgradewallet", 0);
    if (nMaxVersion == 0) // the -upgradewallet without argument case
    {
        LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
        nMaxVersion = CLIENT_VERSION;
        pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
    } else
        LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
    if (nMaxVersion < pwalletMain->GetVersion()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot downgrade wallet");
    }

    pwalletMain->SetMaxVersion(nMaxVersion);

    // Do not upgrade versions to any version between HD_SPLIT and FEATURE_PRE_SPLIT_KEYPOOL unless already supporting HD_SPLIT
    int max_version = pwalletMain->GetVersion();
    if (!pwalletMain->CanSupportFeature(FEATURE_HD) && max_version >=FEATURE_HD && max_version < FEATURE_PRE_SPLIT_KEYPOOL) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot upgrade a non HD split wallet without upgrading to support pre split keypool. Please use -upgradewallet=169900 or -upgradewallet with no version specified.");
    }

    bool hd_upgrade = false;
    bool split_upgrade = false;
    if (pwalletMain->CanSupportFeature(FEATURE_HD) && !pwalletMain->IsHDEnabled()) {
        LogPrintf("Upgrading wallet to HD\n");
        pwalletMain->SetMinVersion(FEATURE_HD);

        if (walletModel->getEncryptionStatus() == WalletModel::Locked || walletModel->getEncryptionStatus() == WalletModel::UnlockedForStaking) {
            AskPassphraseDialog dlg(AskPassphraseDialog::Mode::Unlock, this, walletModel, AskPassphraseDialog::Context::ToggleLock);
            dlg.exec();
            strWalletPass = dlg.getPassword();
        } else {
            strWalletPass = std::string().c_str();
        }

        StartOptionsMain dlg(nullptr);
        dlg.exec();
        words = dlg.getWords();

        pwalletMain->GenerateNewHDChain(words, strWalletPass);

        hd_upgrade = true;
    }

    // Upgrade to HD chain split if necessary
    if (pwalletMain->CanSupportFeature(FEATURE_HD)) {
        LogPrintf("Upgrading wallet to use HD chain split\n");
        pwalletMain->SetMinVersion(FEATURE_PRE_SPLIT_KEYPOOL);
        split_upgrade = FEATURE_HD > prev_version;
    }

    // Mark all keys currently in the keypool as pre-split
    if (split_upgrade) {
        pwalletMain->MarkPreSplitKeys();
    }

    // Regenerate the keypool if upgraded to HD
    if (hd_upgrade) {
        if (!pwalletMain->TopUpKeyPool()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unable to generate keys\n");
        }
    }

    buildParameterlist(RESCAN);

}


/** Build command-line parameter list for restart */
void RPCConsole::buildParameterlist(QString arg)
{
    // Get command-line arguments and remove the application name
    QStringList args = QApplication::arguments();
    args.removeFirst();

    // Remove existing repair-options
    args.removeAll(SALVAGEWALLET);
    args.removeAll(RESCAN);
    args.removeAll(ZAPTXES1);
    args.removeAll(ZAPTXES2);
    args.removeAll(UPGRADEWALLET);
    args.removeAll(REINDEX);

    // Append repair parameter to command line.
    args.append(arg);

    // Send command-line arguments to BitcoinGUI::handleRestart()
    Q_EMIT handleRestart(args);
}

void RPCConsole::clear()
{
    ui->messagesWidget->clear();
    history.clear();
    historyPtr = 0;
    ui->lineEdit->clear();
    ui->lineEdit->setFocus();

    // Add smoothly scaled icon images.
    // (when using width/height on an img, Qt uses nearest instead of linear interpolation)
    for (int i = 0; ICON_MAPPING[i].url; ++i) {
        ui->messagesWidget->document()->addResource(
            QTextDocument::ImageResource,
            QUrl(ICON_MAPPING[i].url),
            QImage(ICON_MAPPING[i].source).scaled(ICON_SIZE, Qt::IgnoreAspectRatio, Qt::SmoothTransformation));
    }

    // Set default style sheet
    ui->messagesWidget->document()->setDefaultStyleSheet(
        "table { }"
        "td.time { color: #808080; padding-top: 3px; } "
        "td.message { font-family: Courier, Courier New, Lucida Console, monospace; font-size: 12px; } " // Todo: Remove fixed font-size
        "td.cmd-request { color: #006060; } "
        "td.cmd-error { color: red; } "
        ".secwarning { color: red; }"
        "b { color: #006060; } ");

#ifdef Q_OS_MAC
    QString clsKey = "(⌘)-L";
#else
    QString clsKey = "Ctrl-L";
#endif

    message(CMD_REPLY, (tr("Welcome to the DIGIWAGE RPC console.") + "<br>" +
                        tr("Use up and down arrows to navigate history, and %1 to clear screen.").arg("<b>"+clsKey+"</b>") + "<br>" +
                        tr("Type <b>help</b> for an overview of available commands.") +
                        "<br><span class=\"secwarning\"><br>" +
                        tr("WARNING: Scammers have been active, telling users to type commands here, stealing their wallet contents. Do not use this console without fully understanding the ramifications of a command.") +
                        "</span>"),
                        true);
}

void RPCConsole::reject()
{
    // Ignore escape keypress if this is not a seperate window
    if (windowType() != Qt::Widget)
        QDialog::reject();
}

void RPCConsole::message(int category, const QString& message, bool html)
{
    QTime time = QTime::currentTime();
    QString timeString = time.toString();
    QString out;
    out += "<table><tr><td class=\"time\" width=\"65\">" + timeString + "</td>";
    out += "<td class=\"icon\" width=\"32\"><img src=\"" + categoryClass(category) + "\"></td>";
    out += "<td class=\"message " + categoryClass(category) + "\" valign=\"middle\">";
    if (html)
        out += message;
    else
        out += GUIUtil::HtmlEscape(message, true);
    out += "</td></tr></table>";
    ui->messagesWidget->append(out);
}

void RPCConsole::setNumConnections(int count)
{
    if (!clientModel)
        return;

    QString connections = QString::number(count) + " (";
    connections += tr("In:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_IN)) + " / ";
    connections += tr("Out:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_OUT)) + ")";

    ui->numberOfConnections->setText(connections);
}

void RPCConsole::setNumBlocks(int count)
{
    ui->numberOfBlocks->setText(QString::number(count));
    if (clientModel) {
        ui->lastBlockTime->setText(clientModel->getLastBlockDate().toString());
        ui->lastBlockHash->setText(clientModel->getLastBlockHash());
    }
}

void RPCConsole::setMasternodeCount(const QString& strMasternodes)
{
    ui->masternodeCount->setText(strMasternodes);
}

void RPCConsole::on_lineEdit_returnPressed()
{
    QString cmd = ui->lineEdit->text();
    ui->lineEdit->clear();

    if (!cmd.isEmpty()) {
        message(CMD_REQUEST, cmd);
        Q_EMIT cmdRequest(cmd);
        // Remove command, if already in history
        history.removeOne(cmd);
        // Append command to history
        history.append(cmd);
        // Enforce maximum history size
        while (history.size() > CONSOLE_HISTORY)
            history.removeFirst();
        // Set pointer to end of history
        historyPtr = history.size();
        // Scroll console view to end
        scrollToEnd();
    }
}

void RPCConsole::browseHistory(int offset)
{
    historyPtr += offset;
    if (historyPtr < 0)
        historyPtr = 0;
    if (historyPtr > history.size())
        historyPtr = history.size();
    QString cmd;
    if (historyPtr < history.size())
        cmd = history.at(historyPtr);
    ui->lineEdit->setText(cmd);
}

void RPCConsole::startExecutor()
{
    QThread* thread = new QThread;
    RPCExecutor* executor = new RPCExecutor();
    executor->moveToThread(thread);

    // Replies from executor object must go to this object
    connect(executor, SIGNAL(reply(int, QString)), this, SLOT(message(int, QString)));
    // Requests from this object must go to executor
    connect(this, SIGNAL(cmdRequest(QString)), executor, SLOT(request(QString)));

    // On stopExecutor signal
    // - queue executor for deletion (in execution thread)
    // - quit the Qt event loop in the execution thread
    connect(this, SIGNAL(stopExecutor()), executor, SLOT(deleteLater()));
    connect(this, SIGNAL(stopExecutor()), thread, SLOT(quit()));
    // Queue the thread for deletion (in this thread) when it is finished
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

    // Default implementation of QThread::run() simply spins up an event loop in the thread,
    // which is what we want.
    thread->start();
}

void RPCConsole::on_tabWidget_currentChanged(int index)
{
    if (ui->tabWidget->widget(index) == ui->tab_console) {
        ui->lineEdit->setFocus();
    } else if (ui->tabWidget->widget(index) != ui->tab_peers) {
        clearSelectedNode();
    }
}

void RPCConsole::on_openDebugLogfileButton_clicked()
{
    GUIUtil::openDebugLogfile();
}

void RPCConsole::scrollToEnd()
{
    QScrollBar* scrollbar = ui->messagesWidget->verticalScrollBar();
    scrollbar->setValue(scrollbar->maximum());
}

void RPCConsole::on_sldGraphRange_valueChanged(int value)
{
    const int multiplier = 5; // each position on the slider represents 5 min
    int mins = value * multiplier;
    setTrafficGraphRange(mins);
}

QString RPCConsole::FormatBytes(quint64 bytes)
{
    if (bytes < 1024)
        return QString(tr("%1 B")).arg(bytes);
    if (bytes < 1024 * 1024)
        return QString(tr("%1 KB")).arg(bytes / 1024);
    if (bytes < 1024 * 1024 * 1024)
        return QString(tr("%1 MB")).arg(bytes / 1024 / 1024);

    return QString(tr("%1 GB")).arg(bytes / 1024 / 1024 / 1024);
}

void RPCConsole::setTrafficGraphRange(int mins)
{
    ui->trafficGraph->setGraphRangeMins(mins);
    ui->lblGraphRange->setText(GUIUtil::formatDurationStr(mins * 60));
}

void RPCConsole::updateTrafficStats(quint64 totalBytesIn, quint64 totalBytesOut)
{
    ui->lblBytesIn->setText(FormatBytes(totalBytesIn));
    ui->lblBytesOut->setText(FormatBytes(totalBytesOut));
}

void RPCConsole::showInfo()
{
    ui->tabWidget->setCurrentIndex(0);
    show();
}

void RPCConsole::showConsole()
{
    ui->tabWidget->setCurrentIndex(1);
    show();
}

void RPCConsole::showNetwork()
{
    ui->tabWidget->setCurrentIndex(2);
    show();
}

void RPCConsole::showPeers()
{
    ui->tabWidget->setCurrentIndex(3);
    show();
}

void RPCConsole::showRepair()
{
    ui->tabWidget->setCurrentIndex(4);
    show();
}

void RPCConsole::showConfEditor()
{
    GUIUtil::openConfigfile();
}

void RPCConsole::showMNConfEditor()
{
    GUIUtil::openMNConfigfile();
}

void RPCConsole::peerSelected(const QItemSelection& selected, const QItemSelection& deselected)
{
    Q_UNUSED(deselected);

    if (!clientModel || !clientModel->getPeerTableModel() || selected.indexes().isEmpty())
        return;

    const CNodeCombinedStats* stats = clientModel->getPeerTableModel()->getNodeStats(selected.indexes().first().row());
    if (stats)
        updateNodeDetail(stats);
}

void RPCConsole::peerLayoutChanged()
{
    if (!clientModel || !clientModel->getPeerTableModel())
        return;

    const CNodeCombinedStats* stats = NULL;
    bool fUnselect = false;
    bool fReselect = false;

    if (cachedNodeid == -1) // no node selected yet
        return;

    // find the currently selected row
    int selectedRow = -1;
    QModelIndexList selectedModelIndex = ui->peerWidget->selectionModel()->selectedIndexes();
    if (!selectedModelIndex.isEmpty()) {
        selectedRow = selectedModelIndex.first().row();
    }

    // check if our detail node has a row in the table (it may not necessarily
    // be at selectedRow since its position can change after a layout change)
    int detailNodeRow = clientModel->getPeerTableModel()->getRowByNodeId(cachedNodeid);

    if (detailNodeRow < 0) {
        // detail node dissapeared from table (node disconnected)
        fUnselect = true;
    } else {
        if (detailNodeRow != selectedRow) {
            // detail node moved position
            fUnselect = true;
            fReselect = true;
        }

        // get fresh stats on the detail node.
        stats = clientModel->getPeerTableModel()->getNodeStats(detailNodeRow);
    }

    if (fUnselect && selectedRow >= 0) {
        clearSelectedNode();
    }

    if (fReselect) {
        ui->peerWidget->selectRow(detailNodeRow);
    }

    if (stats)
        updateNodeDetail(stats);
}

void RPCConsole::updateNodeDetail(const CNodeCombinedStats* stats)
{
    // Update cached nodeid
    cachedNodeid = stats->nodeStats.nodeid;

    // update the detail ui with latest node information
    QString peerAddrDetails(QString::fromStdString(stats->nodeStats.addrName) + " ");
    peerAddrDetails += tr("(node id: %1)").arg(QString::number(stats->nodeStats.nodeid));
    if (!stats->nodeStats.addrLocal.empty())
        peerAddrDetails += "<br />" + tr("via %1").arg(QString::fromStdString(stats->nodeStats.addrLocal));
    ui->peerHeading->setText(peerAddrDetails);
    ui->peerServices->setText(GUIUtil::formatServicesStr(stats->nodeStats.nServices));
    ui->peerLastSend->setText(stats->nodeStats.nLastSend ? GUIUtil::formatDurationStr(GetTime() - stats->nodeStats.nLastSend) : tr("never"));
    ui->peerLastRecv->setText(stats->nodeStats.nLastRecv ? GUIUtil::formatDurationStr(GetTime() - stats->nodeStats.nLastRecv) : tr("never"));
    ui->peerBytesSent->setText(FormatBytes(stats->nodeStats.nSendBytes));
    ui->peerBytesRecv->setText(FormatBytes(stats->nodeStats.nRecvBytes));
    ui->peerConnTime->setText(GUIUtil::formatDurationStr(GetTime() - stats->nodeStats.nTimeConnected));
    ui->peerPingTime->setText(GUIUtil::formatPingTime(stats->nodeStats.dPingTime));
    ui->peerPingWait->setText(GUIUtil::formatPingTime(stats->nodeStats.dPingWait));
    ui->timeoffset->setText(GUIUtil::formatTimeOffset(stats->nodeStats.nTimeOffset));
    ui->peerVersion->setText(QString("%1").arg(QString::number(stats->nodeStats.nVersion)));
    ui->peerSubversion->setText(QString::fromStdString(stats->nodeStats.cleanSubVer));
    ui->peerDirection->setText(stats->nodeStats.fInbound ? tr("Inbound") : tr("Outbound"));
    ui->peerHeight->setText(QString("%1").arg(QString::number(stats->nodeStats.nStartingHeight)));
    ui->peerWhitelisted->setText(stats->nodeStats.fWhitelisted ? tr("Yes") : tr("No"));

    // This check fails for example if the lock was busy and
    // nodeStateStats couldn't be fetched.
    if (stats->fNodeStateStatsAvailable) {
        // Ban score is init to 0
        ui->peerBanScore->setText(QString("%1").arg(stats->nodeStateStats.nMisbehavior));

        // Sync height is init to -1
        if (stats->nodeStateStats.nSyncHeight > -1)
            ui->peerSyncHeight->setText(QString("%1").arg(stats->nodeStateStats.nSyncHeight));
        else
            ui->peerSyncHeight->setText(tr("Unknown"));

        // Common height is init to -1
        if (stats->nodeStateStats.nCommonHeight > -1)
            ui->peerCommonHeight->setText(QString("%1").arg(stats->nodeStateStats.nCommonHeight));
        else
            ui->peerCommonHeight->setText(tr("Unknown"));
    }

    ui->detailWidget->show();
}

void RPCConsole::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void RPCConsole::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (!clientModel || !clientModel->getPeerTableModel())
        return;

    // start PeerTableModel auto refresh
    clientModel->getPeerTableModel()->startAutoRefresh();
}

void RPCConsole::hideEvent(QHideEvent* event)
{
    QWidget::hideEvent(event);

    if (!clientModel || !clientModel->getPeerTableModel())
        return;

    // stop PeerTableModel auto refresh
    clientModel->getPeerTableModel()->stopAutoRefresh();
}

void RPCConsole::showBackups()
{
    GUIUtil::showBackups();
}

void RPCConsole::showPeersTableContextMenu(const QPoint& point)
{
    QModelIndex index = ui->peerWidget->indexAt(point);
    if (index.isValid())
    peersTableContextMenu->exec(QCursor::pos());
}

void RPCConsole::showBanTableContextMenu(const QPoint& point)
{
    QModelIndex index = ui->banlistWidget->indexAt(point);
    if (index.isValid())
        banTableContextMenu->exec(QCursor::pos());
}

void RPCConsole::disconnectSelectedNode()
{
    // Get currently selected peer address
    QString strNode = GUIUtil::getEntryData(ui->peerWidget, 0, PeerTableModel::Address);
    // Find the node, disconnect it and clear the selected node
    if (CNode *bannedNode = FindNode(strNode.toStdString())) {
        bannedNode->CloseSocketDisconnect();
        clearSelectedNode();
    }
}

void RPCConsole::banSelectedNode(int bantime)
{
    if (!clientModel)
        return;

    // Get currently selected peer address
    QString strNode = GUIUtil::getEntryData(ui->peerWidget, 0, PeerTableModel::Address);
    // Find possible nodes, ban it and clear the selected node
    if (FindNode(strNode.toStdString())) {
        std::string nStr = strNode.toStdString();
        std::string addr;
        int port = 0;
        SplitHostPort(nStr, port, addr);

        CNode::Ban(CNetAddr(addr), BanReasonManuallyAdded, bantime);

        clearSelectedNode();
        clientModel->getBanTableModel()->refresh();
    }
}

void RPCConsole::unbanSelectedNode()
{
    if (!clientModel)
        return;

    // Get currently selected ban address
    QString strNode = GUIUtil::getEntryData(ui->banlistWidget, 0, BanTableModel::Address);
    CSubNet possibleSubnet(strNode.toStdString());

    if (possibleSubnet.IsValid())
    {
        CNode::Unban(possibleSubnet);
        clientModel->getBanTableModel()->refresh();
    }
}

void RPCConsole::clearSelectedNode()
{
    ui->peerWidget->selectionModel()->clearSelection();
    cachedNodeid = -1;
    ui->detailWidget->hide();
    ui->peerHeading->setText(tr("Select a peer to view detailed information."));
}

void RPCConsole::showOrHideBanTableIfRequired()
{
    if (!clientModel)
        return;

    bool visible = clientModel->getBanTableModel()->shouldShow();
    ui->banlistWidget->setVisible(visible);
    ui->banHeading->setVisible(visible);
}
