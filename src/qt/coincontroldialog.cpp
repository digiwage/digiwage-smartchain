// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coincontroldialog.h"
#include "ui_coincontroldialog.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "init.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include "coincontrol.h"
#include "main.h"
#include "obfuscation.h"
#include "wallet/wallet.h"

#include "qt/digiwage/qtutils.h"

#include <boost/assign/list_of.hpp> // for 'map_list_of()'

#include <QApplication>
#include <QCheckBox>
#include <QCursor>
#include <QDialogButtonBox>
#include <QFlags>
#include <QIcon>
#include <QSettings>
#include <QString>
#include <QTreeWidget>

QList<CAmount> CoinControlDialog::payAmounts;
int CoinControlDialog::nSplitBlockDummy;
CCoinControl* CoinControlDialog::coinControl = new CCoinControl();


bool CCoinControlWidgetItem::operator<(const QTreeWidgetItem &other) const {
    int column = treeWidget()->sortColumn();
    if (column == CoinControlDialog::COLUMN_AMOUNT || column == CoinControlDialog::COLUMN_DATE || column == CoinControlDialog::COLUMN_CONFIRMATIONS)
        return data(column, Qt::UserRole).toLongLong() < other.data(column, Qt::UserRole).toLongLong();
    return QTreeWidgetItem::operator<(other);
}


CoinControlDialog::CoinControlDialog(QWidget* parent, bool fMultisigEnabled) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                        ui(new Ui::CoinControlDialog),
                                                        model(0)
{
    ui->setupUi(this);

    /* Open CSS when configured */
    this->setStyleSheet(GUIUtil::loadStyleSheet());

    setCssProperty({ui->frameContainer,
                    ui->layoutAmount,
                    ui->layoutAfter,
                    ui->layoutBytes,
                    ui->layoutChange,
                    ui->layoutDust,
                    ui->layoutFee,
                    ui->layoutQuantity
                    }, "container-border-purple");

    // Title
    ui->labelTitle->setProperty("cssClass", "text-title-dialog");

    // Label Style
    setCssProperty({ui->labelCoinControlAfterFeeText,
                    ui->labelCoinControlAmountText,
                    ui->labelCoinControlBytesText,
                    ui->labelCoinControlChangeText,
                    ui->labelCoinControlLowOutputText,
                    ui->labelCoinControlFeeText,
                    ui->labelCoinControlQuantityText
                    }, "text-main-purple");

    // Value Style
    setCssProperty({ui->labelCoinControlAfterFee,
                    ui->labelCoinControlAmount,
                    ui->labelCoinControlBytes,
                    ui->labelCoinControlChange,
                    ui->labelCoinControlLowOutput,
                    ui->labelCoinControlFee,
                    ui->labelCoinControlQuantity
                    }, "text-main-purple");

    ui->groupBox_2->setProperty("cssClass", "group-box");
    ui->treeWidget->setProperty("cssClass", "table-tree");
    ui->labelLocked->setProperty("cssClass", "text-main-purple");

    // Buttons
    setCssProperty({ui->pushButtonSelectAll, ui->pushButtonToggleLock}, "btn-check");
    ui->btnEsc->setProperty("cssClass", "ic-close");
    ui->pushButtonOk->setProperty("cssClass", "btn-primary");

    connect(ui->btnEsc, SIGNAL(clicked()), this, SLOT(close()));

    this->fMultisigEnabled = fMultisigEnabled;

    // context menu actions
    QAction* copyAddressAction = new QAction(tr("Copy address"), this);
    QAction* copyLabelAction = new QAction(tr("Copy label"), this);
    QAction* copyAmountAction = new QAction(tr("Copy amount"), this);
    copyTransactionHashAction = new QAction(tr("Copy transaction ID"), this); // we need to enable/disable this
    lockAction = new QAction(tr("Lock unspent"), this);                       // we need to enable/disable this
    unlockAction = new QAction(tr("Unlock unspent"), this);                   // we need to enable/disable this

    // context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyAmountAction);
    contextMenu->addAction(copyTransactionHashAction);
    contextMenu->addSeparator();
    contextMenu->addAction(lockAction);
    contextMenu->addAction(unlockAction);

    // context menu signals
    connect(ui->treeWidget, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));
    connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(copyAddress()));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(copyLabel()));
    connect(copyAmountAction, SIGNAL(triggered()), this, SLOT(copyAmount()));
    connect(copyTransactionHashAction, SIGNAL(triggered()), this, SLOT(copyTransactionHash()));
    connect(lockAction, SIGNAL(triggered()), this, SLOT(lockCoin()));
    connect(unlockAction, SIGNAL(triggered()), this, SLOT(unlockCoin()));

    // clipboard actions
    setCssProperty({
        ui->pushButtonAmount,
        ui->pushButtonQuantity,
        ui->pushButtonFee,
        ui->pushButtonAlterFee,
        ui->pushButtonBytes,
        ui->pushButtonChange,
        ui->pushButtonDust
        }, "ic-copy-big"
    );

    connect(ui->pushButtonQuantity, &QPushButton::clicked, this, &CoinControlDialog::clipboardQuantity);
    connect(ui->pushButtonAmount, &QPushButton::clicked, this, &CoinControlDialog::clipboardAmount);
    connect(ui->pushButtonFee, &QPushButton::clicked, this, &CoinControlDialog::clipboardFee);
    connect(ui->pushButtonAlterFee, &QPushButton::clicked, this, &CoinControlDialog::clipboardAfterFee);
    connect(ui->pushButtonBytes, &QPushButton::clicked, this, &CoinControlDialog::clipboardBytes);
    connect(ui->pushButtonDust, &QPushButton::clicked, this, &CoinControlDialog::clipboardLowOutput);
    connect(ui->pushButtonChange, &QPushButton::clicked, this, &CoinControlDialog::clipboardChange);

    if (ui->pushButtonSelectAll->isChecked()){
        ui->pushButtonSelectAll->setText(tr("Unselect all"));
    }else{
        ui->pushButtonSelectAll->setText(tr("Select all"));
    }

    // toggle tree/list mode
    connect(ui->radioTreeMode, SIGNAL(toggled(bool)), this, SLOT(radioTreeMode(bool)));
    connect(ui->radioListMode, SIGNAL(toggled(bool)), this, SLOT(radioListMode(bool)));

    // click on checkbox
    connect(ui->treeWidget, SIGNAL(itemChanged(QTreeWidgetItem*, int)), this, SLOT(viewItemChanged(QTreeWidgetItem*, int)));

    // click on header
    ui->treeWidget->header()->setSectionsClickable(true);
    connect(ui->treeWidget->header(), SIGNAL(sectionClicked(int)), this, SLOT(headerSectionClicked(int)));

    // ok button
    connect(ui->pushButtonOk, SIGNAL(clicked()), this, SLOT(accept()));

    // (un)select all
    connect(ui->pushButtonSelectAll, SIGNAL(clicked()), this, SLOT(buttonSelectAllClicked()));

    // Toggle lock state
    connect(ui->pushButtonToggleLock, SIGNAL(clicked()), this, SLOT(buttonToggleLockClicked()));

    // change coin control first column label due Qt4 bug.
    // see https://github.com/bitcoin/bitcoin/issues/5716
    ui->treeWidget->headerItem()->setText(COLUMN_CHECKBOX, QString());

    ui->treeWidget->setColumnWidth(COLUMN_CHECKBOX, 84);
    ui->treeWidget->setColumnWidth(COLUMN_AMOUNT, 120);
    ui->treeWidget->setColumnWidth(COLUMN_LABEL, 170);
    ui->treeWidget->setColumnWidth(COLUMN_ADDRESS, 310);
    ui->treeWidget->setColumnWidth(COLUMN_DATE, 100);
    ui->treeWidget->setColumnWidth(COLUMN_CONFIRMATIONS, 100);
    ui->treeWidget->setColumnHidden(COLUMN_TXHASH, true);         // store transacton hash in this column, but dont show it
    ui->treeWidget->setColumnHidden(COLUMN_VOUT_INDEX, true);     // store vout index in this column, but dont show it

    ui->treeWidget->header()->setStretchLastSection(true);
    // default view is sorted by amount desc
    sortView(COLUMN_AMOUNT, Qt::DescendingOrder);

    // restore list mode and sortorder as a convenience feature
    QSettings settings;
    if (settings.contains("nCoinControlMode") && !settings.value("nCoinControlMode").toBool()) {
        ui->radioTreeMode->setChecked(true);
        ui->treeWidget->setRootIsDecorated(true);
        ui->radioTreeMode->click();
    }else{
        ui->radioListMode->setChecked(true);
        ui->treeWidget->setRootIsDecorated(false);
    }
    if (settings.contains("nCoinControlSortColumn") && settings.contains("nCoinControlSortOrder"))
        sortView(settings.value("nCoinControlSortColumn").toInt(), ((Qt::SortOrder)settings.value("nCoinControlSortOrder").toInt()));
}

CoinControlDialog::~CoinControlDialog()
{
    QSettings settings;
    settings.setValue("nCoinControlMode", ui->radioListMode->isChecked());
    settings.setValue("nCoinControlSortColumn", sortColumn);
    settings.setValue("nCoinControlSortOrder", (int)sortOrder);

    delete ui;
}

void CoinControlDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel() && model->getAddressTableModel()) {
        updateView();
        updateLabelLocked();
        CoinControlDialog::updateLabels(model, this);
        updateDialogLabels();
    }
}

// (un)select all
void CoinControlDialog::buttonSelectAllClicked()
{
    // "Select all": if some entry is unchecked, then check it
    // "Unselect all": if some entry is checked, then uncheck it
    Qt::CheckState wantedState = fSelectAllToggled ? Qt::Checked : Qt::Unchecked;
    ui->treeWidget->setEnabled(false);
    for (int i = 0; i < ui->treeWidget->topLevelItemCount(); i++)
        if (ui->treeWidget->topLevelItem(i)->checkState(COLUMN_CHECKBOX) != wantedState)
            ui->treeWidget->topLevelItem(i)->setCheckState(COLUMN_CHECKBOX, wantedState);
    ui->treeWidget->setEnabled(true);
    if (!fSelectAllToggled) {
        coinControl->UnSelectAll(); // just to be sure
        ui->pushButtonSelectAll->setText(tr("Select all"));
    } else {
        ui->pushButtonSelectAll->setText(tr("Unselect all"));
    }
    fSelectAllToggled = !fSelectAllToggled;
    CoinControlDialog::updateLabels(model, this);
    updateDialogLabels();
}

// Toggle lock state
void CoinControlDialog::buttonToggleLockClicked()
{
    QTreeWidgetItem* item;
    // Works in list-mode only
    if (ui->radioListMode->isChecked()) {
        ui->treeWidget->setEnabled(false);
        for (int i = 0; i < ui->treeWidget->topLevelItemCount(); i++) {
            item = ui->treeWidget->topLevelItem(i);

            COutPoint outpt(uint256(item->text(COLUMN_TXHASH).toStdString()), item->text(COLUMN_VOUT_INDEX).toUInt());
            if (model->isLockedCoin(uint256(item->text(COLUMN_TXHASH).toStdString()), item->text(COLUMN_VOUT_INDEX).toUInt())) {
                model->unlockCoin(outpt);
                item->setDisabled(false);
                // restore cold-stake snowflake icon for P2CS which were previously locked
                if (item->data(COLUMN_CHECKBOX, Qt::UserRole) == QString("Delegated"))
                    item->setIcon(COLUMN_CHECKBOX, QIcon("://ic-nav-cold-staking-active"));
                else
                    item->setIcon(COLUMN_CHECKBOX, QIcon());
            } else {
                model->lockCoin(outpt);
                item->setDisabled(true);
                item->setIcon(COLUMN_CHECKBOX, QIcon(":/icons/lock_closed"));
            }
            updateLabelLocked();
        }
        ui->treeWidget->setEnabled(true);
        CoinControlDialog::updateLabels(model, this);
        updateDialogLabels();
    } else {
        QMessageBox msgBox;
        msgBox.setObjectName("lockMessageBox");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setText(tr("Please switch to \"List mode\" to use this function."));
        msgBox.exec();
    }
}

// context menu
void CoinControlDialog::showMenu(const QPoint& point)
{
    QTreeWidgetItem* item = ui->treeWidget->itemAt(point);
    if (item) {
        contextMenuItem = item;

        // disable some items (like Copy Transaction ID, lock, unlock) for tree roots in context menu
        if (item->text(COLUMN_TXHASH).length() == 64) // transaction hash is 64 characters (this means its a child node, so its not a parent node in tree mode)
        {
            copyTransactionHashAction->setEnabled(true);
            if (model->isLockedCoin(uint256(item->text(COLUMN_TXHASH).toStdString()), item->text(COLUMN_VOUT_INDEX).toUInt())) {
                lockAction->setEnabled(false);
                unlockAction->setEnabled(true);
            } else {
                lockAction->setEnabled(true);
                unlockAction->setEnabled(false);
            }
        } else // this means click on parent node in tree mode -> disable all
        {
            copyTransactionHashAction->setEnabled(false);
            lockAction->setEnabled(false);
            unlockAction->setEnabled(false);
        }

        // show context menu
        contextMenu->exec(QCursor::pos());
    }
}

// context menu action: copy amount
void CoinControlDialog::copyAmount()
{
    GUIUtil::setClipboard(BitcoinUnits::removeSpaces(contextMenuItem->text(COLUMN_AMOUNT)));
}

// context menu action: copy label
void CoinControlDialog::copyLabel()
{
    if (ui->radioTreeMode->isChecked() && contextMenuItem->text(COLUMN_LABEL).length() == 0 && contextMenuItem->parent())
        GUIUtil::setClipboard(contextMenuItem->parent()->text(COLUMN_LABEL));
    else
        GUIUtil::setClipboard(contextMenuItem->text(COLUMN_LABEL));
}

// context menu action: copy address
void CoinControlDialog::copyAddress()
{
    if (ui->radioTreeMode->isChecked() && contextMenuItem->text(COLUMN_ADDRESS).length() == 0 && contextMenuItem->parent())
        GUIUtil::setClipboard(contextMenuItem->parent()->text(COLUMN_ADDRESS));
    else
        GUIUtil::setClipboard(contextMenuItem->text(COLUMN_ADDRESS));
}

// context menu action: copy transaction id
void CoinControlDialog::copyTransactionHash()
{
    GUIUtil::setClipboard(contextMenuItem->text(COLUMN_TXHASH));
}

// context menu action: lock coin
void CoinControlDialog::lockCoin()
{
    if (contextMenuItem->checkState(COLUMN_CHECKBOX) == Qt::Checked)
        contextMenuItem->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);

    COutPoint outpt(uint256(contextMenuItem->text(COLUMN_TXHASH).toStdString()), contextMenuItem->text(COLUMN_VOUT_INDEX).toUInt());
    model->lockCoin(outpt);
    contextMenuItem->setDisabled(true);
    contextMenuItem->setIcon(COLUMN_CHECKBOX, QIcon(":/icons/lock_closed"));
    updateLabelLocked();
}

// context menu action: unlock coin
void CoinControlDialog::unlockCoin()
{
    COutPoint outpt(uint256(contextMenuItem->text(COLUMN_TXHASH).toStdString()), contextMenuItem->text(COLUMN_VOUT_INDEX).toUInt());
    model->unlockCoin(outpt);
    contextMenuItem->setDisabled(false);
    // restore cold-stake snowflake icon for P2CS which were previously locked
    if (contextMenuItem->data(COLUMN_CHECKBOX, Qt::UserRole) == QString("Delegated"))
        contextMenuItem->setIcon(COLUMN_CHECKBOX, QIcon("://ic-nav-cold-staking-active"));
    else
        contextMenuItem->setIcon(COLUMN_CHECKBOX, QIcon());
    updateLabelLocked();
}

// copy label "Quantity" to clipboard
void CoinControlDialog::clipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
    inform(tr("Quantity Copied"));
}

// copy label "Amount" to clipboard
void CoinControlDialog::clipboardAmount()
{
    GUIUtil::setClipboard(BitcoinUnits::removeSpaces(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" "))));
    inform(tr("Amount Copied"));
}

// copy label "Fee" to clipboard
void CoinControlDialog::clipboardFee()
{
    GUIUtil::setClipboard(BitcoinUnits::removeSpaces(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace("~", "")));
    inform(tr("Fee Copied"));
}

// copy label "After fee" to clipboard
void CoinControlDialog::clipboardAfterFee()
{
    GUIUtil::setClipboard(BitcoinUnits::removeSpaces(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace("~", "")));
    inform(tr("After Fee Copied"));
}

// copy label "Bytes" to clipboard
void CoinControlDialog::clipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace("~", ""));
    inform(tr("Bytes Copied"));
}

// copy label "Dust" to clipboard
void CoinControlDialog::clipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
    inform(tr("Dust Copied"));
}

// copy label "Change" to clipboard
void CoinControlDialog::clipboardChange()
{
    GUIUtil::setClipboard(BitcoinUnits::removeSpaces(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace("~", "")));
    inform(tr("Change Copied"));
}

// treeview: sort
void CoinControlDialog::sortView(int column, Qt::SortOrder order)
{
    sortColumn = column;
    sortOrder = order;
    ui->treeWidget->sortItems(column, order);
    ui->treeWidget->header()->setSortIndicator(sortColumn, sortOrder);
}

// treeview: clicked on header
void CoinControlDialog::headerSectionClicked(int logicalIndex)
{
    if (logicalIndex == COLUMN_CHECKBOX) // click on most left column -> do nothing
    {
        ui->treeWidget->header()->setSortIndicator(sortColumn, sortOrder);
    } else {
        if (sortColumn == logicalIndex)
            sortOrder = ((sortOrder == Qt::AscendingOrder) ? Qt::DescendingOrder : Qt::AscendingOrder);
        else {
            sortColumn = logicalIndex;
            sortOrder = ((sortColumn == COLUMN_LABEL || sortColumn == COLUMN_ADDRESS) ? Qt::AscendingOrder : Qt::DescendingOrder); // if label or address then default => asc, else default => desc
        }

        sortView(sortColumn, sortOrder);
    }
}

// toggle tree mode
void CoinControlDialog::radioTreeMode(bool checked)
{
    if (checked && model)
        updateView();
}

// toggle list mode
void CoinControlDialog::radioListMode(bool checked)
{
    if (checked && model)
        updateView();
}

// checkbox clicked by user
void CoinControlDialog::viewItemChanged(QTreeWidgetItem* item, int column)
{
    if (column == COLUMN_CHECKBOX && item->text(COLUMN_TXHASH).length() == 64) // transaction hash is 64 characters (this means its a child node, so its not a parent node in tree mode)
    {
        COutPoint outpt(uint256(item->text(COLUMN_TXHASH).toStdString()), item->text(COLUMN_VOUT_INDEX).toUInt());

        if (item->checkState(COLUMN_CHECKBOX) == Qt::Unchecked)
            coinControl->UnSelect(outpt);
        else if (item->isDisabled()) // locked (this happens if "check all" through parent node)
            item->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);
        else
            coinControl->Select(outpt);

        // selection changed -> update labels
        if (ui->treeWidget->isEnabled()){ // do not update on every click for (un)select all
            CoinControlDialog::updateLabels(model, this);
            updateDialogLabels();
        }
    }

    // TODO: Remove this temporary qt5 fix after Qt5.3 and Qt5.4 are no longer used.
    //       Fixed in Qt5.5 and above: https://bugreports.qt.io/browse/QTBUG-43473
    else if (column == COLUMN_CHECKBOX && item->childCount() > 0)
    {
        if (item->checkState(COLUMN_CHECKBOX) == Qt::PartiallyChecked && item->child(0)->checkState(COLUMN_CHECKBOX) == Qt::PartiallyChecked)
            item->setCheckState(COLUMN_CHECKBOX, Qt::Checked);
    }
}

// return human readable label for priority number
QString CoinControlDialog::getPriorityLabel(double dPriority, double mempoolEstimatePriority)
{
    double dPriorityMedium = mempoolEstimatePriority;

    if (dPriorityMedium <= 0)
        dPriorityMedium = AllowFreeThreshold(); // not enough data, back to hard-coded

    if (dPriority / 1000000 > dPriorityMedium)
        return tr("highest");
    else if (dPriority / 100000 > dPriorityMedium)
        return tr("higher");
    else if (dPriority / 10000 > dPriorityMedium)
        return tr("high");
    else if (dPriority / 1000 > dPriorityMedium)
        return tr("medium-high");
    else if (dPriority > dPriorityMedium)
        return tr("medium");
    else if (dPriority * 10 > dPriorityMedium)
        return tr("low-medium");
    else if (dPriority * 100 > dPriorityMedium)
        return tr("low");
    else if (dPriority * 1000 > dPriorityMedium)
        return tr("lower");
    else
        return tr("lowest");
}

// shows count of locked unspent outputs
void CoinControlDialog::updateLabelLocked()
{
    std::vector<COutPoint> vOutpts;
    model->listLockedCoins(vOutpts);
    if (vOutpts.size() > 0) {
        ui->labelLocked->setText(tr("(%1 locked)").arg(vOutpts.size()));
        ui->labelLocked->setVisible(true);
    } else
        ui->labelLocked->setVisible(false);
}

void CoinControlDialog::updateDialogLabels()
{

    if (this->parentWidget() == nullptr) {
        CoinControlDialog::updateLabels(model, this);
        return;
    }

    std::vector<COutPoint> vCoinControl;
    std::vector<COutput> vOutputs;
    coinControl->ListSelected(vCoinControl);
    model->getOutputs(vCoinControl, vOutputs);

    CAmount nAmount = 0;
    unsigned int nQuantity = 0;
    for (const COutput& out : vOutputs) {
        // unselect already spent, very unlikely scenario, this could happen
        // when selected are spent elsewhere, like rpc or another computer
        uint256 txhash = out.tx->GetHash();
        COutPoint outpt(txhash, out.i);
        if(model->isSpent(outpt)) {
            coinControl->UnSelect(outpt);
            continue;
        }

        // Quantity
        nQuantity++;

        // Amount
        nAmount += out.tx->vout[out.i].nValue;
    }
}

void CoinControlDialog::updateLabels(WalletModel* model, QDialog* dialog)
{
    if (!model)
        return;

    // nPayAmount
    CAmount nPayAmount = 0;
    bool fDust = false;
    CMutableTransaction txDummy;
    Q_FOREACH (const CAmount& amount, CoinControlDialog::payAmounts) {
        nPayAmount += amount;

        if (amount > 0) {
            CTxOut txout(amount, (CScript)std::vector<unsigned char>(24, 0));
            txDummy.vout.push_back(txout);
            if (txout.IsDust(::minRelayTxFee))
                fDust = true;
        }
    }

    QString sPriorityLabel = tr("none");
    CAmount nAmount = 0;
    CAmount nPayFee = 0;
    CAmount nAfterFee = 0;
    CAmount nChange = 0;
    unsigned int nBytes = 0;
    unsigned int nBytesInputs = 0;
    double dPriority = 0;
    double dPriorityInputs = 0;
    unsigned int nQuantity = 0;
    int nQuantityUncompressed = 0;
    bool fAllowFree = false;

    std::vector<COutPoint> vCoinControl;
    std::vector<COutput> vOutputs;
    coinControl->ListSelected(vCoinControl);
    model->getOutputs(vCoinControl, vOutputs);

    for (const COutput& out : vOutputs) {
        // unselect already spent, very unlikely scenario, this could happen
        // when selected are spent elsewhere, like rpc or another computer
        uint256 txhash = out.tx->GetHash();
        COutPoint outpt(txhash, out.i);
        if (model->isSpent(outpt)) {
            coinControl->UnSelect(outpt);
            continue;
        }

        // Quantity
        nQuantity++;

        // Amount
        nAmount += out.tx->vout[out.i].nValue;

        // Priority
        dPriorityInputs += (double)out.tx->vout[out.i].nValue * (out.nDepth + 1);

        // Bytes
        CTxDestination address;
        if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address)) {
            CPubKey pubkey;
            CKeyID* keyid = boost::get<CKeyID>(&address);
            if (keyid && model->getPubKey(*keyid, pubkey)) {
                nBytesInputs += (pubkey.IsCompressed() ? 148 : 180);
                if (!pubkey.IsCompressed())
                    nQuantityUncompressed++;
            } else
                nBytesInputs += 148; // in all error cases, simply assume 148 here
        } else
            nBytesInputs += 148;
    }

    // calculation
    if (nQuantity > 0) {
        // Bytes
        nBytes = nBytesInputs + ((CoinControlDialog::payAmounts.size() > 0 ? CoinControlDialog::payAmounts.size() + std::max(1, CoinControlDialog::nSplitBlockDummy) : 2) * 34) + 10; // always assume +1 output for change here

        // Priority
        double mempoolEstimatePriority = mempool.estimatePriority(nTxConfirmTarget);
        dPriority = dPriorityInputs / (nBytes - nBytesInputs + (nQuantityUncompressed * 29)); // 29 = 180 - 151 (uncompressed public keys are over the limit. max 151 bytes of the input are ignored for priority)
        sPriorityLabel = CoinControlDialog::getPriorityLabel(dPriority, mempoolEstimatePriority);

        // Fee
        nPayFee = CWallet::GetMinimumFee(nBytes, nTxConfirmTarget, mempool);

        // IX Fee
        if (coinControl->useSwiftTX) nPayFee = std::max(nPayFee, CENT);
        // Allow free?
        double dPriorityNeeded = mempoolEstimatePriority;
        if (dPriorityNeeded <= 0)
            dPriorityNeeded = AllowFreeThreshold(); // not enough data, back to hard-coded
        fAllowFree = (dPriority >= dPriorityNeeded);

        if (fSendFreeTransactions)
            if (fAllowFree && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE)
                nPayFee = 0;

        if (nPayAmount > 0) {
            nChange = nAmount - nPayFee - nPayAmount;

            // Never create dust outputs; if we would, just add the dust to the fee.
            if (nChange > 0 && nChange < CENT) {
                CTxOut txout(nChange, (CScript)std::vector<unsigned char>(24, 0));
                if (txout.IsDust(::minRelayTxFee)) {
                    nPayFee += nChange;
                    nChange = 0;
                }
            }

            if (nChange == 0)
                nBytes -= 34;
        }

        // after fee
        nAfterFee = nAmount - nPayFee;
        if (nAfterFee < 0)
            nAfterFee = 0;
    }

    // actually update labels
    int nDisplayUnit = BitcoinUnits::PIV;
    if (model && model->getOptionsModel())
        nDisplayUnit = model->getOptionsModel()->getDisplayUnit();

    QLabel* l1 = dialog->findChild<QLabel*>("labelCoinControlQuantity");
    QLabel* l2 = dialog->findChild<QLabel*>("labelCoinControlAmount");
    QLabel* l3 = dialog->findChild<QLabel*>("labelCoinControlFee");
    QLabel* l4 = dialog->findChild<QLabel*>("labelCoinControlAfterFee");
    QLabel* l5 = dialog->findChild<QLabel*>("labelCoinControlBytes");
    QLabel* l7 = dialog->findChild<QLabel*>("labelCoinControlLowOutput");
    QLabel* l8 = dialog->findChild<QLabel*>("labelCoinControlChange");

    // enable/disable "dust" and "change"
    dialog->findChild<QLabel*>("labelCoinControlLowOutputText")->setEnabled(nPayAmount > 0);
    dialog->findChild<QLabel*>("labelCoinControlLowOutput")->setEnabled(nPayAmount > 0);
    dialog->findChild<QLabel*>("labelCoinControlChangeText")->setEnabled(nPayAmount > 0);
    dialog->findChild<QLabel*>("labelCoinControlChange")->setEnabled(nPayAmount > 0);

    // stats
    l1->setText(QString::number(nQuantity));                            // Quantity
    l2->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, nAmount));   // Amount
    l3->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, nPayFee));   // Fee
    l4->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, nAfterFee)); // After Fee
    l5->setText(((nBytes > 0) ? "~" : "") + QString::number(nBytes));   // Bytes
    l7->setText(fDust ? tr("yes") : tr("no"));                          // Dust
    l8->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, nChange));   // Change
    if (nPayFee > 0 && !(payTxFee.GetFeePerK() > 0 && fPayAtLeastCustomFee && nBytes < 1000)) {
        l3->setText("~" + l3->text());
        l4->setText("~" + l4->text());
        if (nChange > 0)
            l8->setText("~" + l8->text());
    }

    // turn labels "red"
    l5->setStyleSheet((nBytes >= MAX_FREE_TRANSACTION_CREATE_SIZE) ? "color:red;" : ""); // Bytes >= 1000
    l7->setStyleSheet((fDust) ? "color:red;" : "");                                      // Dust = "yes"

    // tool tips
    QString toolTip1 = tr("This label turns red, if the transaction size is greater than 1000 bytes.") + "<br /><br />";
    toolTip1 += tr("This means a fee of at least %1 per kB is required.").arg(BitcoinUnits::formatWithUnit(nDisplayUnit, CWallet::minTxFee.GetFeePerK())) + "<br /><br />";
    toolTip1 += tr("Can vary +/- 1 byte per input.");

    QString toolTip2 = tr("Transactions with higher priority are more likely to get included into a block.") + "<br /><br />";
    toolTip2 += tr("This label turns red, if the priority is smaller than \"medium\".") + "<br /><br />";
    toolTip2 += tr("This means a fee of at least %1 per kB is required.").arg(BitcoinUnits::formatWithUnit(nDisplayUnit, CWallet::minTxFee.GetFeePerK()));

    QString toolTip3 = tr("This label turns red, if any recipient receives an amount smaller than %1.").arg(BitcoinUnits::formatWithUnit(nDisplayUnit, ::minRelayTxFee.GetFee(546)));

    // how many zens the estimated fee can vary per byte we guess wrong
    double dFeeVary;
    if (payTxFee.GetFeePerK() > 0)
        dFeeVary = (double)std::max(CWallet::minTxFee.GetFeePerK(), payTxFee.GetFeePerK()) / 1000;
    else
        dFeeVary = (double)std::max(CWallet::minTxFee.GetFeePerK(), mempool.estimateFee(nTxConfirmTarget).GetFeePerK()) / 1000;
    QString toolTip4 = tr("Can vary +/- %1 uWAGE per input.").arg(dFeeVary);

    l3->setToolTip(toolTip4);
    l4->setToolTip(toolTip4);
    l5->setToolTip(toolTip1);
    l7->setToolTip(toolTip3);
    l8->setToolTip(toolTip4);
    dialog->findChild<QLabel*>("labelCoinControlFeeText")->setToolTip(l3->toolTip());
    dialog->findChild<QLabel*>("labelCoinControlAfterFeeText")->setToolTip(l4->toolTip());
    dialog->findChild<QLabel*>("labelCoinControlBytesText")->setToolTip(l5->toolTip());
    dialog->findChild<QLabel*>("labelCoinControlLowOutputText")->setToolTip(l7->toolTip());
    dialog->findChild<QLabel*>("labelCoinControlChangeText")->setToolTip(l8->toolTip());

    // Insufficient funds
    QLabel* label = dialog->findChild<QLabel*>("labelCoinControlInsuffFunds");
    if (label)
        label->setVisible(nChange < 0);
}

void CoinControlDialog::updateView()
{
    if (!model || !model->getOptionsModel() || !model->getAddressTableModel())
        return;

    bool treeMode = ui->radioTreeMode->isChecked();

    if(treeMode){
        ui->treeWidget->setRootIsDecorated(true);
    }else{
        ui->treeWidget->setRootIsDecorated(false);
    }

    ui->treeWidget->clear();
    ui->treeWidget->setEnabled(false); // performance, otherwise updateLabels would be called for every checked checkbox
    QFlags<Qt::ItemFlag> flgCheckbox = Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsUserCheckable;
    QFlags<Qt::ItemFlag> flgTristate = Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsUserCheckable | Qt::ItemIsTristate;

    int nDisplayUnit = model->getOptionsModel()->getDisplayUnit();
//    double mempoolEstimatePriority = mempool.estimatePriority(nTxConfirmTarget);

    std::map<QString, std::vector<COutput>> mapCoins;
    model->listCoins(mapCoins);

    for (PAIRTYPE(QString, std::vector<COutput>) coins : mapCoins) {
        CCoinControlWidgetItem* itemWalletAddress = new CCoinControlWidgetItem();
        itemWalletAddress->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);
        QString sWalletAddress = coins.first;
        QString sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");

        if (treeMode) {
            // wallet address
            ui->treeWidget->addTopLevelItem(itemWalletAddress);

            itemWalletAddress->setFlags(flgTristate);
            itemWalletAddress->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);

            // label
            itemWalletAddress->setText(COLUMN_LABEL, sWalletLabel);
            itemWalletAddress->setToolTip(COLUMN_LABEL, sWalletLabel);

            // address
            itemWalletAddress->setText(COLUMN_ADDRESS, sWalletAddress);
            itemWalletAddress->setToolTip(COLUMN_ADDRESS, sWalletAddress);
        }

        CAmount nSum = 0;
        double dPrioritySum = 0;
        int nChildren = 0;
        int nInputSum = 0;
        for(const COutput& out: coins.second) {
            isminetype mine = pwalletMain->IsMine(out.tx->vout[out.i]);
            bool fMultiSigUTXO = (mine & ISMINE_MULTISIG);
            // when multisig is enabled, it will only display outputs from multisig addresses
            if (fMultisigEnabled && !fMultiSigUTXO)
                continue;
            int nInputSize = 0;
            nSum += out.tx->vout[out.i].nValue;
            nChildren++;

            CCoinControlWidgetItem* itemOutput;
            if (treeMode)
                itemOutput = new CCoinControlWidgetItem(itemWalletAddress);
            else
                itemOutput = new CCoinControlWidgetItem(ui->treeWidget);
            itemOutput->setFlags(flgCheckbox);
            itemOutput->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);

            //MultiSig
            if (fMultiSigUTXO) {

                if (!fMultisigEnabled) {
                    COutPoint outpt(out.tx->GetHash(), out.i);
                    coinControl->UnSelect(outpt); // just to be sure
                    itemOutput->setDisabled(true);
                    itemOutput->setIcon(COLUMN_CHECKBOX, QIcon(":/icons/lock_closed"));
                }
            }

            // address
            const bool fDelegated = (bool)(mine & ISMINE_SPENDABLE_DELEGATED);
            CTxDestination outputAddress;
            CTxDestination outputAddressStaker;
            QString sAddress = "";
            bool haveDest = false;
            if (fDelegated) {
                txnouttype type; std::vector<CTxDestination> addresses; int nRequired;
                haveDest = (ExtractDestinations(out.tx->vout[out.i].scriptPubKey, type, addresses, nRequired)
                            && addresses.size() == 2);
                if (haveDest) {
                    outputAddressStaker = addresses[0];
                    outputAddress = addresses[1];
                }
            } else {
                haveDest = ExtractDestination(out.tx->vout[out.i].scriptPubKey, outputAddress);
            }
            if (haveDest) {
                sAddress = QString::fromStdString(CBitcoinAddress(outputAddress).ToString());

                // if listMode or change => show DIGIWAGE address. In tree mode, address is not shown again for direct wallet address outputs
                if (!treeMode || (!(sAddress == sWalletAddress)))
                    itemOutput->setText(COLUMN_ADDRESS, sAddress);
                else
                    itemOutput->setToolTip(COLUMN_ADDRESS, sAddress);

                CPubKey pubkey;
                CKeyID* keyid = boost::get<CKeyID>(&outputAddress);
                if (keyid && model->getPubKey(*keyid, pubkey) && !pubkey.IsCompressed())
                    nInputSize = 29; // 29 = 180 - 151 (public key is 180 bytes, priority free area is 151 bytes)
            }

            // label
            if (!(sAddress == sWalletAddress)) // change
            {
                // tooltip from where the change comes from
                itemOutput->setToolTip(COLUMN_LABEL, tr("change from %1 (%2)").arg(sWalletLabel).arg(sWalletAddress));
                itemOutput->setText(COLUMN_LABEL, tr("(change)"));
            } else if (!treeMode) {
                QString sLabel = model->getAddressTableModel()->labelForAddress(sAddress);
                if (sLabel.isEmpty())
                    sLabel = tr("(no label)");
                itemOutput->setText(COLUMN_LABEL, sLabel);
            }

            // amount
            itemOutput->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, out.tx->vout[out.i].nValue));
            itemOutput->setToolTip(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, out.tx->vout[out.i].nValue));
            itemOutput->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong) out.tx->vout[out.i].nValue));

            // date
            itemOutput->setText(COLUMN_DATE, GUIUtil::dateTimeStr(out.tx->GetTxTime()));
            itemOutput->setToolTip(COLUMN_DATE, GUIUtil::dateTimeStr(out.tx->GetTxTime()));
            itemOutput->setData(COLUMN_DATE, Qt::UserRole, QVariant((qlonglong) out.tx->GetTxTime()));

            // confirmations
            itemOutput->setText(COLUMN_CONFIRMATIONS, QString::number(out.nDepth));
            itemOutput->setData(COLUMN_CONFIRMATIONS, Qt::UserRole, QVariant((qlonglong) out.nDepth));

            // priority
            dPrioritySum += (double)out.tx->vout[out.i].nValue * (out.nDepth + 1);
            nInputSum += nInputSize;

            // transaction hash
            uint256 txhash = out.tx->GetHash();
            itemOutput->setText(COLUMN_TXHASH, QString::fromStdString(txhash.GetHex()));

            // vout index
            itemOutput->setText(COLUMN_VOUT_INDEX, QString::number(out.i));

            // outputs delegated (for cold staking)
            if (fDelegated) {
                itemOutput->setData(COLUMN_CHECKBOX, Qt::UserRole, QString("Delegated"));
                itemOutput->setIcon(COLUMN_CHECKBOX, QIcon("://ic-nav-cold-staking-active"));
                if (haveDest) {
                    sAddress = QString::fromStdString(CBitcoinAddress(outputAddressStaker, CChainParams::STAKING_ADDRESS).ToString());
                    itemOutput->setToolTip(COLUMN_CHECKBOX, tr("delegated to %1 for Cold Staking").arg(sAddress));
                }
            }

            // disable locked coins
            if (model->isLockedCoin(txhash, out.i)) {
                COutPoint outpt(txhash, out.i);
                coinControl->UnSelect(outpt); // just to be sure
                itemOutput->setDisabled(true);
                itemOutput->setIcon(COLUMN_CHECKBOX, QIcon(":/icons/lock_closed"));
            }

            // set checkbox
            if (coinControl->IsSelected(txhash, out.i))
                itemOutput->setCheckState(COLUMN_CHECKBOX, Qt::Checked);
        }

        // amount
        if (treeMode) {
            dPrioritySum = dPrioritySum / (nInputSum + 78);
            itemWalletAddress->setText(COLUMN_CHECKBOX, "(" + QString::number(nChildren) + ")");
            itemWalletAddress->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, nSum));
            itemWalletAddress->setToolTip(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, nSum));
            itemWalletAddress->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong) nSum));
        }
    }

    // expand all partially selected
    if (treeMode) {
        for (int i = 0; i < ui->treeWidget->topLevelItemCount(); i++)
            if (ui->treeWidget->topLevelItem(i)->checkState(COLUMN_CHECKBOX) == Qt::PartiallyChecked)
                ui->treeWidget->topLevelItem(i)->setExpanded(true);
    }

    // sort view
    sortView(sortColumn, sortOrder);
    ui->treeWidget->setEnabled(true);
}

void CoinControlDialog::refreshDialog()
{
    updateView();
    updateLabelLocked();
    CoinControlDialog::updateLabels(model, this);
    updateDialogLabels();
}

void CoinControlDialog::inform(const QString& text)
{
    if (!snackBar) snackBar = new SnackBar(nullptr, this);
    snackBar->setText(text);
    snackBar->resize(this->width(), snackBar->height());
    openDialog(snackBar, this);
}
