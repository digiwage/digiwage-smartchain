// Copyright (c) 2019-2020 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/send.h"
#include "qt/digiwage/forms/ui_send.h"
#include "qt/digiwage/addnewcontactdialog.h"
#include "qt/digiwage/qtutils.h"
#include "qt/digiwage/sendchangeaddressdialog.h"
#include "qt/digiwage/optionbutton.h"
#include "qt/digiwage/sendconfirmdialog.h"
#include "qt/digiwage/myaddressrow.h"
#include "qt/digiwage/guitransactionsutils.h"
#include "clientmodel.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "coincontrol.h"
#include "script/standard.h"
#include "openuridialog.h"

SendWidget::SendWidget(DIGIWAGEGUI* parent) :
    PWidget(parent),
    ui(new Ui::send),
    coinIcon(new QPushButton()),
    btnContacts(new QPushButton())
{
    ui->setupUi(this);

    this->setStyleSheet(parent->styleSheet());

    /* Containers */
    setCssProperty(ui->left, "container");
    ui->left->setContentsMargins(0,20,0,20);
    setCssProperty(ui->right, "container-right");
    ui->right->setContentsMargins(20,10,20,20);

    /* Light Font */
    QFont fontLight;
    fontLight.setWeight(QFont::Light);

    /* Title */
    ui->labelTitle->setText(tr("Send"));
    setCssProperty(ui->labelTitle, "text-title-screen");
    ui->labelTitle->setFont(fontLight);

    /* Subtitle */
    setCssProperty(ui->labelSubtitle1, "text-subtitle");

    /* Address */
    ui->labelSubtitleAddress->setText(tr("DIGIWAGE address or contact label"));
    setCssProperty(ui->labelSubtitleAddress, "text-title");


    /* Amount */
    ui->labelSubtitleAmount->setText(tr("Amount"));
    setCssProperty(ui->labelSubtitleAmount, "text-title");

    /* Buttons */
    ui->pushButtonFee->setText(tr("Customize fee"));
    setCssBtnSecondary(ui->pushButtonFee);

    ui->pushButtonClear->setText(tr("Clear all"));
    setCssProperty(ui->pushButtonClear, "btn-secundary-clear");

    ui->pushButtonAddRecipient->setText(tr("Add recipient"));
    setCssProperty(ui->pushButtonAddRecipient, "btn-secundary-add");

    setCssBtnPrimary(ui->pushButtonSave);
    ui->pushButtonReset->setText(tr("Reset to default"));
    setCssBtnSecondary(ui->pushButtonReset);

    // Coin control
    ui->btnCoinControl->setTitleClassAndText("btn-title-grey", "Coin Control");
    ui->btnCoinControl->setSubTitleClassAndText("text-subtitle", "Select the source of the coins.");

    // Change address option
    ui->btnChangeAddress->setTitleClassAndText("btn-title-grey", "Change Address");
    ui->btnChangeAddress->setSubTitleClassAndText("text-subtitle", "Customize the change address.");

    // Uri
    ui->btnUri->setTitleClassAndText("btn-title-grey", "Open URI");
    ui->btnUri->setSubTitleClassAndText("text-subtitle", "Parse a payment request.");

    connect(ui->pushButtonFee, SIGNAL(clicked()), this, SLOT(onChangeCustomFeeClicked()));
    connect(ui->btnCoinControl, SIGNAL(clicked()), this, SLOT(onCoinControlClicked()));
    connect(ui->btnChangeAddress, SIGNAL(clicked()), this, SLOT(onChangeAddressClicked()));
    connect(ui->btnUri, SIGNAL(clicked()), this, SLOT(onOpenUriClicked()));
    connect(ui->pushButtonReset, &QPushButton::clicked, [this](){ onResetCustomOptions(true); });

    setCssProperty(ui->coinWidget, "container-coin-type");
    setCssProperty(ui->labelLine, "container-divider");


    // Total Send
    ui->labelTitleTotalSend->setText(tr("Total to send"));
    setCssProperty(ui->labelTitleTotalSend, "text-title");

    ui->labelAmountSend->setText("0.00 WAGE");
    setCssProperty(ui->labelAmountSend, "text-body1");

    // Total Remaining
    setCssProperty(ui->labelTitleTotalRemaining, "text-title");

    setCssProperty(ui->labelAmountRemaining, "text-body1");

    // Icon Send
    ui->stackedWidget->addWidget(coinIcon);
    coinIcon->show();
    coinIcon->raise();

    setCssProperty(coinIcon, "coin-icon-piv");

    QSize BUTTON_SIZE = QSize(24, 24);
    coinIcon->setMinimumSize(BUTTON_SIZE);
    coinIcon->setMaximumSize(BUTTON_SIZE);

    int posX = 0;
    int posY = 20;
    coinIcon->move(posX, posY);

    // Entry
    addEntry();

    // Connect
    connect(ui->pushButtonSave, SIGNAL(clicked()), this, SLOT(onSendClicked()));
    connect(ui->pushButtonAddRecipient, SIGNAL(clicked()), this, SLOT(onAddEntryClicked()));
    connect(ui->pushButtonClear, SIGNAL(clicked()), this, SLOT(clearAll()));
}

void SendWidget::refreshView(){
    QString btnText;
    btnText = tr("Send WAGE");
    ui->pushButtonAddRecipient->setVisible(true);
    ui->pushButtonSave->setText(btnText);

    refreshAmounts();
}

void SendWidget::refreshAmounts() {

    CAmount total = 0;
    QMutableListIterator<SendMultiRow*> it(entries);
    while (it.hasNext()) {
        SendMultiRow* entry = it.next();
        CAmount amount = entry->getAmountValue();
        if (amount > 0)
            total += amount;
    }
    nDisplayUnit = walletModel->getOptionsModel()->getDisplayUnit();

    QString strAmountSend = GUIUtil::formatBalance(total, nDisplayUnit);

    /* Fiat display */
    // Only display fiat when we're using the largest denomination of coin display
    int nPriceUSD = walletModel->getPriceUSD();
    bool fDisplayFiat = false;
    if (nDisplayUnit == BitcoinUnits::PIV) {
        // We only display fiat if we've recieved a valid price oracle, zero means we're missing data.
        if ((nPriceUSD * 0.01) >= 0.01) {
            // We have data! Convert from integer to double, then append the display.
            fDisplayFiat = true;
            float totalUSD = (total / COIN) * (nPriceUSD * 0.01);
            if (totalUSD > 0.01) {
                // To save space; Only display fiat if we have a penny or more.
                strAmountSend += QString::fromStdString(" ($" + strprintf("%.2f", totalUSD) + ")");
            }
        }
    }

    ui->labelAmountSend->setText(strAmountSend);

    CAmount totalAmount = 0;
    if (CoinControlDialog::coinControl->HasSelected()){
        // Set remaining balance to the sum of the coinControl selected inputs
        totalAmount = walletModel->getBalance(CoinControlDialog::coinControl) - total;
        ui->labelTitleTotalRemaining->setText(tr("Total Remaining (Selected UTXO)"));
    } else {
        // Wallet's available balance (Coins that are spendable right now, excluding locked, pending and immature)
        totalAmount = (walletModel->getBalance() - total) - walletModel->getLockedBalance();
        ui->labelTitleTotalRemaining->setText(tr("Total Remaining"));
    }
    QString strAmountRemaining = GUIUtil::formatBalance(totalAmount, nDisplayUnit);

    // Remaining (Fiat)
    if (fDisplayFiat) {
        float totalUSD = (totalAmount / COIN) * (nPriceUSD * 0.01);
        if (totalUSD > 0.01) {
            strAmountRemaining += QString::fromStdString(" ($" + strprintf("%.2f", totalUSD) + ")");
        }
    }

    ui->labelAmountRemaining->setText(strAmountRemaining);
}

void SendWidget::loadClientModel(){
    if (clientModel) {
        connect(clientModel, &ClientModel::numBlocksChanged, [this](){
            if (customFeeDialog) customFeeDialog->updateFee();
        });
    }
}

void SendWidget::loadWalletModel() {
    if (walletModel && walletModel->getOptionsModel()) {
        // display unit
        nDisplayUnit = walletModel->getOptionsModel()->getDisplayUnit();

        for(SendMultiRow *entry : entries){
            if(entry){
                entry->setWalletModel(walletModel);
            }
        }

        // Refresh view
        refreshView();

        // TODO: This only happen when the coin control features are modified in other screen, check before do this if the wallet has another screen modifying it.
        // Coin Control
        //connect(model->getOptionsModel(), SIGNAL(coinControlFeaturesChanged(bool)), this, SLOT(coinControlFeatureChanged(bool)));
        //ui->frameCoinControl->setVisible(model->getOptionsModel()->getCoinControlFeatures());
        //coinControlUpdateLabels();
    }
}

void SendWidget::clearAll(){
    onResetCustomOptions(false);
    if(customFeeDialog) customFeeDialog->clear();
    ui->pushButtonFee->setText(tr("Customize Fee"));
    if(walletModel) walletModel->setWalletDefaultFee();
    clearEntries();
    refreshAmounts();
}

void SendWidget::onResetCustomOptions(bool fRefreshAmounts){
    CoinControlDialog::coinControl->SetNull();
    ui->btnChangeAddress->setActive(false);
    ui->btnCoinControl->setActive(false);
    if (fRefreshAmounts) {
        refreshAmounts();
    }
}

void SendWidget::clearEntries(){
    int num = entries.length();
    for (int i = 0; i < num; ++i) {
        ui->scrollAreaWidgetContents->layout()->takeAt(0)->widget()->deleteLater();
    }
    entries.clear();

    addEntry();
}

void SendWidget::addEntry(){
    if(entries.isEmpty()){
        createEntry();
    } else {
        if (entries.length() == 1) {
            SendMultiRow *entry = entries.at(0);
            entry->hideLabels();
            entry->setNumber(1);
        }else if(entries.length() == MAX_SEND_POPUP_ENTRIES){
            inform(tr("Maximum amount of outputs reached"));
            return;
        }

        SendMultiRow *sendMultiRow = createEntry();
        sendMultiRow->setNumber(entries.length());
        sendMultiRow->hideLabels();
    }
}

SendMultiRow* SendWidget::createEntry(){
    SendMultiRow *sendMultiRow = new SendMultiRow(this);
    if(this->walletModel) sendMultiRow->setWalletModel(this->walletModel);
    entries.append(sendMultiRow);
    ui->scrollAreaWidgetContents->layout()->addWidget(sendMultiRow);
    connect(sendMultiRow, &SendMultiRow::onContactsClicked, this, &SendWidget::onContactsClicked);
    connect(sendMultiRow, &SendMultiRow::onMenuClicked, this, &SendWidget::onMenuClicked);
    connect(sendMultiRow, &SendMultiRow::onValueChanged, this, &SendWidget::onValueChanged);
    return sendMultiRow;
}

void SendWidget::onAddEntryClicked(){
    // Check prev valid entries before add a new one.
    for (SendMultiRow* entry : entries){
        if(!entry || !entry->validate()) {
            inform(tr("Invalid entry, previous entries must be valid before add a new one"));
            return;
        }
    }
    addEntry();
}

void SendWidget::resizeEvent(QResizeEvent *event){
    resizeMenu();
    QWidget::resizeEvent(event);
}


void SendWidget::onSendClicked(){

    if (!walletModel || !walletModel->getOptionsModel())
        return;

    QList<SendCoinsRecipient> recipients;

    for (SendMultiRow* entry : entries){
        // TODO: Check UTXO splitter here..
        // Validate send..
        if(entry && entry->validate()) {
            recipients.append(entry->getValue());
        }else{
            inform(tr("Invalid entry"));
            return;
        }
    }

    if (recipients.isEmpty()) {
        inform(tr("No set recipients"));
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        // Unlock wallet was cancelled
        inform(tr("Cannot send, wallet locked"));
        return;
    }

    if(send(recipients)) {
        updateEntryLabels(recipients);
    }
}

bool SendWidget::send(QList<SendCoinsRecipient> recipients){
    // prepare transaction for getting txFee earlier
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;

    prepareStatus = walletModel->prepareTransaction(currentTransaction, CoinControlDialog::coinControl);

    // process prepareStatus and on error generate message shown to user
    GuiTransactionsUtils::ProcessSendCoinsReturnAndInform(
            this,
            prepareStatus,
            walletModel,
            BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(),
                                         currentTransaction.getTransactionFee()),
            true
    );

    if (prepareStatus.status != WalletModel::OK) {
        inform(tr("Cannot create transaction."));
        return false;
    }

    showHideOp(true);
    QString warningStr = QString();
    if (currentTransaction.getTransaction()->fStakeDelegationVoided)
        warningStr = tr("WARNING:\nTransaction spends a cold-stake delegation, voiding it.\n"
                     "These coins will no longer be cold-staked.");
    TxDetailDialog* dialog = new TxDetailDialog(window, true, warningStr);
    dialog->setDisplayUnit(walletModel->getOptionsModel()->getDisplayUnit());
    dialog->setData(walletModel, currentTransaction);
    dialog->adjustSize();
    openDialogWithOpaqueBackgroundY(dialog, window, 3, 5);

    if(dialog->isConfirm()){
        // now send the prepared transaction
        WalletModel::SendCoinsReturn sendStatus = dialog->getStatus();
        // process sendStatus and on error generate message shown to user
        GuiTransactionsUtils::ProcessSendCoinsReturnAndInform(
                this,
                sendStatus,
                walletModel
        );

        if (sendStatus.status == WalletModel::OK) {
            clearAll();
            inform(tr("Transaction sent"));
            dialog->deleteLater();
            return true;
        }
    }

    dialog->deleteLater();
    return false;
}

QString SendWidget::recipientsToString(QList<SendCoinsRecipient> recipients){
    QString s = "";
    for (SendCoinsRecipient rec : recipients){
        s += rec.address + " -> " + BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), rec.amount, false, BitcoinUnits::separatorAlways) + "\n";
    }
    return s;
}

void SendWidget::updateEntryLabels(QList<SendCoinsRecipient> recipients){
    for (SendCoinsRecipient rec : recipients){
        QString label = rec.label;
        if(!label.isNull()) {
            QString labelOld = walletModel->getAddressTableModel()->labelForAddress(rec.address);
            if(label.compare(labelOld) != 0) {
                CTxDestination dest = CBitcoinAddress(rec.address.toStdString()).Get();
                if (!walletModel->updateAddressBookLabels(dest, label.toStdString(),
                                                          this->walletModel->isMine(dest) ?
                                                                  AddressBook::AddressBookPurpose::RECEIVE :
                                                                  AddressBook::AddressBookPurpose::SEND)) {
                    // Label update failed
                    Q_EMIT message("", tr("Address label update failed for address: %1").arg(rec.address), CClientUIInterface::MSG_ERROR);
                    return;
                }
            }
        }

    }
}


void SendWidget::onChangeAddressClicked(){
    showHideOp(true);
    SendChangeAddressDialog* dialog = new SendChangeAddressDialog(window);
    if(!boost::get<CNoDestination>(&CoinControlDialog::coinControl->destChange)){
        dialog->setAddress(QString::fromStdString(CBitcoinAddress(CoinControlDialog::coinControl->destChange).ToString()));
    }
    if(openDialogWithOpaqueBackgroundY(dialog, window, 3, 5)) {
        if(dialog->selected) {
            QString ret;
            if (dialog->getAddress(walletModel, &ret)) {
                CoinControlDialog::coinControl->destChange = CBitcoinAddress(ret.toStdString()).Get();
                ui->btnChangeAddress->setActive(true);
            }else{
                inform(tr("Invalid change address"));
                ui->btnChangeAddress->setActive(false);
            }
        }
    }
    dialog->deleteLater();
}

void SendWidget::onOpenUriClicked(){
    showHideOp(true);
    OpenURIDialog *dlg = new OpenURIDialog(window);
    if (openDialogWithOpaqueBackgroundY(dlg, window, 3, 5)) {

        SendCoinsRecipient rcp;
        if (!GUIUtil::parseBitcoinURI(dlg->getURI(), &rcp)) {
            inform(tr("Invalid URI"));
            return;
        }
        if (!walletModel->validateAddress(rcp.address)) {
            inform(tr("Invalid address in URI"));
            return;
        }

        int listSize = entries.size();
        if (listSize == 1) {
            SendMultiRow *entry = entries[0];
            entry->setAddressAndLabelOrDescription(rcp.address, rcp.message);
            entry->setAmount(BitcoinUnits::format(nDisplayUnit, rcp.amount, false));
        } else {
            // Use the last one if it's invalid or add a new one
            SendMultiRow *entry = entries[listSize - 1];
            if (!entry->validate()) {
                addEntry();
                entry = entries[listSize];
            }
            entry->setAddressAndLabelOrDescription(rcp.address, rcp.message);
            entry->setAmount(BitcoinUnits::format(nDisplayUnit, rcp.amount, false));
        }
        Q_EMIT receivedURI(dlg->getURI());
    }
    dlg->deleteLater();
}

void SendWidget::onChangeCustomFeeClicked(){
    showHideOp(true);
    if (!customFeeDialog) {
        customFeeDialog = new SendCustomFeeDialog(window);
        customFeeDialog->setWalletModel(walletModel);
    }
    if (openDialogWithOpaqueBackgroundY(customFeeDialog, window, 3, 5)){
        ui->pushButtonFee->setText(tr("Custom Fee %1").arg(BitcoinUnits::formatWithUnit(nDisplayUnit, customFeeDialog->getFeeRate().GetFeePerK()) + "/kB"));
        isCustomFeeSelected = true;
        walletModel->setWalletDefaultFee(customFeeDialog->getFeeRate().GetFeePerK());
    } else {
        ui->pushButtonFee->setText(tr("Customize Fee"));
        isCustomFeeSelected = false;
        walletModel->setWalletDefaultFee();
    }
}

void SendWidget::onCoinControlClicked(){
    if (walletModel->getBalance() > 0) {
        if (!coinControlDialog) {
            coinControlDialog = new CoinControlDialog();
            coinControlDialog->setModel(walletModel);
        } else {
            coinControlDialog->refreshDialog();
        }
        coinControlDialog->exec();
        ui->btnCoinControl->setActive(CoinControlDialog::coinControl->HasSelected());
        refreshAmounts();
    } else {
        inform(tr("You don't have any WAGE to select."));
    }
}

void SendWidget::onValueChanged() {
    refreshAmounts();
}

void SendWidget::onPIVSelected(bool _isPIV){
    isPIV = _isPIV;
    setCssProperty(coinIcon, "coin-icon-piv");
    refreshView();
    updateStyle(coinIcon);
}

void SendWidget::onContactsClicked(SendMultiRow* entry){
    focusedEntry = entry;
    if(menu && menu->isVisible()){
        menu->hide();
    }

    int contactsSize = walletModel->getAddressTableModel()->sizeSend();
    if(contactsSize == 0) {
        inform(tr("No contacts available, you can go to the contacts screen and add some there!"));
        return;
    }

    int height = (contactsSize <= 2) ? entry->getEditHeight() * ( 2 * (contactsSize + 1 )) : entry->getEditHeight() * 6;
    int width = entry->getEditWidth();

    if(!menuContacts){
        menuContacts = new ContactsDropdown(
                    width,
                    height,
                    this
        );
        menuContacts->setWalletModel(walletModel, AddressTableModel::Send);
        connect(menuContacts, &ContactsDropdown::contactSelected, [this](QString address, QString label){
            if(focusedEntry){
                focusedEntry->setLabel(label);
                focusedEntry->setAddress(address);
            }
        });

    }

    if(menuContacts->isVisible()){
        menuContacts->hide();
        return;
    }

    menuContacts->resizeList(width, height);
    menuContacts->setStyleSheet(this->styleSheet());
    menuContacts->adjustSize();

    QPoint pos;
    if (entries.size() > 1){
        pos = entry->pos();
        pos.setY((pos.y() + (focusedEntry->getEditHeight() - 12) * 4));
    } else {
        pos = focusedEntry->getEditLineRect().bottomLeft();
        pos.setY((pos.y() + (focusedEntry->getEditHeight() - 12) * 3));
    }
    pos.setX(pos.x() + 20);
    menuContacts->move(pos);
    menuContacts->show();
}

void SendWidget::onMenuClicked(SendMultiRow* entry){
    focusedEntry = entry;
    if(menuContacts && menuContacts->isVisible()){
        menuContacts->hide();
    }
    QPoint pos = entry->pos();
    pos.setX(pos.x() + (entry->width() - entry->getMenuBtnWidth()));
    pos.setY(pos.y() + entry->height() + (entry->getMenuBtnWidth()));

    if(!this->menu){
        this->menu = new TooltipMenu(window, this);
        this->menu->setCopyBtnVisible(false);
        this->menu->setEditBtnText(tr("Save contact"));
        this->menu->setMinimumSize(this->menu->width() + 30,this->menu->height());
        connect(this->menu, &TooltipMenu::message, this, &AddressesWidget::message);
        connect(this->menu, SIGNAL(onEditClicked()), this, SLOT(onContactMultiClicked()));
        connect(this->menu, SIGNAL(onDeleteClicked()), this, SLOT(onDeleteClicked()));
    }else {
        this->menu->hide();
    }
    menu->move(pos);
    menu->show();
}

void SendWidget::onContactMultiClicked(){
    if(focusedEntry) {
        QString address = focusedEntry->getAddress();
        if (address.isEmpty()) {
            inform(tr("Address field is empty"));
            return;
        }
        if (!walletModel->validateAddress(address)) {
            inform(tr("Invalid address"));
            return;
        }
        CBitcoinAddress wageAdd = CBitcoinAddress(address.toStdString());
        if (walletModel->isMine(wageAdd)) {
            inform(tr("Cannot store your own address as contact"));
            return;
        }

        showHideOp(true);
        AddNewContactDialog *dialog = new AddNewContactDialog(window);
        QString label = walletModel->getAddressTableModel()->labelForAddress(address);
        if (!label.isNull()){
            dialog->setTexts(tr("Update Contact"), "Edit label for the selected address:\n%1");
            dialog->setData(address, label);
        } else {
            dialog->setTexts(tr("Create New Contact"), "Save label for the selected address:\n%1");
            dialog->setData(address, "");
        }
        openDialogWithOpaqueBackgroundY(dialog, window, 3, 5);
        if (dialog->res) {
            if (label == dialog->getLabel()) {
                return;
            }
            if (walletModel->updateAddressBookLabels(wageAdd.Get(), dialog->getLabel().toStdString(),
                    AddressBook::AddressBookPurpose::SEND)) {
                inform(tr("New Contact Stored"));
            } else {
                inform(tr("Error Storing Contact"));
            }
        }
        dialog->deleteLater();
    }

}

void SendWidget::onDeleteClicked(){
    if (focusedEntry) {
        focusedEntry->hide();
        focusedEntry->deleteLater();
        int entryNumber = focusedEntry->getNumber();

        // remove selected entry and update row number for the others
        QMutableListIterator<SendMultiRow*> it(entries);
        while (it.hasNext()) {
            SendMultiRow* entry = it.next();
            if (focusedEntry == entry){
                it.remove();
            } else if (focusedEntry && entry->getNumber() > entryNumber){
                entry->setNumber(entry->getNumber() - 1);
            }
        }

        if (entries.size() == 1) {
            SendMultiRow* sendMultiRow = QMutableListIterator<SendMultiRow*>(entries).next();
            sendMultiRow->setNumber(entries.length());
            sendMultiRow->showLabels();
        }

        focusedEntry = nullptr;

        // Update total amounts
        refreshAmounts();
    }
}

void SendWidget::resizeMenu(){
    if(menuContacts && menuContacts->isVisible() && focusedEntry){
        int width = focusedEntry->getEditWidth();
        menuContacts->resizeList(width, menuContacts->height());
        menuContacts->resize(width, menuContacts->height());
        QPoint pos = focusedEntry->getEditLineRect().bottomLeft();
        pos.setX(pos.x() + 20);
        pos.setY(pos.y() + ((focusedEntry->getEditHeight() - 12)  * 3));
        menuContacts->move(pos);
    }
}

void SendWidget::changeTheme(bool isLightTheme, QString& theme){
    if (coinControlDialog) coinControlDialog->setStyleSheet(theme);
}

SendWidget::~SendWidget(){
    delete ui;
}
