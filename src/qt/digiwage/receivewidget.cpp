// Copyright (c) 2019-2020 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/receivewidget.h"
#include "qt/digiwage/forms/ui_receivewidget.h"
#include "qt/digiwage/requestdialog.h"
#include "qt/digiwage/addnewcontactdialog.h"
#include "qt/digiwage/qtutils.h"
#include "qt/digiwage/myaddressrow.h"
#include "qt/digiwage/furlistrow.h"
#include "qt/digiwage/addressholder.h"
#include "walletmodel.h"
#include "guiutil.h"
#include "pairresult.h"

#include <QModelIndex>
#include <QColor>
#include <QDateTime>

#define DECORATION_SIZE 70
#define NUM_ITEMS 3

ReceiveWidget::ReceiveWidget(DIGIWAGEGUI* parent) :
    PWidget(parent),
    ui(new Ui::ReceiveWidget)
{
    ui->setupUi(this);
    this->setStyleSheet(parent->styleSheet());

    delegate = new FurAbstractListItemDelegate(
                DECORATION_SIZE,
                new AddressHolder(isLightTheme()),
                this
                );

    // Containers
    setCssProperty(ui->left, "container");
    ui->left->setContentsMargins(20,20,20,20);
    setCssProperty(ui->right, "container-right");
    ui->right->setContentsMargins(0,9,0,0);

    // Title
    ui->labelTitle->setText(tr("Receive"));
    ui->labelSubtitle1->setText(tr("Scan the QR code or copy the address to receive WAGE."));
    setCssTitleScreen(ui->labelTitle);
    setCssSubtitleScreen(ui->labelSubtitle1);

    // Address
    ui->labelAddress->setText(tr("No address "));
    setCssProperty(ui->labelAddress, "label-address-box");

    ui->labelDate->setText("Dec. 19, 2018");
    setCssSubtitleScreen(ui->labelDate);
    ui->labelLabel->setText("");
    setCssSubtitleScreen(ui->labelLabel);

    // Options
    ui->btnMyAddresses->setTitleClassAndText("btn-title-grey", "My Addresses");
    ui->btnMyAddresses->setSubTitleClassAndText("text-subtitle", "List your own addresses.");
    ui->btnMyAddresses->layout()->setMargin(0);
    ui->btnMyAddresses->setRightIconClass("ic-arrow");

    ui->btnRequest->setTitleClassAndText("btn-title-grey", "Create Request");
    ui->btnRequest->setSubTitleClassAndText("text-subtitle", "Request payment with a fixed amount.");
    ui->btnRequest->layout()->setMargin(0);

    ui->pushButtonLabel->setText(tr("Add Label"));
    ui->pushButtonLabel->setLayoutDirection(Qt::RightToLeft);
    setCssProperty(ui->pushButtonLabel, "btn-secundary-label");

    ui->pushButtonNewAddress->setText(tr("Generate Address"));
    ui->pushButtonNewAddress->setLayoutDirection(Qt::RightToLeft);
    setCssProperty(ui->pushButtonNewAddress, "btn-secundary-new-address");

    ui->pushButtonCopy->setText(tr("Copy"));
    ui->pushButtonCopy->setLayoutDirection(Qt::RightToLeft);
    setCssProperty(ui->pushButtonCopy, "btn-secundary-copy");

    // List Addresses
    setCssProperty(ui->listViewAddress, "container");
    ui->listViewAddress->setItemDelegate(delegate);
    ui->listViewAddress->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listViewAddress->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listViewAddress->setAttribute(Qt::WA_MacShowFocusRect, false);
    ui->listViewAddress->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->listViewAddress->setUniformItemSizes(true);

    spacer = new QSpacerItem(40, 20, QSizePolicy::Maximum, QSizePolicy::Expanding);
    ui->btnMyAddresses->setChecked(true);
    ui->container_right->addItem(spacer);
    ui->listViewAddress->setVisible(false);

    // Sort Controls
    SortEdit* lineEdit = new SortEdit(ui->comboBoxSort);
    connect(lineEdit, &SortEdit::Mouse_Pressed, [this](){ui->comboBoxSort->showPopup();});
    connect(ui->comboBoxSort, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &ReceiveWidget::onSortChanged);
    SortEdit* lineEditOrder = new SortEdit(ui->comboBoxSortOrder);
    connect(lineEditOrder, &SortEdit::Mouse_Pressed, [this](){ui->comboBoxSortOrder->showPopup();});
    connect(ui->comboBoxSortOrder, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &ReceiveWidget::onSortOrderChanged);
    fillAddressSortControls(lineEdit, lineEditOrder, ui->comboBoxSort, ui->comboBoxSortOrder);
    ui->sortWidget->setVisible(false);

    // Connect
    connect(ui->pushButtonLabel, SIGNAL(clicked()), this, SLOT(onLabelClicked()));
    connect(ui->pushButtonCopy, SIGNAL(clicked()), this, SLOT(onCopyClicked()));
    connect(ui->pushButtonNewAddress, SIGNAL(clicked()), this, SLOT(onNewAddressClicked()));
    connect(ui->listViewAddress, SIGNAL(clicked(QModelIndex)), this, SLOT(handleAddressClicked(QModelIndex)));
    connect(ui->btnRequest, SIGNAL(clicked()), this, SLOT(onRequestClicked()));
    connect(ui->btnMyAddresses, SIGNAL(clicked()), this, SLOT(onMyAddressesClicked()));
}

void ReceiveWidget::loadWalletModel(){
    if(walletModel) {
        this->addressTableModel = walletModel->getAddressTableModel();
        this->filter = new AddressFilterProxyModel(AddressTableModel::Receive, this);
        this->filter->setSourceModel(addressTableModel);
        this->filter->sort(AddressTableModel::Label, Qt::AscendingOrder);
        this->filter->sort(sortType, sortOrder);
        ui->listViewAddress->setModel(this->filter);
        ui->listViewAddress->setModelColumn(AddressTableModel::Address);

        if(!info) info = new SendCoinsRecipient();
        refreshView();

        // data change
        connect(this->addressTableModel, SIGNAL(dataChanged(QModelIndex, QModelIndex)), this, SLOT(refreshView(QModelIndex, QModelIndex)));
    }
}

void ReceiveWidget::refreshView(const QModelIndex& tl, const QModelIndex& br)
{
    const QModelIndex& index = tl.sibling(tl.row(), AddressTableModel::Address);
    return refreshView(index.data(Qt::DisplayRole).toString());
}

void ReceiveWidget::refreshView(QString refreshAddress)
{
    try {
        QString latestAddress = (refreshAddress.isEmpty()) ? this->addressTableModel->getAddressToShow() : refreshAddress;
        if (latestAddress.isEmpty()) { // new default address
            CBitcoinAddress newAddress;
            PairResult r = walletModel->getNewAddress(newAddress, "Default");
            // Check for generation errors
            if (!r.result) {
                ui->labelQrImg->setText(tr("No available address, try unlocking the wallet"));
                inform(tr("Error generating address"));
                return;
            }
            latestAddress = QString::fromStdString(newAddress.ToString());
        }
        ui->labelAddress->setText(latestAddress);
        int64_t time = walletModel->getKeyCreationTime(CBitcoinAddress(latestAddress.toStdString()));
        ui->labelDate->setText(GUIUtil::dateTimeStr(QDateTime::fromTime_t(static_cast<uint>(time))));
        updateQr(latestAddress);
        updateLabel();
    } catch (const std::runtime_error& error){
        ui->labelQrImg->setText(tr("No available address, try unlocking the wallet"));
        inform(tr("Error generating address"));
    }
}

void ReceiveWidget::updateLabel(){
    if(!info->address.isEmpty()) {
        // Check if address label exists
        QString label = addressTableModel->labelForAddress(info->address);
        if (!label.isEmpty()) {
            ui->labelLabel->setVisible(true);
            ui->labelLabel->setText(label);
            ui->pushButtonLabel->setText(tr("Edit Label"));
        }else{
            ui->labelLabel->setVisible(false);
        }
    }
}

void ReceiveWidget::updateQr(QString address){
    info->address = address;
    QString uri = GUIUtil::formatBitcoinURI(*info);
    ui->labelQrImg->setText("");

    QString error;
    QColor qrColor("#1d1c1a");
    QPixmap pixmap = encodeToQr(uri, error, qrColor);
    if(!pixmap.isNull()){
        qrImage = &pixmap;
        ui->labelQrImg->setPixmap(qrImage->scaled(ui->labelQrImg->width(), ui->labelQrImg->height()));
    }else{
        ui->labelQrImg->setText(!error.isEmpty() ? error : "Error encoding address");
    }
}

void ReceiveWidget::handleAddressClicked(const QModelIndex &index){
    QModelIndex rIndex = filter->mapToSource(index);
    refreshView(rIndex.data(Qt::DisplayRole).toString());
}

void ReceiveWidget::onLabelClicked(){
    if(walletModel && !isShowingDialog) {
        isShowingDialog = true;
        showHideOp(true);
        AddNewContactDialog *dialog = new AddNewContactDialog(window);
        dialog->setTexts(tr("Edit Address Label"));
        dialog->setData(info->address, addressTableModel->labelForAddress(info->address));
        if (openDialogWithOpaqueBackgroundY(dialog, window, 3.5, 6)) {
            QString label = dialog->getLabel();
            const CBitcoinAddress address = CBitcoinAddress(info->address.toUtf8().constData());
            if (!label.isEmpty() && walletModel->updateAddressBookLabels(
                    address.Get(),
                    label.toUtf8().constData(),
                    AddressBook::AddressBookPurpose::RECEIVE
            )
                    ) {
                // update label status (icon color)
                updateLabel();
                inform(tr("Address label saved"));
            } else {
                inform(tr("Error storing address label"));
            }
        }
        isShowingDialog = false;
    }
}

void ReceiveWidget::onNewAddressClicked(){
    try {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            // Unlock wallet was cancelled
            inform(tr("Cannot create new address, wallet locked"));
            return;
        }
        CBitcoinAddress address;
        PairResult r = walletModel->getNewAddress(address, "");

        // Check for validity
        if(!r.result) {
            inform(r.status->c_str());
            return;
        }

        updateQr(QString::fromStdString(address.ToString()));
        ui->labelAddress->setText(!info->address.isEmpty() ? info->address : tr("No address"));
        updateLabel();
        inform(tr("New address created"));
    } catch (const std::runtime_error& error){
        // Error generating address
        inform("Error generating address");
    }
}

void ReceiveWidget::onCopyClicked(){
    GUIUtil::setClipboard(info->address);
    inform(tr("Address copied"));
}


void ReceiveWidget::onRequestClicked(){
    showAddressGenerationDialog(true);
}

void ReceiveWidget::showAddressGenerationDialog(bool isPaymentRequest) {
    if(walletModel && !isShowingDialog) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            // Unlock wallet was cancelled
            inform(tr("Cannot perform operation, wallet locked"));
            return;
        }
        isShowingDialog = true;
        showHideOp(true);
        RequestDialog *dialog = new RequestDialog(window);
        dialog->setWalletModel(walletModel);
        dialog->setPaymentRequest(isPaymentRequest);
        openDialogWithOpaqueBackgroundY(dialog, window, 3.5, 12);
        if (dialog->res == 1){
            inform(tr("URI copied to clipboard"));
        } else if (dialog->res == 2){
            inform(tr("Address copied to clipboard"));
        }
        dialog->deleteLater();
        isShowingDialog = false;
    }
}

void ReceiveWidget::onMyAddressesClicked(){
    bool isVisible = ui->listViewAddress->isVisible();
    if(!isVisible){
        ui->btnMyAddresses->setRightIconClass("btn-dropdown", true);
        ui->listViewAddress->setVisible(true);
        ui->sortWidget->setVisible(true);
        ui->container_right->removeItem(spacer);
        ui->listViewAddress->update();
    }else{
        ui->btnMyAddresses->setRightIconClass("ic-arrow", true);
        ui->container_right->addItem(spacer);
        ui->listViewAddress->setVisible(false);
        ui->sortWidget->setVisible(false);
    }
}

void ReceiveWidget::onSortChanged(int idx)
{
    sortType = (AddressTableModel::ColumnIndex) ui->comboBoxSort->itemData(idx).toInt();
    sortAddresses();
}

void ReceiveWidget::onSortOrderChanged(int idx)
{
    sortOrder = (Qt::SortOrder) ui->comboBoxSortOrder->itemData(idx).toInt();
    sortAddresses();
}

void ReceiveWidget::sortAddresses()
{
    if (this->filter)
        this->filter->sort(sortType, sortOrder);
}

void ReceiveWidget::changeTheme(bool isLightTheme, QString& theme){
    static_cast<AddressHolder*>(this->delegate->getRowFactory())->isLightTheme = isLightTheme;
}

ReceiveWidget::~ReceiveWidget(){
    delete ui;
}
