// Copyright (c) 2019-2020 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/addresseswidget.h"
#include "qt/digiwage/forms/ui_addresseswidget.h"
#include "qt/digiwage/addresslabelrow.h"
#include "qt/digiwage/addnewaddressdialog.h"
#include "qt/digiwage/tooltipmenu.h"

#include "qt/digiwage/addnewcontactdialog.h"
#include "qt/digiwage/digiwagegui.h"
#include "guiutil.h"
#include "qt/digiwage/qtutils.h"
#include "walletmodel.h"

#include <QModelIndex>
#include <QRegExpValidator>

#define DECORATION_SIZE 60
#define NUM_ITEMS 3

class ContactsHolder : public FurListRow<QWidget*>
{
public:
    ContactsHolder();

    explicit ContactsHolder(bool _isLightTheme) : FurListRow(), isLightTheme(_isLightTheme){}

    AddressLabelRow* createHolder(int pos) override{
        if (!cachedRow) cachedRow = new AddressLabelRow();
        cachedRow->init(isLightTheme, false);
        return cachedRow;
    }

    void init(QWidget* holder,const QModelIndex &index, bool isHovered, bool isSelected) const override{
        AddressLabelRow* row = static_cast<AddressLabelRow*>(holder);

        row->updateState(isLightTheme, isHovered, isSelected);

        QString address = index.data(Qt::DisplayRole).toString();
        QModelIndex sibling = index.sibling(index.row(), AddressTableModel::Label);
        QString label = sibling.data(Qt::DisplayRole).toString();

        row->updateView(address, label);
    }

    QColor rectColor(bool isHovered, bool isSelected) override{
        return getRowColor(isLightTheme, isHovered, isSelected);
    }

    ~ContactsHolder() override{}

    bool isLightTheme;
    AddressLabelRow* cachedRow = nullptr;
};


AddressesWidget::AddressesWidget(DIGIWAGEGUI* parent) :
    PWidget(parent),
    ui(new Ui::AddressesWidget)
{
    ui->setupUi(this);

    this->setStyleSheet(parent->styleSheet());

    delegate = new FurAbstractListItemDelegate(
                DECORATION_SIZE,
                new ContactsHolder(isLightTheme()),
                this
    );

    /* Containers */
    setCssProperty(ui->left, "container");
    ui->left->setContentsMargins(0,20,0,20);
    setCssProperty(ui->right, "container-right");
    ui->right->setContentsMargins(20,10,20,20);
    setCssProperty(ui->listAddresses, "container");

    // Title
    ui->labelTitle->setText(tr("Contacts"));
    ui->labelSubtitle1->setText(tr("You can add a new one in the options menu to the side."));
    setCssTitleScreen(ui->labelTitle);
    setCssSubtitleScreen(ui->labelSubtitle1);

    // Change address option
    ui->btnAddContact->setTitleClassAndText("btn-title-grey", "Add new contact");
    ui->btnAddContact->setSubTitleClassAndText("text-subtitle", "Generate a new address to receive tokens.");
    ui->btnAddContact->setRightIconClass("ic-arrow-down");

    // List Addresses
    ui->listAddresses->setItemDelegate(delegate);
    ui->listAddresses->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listAddresses->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listAddresses->setAttribute(Qt::WA_MacShowFocusRect, false);
    ui->listAddresses->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->listAddresses->setUniformItemSizes(true);

    // Sort Controls
    SortEdit* lineEdit = new SortEdit(ui->comboBoxSort);
    connect(lineEdit, &SortEdit::Mouse_Pressed, [this](){ui->comboBoxSort->showPopup();});
    connect(ui->comboBoxSort, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &AddressesWidget::onSortChanged);
    SortEdit* lineEditOrder = new SortEdit(ui->comboBoxSortOrder);
    connect(lineEditOrder, &SortEdit::Mouse_Pressed, [this](){ui->comboBoxSortOrder->showPopup();});
    connect(ui->comboBoxSortOrder, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &AddressesWidget::onSortOrderChanged);
    fillAddressSortControls(lineEdit, lineEditOrder, ui->comboBoxSort, ui->comboBoxSortOrder);

    //Empty List
    ui->emptyContainer->setVisible(false);
    setCssProperty(ui->pushImgEmpty, "img-empty-contacts");

    ui->labelEmpty->setText(tr("No contacts yet"));
    setCssProperty(ui->labelEmpty, "text-empty");

    // Add Contact
    setCssProperty(ui->layoutNewContact, "container-options");

    // Name
    ui->labelName->setText(tr("Contact name"));
    setCssProperty(ui->labelName, "text-title");
    ui->lineEditName->setPlaceholderText(tr("e.g. John Doe"));
    setCssEditLine(ui->lineEditName, true);

    // Address
    ui->labelAddress->setText(tr("Enter DIGIWAGE address"));
    setCssProperty(ui->labelAddress, "text-title");
    ui->lineEditAddress->setPlaceholderText("e.g. ZmkEBAFKzay6fMaYp3ZB…");
    setCssEditLine(ui->lineEditAddress, true);
    ui->lineEditAddress->setValidator(new QRegExpValidator(QRegExp("^[A-Za-z0-9]+"), ui->lineEditName));

    // Buttons
    ui->btnSave->setText(tr("SAVE"));
    setCssBtnPrimary(ui->btnSave);

    connect(ui->listAddresses, SIGNAL(clicked(QModelIndex)), this, SLOT(handleAddressClicked(QModelIndex)));
    connect(ui->btnSave, SIGNAL(clicked()), this, SLOT(onStoreContactClicked()));
    connect(ui->btnAddContact, SIGNAL(clicked()), this, SLOT(onAddContactShowHideClicked()));
}

void AddressesWidget::handleAddressClicked(const QModelIndex &index){
    ui->listAddresses->setCurrentIndex(index);
    QRect rect = ui->listAddresses->visualRect(index);
    QPoint pos = rect.topRight();
    pos.setX(pos.x() - (DECORATION_SIZE * 2));
    pos.setY(pos.y() + (DECORATION_SIZE));

    QModelIndex rIndex = filter->mapToSource(index);

    if(!this->menu){
        this->menu = new TooltipMenu(window, this);
        connect(this->menu, &TooltipMenu::message, this, &AddressesWidget::message);
        connect(this->menu, SIGNAL(onEditClicked()), this, SLOT(onEditClicked()));
        connect(this->menu, SIGNAL(onDeleteClicked()), this, SLOT(onDeleteClicked()));
        connect(this->menu, SIGNAL(onCopyClicked()), this, SLOT(onCopyClicked()));
    }else {
        this->menu->hide();
    }
    this->index = rIndex;
    menu->move(pos);
    menu->show();
}

void AddressesWidget::loadWalletModel(){
    if(walletModel) {
        addressTablemodel = walletModel->getAddressTableModel();
        this->filter = new AddressFilterProxyModel(QStringList({AddressTableModel::Send, AddressTableModel::ColdStakingSend}), this);
        this->filter->setSourceModel(addressTablemodel);
        this->filter->sort(AddressTableModel::Label, Qt::AscendingOrder);
        this->filter->sort(sortType, sortOrder);
        ui->listAddresses->setModel(this->filter);
        ui->listAddresses->setModelColumn(AddressTableModel::Address);

        updateListView();
    }
}

void AddressesWidget::updateListView(){
    bool empty = addressTablemodel->sizeSend() == 0;
    ui->emptyContainer->setVisible(empty);
    ui->listAddresses->setVisible(!empty);
}

void AddressesWidget::onStoreContactClicked(){
    if (walletModel) {
        QString label = ui->lineEditName->text();
        QString address = ui->lineEditAddress->text();

        if (!walletModel->validateAddress(address)) {
            setCssEditLine(ui->lineEditAddress, false, true);
            inform(tr("Invalid Contact Address"));
            return;
        }

        CBitcoinAddress wageAdd = CBitcoinAddress(address.toUtf8().constData());
        if (walletModel->isMine(wageAdd)) {
            setCssEditLine(ui->lineEditAddress, false, true);
            inform(tr("Cannot store your own address as contact"));
            return;
        }

        QString storedLabel = walletModel->getAddressTableModel()->labelForAddress(address);

        if(!storedLabel.isEmpty()){
            inform(tr("Address already stored, label: %1").arg("\'"+storedLabel+"\'"));
            return;
        }

        if (walletModel->updateAddressBookLabels(wageAdd.Get(), label.toUtf8().constData(),
                wageAdd.IsStakingAddress() ? AddressBook::AddressBookPurpose::COLD_STAKING_SEND : AddressBook::AddressBookPurpose::SEND)
                ) {
            ui->lineEditAddress->setText("");
            ui->lineEditName->setText("");
            setCssEditLine(ui->lineEditAddress, true, true);
            setCssEditLine(ui->lineEditName, true, true);

            if (ui->emptyContainer->isVisible()) {
                ui->emptyContainer->setVisible(false);
                ui->listAddresses->setVisible(true);
            }
            inform(tr("New Contact Stored"));
        } else {
            inform(tr("Error Storing Contact"));
        }
    }
}

void AddressesWidget::onEditClicked(){
    QString address = index.data(Qt::DisplayRole).toString();
    QString currentLabel = index.sibling(index.row(), AddressTableModel::Label).data(Qt::DisplayRole).toString();
    showHideOp(true);
    AddNewContactDialog *dialog = new AddNewContactDialog(window);
    dialog->setData(address, currentLabel);
    if(openDialogWithOpaqueBackground(dialog, window)){
        if(walletModel->updateAddressBookLabels(
                CBitcoinAddress(address.toStdString()).Get(), dialog->getLabel().toStdString(), addressTablemodel->purposeForAddress(address.toStdString()))){
            inform(tr("Contact edited"));
        }else{
            inform(tr("Contact edit failed"));
        }
    }
    dialog->deleteLater();
}

void AddressesWidget::onDeleteClicked(){
    if(walletModel) {
        if (ask(tr("Delete Contact"), tr("You are just about to remove the contact:\n\n%1\n\nAre you sure?").arg(index.data(Qt::DisplayRole).toString().toUtf8().constData()))
        ) {
            if (this->walletModel->getAddressTableModel()->removeRows(index.row(), 1, index)) {
                updateListView();
                inform(tr("Contact Deleted"));
            } else {
                inform(tr("Error deleting a contact"));
            }
        }
    }
}

void AddressesWidget::onCopyClicked(){
    GUIUtil::setClipboard(index.data(Qt::DisplayRole).toString());
    inform(tr("Address copied"));
}

void AddressesWidget::onAddContactShowHideClicked(){
    if(!ui->layoutNewContact->isVisible()){
        ui->btnAddContact->setRightIconClass("btn-dropdown", true);
        ui->layoutNewContact->setVisible(true);
    }else {
        ui->btnAddContact->setRightIconClass("ic-arrow", true);
        ui->layoutNewContact->setVisible(false);
    }
}

void AddressesWidget::onSortChanged(int idx)
{
    sortType = (AddressTableModel::ColumnIndex) ui->comboBoxSort->itemData(idx).toInt();
    sortAddresses();
}

void AddressesWidget::onSortOrderChanged(int idx)
{
    sortOrder = (Qt::SortOrder) ui->comboBoxSortOrder->itemData(idx).toInt();
    sortAddresses();
}

void AddressesWidget::sortAddresses()
{
    if (this->filter)
        this->filter->sort(sortType, sortOrder);
}

void AddressesWidget::changeTheme(bool isLightTheme, QString& theme){
    static_cast<ContactsHolder*>(this->delegate->getRowFactory())->isLightTheme = isLightTheme;
}

AddressesWidget::~AddressesWidget(){
    delete ui;
}
