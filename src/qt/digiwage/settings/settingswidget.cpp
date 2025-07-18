// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/settings/settingswidget.h"
#include "qt/digiwage/settings/forms/ui_settingswidget.h"
#include "qt/digiwage/settings/settingsbackupwallet.h"
#include "qt/digiwage/settings/settingsbittoolwidget.h"
#include "qt/digiwage/settings/settingswalletrepairwidget.h"
#include "qt/digiwage/settings/settingswalletoptionswidget.h"
#include "qt/digiwage/settings/settingsmainoptionswidget.h"
#include "qt/digiwage/settings/settingsdisplayoptionswidget.h"
#include "qt/digiwage/settings/settingsmultisendwidget.h"
#include "qt/digiwage/settings/settingsinformationwidget.h"
#include "qt/digiwage/settings/settingsconsolewidget.h"
#include "qt/digiwage/qtutils.h"
#include "qt/digiwage/defaultdialog.h"
#include "optionsmodel.h"
#include "clientmodel.h"
#include "utilitydialog.h"
#include "wallet/wallet.h"
#include <QScrollBar>
#include <QDataWidgetMapper>

SettingsWidget::SettingsWidget(DIGIWAGEGUI* parent) :
    PWidget(parent),
    ui(new Ui::SettingsWidget)
{
    ui->setupUi(this);

    this->setStyleSheet(parent->styleSheet());

    /* Containers */
    setCssProperty(ui->scrollArea, "container");
    setCssProperty(ui->left, "container");
    ui->left->setContentsMargins(0,20,0,20);
    setCssProperty(ui->right, "container-right");
    ui->right->setContentsMargins(20,10,20,20);

    ui->verticalLayout->setAlignment(Qt::AlignTop);

    /* Light Font */
    QFont fontLight;
    fontLight.setWeight(QFont::Light);

    /* Title */
    setCssProperty(ui->labelTitle, "text-title-screen");
    ui->labelTitle->setFont(fontLight);

    setCssProperty(ui->pushButtonFile, "btn-settings-check");
    setCssProperty(ui->pushButtonFile2, "btn-settings-options");
    setCssProperty(ui->pushButtonFile3, "btn-settings-options");
    setCssProperty(ui->pushButtonExportCsv, "btn-settings-options");

    setCssProperty(ui->pushButtonConfiguration, "btn-settings-check");
    setCssProperty(ui->pushButtonConfiguration3, "btn-settings-options");
    setCssProperty(ui->pushButtonConfiguration4, "btn-settings-options");

    setCssProperty(ui->pushButtonOptions, "btn-settings-check");
    setCssProperty(ui->pushButtonOptions1, "btn-settings-options");
    setCssProperty(ui->pushButtonOptions2, "btn-settings-options");
    setCssProperty(ui->pushButtonOptions5, "btn-settings-options");

    setCssProperty(ui->pushButtonTools, "btn-settings-check");
    setCssProperty(ui->pushButtonTools1, "btn-settings-options");
    setCssProperty(ui->pushButtonTools2, "btn-settings-options");
    setCssProperty(ui->pushButtonTools5, "btn-settings-options");

    setCssProperty(ui->pushButtonHelp, "btn-settings-check");
    setCssProperty(ui->pushButtonHelp1, "btn-settings-options");
    setCssProperty(ui->pushButtonHelp2, "btn-settings-options");

    options = {
        ui->pushButtonFile2,
        ui->pushButtonFile3,
        ui->pushButtonExportCsv,
        ui->pushButtonOptions1,
        ui->pushButtonOptions2,
        ui->pushButtonOptions5,
        ui->pushButtonConfiguration3,
        ui->pushButtonConfiguration4,
        ui->pushButtonHelp2,
        ui->pushButtonTools1,
        ui->pushButtonTools2,
        ui->pushButtonTools5,
    };

    menus.insert(ui->pushButtonFile, ui->fileButtonsWidget);
    menus.insert(ui->pushButtonConfiguration, ui->configurationButtonsWidget);
    menus.insert(ui->pushButtonOptions, ui->optionsButtonsWidget);
    menus.insert(ui->pushButtonTools, ui->toolsButtonsWidget);
    menus.insert(ui->pushButtonHelp, ui->helpButtonsWidget);

    settingsBackupWallet = new SettingsBackupWallet(window, this);
    settingsExportCsvWidget = new SettingsExportCSV(window, this);
    settingsBitToolWidget = new SettingsBitToolWidget(window, this);
    settingsSingMessageWidgets = new SettingsSignMessageWidgets(window, this);
    settingsWalletRepairWidget = new SettingsWalletRepairWidget(window, this);
    settingsWalletOptionsWidget = new SettingsWalletOptionsWidget(window, this);
    settingsMainOptionsWidget = new SettingsMainOptionsWidget(window, this);
    settingsDisplayOptionsWidget = new SettingsDisplayOptionsWidget(window, this);
    settingsMultisendWidget = new SettingsMultisendWidget(this);
    settingsInformationWidget = new SettingsInformationWidget(window, this);
    settingsConsoleWidget = new SettingsConsoleWidget(window, this);

    ui->stackedWidgetContainer->addWidget(settingsBackupWallet);
    ui->stackedWidgetContainer->addWidget(settingsExportCsvWidget);
    ui->stackedWidgetContainer->addWidget(settingsBitToolWidget);
    ui->stackedWidgetContainer->addWidget(settingsSingMessageWidgets);
    ui->stackedWidgetContainer->addWidget(settingsWalletRepairWidget);
    ui->stackedWidgetContainer->addWidget(settingsWalletOptionsWidget);
    ui->stackedWidgetContainer->addWidget(settingsMainOptionsWidget);
    ui->stackedWidgetContainer->addWidget(settingsDisplayOptionsWidget);
    ui->stackedWidgetContainer->addWidget(settingsMultisendWidget);
    ui->stackedWidgetContainer->addWidget(settingsInformationWidget);
    ui->stackedWidgetContainer->addWidget(settingsConsoleWidget);
    ui->stackedWidgetContainer->setCurrentWidget(settingsBackupWallet);

    // File Section
    connect(ui->pushButtonFile, SIGNAL(clicked()), this, SLOT(onFileClicked()));
    connect(ui->pushButtonFile2, SIGNAL(clicked()), this, SLOT(onBackupWalletClicked()));
    connect(ui->pushButtonFile3, SIGNAL(clicked()), this, SLOT(onMultisendClicked()));
    connect(ui->pushButtonExportCsv, SIGNAL(clicked()), this, SLOT(onExportCSVClicked()));

    // Options
    connect(ui->pushButtonOptions, SIGNAL(clicked()), this, SLOT(onOptionsClicked()));
    connect(ui->pushButtonOptions1, SIGNAL(clicked()), this, SLOT(onMainOptionsClicked()));
    connect(ui->pushButtonOptions2, SIGNAL(clicked()), this, SLOT(onWalletOptionsClicked()));
    connect(ui->pushButtonOptions5, SIGNAL(clicked()), this, SLOT(onDisplayOptionsClicked()));

    // Configuration
    connect(ui->pushButtonConfiguration, SIGNAL(clicked()), this, SLOT(onConfigurationClicked()));
    connect(ui->pushButtonConfiguration3, SIGNAL(clicked()), this, SLOT(onBipToolClicked()));
    connect(ui->pushButtonConfiguration4, SIGNAL(clicked()), this, SLOT(onSignMessageClicked()));

    // Tools
    connect(ui->pushButtonTools, SIGNAL(clicked()), this, SLOT(onToolsClicked()));
    connect(ui->pushButtonTools1, SIGNAL(clicked()), this, SLOT(onInformationClicked()));
    connect(ui->pushButtonTools2, SIGNAL(clicked()), this, SLOT(onDebugConsoleClicked()));
    ui->pushButtonTools2->setShortcut(QKeySequence(SHORT_KEY + Qt::Key_C));
    connect(ui->pushButtonTools5, SIGNAL(clicked()), this, SLOT(onWalletRepairClicked()));

    // Help
    connect(ui->pushButtonHelp, SIGNAL(clicked()), this, SLOT(onHelpClicked()));
    connect(ui->pushButtonHelp1, SIGNAL(clicked()), window, SLOT(openFAQ()));
    connect(ui->pushButtonHelp2, SIGNAL(clicked()), this, SLOT(onAboutClicked()));

    // Get restart command-line parameters and handle restart
    connect(settingsWalletRepairWidget, &SettingsWalletRepairWidget::handleRestart, [this](QStringList arg){Q_EMIT handleRestart(arg);});

    connect(settingsBackupWallet, &SettingsBackupWallet::message,this, &SettingsWidget::message);
    connect(settingsBackupWallet, &SettingsBackupWallet::showHide, this, &SettingsWidget::showHide);
    connect(settingsBackupWallet, &SettingsBackupWallet::execDialog, this, &SettingsWidget::execDialog);
    connect(settingsExportCsvWidget, &SettingsExportCSV::message,this, &SettingsWidget::message);
    connect(settingsExportCsvWidget, &SettingsExportCSV::showHide, this, &SettingsWidget::showHide);
    connect(settingsExportCsvWidget, &SettingsExportCSV::execDialog, this, &SettingsWidget::execDialog);
    connect(settingsMultisendWidget, &SettingsMultisendWidget::showHide, this, &SettingsWidget::showHide);
    connect(settingsMultisendWidget, &SettingsMultisendWidget::message, this, &SettingsWidget::message);
    connect(settingsMainOptionsWidget, &SettingsMainOptionsWidget::message, this, &SettingsWidget::message);
    connect(settingsDisplayOptionsWidget, &SettingsDisplayOptionsWidget::message, this, &SettingsWidget::message);
    connect(settingsWalletOptionsWidget, &SettingsWalletOptionsWidget::message, this, &SettingsWidget::message);
    connect(settingsInformationWidget, &SettingsInformationWidget::message,this, &SettingsWidget::message);

    /* Widget-to-option mapper */
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
    mapper->setOrientation(Qt::Vertical);

    // scroll area
    ui->scrollArea->setWidgetResizable(true);
    QSizePolicy scrollAreaPolicy = ui->scrollArea->sizePolicy();
    scrollAreaPolicy.setVerticalStretch(1);
    ui->scrollArea->setSizePolicy(scrollAreaPolicy);
    QSizePolicy scrollVertPolicy = ui->scrollAreaWidgetContents->sizePolicy();
    scrollVertPolicy.setVerticalStretch(1);
    ui->scrollAreaWidgetContents->setSizePolicy(scrollVertPolicy);

    ui->pushButtonFile->setChecked(true);
    onFileClicked();
    ui->pushButtonFile2->setChecked(true);
}

void SettingsWidget::loadClientModel()
{
    if(clientModel) {
        this->settingsInformationWidget->setClientModel(this->clientModel);
        this->settingsConsoleWidget->setClientModel(this->clientModel);

        OptionsModel *optionsModel = this->clientModel->getOptionsModel();
        if (optionsModel) {
            mapper->setModel(optionsModel);
            setMapper();
            mapper->toFirst();
            settingsMainOptionsWidget->setClientModel(clientModel);
            settingsDisplayOptionsWidget->setClientModel(clientModel);
            settingsWalletOptionsWidget->setClientModel(clientModel);
            /* keep consistency for action triggered elsewhere */
            //connect(optionsModel, SIGNAL(hideOrphansChanged(bool)), this, SLOT(updateHideOrphans(bool)));

            // TODO: Connect show restart needed and apply changes.
        }
    }
}

void SettingsWidget::loadWalletModel(){
    this->settingsInformationWidget->setWalletModel(this->walletModel);
    this->settingsBackupWallet->setWalletModel(this->walletModel);
    this->settingsExportCsvWidget->setWalletModel(this->walletModel);
    this->settingsSingMessageWidgets->setWalletModel(this->walletModel);
    this->settingsBitToolWidget->setWalletModel(this->walletModel);
    this->settingsMultisendWidget->setWalletModel(this->walletModel);
    this->settingsDisplayOptionsWidget->setWalletModel(this->walletModel);
    this->settingsWalletRepairWidget->setWalletModel(this->walletModel);
}

void SettingsWidget::onResetAction(){
    if (walletModel) {
        // confirmation dialog
        if (!ask(tr("Confirm options reset"), tr("Client restart required to activate changes.") + "<br><br>" + tr("Client will be shutdown, do you want to proceed?")))
            return;

        /* reset all options and close GUI */
        this->clientModel->getOptionsModel()->Reset();
        QApplication::quit();
    }
}

void SettingsWidget::onSaveOptionsClicked(){
    if(mapper->submit()) {
        pwalletMain->MarkDirty();
        if (this->clientModel->getOptionsModel()->isRestartRequired()) {
            bool fAcceptRestart = openStandardDialog(tr("Restart required"), tr("Your wallet needs to be restarted to apply the changes\n"), tr("Restart Now"), tr("Restart Later"));

            if (fAcceptRestart) {
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

                Q_EMIT handleRestart(args);
            } else {
                inform(tr("Options will be applied on next wallet restart"));
            }
        } else {
            inform(tr("Options stored"));
        }
    } else {
        inform(tr("Options store failed"));
    }
}

void SettingsWidget::selectMenu(QPushButton* btn)
{
    QWidget* subMenuSelected = menus[btn];
    if (btn->isChecked()) {
        QMapIterator<QPushButton*, QWidget*> it(menus);
        while (it.hasNext()) {
            it.next();
            QWidget* value = it.value();
            QPushButton* key = it.key();
            value->setVisible(value == subMenuSelected);
            if (key != btn) key->setChecked(false);
        }
    } else {
        subMenuSelected->setVisible(false);
    }
}

void SettingsWidget::onFileClicked()
{
    selectMenu(ui->pushButtonFile);
}

void SettingsWidget::onBackupWalletClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsBackupWallet);
    selectOption(ui->pushButtonFile2);
}

void SettingsWidget::onSignMessageClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsSingMessageWidgets);
    selectOption(ui->pushButtonConfiguration4);
}

void SettingsWidget::onConfigurationClicked() {
    selectMenu(ui->pushButtonConfiguration);
}

void SettingsWidget::onBipToolClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsBitToolWidget);
    selectOption(ui->pushButtonConfiguration3);
}

void SettingsWidget::onMultisendClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsMultisendWidget);
    selectOption(ui->pushButtonFile3);
}

void SettingsWidget::onExportCSVClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsExportCsvWidget);
    selectOption(ui->pushButtonExportCsv);
}

void SettingsWidget::onOptionsClicked() {
    selectMenu(ui->pushButtonOptions);
}

void SettingsWidget::onMainOptionsClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsMainOptionsWidget);
    selectOption(ui->pushButtonOptions1);
}

void SettingsWidget::onWalletOptionsClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsWalletOptionsWidget);
    selectOption(ui->pushButtonOptions2);
}

void SettingsWidget::onDisplayOptionsClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsDisplayOptionsWidget);
    selectOption(ui->pushButtonOptions5);
}


void SettingsWidget::onToolsClicked() {
    selectMenu(ui->pushButtonTools);
}

void SettingsWidget::onInformationClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsInformationWidget);
    selectOption(ui->pushButtonTools1);
}

void SettingsWidget::showDebugConsole(){
    ui->pushButtonTools->setChecked(true);
    onToolsClicked();
    ui->pushButtonTools2->setChecked(true);
    onDebugConsoleClicked();
}

void SettingsWidget::showInformation()
{
    ui->pushButtonTools->setChecked(true);
    onToolsClicked();
    ui->pushButtonTools1->setChecked(true);
    onInformationClicked();
}

void SettingsWidget::onDebugConsoleClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsConsoleWidget);
    selectOption(ui->pushButtonTools2);
}

void SettingsWidget::onWalletRepairClicked() {
    ui->stackedWidgetContainer->setCurrentWidget(settingsWalletRepairWidget);
    selectOption(ui->pushButtonTools5);
}


void SettingsWidget::onHelpClicked() {
    selectMenu(ui->pushButtonHelp);
}

void SettingsWidget::onAboutClicked() {
    if (!clientModel)
        return;

    HelpMessageDialog dlg(this, true);
    dlg.exec();

}

void SettingsWidget::openNetworkMonitor()
{
    settingsInformationWidget->openNetworkMonitor();
}

void SettingsWidget::selectOption(QPushButton* option){
    for (QPushButton* wid : options) {
        if(wid) wid->setChecked(wid == option);
    }
}

void SettingsWidget::onDiscardChanges(){
    if(clientModel) {
        if (!ask(tr("Discard Unsaved Changes"), tr("You are just about to discard all of your unsaved options.\n\nAre you sure?\n")))
            return;
        clientModel->getOptionsModel()->refreshDataView();
    }
}

void SettingsWidget::setMapper(){
    settingsMainOptionsWidget->setMapper(mapper);
    settingsWalletOptionsWidget->setMapper(mapper);
    settingsDisplayOptionsWidget->setMapper(mapper);
}

bool SettingsWidget::openStandardDialog(const QString& title, const QString& body, const QString& okBtn, const QString& cancelBtn)
{
    showHideOp(true);
    DefaultDialog *confirmDialog = new DefaultDialog(window);
    confirmDialog->setText(title, body, okBtn, cancelBtn);
    confirmDialog->adjustSize();
    openDialogWithOpaqueBackground(confirmDialog, window);
    confirmDialog->deleteLater();
    return confirmDialog->isOk;
}

SettingsWidget::~SettingsWidget(){
    delete ui;
}