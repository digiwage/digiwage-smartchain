// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/defaultdialog.h"
#include "qt/digiwage/forms/ui_defaultdialog.h"
#include "guiutil.h"
#include <QKeyEvent>

DefaultDialog::DefaultDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DefaultDialog)
{
    ui->setupUi(this);

    // Stylesheet
    this->setStyleSheet(parent ? parent->styleSheet() : GUIUtil::loadStyleSheet());

    // Container
    ui->frame->setProperty("cssClass", "container-dialog");

    // Text
    ui->labelTitle->setText("Dialog Title");
    ui->labelTitle->setProperty("cssClass", "text-title-dialog");


    ui->labelMessage->setText("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.");
    ui->labelMessage->setProperty("cssClass", "text-main-grey");

    // Buttons
    ui->btnEsc->setText("");
    ui->btnEsc->setProperty("cssClass", "ic-close");

    ui->btnCancel->setProperty("cssClass", "btn-dialog-cancel");
    ui->btnSave->setText("OK");
    ui->btnSave->setProperty("cssClass", "btn-primary");

    connect(ui->btnEsc, SIGNAL(clicked()), this, SLOT(close()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(close()));
    connect(ui->btnSave, &QPushButton::clicked, this, &DefaultDialog::accept);
}

void DefaultDialog::showEvent(QShowEvent *event)
{
    setFocus();
}


void DefaultDialog::setText(QString title, QString message, QString okBtnText, QString cancelBtnText)
{
    if(!okBtnText.isNull()) ui->btnSave->setText(okBtnText);
    if(!cancelBtnText.isNull()){
        ui->btnCancel->setVisible(true);
        ui->btnCancel->setText(cancelBtnText);
    }else{
        ui->btnCancel->setVisible(false);
    }
    if(!message.isNull()) ui->labelMessage->setText(message);
    if(!title.isNull()) ui->labelTitle->setText(title);
}

void DefaultDialog::accept()
{
    this->isOk = true;
    QDialog::accept();
}

void DefaultDialog::keyPressEvent(QKeyEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent* ke = static_cast<QKeyEvent*>(event);
        // Detect Enter key press
        if (ke->key() == Qt::Key_Enter || ke->key() == Qt::Key_Return) accept();
        // Detect Esc key press
        if (ke->key() == Qt::Key_Escape) close();
    }
}

DefaultDialog::~DefaultDialog()
{
    delete ui;
}
