// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/snackbar.h"
#include "qt/digiwage/forms/ui_snackbar.h"
#include "qt/digiwage/qtutils.h"
#include <QTimer>


SnackBar::SnackBar(DIGIWAGEGUI* _window, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SnackBar),
    window(_window),
    timeout(MIN_TIMEOUT)
{
    ui->setupUi(this);

    this->setStyleSheet(parent->styleSheet());
    ui->snackContainer->setProperty("cssClass", "container-snackbar");
    ui->label->setProperty("cssClass", "text-snackbar");
    ui->pushButton->setProperty("cssClass", "ic-close");

    connect(ui->pushButton, SIGNAL(clicked()), this, SLOT(close()));
    if (window)
        connect(window, SIGNAL(windowResizeEvent(QResizeEvent*)), this, SLOT(windowResizeEvent(QResizeEvent*)));
    else {
        ui->horizontalLayout->setContentsMargins(0,0,0,0);
        ui->label->setStyleSheet("font-size: 15px; color:white;");
    }
}

void SnackBar::windowResizeEvent(QResizeEvent* event){
    this->resize(qobject_cast<QWidget*>(parent())->width(), this->height());
    this->move(QPoint(0, window->height() - this->height() ));
}

void SnackBar::showEvent(QShowEvent *event){
    QTimer::singleShot(timeout, this, &SnackBar::hideAnim);
}

void SnackBar::hideAnim(){
    if (window) closeDialog(this, window);
    QTimer::singleShot(310, this, SLOT(hide()));
}

void SnackBar::setText(const QString& text)
{
    ui->label->setText(text);
    setTimeoutForText(text);
}

void SnackBar::setTimeoutForText(const QString& text){
    timeout = std::max(MIN_TIMEOUT, std::min(MAX_TIMEOUT, GetTimeout(text)));
}

int SnackBar::GetTimeout(const QString& message){
    // 50 milliseconds per char
    return (50 * message.length());
}

SnackBar::~SnackBar(){
    delete ui;
}

const int SnackBar::MIN_TIMEOUT;
const int SnackBar::MAX_TIMEOUT;