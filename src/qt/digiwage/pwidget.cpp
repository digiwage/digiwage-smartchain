// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/pwidget.h"
#include "qt/digiwage/qtutils.h"
#include "qt/digiwage/loadingdialog.h"
#include <QRunnable>
#include <QThreadPool>

PWidget::PWidget(DIGIWAGEGUI* _window, QWidget *parent) : QWidget((parent) ? parent : _window), window(_window){init();}
PWidget::PWidget(PWidget* parent) : QWidget(parent), window(parent->getWindow()){init();}

void PWidget::init() {
    if(window)
        connect(window, SIGNAL(themeChanged(bool, QString&)), this, SLOT(onChangeTheme(bool, QString&)));
}

void PWidget::setClientModel(ClientModel* model){
    this->clientModel = model;
    loadClientModel();
}

void PWidget::setWalletModel(WalletModel* model){
    this->walletModel = model;
    loadWalletModel();
}

void PWidget::onChangeTheme(bool isLightTheme, QString& theme){
    this->setStyleSheet(theme);
    changeTheme(isLightTheme, theme);
    updateStyle(this);
}

void PWidget::showHideOp(bool show){
    Q_EMIT showHide(show);
}

void PWidget::inform(const QString& message){
    emitMessage("", message, CClientUIInterface::MSG_INFORMATION_SNACK);
}

void PWidget::warn(const QString& title, const QString& message){
    emitMessage(title, message, CClientUIInterface::MSG_ERROR);
}

bool PWidget::ask(const QString& title, const QString& message){
    bool ret = false;
    emitMessage(title, message, CClientUIInterface::MSG_INFORMATION | CClientUIInterface::BTN_MASK | CClientUIInterface::MODAL, &ret);
    return ret;
}

void PWidget::showDialog(QDialog *dlg, int xDiv, int yDiv){
    Q_EMIT execDialog(dlg, xDiv, yDiv);
}

void PWidget::emitMessage(const QString& title, const QString& body, unsigned int style, bool* ret){
    Q_EMIT message(title, body, style, ret);
}

class WorkerTask : public QRunnable {

public:
    WorkerTask(QPointer<Worker> worker) {
        this->worker = worker;
    }

    ~WorkerTask() {
        if (!worker.isNull()) worker.clear();
    }

    void run() override {
        if (!worker.isNull()) worker.data()->process();
    }

    QPointer<Worker> worker;
};

bool PWidget::execute(int type){
    if (task.isNull()) {
        Worker* worker = new Worker(this, type);
        connect(worker, SIGNAL (error(QString, int)), this, SLOT (errorString(QString, int)));

        WorkerTask* workerTask = new WorkerTask(QPointer<Worker>(worker));
        workerTask->setAutoDelete(false);
        task = QSharedPointer<WorkerTask>(workerTask);
    }
    QThreadPool::globalInstance()->start(task.data());
    return true;
}

void PWidget::errorString(QString error, int type) {
    onError(error, type);
}


////////////////////////////////////////////////////////////////
//////////////////Override methods//////////////////////////////
////////////////////////////////////////////////////////////////


void PWidget::loadClientModel(){
    // override
}

void PWidget::loadWalletModel(){
    // override
}

void PWidget::changeTheme(bool isLightTheme, QString& theme){
    // override
}

void PWidget::run(int type) {
    // override
}
void PWidget::onError(QString error, int type) {
    // override
}
