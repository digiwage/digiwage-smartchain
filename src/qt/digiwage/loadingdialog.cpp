// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/loadingdialog.h"
#include "qt/digiwage/forms/ui_loadingdialog.h"
#include <QMovie>

void Worker::process(){
    if (runnable) {
        try {
            runnable->run(type);
        } catch (std::exception &e) {
            QString errorStr = QString::fromStdString(e.what());
            runnable->onError(errorStr, type);
            Q_EMIT error(errorStr, type);
        } catch (...) {
            QString errorStr = QString::fromStdString("Unknown error running background task");
            runnable->onError(errorStr, type);
            Q_EMIT error(errorStr, type);
        }
    } else {
        Q_EMIT error("Null runnable", type);
    }
    Q_EMIT finished();
};

LoadingDialog::LoadingDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LoadingDialog)
{
    ui->setupUi(this);

    this->setStyleSheet(parent->styleSheet());

    ui->frame->setProperty("cssClass", "container-loading");

    QMovie *movie = new QMovie("://ani-loading-dark");
    ui->labelMovie->setText("");
    ui->labelMovie->setMovie(movie);
    movie->start();

    ui->labelMessage->setText(tr("Loading"));
    ui->labelMessage->setProperty("cssClass", "text-loading");
    ui->labelDots->setProperty("cssClass", "text-loading");
}

void LoadingDialog::execute(Runnable *runnable, int type){
    loadingTimer = new QTimer(this);
    connect(loadingTimer, SIGNAL(timeout()), this, SLOT(loadingTextChange()));
    loadingTimer->start(250);

    QThread* thread = new QThread;
    Worker* worker = new Worker(runnable, type);
    worker->moveToThread(thread);
    connect(thread, &QThread::started, worker, &Worker::process);
    connect(worker, &Worker::finished, thread, &QThread::quit);
    connect(worker, &Worker::finished, worker, &Worker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);
    connect(worker, &Worker::finished, this, &LoadingDialog::finished);
    thread->start();
}

void LoadingDialog::loadingTextChange(){
    if (loading == 4) {
        loading = 0;
    } else {
        loading++;
    }
    switch (loading) {
        case 1:
            ui->labelDots->setText("");
            break;
        case 2:
            ui->labelDots->setText(".");
            break;
        case 3:
            ui->labelDots->setText("..");
            break;
        case 4:
            ui->labelDots->setText("...");
            break;
    }
}

void LoadingDialog::finished(){
    loadingTimer->stop();
    accept();
    deleteLater();
}

LoadingDialog::~LoadingDialog()
{
    delete ui;
}
