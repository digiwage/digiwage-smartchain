// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/digiwage/qtutils.h"

#include "qt/digiwage/snackbar.h"
#include "qrencode.h"
#include "guiconstants.h"

#include <QFile>
#include <QStyle>
#include <QListView>
#include <QGraphicsDropShadowEffect>

Qt::Modifier SHORT_KEY
#ifdef Q_OS_MAC
        = Qt::CTRL;
#else
        = Qt::ALT;
#endif

// Open dialog at the bottom
bool openDialog(QDialog *widget, QWidget *gui){
    widget->setWindowFlags(Qt::CustomizeWindowHint);
    widget->setAttribute(Qt::WA_TranslucentBackground, true);
    QPropertyAnimation* animation = new QPropertyAnimation(widget, "pos");
    animation->setDuration(300);
    animation->setStartValue(QPoint(0, gui->height()));
    animation->setEndValue(QPoint(0, gui->height() - widget->height()));
    animation->setEasingCurve(QEasingCurve::OutQuad);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
    widget->activateWindow();
    widget->raise();
    return widget->exec();
}

void closeDialog(QDialog *widget, DIGIWAGEGUI *gui){
    widget->setWindowFlags(Qt::CustomizeWindowHint);
    widget->setAttribute(Qt::WA_TranslucentBackground, true);
    QPropertyAnimation* animation = new QPropertyAnimation(widget, "pos");
    animation->setDuration(300);
    animation->setStartValue(widget->pos());
    animation->setEndValue(QPoint(0, gui->height() + 100));
    animation->setEasingCurve(QEasingCurve::OutQuad);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

void openDialogFullScreen(QWidget *parent, QWidget * dialog){
    dialog->setWindowFlags(Qt::CustomizeWindowHint);
    dialog->move(0, 0);
    dialog->show();
    dialog->activateWindow();
    dialog->resize(parent->width(),parent->height());
}

bool openDialogWithOpaqueBackgroundY(QDialog *widget, DIGIWAGEGUI *gui, double posX, int posY){
    widget->setWindowFlags(Qt::CustomizeWindowHint);
    widget->setAttribute(Qt::WA_TranslucentBackground, true);
    QPropertyAnimation* animation = new QPropertyAnimation(widget, "pos");
    animation->setDuration(300);
    int xPos = gui->width() / posX ;
    animation->setStartValue(QPoint(xPos, gui->height()));
    animation->setEndValue(QPoint(xPos, gui->height() / posY));//- (gui->height()) / posY  ));
    animation->setEasingCurve(QEasingCurve::OutQuad);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
    widget->activateWindow();
    bool res = widget->exec();
    gui->showHide(false);
    return res;
}

bool openDialogWithOpaqueBackground(QDialog *widget, DIGIWAGEGUI *gui, double posX){
    return openDialogWithOpaqueBackgroundY(widget, gui, posX, 5);
}

bool openDialogWithOpaqueBackgroundFullScreen(QDialog *widget, DIGIWAGEGUI *gui){
    widget->setWindowFlags(Qt::CustomizeWindowHint);
    widget->setAttribute(Qt::WA_TranslucentBackground, true);

    widget->activateWindow();
    widget->resize(gui->width(),gui->height());

    QPropertyAnimation* animation = new QPropertyAnimation(widget, "pos");
    animation->setDuration(300);
    int xPos = 0;
    animation->setStartValue(QPoint(xPos, gui->height()));
    animation->setEndValue(QPoint(xPos, 0));
    animation->setEasingCurve(QEasingCurve::OutQuad);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
    widget->activateWindow();
    bool res = widget->exec();
    gui->showHide(false);
    return res;
}

QPixmap encodeToQr(QString str, QString &errorStr, QColor qrColor){
    if (!str.isEmpty()) {
        // limit URI length
        if (str.length() > MAX_URI_LENGTH) {
            errorStr = "Resulting URI too long, try to reduce the text for label / message.";
            return QPixmap();
        } else {
            QRcode* code = QRcode_encodeString(str.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
            if (!code) {
                errorStr = "Error encoding URI into QR Code.";
                return QPixmap();
            }
            QImage myImage = QImage(code->width + 8, code->width + 8, QImage::Format_RGB32);
            myImage.fill(0xffffff);
            unsigned char* p = code->data;
            for (int y = 0; y < code->width; y++) {
                for (int x = 0; x < code->width; x++) {
                    myImage.setPixel(x + 4, y + 4, ((*p & 1) ? qrColor.rgb() : 0xffffff));
                    p++;
                }
            }
            QRcode_free(code);
            return QPixmap::fromImage(myImage);
        }
    }
    return QPixmap();
}

void setFilterAddressBook(QComboBox* filter, SortEdit* lineEdit) {
    initComboBox(filter, lineEdit);
    filter->addItem("All", "");
    filter->addItem("Receiving", AddressTableModel::Receive);
    filter->addItem("Contacts", AddressTableModel::Send);
    filter->addItem("Cold Staking", AddressTableModel::ColdStaking);
    filter->addItem("Delegators", AddressTableModel::Delegators);
    filter->addItem("Staking Contacts", AddressTableModel::ColdStakingSend);
}

void setSortTx(QComboBox* filter, SortEdit* lineEdit) {
    // Sort Transactions
    initComboBox(filter, lineEdit);
    filter->addItem("Date desc", SortTx::DATE_DESC);
    filter->addItem("Date asc", SortTx::DATE_ASC);
    filter->addItem("Amount desc", SortTx::AMOUNT_ASC);
    filter->addItem("Amount asc", SortTx::AMOUNT_DESC);
}

void setSortTxTypeFilter(QComboBox* filter, SortEdit* lineEditType) {
    initComboBox(filter, lineEditType);
    filter->addItem(filter->tr("All"), TransactionFilterProxy::ALL_TYPES);
    filter->addItem(filter->tr("Received"), TransactionFilterProxy::TYPE(TransactionRecord::RecvWithAddress) | TransactionFilterProxy::TYPE(TransactionRecord::RecvFromOther));
    filter->addItem(filter->tr("Sent"), TransactionFilterProxy::TYPE(TransactionRecord::SendToAddress) | TransactionFilterProxy::TYPE(TransactionRecord::SendToOther));
    filter->addItem(filter->tr("Burned"), TransactionFilterProxy::TYPE(TransactionRecord::Burned));
    filter->addItem(filter->tr("Mined"), TransactionFilterProxy::TYPE(TransactionRecord::Generated));
    filter->addItem(filter->tr("Stakes"), TransactionFilterProxy::TYPE(TransactionRecord::StakeMint));
    filter->addItem(filter->tr("SuperStakes"), TransactionFilterProxy::TYPE(TransactionRecord::SuperStake));
    filter->addItem(filter->tr("MN reward"), TransactionFilterProxy::TYPE(TransactionRecord::MNReward));
    filter->addItem(filter->tr("To yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SendToSelf));
    filter->addItem(filter->tr("Cold stakes"), TransactionFilterProxy::TYPE(TransactionRecord::StakeDelegated));
    filter->addItem(filter->tr("Hot stakes"), TransactionFilterProxy::TYPE(TransactionRecord::StakeHot));
    filter->addItem(filter->tr("Delegated"), TransactionFilterProxy::TYPE(TransactionRecord::P2CSDelegationSent) | TransactionFilterProxy::TYPE(TransactionRecord::P2CSDelegationSentOwner));
    filter->addItem(filter->tr("Delegations"), TransactionFilterProxy::TYPE(TransactionRecord::P2CSDelegation));
}

void setupSettings(QSettings *settings){
    if(!settings->contains("lightTheme")){
        settings->setValue("lightTheme", true);
    }
}

QSettings *settings = nullptr;

QSettings* getSettings(){
    if(!settings){
        settings = new QSettings();
        // Setup initial values if them are not there
        setupSettings(settings);
    }

    return settings;
}

bool isLightTheme(){
    return getSettings()->value("lightTheme", true).toBool();
}

void setTheme(bool isLight){
    QSettings* settings =  getSettings();
    settings->setValue("theme", isLight ? "default" : "default-dark");
    settings->setValue("lightTheme", isLight);
}


// Style

void updateStyle(QWidget* widget){
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
}


QColor getRowColor(bool isLightTheme, bool isHovered, bool isSelected){
    if (isLightTheme) {
        if (isSelected) {
            return QColor("#25fcdd1f");
        } else if (isHovered) {
            return QColor("#25bababa");
        } else {
            return QColor("#ffffff");
        }
    } else {
        if (isSelected) {
            return QColor("#25fcdd1f");
        } else if (isHovered) {
            return QColor("#25bababa");
        } else {
            return QColor("#080808");
        }
    }
}

void initComboBox(QComboBox* combo, QLineEdit* lineEdit, QString cssClass){
    setCssProperty(combo, cssClass);
    combo->setEditable(true);
    if (lineEdit) {
        lineEdit->setReadOnly(true);
        lineEdit->setAlignment(Qt::AlignRight);
        combo->setLineEdit(lineEdit);
    }
    combo->setStyleSheet("selection-background-color:transparent; selection-color:transparent;");
    combo->setView(new QListView());
}

void fillAddressSortControls(SortEdit* seType, SortEdit* seOrder, QComboBox* boxType, QComboBox* boxOrder)
{
    // Sort Type
    initComboBox(boxType, seType, "btn-combo-small");
    boxType->addItem(QObject::tr("by Label"), AddressTableModel::Label);
    boxType->addItem(QObject::tr("by Address"), AddressTableModel::Address);
    boxType->addItem(QObject::tr("by Date"), AddressTableModel::Date);
    boxType->setCurrentIndex(0);
    // Sort Order
    initComboBox(boxOrder, seOrder, "btn-combo-small");
    boxOrder->addItem("asc", Qt::AscendingOrder);
    boxOrder->addItem("desc", Qt::DescendingOrder);
    boxOrder->setCurrentIndex(0);
}

void initCssEditLine(QLineEdit *edit, bool isDialog){
    if (isDialog) setCssEditLineDialog(edit, true, false);
    else setCssEditLine(edit, true, false);
    setShadow(edit);
    edit->setAttribute(Qt::WA_MacShowFocusRect, 0);
}

void setCssEditLine(QLineEdit *edit, bool isValid, bool forceUpdate){
    setCssProperty(edit, isValid ? "edit-primary" : "edit-primary-error", forceUpdate);
}

void setCssEditLineDialog(QLineEdit *edit, bool isValid, bool forceUpdate){
    setCssProperty(edit, isValid ? "edit-primary-dialog" : "edit-primary-dialog-error", forceUpdate);
}

void setShadow(QWidget *edit){
    QGraphicsDropShadowEffect* shadowEffect = new QGraphicsDropShadowEffect();
    shadowEffect->setColor(QColor(0, 0, 0, 22));
    shadowEffect->setXOffset(0);
    shadowEffect->setYOffset(3);
    shadowEffect->setBlurRadius(6);
    edit->setGraphicsEffect(shadowEffect);
}

void setCssBtnPrimary(QPushButton *btn, bool forceUpdate){
    setCssProperty(btn, "btn-primary", forceUpdate);
}

void setCssBtnSecondary(QPushButton *btn, bool forceUpdate){
    setCssProperty(btn, "btn-secundary", forceUpdate);
}

void setCssTextBodyDialog(std::initializer_list<QWidget*> args){
    Q_FOREACH (QWidget* w, args) { setCssTextBodyDialog(w); }
}

void setCssTextBodyDialog(QWidget* widget) {
    setCssProperty(widget, "text-body1-dialog", false);
}

void setCssTitleScreen(QLabel* label) {
    setCssProperty(label, "text-title-screen", false);
}

void setCssSubtitleScreen(QWidget* wid) {
    setCssProperty(wid, "text-subtitle", false);
}

void setCssProperty(std::initializer_list<QWidget*> args, QString value){
    Q_FOREACH (QWidget* w, args) { setCssProperty(w, value); }
}

void setCssProperty(QWidget *wid, QString value, bool forceUpdate){
    wid->setProperty("cssClass", value);
    forceUpdateStyle(wid, forceUpdate);
}

void forceUpdateStyle(QWidget *widget, bool forceUpdate){
    if(forceUpdate)
        updateStyle(widget);
}

void forceUpdateStyle(std::initializer_list<QWidget*> args){
    Q_FOREACH (QWidget* w, args) { forceUpdateStyle(w, true); }
}
