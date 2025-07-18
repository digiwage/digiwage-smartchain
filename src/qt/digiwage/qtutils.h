// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QTUTILS_H
#define QTUTILS_H

#include <QWidget>
#include <QDialog>
#include <QPropertyAnimation>
#include <QAbstractAnimation>
#include <QPoint>
#include <QString>
#include <QColor>
#include <QComboBox>
#include <QSettings>
#include <QPixmap>
#include <QStandardPaths>
#include <initializer_list>
#include "qt/digiwage/digiwagegui.h"

// Repair parameters
const QString SALVAGEWALLET("-salvagewallet");
const QString RESCAN("-rescan");
const QString ZAPTXES1("-zapwallettxes=1");
const QString ZAPTXES2("-zapwallettxes=2");
const QString UPGRADEWALLET("-upgradewallet");
const QString REINDEX("-reindex");
const QString RESYNC("-resync");

extern Qt::Modifier SHORT_KEY;

bool openDialog(QDialog *widget, QWidget *gui);
void closeDialog(QDialog *widget, DIGIWAGEGUI *gui);
void openDialogFullScreen(QWidget *parent, QWidget * dialog);
bool openDialogWithOpaqueBackgroundY(QDialog *widget, DIGIWAGEGUI *gui, double posX = 3, int posY = 5);
bool openDialogWithOpaqueBackground(QDialog *widget, DIGIWAGEGUI *gui, double posX = 3);
bool openDialogWithOpaqueBackgroundFullScreen(QDialog *widget, DIGIWAGEGUI *gui);

// QR codes
QPixmap encodeToQr(QString str, QString &errorStr, QColor qrColor = Qt::black);

// Helpers
void updateStyle(QWidget* widget);
QColor getRowColor(bool isLightTheme, bool isHovered, bool isSelected);

// filters
void setFilterAddressBook(QComboBox* filter, SortEdit* lineEdit);
void setSortTx(QComboBox* filter, SortEdit* lineEdit);
void setSortTxTypeFilter(QComboBox* filter, SortEdit* lineEdit);

// Settings
QSettings* getSettings();
void setupSettings(QSettings *settings);

bool isLightTheme();
void setTheme(bool isLight);

void initComboBox(QComboBox* combo, QLineEdit* lineEdit = nullptr, QString cssClass = "btn-combo");
void fillAddressSortControls(SortEdit* seType, SortEdit* seOrder, QComboBox* boxType, QComboBox* boxOrder);
void initCssEditLine(QLineEdit *edit, bool isDialog = false);
void setCssEditLine(QLineEdit *edit, bool isValid, bool forceUpdate = false);
void setCssEditLineDialog(QLineEdit *edit, bool isValid, bool forceUpdate = false);
void setShadow(QWidget *edit);

void setCssBtnPrimary(QPushButton *btn, bool forceUpdate = false);
void setCssBtnSecondary(QPushButton *btn, bool forceUpdate = false);
void setCssTitleScreen(QLabel* label);
void setCssSubtitleScreen(QWidget* wid);
void setCssTextBodyDialog(std::initializer_list<QWidget*> args);
void setCssTextBodyDialog(QWidget* widget);
void setCssProperty(std::initializer_list<QWidget*> args, QString value);
void setCssProperty(QWidget *wid, QString value, bool forceUpdate = false);
void forceUpdateStyle(QWidget *widget, bool forceUpdate);
void forceUpdateStyle(std::initializer_list<QWidget*> args);

#endif // QTUTILS_H
