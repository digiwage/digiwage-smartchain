// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIGIWAGE_CORE_NEW_GUI_ADDRESSFILTERPROXYMODEL_H
#define DIGIWAGE_CORE_NEW_GUI_ADDRESSFILTERPROXYMODEL_H

#include <QSortFilterProxyModel>
#include "addresstablemodel.h"


class AddressFilterProxyModel final : public QSortFilterProxyModel
{

public:
    AddressFilterProxyModel(const QString& type, QObject* parent)
            : QSortFilterProxyModel(parent)
            , m_types({type}) {
        init();
    }

    AddressFilterProxyModel(const QStringList& types, QObject* parent)
            : QSortFilterProxyModel(parent)
            , m_types(types) {
        init();
    }

    void init() {
        setDynamicSortFilter(true);
        setFilterCaseSensitivity(Qt::CaseInsensitive);
        setSortCaseSensitivity(Qt::CaseInsensitive);
    }

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;

    void setType(const QString& type);
    void setType(const QStringList& types);

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override;

private:
    QStringList m_types;
};


#endif //DIGIWAGE_CORE_NEW_GUI_ADDRESSFILTERPROXYMODEL_H
