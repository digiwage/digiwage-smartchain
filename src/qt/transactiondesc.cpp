// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactiondesc.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "paymentserver.h"
#include "transactionrecord.h"

#include "base58.h"
#include "db.h"
#include "main.h"
#include "script/script.h"
#include "timedata.h"
#include "guiinterface.h"
#include "util.h"
#include "wallet/wallet.h"

#include <stdint.h>
#include <string>


QString TransactionDesc::FormatTxStatus(const CWalletTx& wtx)
{
    AssertLockHeld(cs_main);
    if (!IsFinalTx(wtx, chainActive.Height() + 1)) {
        if (wtx.nLockTime < LOCKTIME_THRESHOLD)
            return tr("Open for %n more block(s)", "", wtx.nLockTime - chainActive.Height());
        else
            return tr("Open until %1").arg(GUIUtil::dateTimeStr(wtx.nLockTime));
    } else {
        const int signatures = wtx.GetTransactionLockSignatures();
        QString strUsingIX = "";
        bool fConflicted;
        const int nDepth = wtx.GetDepthAndMempool(fConflicted);

        if (nDepth < 0 || fConflicted)
            return tr("conflicted");

        if (signatures >= 0) {
            if (signatures >= SWIFTTX_SIGNATURES_REQUIRED) {
                if (nDepth < 6)
                    return tr("%1/confirmed (verified via SwiftX)").arg(nDepth);
                else
                    return tr("%1 confirmations (verified via SwiftX)").arg(nDepth);
            } else {
                if (!wtx.IsTransactionLockTimedOut()) {
                    if (nDepth < 6)
                        return tr("%1/confirmed (SwiftX verification in progress - %2 of %3 signatures )").arg(nDepth).arg(signatures).arg(SWIFTTX_SIGNATURES_TOTAL);
                    else
                        return tr("%1 confirmations (SwiftX verification in progress - %2 of %3 signatures)").arg(nDepth).arg(signatures).arg(SWIFTTX_SIGNATURES_TOTAL);
                } else {
                    if (nDepth < 6)
                        return tr("%1/confirmed (SwiftX verification failed)").arg(nDepth);
                    else
                        return tr("%1 confirmations").arg(nDepth);
                }
            }
        } else {
            if (nDepth < 6)
                return tr("%1/unconfirmed").arg(nDepth);
            else
                return tr("%1 confirmations").arg(nDepth);
        }
    }
}

QString TransactionDesc::toHTML(CWallet* wallet, CWalletTx& wtx, TransactionRecord* rec, int unit)
{
    QString strHTML;

    LOCK2(cs_main, wallet->cs_wallet);
    strHTML.reserve(4000);
    strHTML += "<html><font face='verdana, arial, helvetica, sans-serif'>";

    CAmount nNet = rec->credit + rec->debit;

    strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(wtx);
    strHTML += "<br>";

    strHTML += "<b>" + tr("Date") + ":</b> " + (rec->time ? GUIUtil::dateTimeStr(rec->time) : "") + "<br>";

    //
    // From
    //
    if (wtx.IsCoinBase()) {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
    } else if (wtx.mapValue.count("from") && !wtx.mapValue["from"].empty()) {
        // Online transaction
        strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.mapValue["from"]) + "<br>";
    } else {
        // Offline transaction
        if (nNet > 0) {
            // Credit
            if (CBitcoinAddress(rec->address).IsValid()) {
                CTxDestination address = CBitcoinAddress(rec->address).Get();
                if (wallet->mapAddressBook.count(address)) {
                    strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    strHTML += GUIUtil::HtmlEscape(rec->address);
                    QString addressOwned = (::IsMine(*wallet, address) == ISMINE_SPENDABLE) ? tr("own address") : tr("watch-only");
                    if (!wallet->mapAddressBook[address].name.empty())
                        strHTML += " (" + addressOwned + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";
                    strHTML += "<br>";
                }
            }
        }
    }

    //
    // To
    //
    if (wtx.mapValue.count("to") && !wtx.mapValue["to"].empty()) {
        // Online transaction
        std::string strAddress = wtx.mapValue["to"];
        strHTML += "<b>" + tr("To") + ":</b> ";
        CTxDestination dest = CBitcoinAddress(strAddress).Get();
        if (wallet->mapAddressBook.count(dest) && !wallet->mapAddressBook[dest].name.empty())
            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[dest].name) + " ";
        strHTML += GUIUtil::HtmlEscape(strAddress) + "<br>";
    }

    //
    // Amount
    //
    if (wtx.IsCoinBase() && rec->credit == 0) {
        //
        // Coinbase
        //
        CAmount nUnmatured = 0;
        for (const CTxOut& txout : wtx.vout)
            nUnmatured += wallet->GetCredit(txout, ISMINE_ALL);
        strHTML += "<b>" + tr("Credit") + ":</b> ";
        if (wtx.IsInMainChain())
            strHTML += BitcoinUnits::formatHtmlWithUnit(unit, nUnmatured) + " (" + tr("matures in %n more block(s)", "", wtx.GetBlocksToMaturity()) + ")";
        else
            strHTML += "(" + tr("not accepted") + ")";
        strHTML += "<br>";
    } else if (nNet > 0) {
        //
        // Credit
        //
        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet) + "<br>";
    } else {
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        for (const CTxIn& txin : wtx.vin) {
            isminetype mine = wallet->IsMine(txin);
            if (fAllFromMe > mine) fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        for (const CTxOut& txout : wtx.vout) {
            isminetype mine = wallet->IsMine(txout);
            if (fAllToMe > mine) fAllToMe = mine;
        }

        if (fAllFromMe) {
            if (fAllFromMe == ISMINE_WATCH_ONLY)
                strHTML += "<b>" + tr("From") + ":</b> " + tr("watch-only") + "<br>";

            //
            // Debit
            //
            for (const CTxOut& txout : wtx.vout) {
                // Ignore change
                isminetype toSelf = wallet->IsMine(txout);
                if ((toSelf == ISMINE_SPENDABLE) && (fAllFromMe == ISMINE_SPENDABLE))
                    continue;

                if (!wtx.mapValue.count("to") || wtx.mapValue["to"].empty()) {
                    // Offline transaction
                    CTxDestination address;
                    if (ExtractDestination(txout.scriptPubKey, address)) {
                        strHTML += "<b>" + tr("To") + ":</b> ";
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += GUIUtil::HtmlEscape(CBitcoinAddress(address).ToString());
                        if (toSelf == ISMINE_SPENDABLE)
                            strHTML += " (own address)";
                        else if (toSelf == ISMINE_WATCH_ONLY)
                            strHTML += " (watch-only)";
                        strHTML += "<br>";
                    }
                }

                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -txout.nValue) + "<br>";
                if (toSelf)
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, txout.nValue) + "<br>";
            }

            if (fAllToMe) {
                // Payment to self
                CAmount nChange = wtx.GetChange();
                CAmount nValue = rec->credit - nChange;
                strHTML += "<b>" + tr("Total debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nValue) + "<br>";
                strHTML += "<b>" + tr("Total credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nValue) + "<br>";
            }

            CAmount nTxFee = rec->debit - wtx.GetValueOut();
            if (nTxFee > 0)
                strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        } else {
            //
            // Mixed debit transaction
            //
            for (const CTxIn& txin : wtx.vin)
                if (wallet->IsMine(txin))
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, ISMINE_ALL)) + "<br>";
            for (const CTxOut& txout : wtx.vout)
                if (wallet->IsMine(txout))
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";
        }
    }

    strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";

    //
    // Message
    //
    if (wtx.mapValue.count("message") && !wtx.mapValue["message"].empty())
        strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["message"], true) + "<br>";
    if (wtx.mapValue.count("comment") && !wtx.mapValue["comment"].empty())
        strHTML += "<br><b>" + tr("Comment") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["comment"], true) + "<br>";

    strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxID() + "<br>";
    strHTML += "<b>" + tr("Output index") + ":</b> " + QString::number(rec->getOutputIndex()) + "<br>";

    // Message from normal digiwage:URI (digiwage:XyZ...?message=example)
    Q_FOREACH (const PAIRTYPE(std::string, std::string) & r, wtx.vOrderForm)
        if (r.first == "Message")
            strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(r.second, true) + "<br>";

    //
    // PaymentRequest info:
    //
    Q_FOREACH (const PAIRTYPE(std::string, std::string) & r, wtx.vOrderForm) {
        if (r.first == "PaymentRequest") {
            PaymentRequestPlus req;
            req.parse(QByteArray::fromRawData(r.second.data(), r.second.size()));
            QString merchant;
            if (req.getMerchant(PaymentServer::getCertStore(), merchant))
                strHTML += "<b>" + tr("Merchant") + ":</b> " + GUIUtil::HtmlEscape(merchant) + "<br>";
        }
    }

    if (wtx.IsCoinBase()) {
        //quint32 numBlocksToMaturity = Params().GetConsensus().nCoinbaseMaturity + 1;
        //strHTML += "<br>" + tr("Generated coins must mature %1 blocks before they can be spent. When you generated this block, it was broadcast to the network to be added to the block chain. If it fails to get into the chain, its state will change to \"not accepted\" and it won't be spendable. This may occasionally happen if another node generates a block within a few seconds of yours.").arg(QString::number(numBlocksToMaturity)) + "<br>";
    }

    //
    // Debug view
    //
    if (fDebug) {
        strHTML += "<hr><br>" + tr("Debug information") + "<br><br>";
        for (const CTxIn& txin : wtx.vin)
            if (wallet->IsMine(txin))
                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, ISMINE_ALL)) + "<br>";
        for (const CTxOut& txout : wtx.vout)
            if (wallet->IsMine(txout))
                strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";

        strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
        strHTML += GUIUtil::HtmlEscape(wtx.ToString(), true);

        strHTML += "<br><b>" + tr("Inputs") + ":</b>";
        strHTML += "<ul>";

        for (const CTxIn& txin : wtx.vin) {
            COutPoint prevout = txin.prevout;

            CCoins prev;
            if (pcoinsTip->GetCoins(prevout.hash, prev)) {
                if (prevout.n < prev.vout.size()) {
                    strHTML += "<li>";
                    const CTxOut& vout = prev.vout[prevout.n];
                    CTxDestination address;
                    if (ExtractDestination(vout.scriptPubKey, address)) {
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += QString::fromStdString(CBitcoinAddress(address).ToString());
                    }
                    strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatHtmlWithUnit(unit, vout.nValue);
                    strHTML = strHTML + " IsMine=" + (wallet->IsMine(vout) & ISMINE_SPENDABLE ? tr("true") : tr("false"));
                    strHTML = strHTML + " IsWatchOnly=" + (wallet->IsMine(vout) & ISMINE_WATCH_ONLY ? tr("true") : tr("false")) + "</li>";
                }
            }
        }

        strHTML += "</ul>";
    }

    strHTML += "</font></html>";
    return strHTML;
}
