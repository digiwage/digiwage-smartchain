// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/digiwage-config.h"
#endif

#include "qt/digiwage/digiwagegui.h"

#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "intro.h"
#include "net.h"
#include "networkstyle.h"
#include "optionsmodel.h"
#include "qt/digiwage/splash.h"
#include "qt/digiwage/welcomecontentwidget.h"
#include "utilitydialog.h"
#include "winshutdownmonitor.h"

#ifdef ENABLE_WALLET
#include "paymentserver.h"
#include "walletmodel.h"
#endif
#include "masternodeconfig.h"
#include "forgeman.h"

#include "qt/startoptionsmain.h"

#include "init.h"
#include "main.h"
#include "rpc/server.h"
#include "guiinterface.h"
#include "util.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/filesystem/operations.hpp>
#include <boost/thread.hpp>

#include <QApplication>
#include <QDebug>
#include <QLibraryInfo>
#include <QLocale>
#include <QMessageBox>
#include <QProcess>
#include <QSettings>
#include <QThread>
#include <QTimer>
#include <QTranslator>
#include <vector>

#if defined(QT_STATICPLUGIN)
#include <QtPlugin>
#if defined(QT_QPA_PLATFORM_XCB)
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_WINDOWS)
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_COCOA)
Q_IMPORT_PLUGIN(QCocoaIntegrationPlugin);
#endif
Q_IMPORT_PLUGIN(QSvgPlugin);
Q_IMPORT_PLUGIN(QSvgIconPlugin);
#endif

// Declare meta types used for QMetaObject::invokeMethod
Q_DECLARE_METATYPE(bool*)
Q_DECLARE_METATYPE(CAmount)

static void InitMessage(const std::string& message)
{
    LogPrintf("init message: %s\n", message);
}

/*
   Translate string to current locale using Qt.
 */
static std::string Translate(const char* psz)
{
    return QCoreApplication::translate("digiwage-core", psz).toStdString();
}

static QString GetLangTerritory()
{
    QSettings settings;
    // Get desired locale (e.g. "de_DE")
    // 1) System default language
    QString lang_territory = QLocale::system().name();
    // 2) Language from QSettings
    QString lang_territory_qsettings = settings.value("language", "").toString();
    if (!lang_territory_qsettings.isEmpty())
        lang_territory = lang_territory_qsettings;
    // 3) -lang command line argument
    lang_territory = QString::fromStdString(GetArg("-lang", lang_territory.toStdString()));
    return lang_territory;
}

/** Set up translations */
static void initTranslations(QTranslator& qtTranslatorBase, QTranslator& qtTranslator, QTranslator& translatorBase, QTranslator& translator)
{
    // Remove old translators
    QApplication::removeTranslator(&qtTranslatorBase);
    QApplication::removeTranslator(&qtTranslator);
    QApplication::removeTranslator(&translatorBase);
    QApplication::removeTranslator(&translator);

    // Get desired locale (e.g. "de_DE")
    // 1) System default language
    QString lang_territory = GetLangTerritory();

    // Convert to "de" only by truncating "_DE"
    QString lang = lang_territory;
    lang.truncate(lang_territory.lastIndexOf('_'));

    // Load language files for configured locale:
    // - First load the translator for the base language, without territory
    // - Then load the more specific locale translator

    // Load e.g. qt_de.qm
    if (qtTranslatorBase.load("qt_" + lang, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(&qtTranslatorBase);

    // Load e.g. qt_de_DE.qm
    if (qtTranslator.load("qt_" + lang_territory, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(&qtTranslator);

    // Load e.g. bitcoin_de.qm (shortcut "de" needs to be defined in digiwage.qrc)
    if (translatorBase.load(lang, ":/translations/"))
        QApplication::installTranslator(&translatorBase);

    // Load e.g. bitcoin_de_DE.qm (shortcut "de_DE" needs to be defined in digiwage.qrc)
    if (translator.load(lang_territory, ":/translations/"))
        QApplication::installTranslator(&translator);
}

/* qDebug() message handler --> debug.log */
void DebugMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg)
{
    Q_UNUSED(context);
    const char* category = (type == QtDebugMsg) ? "qt" : NULL;
    LogPrint(category, "GUI: %s\n", msg.toStdString());
}

/** Class encapsulating DIGIWAGE Core startup and shutdown.
 * Allows running startup and shutdown in a different thread from the UI thread.
 */
class BitcoinCore : public QObject
{
    Q_OBJECT
public:
    explicit BitcoinCore(std::vector<std::string>& wordlist);

public Q_SLOTS:
    void initialize();
    void shutdown();
    void restart(QStringList args);

Q_SIGNALS:
    void initializeResult(int retval);
    void shutdownResult(int retval);
    void runawayException(const QString& message);

private:
    /// Flag indicating a restart
    bool execute_restart;

    /// Pass fatal exception message to UI thread
    void handleRunawayException(const std::exception* e);
    std::vector<std::string> words;
};

/** Main DIGIWAGE application object */
class BitcoinApplication : public QApplication
{
    Q_OBJECT
public:
    explicit BitcoinApplication(int& argc, char** argv);
    ~BitcoinApplication();

#ifdef ENABLE_WALLET
    /// Create payment server
    void createPaymentServer();
#endif
    /// parameter interaction/setup based on rules
    void parameterSetup();
    /// Create options model
    void createOptionsModel();
    /// Create main window
    bool createWindow(const NetworkStyle* networkStyle);
    /// Create splash screen
    void createSplashScreen(const NetworkStyle* networkStyle);

    /// Create tutorial screen
    bool createTutorialScreen();

    /// Get mnemonic words on first startup
    bool setupMnemonicWords(std::vector<std::string>& wordlist);

    /// Request core initialization
    void requestInitialize();
    /// Request core shutdown
    void requestShutdown();

    /// Get process return value
    int getReturnValue() { return returnValue; }

    /// Get window identifier of QMainWindow (DIGIWAGEGUI)
    WId getMainWinId() const;

public Q_SLOTS:
    void initializeResult(int retval);
    void shutdownResult(int retval);
    /// Handle runaway exceptions. Shows a message box with the problem and quits the program.
    void handleRunawayException(const QString& message);
    void updateTranslation();

Q_SIGNALS:
    void requestedInitialize();
    void requestedRestart(QStringList args);
    void requestedShutdown();
    void stopThread();
    void splashFinished(QWidget* window);

private:
    QThread* coreThread;
    OptionsModel* optionsModel;
    ClientModel* clientModel;
    DIGIWAGEGUI* window;
    QTimer* pollShutdownTimer;
#ifdef ENABLE_WALLET
    PaymentServer* paymentServer;
    WalletModel* walletModel;
#endif
    std::vector<std::string> wordlist;
    int returnValue;
    QTranslator qtTranslatorBase, qtTranslator, translatorBase, translator;

    void startThread();
};

#include "digiwage.moc"

BitcoinCore::BitcoinCore(std::vector<std::string>& wordlist) : QObject(), words(wordlist)
{
}

void BitcoinCore::handleRunawayException(const std::exception* e)
{
    PrintExceptionContinue(e, "Runaway exception");
    Q_EMIT runawayException(QString::fromStdString(strMiscWarning));
}

void BitcoinCore::initialize()
{
    execute_restart = true;

    try {
        qDebug() << __func__ << ": Running AppInit2 in thread";
        int rv = AppInit2(words);
        Q_EMIT initializeResult(rv);
    } catch (const std::exception& e) {
        handleRunawayException(&e);
    } catch (...) {
        handleRunawayException(NULL);
    }
}

void BitcoinCore::restart(QStringList args)
{
    if (execute_restart) { // Only restart 1x, no matter how often a user clicks on a restart-button
        execute_restart = false;
        try {
            qDebug() << __func__ << ": Running Restart in thread";
            Interrupt();
            PrepareShutdown();
            qDebug() << __func__ << ": Shutdown finished";
            Q_EMIT shutdownResult(1);
            CExplicitNetCleanup::callCleanup();
            QProcess::startDetached(QApplication::applicationFilePath(), args);
            qDebug() << __func__ << ": Restart initiated...";
            QApplication::quit();
        } catch (const std::exception& e) {
            handleRunawayException(&e);
        } catch (...) {
            handleRunawayException(NULL);
        }
    }
}

void BitcoinCore::shutdown()
{
    try {
        qDebug() << __func__ << ": Running Shutdown in thread";
        Interrupt();
        Shutdown();
        qDebug() << __func__ << ": Shutdown finished";
        Q_EMIT shutdownResult(1);
    } catch (const std::exception& e) {
        handleRunawayException(&e);
    } catch (...) {
        handleRunawayException(NULL);
    }
}

BitcoinApplication::BitcoinApplication(int& argc, char** argv) : QApplication(argc, argv),
                                                                 coreThread(0),
                                                                 optionsModel(0),
                                                                 clientModel(0),
                                                                 window(0),
                                                                 pollShutdownTimer(0),
#ifdef ENABLE_WALLET
                                                                 paymentServer(0),
                                                                 walletModel(0),
#endif
                                                                 returnValue(0)
{
    setQuitOnLastWindowClosed(false);
}

BitcoinApplication::~BitcoinApplication()
{
    if (coreThread) {
        qDebug() << __func__ << ": Stopping thread";
        Q_EMIT stopThread();
        coreThread->wait();
        qDebug() << __func__ << ": Stopped thread";
    }

    delete window;
    window = 0;
#ifdef ENABLE_WALLET
    delete paymentServer;
    paymentServer = 0;
#endif
    // Delete Qt-settings if user clicked on "Reset Options"
    QSettings settings;
    if (optionsModel && optionsModel->resetSettings) {
        settings.clear();
        settings.sync();
    }
    delete optionsModel;
    optionsModel = 0;
}

#ifdef ENABLE_WALLET
void BitcoinApplication::createPaymentServer()
{
    paymentServer = new PaymentServer(this);
}
#endif

void BitcoinApplication::createOptionsModel()
{
    optionsModel = new OptionsModel();
}

// this will be used to get mnemonic words
bool BitcoinApplication::setupMnemonicWords(std::vector<std::string>& wordlist) {
    namespace fs = boost::filesystem;

    if (GetBoolArg("-skipmnemonicstartupui", false)) {
        return true;
    }

    std::string walletFile = GetArg("-wallet", "wallet.dat");
    if (fs::exists(walletFile)) return true;

    if (CheckIfWalletDatExists()) return true;

    StartOptionsMain dlg(nullptr);
    dlg.exec();
    wordlist = dlg.getWords();
    return false;
}

bool BitcoinApplication::createWindow(const NetworkStyle* networkStyle)
{
    /// Only display the MnemonicWords dialog on a wallet using HD
    if (GetBoolArg("-usehd", false)) {
        if (!setupMnemonicWords(wordlist)) {
          if (wordlist.empty()) return false;
        }
    }
    window = new DIGIWAGEGUI(networkStyle, 0);

    pollShutdownTimer = new QTimer(window);
    connect(pollShutdownTimer, SIGNAL(timeout()), window, SLOT(detectShutdown()));
    pollShutdownTimer->start(200);
    return true;
}

void BitcoinApplication::createSplashScreen(const NetworkStyle* networkStyle)
{
    Splash* splash = new Splash(0, networkStyle);
    // We don't hold a direct pointer to the splash screen after creation, so use
    // Qt::WA_DeleteOnClose to make sure that the window will be deleted eventually.
    splash->setAttribute(Qt::WA_DeleteOnClose);
    splash->show();
    connect(this, SIGNAL(splashFinished(QWidget*)), splash, SLOT(slotFinish(QWidget*)));
}

bool BitcoinApplication::createTutorialScreen()
{
    WelcomeContentWidget* widget = new WelcomeContentWidget();

    connect(widget, &WelcomeContentWidget::onLanguageSelected, [this](){
        updateTranslation();
    });

    widget->exec();
    bool ret = widget->isOk;
    widget->deleteLater();
    return ret;
}

void BitcoinApplication::updateTranslation(){
    // Re-initialize translations after change them
    initTranslations(this->qtTranslatorBase, this->qtTranslator, this->translatorBase, this->translator);
}

void BitcoinApplication::startThread()
{
    if (coreThread)
        return;
    coreThread = new QThread(this);
    BitcoinCore* executor = new BitcoinCore(wordlist);
    executor->moveToThread(coreThread);

    /*  communication to and from thread */
    connect(executor, SIGNAL(initializeResult(int)), this, SLOT(initializeResult(int)));
    connect(executor, SIGNAL(shutdownResult(int)), this, SLOT(shutdownResult(int)));
    connect(executor, SIGNAL(runawayException(QString)), this, SLOT(handleRunawayException(QString)));
    connect(this, SIGNAL(requestedInitialize()), executor, SLOT(initialize()));
    connect(this, SIGNAL(requestedShutdown()), executor, SLOT(shutdown()));
    connect(window, SIGNAL(requestedRestart(QStringList)), executor, SLOT(restart(QStringList)));
    /*  make sure executor object is deleted in its own thread */
    connect(this, SIGNAL(stopThread()), executor, SLOT(deleteLater()));
    connect(this, SIGNAL(stopThread()), coreThread, SLOT(quit()));

    coreThread->start();
}

void BitcoinApplication::parameterSetup()
{
    InitLogging();
    InitParameterInteraction();
}

void BitcoinApplication::requestInitialize()
{
    qDebug() << __func__ << ": Requesting initialize";
    startThread();
    Q_EMIT requestedInitialize();
}

void BitcoinApplication::requestShutdown()
{
    qDebug() << __func__ << ": Requesting shutdown";
    startThread();
    window->hide();
    window->setClientModel(0);
    pollShutdownTimer->stop();

#ifdef ENABLE_WALLET
    window->removeAllWallets();
    delete walletModel;
    walletModel = 0;
#endif
    delete clientModel;
    clientModel = 0;

    // Show a simple window indicating shutdown status
    ShutdownWindow::showShutdownWindow(window);

    // Request shutdown from core thread
    Q_EMIT requestedShutdown();
}

void BitcoinApplication::initializeResult(int retval)
{
    qDebug() << __func__ << ": Initialization result: " << retval;
    // Set exit result: 0 if successful, 1 if failure
    returnValue = retval ? 0 : 1;
    if (retval) {
#ifdef ENABLE_WALLET
        PaymentServer::LoadRootCAs();
        paymentServer->setOptionsModel(optionsModel);
#endif

        clientModel = new ClientModel(optionsModel);
        window->setClientModel(clientModel);

#ifdef ENABLE_WALLET
        if (pwalletMain) {
            walletModel = new WalletModel(pwalletMain, optionsModel);

            window->addWallet(DIGIWAGEGUI::DEFAULT_WALLET, walletModel);
            window->setCurrentWallet(DIGIWAGEGUI::DEFAULT_WALLET);

            connect(walletModel, SIGNAL(coinsSent(CWallet*, SendCoinsRecipient, QByteArray)),
                paymentServer, SLOT(fetchPaymentACK(CWallet*, const SendCoinsRecipient&, QByteArray)));
        }
#endif

        // If -min option passed, start window minimized.
        if (GetBoolArg("-min", false)) {
            window->showMinimized();
        } else {
            window->show();
        }
        Q_EMIT splashFinished(window);

#ifdef ENABLE_WALLET
        // Now that initialization/startup is done, process any command-line
        // DIGIWAGE: URIs or payment requests:
        connect(paymentServer, SIGNAL(receivedPaymentRequest(SendCoinsRecipient)),
            window, SLOT(handlePaymentRequest(SendCoinsRecipient)));
        connect(window, SIGNAL(receivedURI(QString)),
            paymentServer, SLOT(handleURIOrFile(QString)));
        connect(paymentServer, SIGNAL(message(QString, QString, unsigned int)),
            window, SLOT(message(QString, QString, unsigned int)));
        QTimer::singleShot(100, paymentServer, SLOT(uiReady()));
#endif
    } else {
        quit(); // Exit main loop
    }
}

void BitcoinApplication::shutdownResult(int retval)
{
    qDebug() << __func__ << ": Shutdown result: " << retval;
    quit(); // Exit main loop after shutdown finished
}

void BitcoinApplication::handleRunawayException(const QString& message)
{
    QMessageBox::critical(0, "Runaway exception", DIGIWAGEGUI::tr("A fatal error occurred. DIGIWAGE can no longer continue safely and will quit.") + QString("\n\n") + message);
    ::exit(1);
}

WId BitcoinApplication::getMainWinId() const
{
    if (!window)
        return 0;

    return window->winId();
}

#ifndef BITCOIN_QT_TEST
int main(int argc, char* argv[])
{
    SetupEnvironment();

    /// 1. Parse command-line options. These take precedence over anything else.
    // Command-line options take precedence:
    ParseParameters(argc, argv);

// Do not refer to data directory yet, this can be overridden by Intro::pickDataDirectory

/// 2. Basic Qt initialization (not dependent on parameters or configuration)
    Q_INIT_RESOURCE(digiwage_locale);
    Q_INIT_RESOURCE(digiwage);

    // Generate high-dpi pixmaps
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#if QT_VERSION >= 0x050600
    QGuiApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif
#ifdef Q_OS_MAC
    QApplication::setAttribute(Qt::AA_DontShowIconsInMenus);
#endif
    BitcoinApplication app(argc, argv);

    // Register meta types used for QMetaObject::invokeMethod
    qRegisterMetaType<bool*>();
    //   Need to pass name here as CAmount is a typedef (see http://qt-project.org/doc/qt-5/qmetatype.html#qRegisterMetaType)
    //   IMPORTANT if it is no longer a typedef use the normal variant above
    qRegisterMetaType<CAmount>("CAmount");

    /// 3. Application identification
    // must be set before OptionsModel is initialized or translations are loaded,
    // as it is used to locate QSettings
    QApplication::setOrganizationName(QAPP_ORG_NAME);
    QApplication::setOrganizationDomain(QAPP_ORG_DOMAIN);
    QApplication::setApplicationName(QAPP_APP_NAME_DEFAULT);
    GUIUtil::SubstituteFonts(GetLangTerritory());

    /// 4. Initialization of translations, so that intro dialog is in user's language
    // Now that QSettings are accessible, initialize translations
    //initTranslations(qtTranslatorBase, qtTranslator, translatorBase, translator);
    app.updateTranslation();
    uiInterface.Translate.connect(Translate);

    // Show help message immediately after parsing command-line options (for "-lang") and setting locale,
    // but before showing splash screen.
    if (mapArgs.count("-?") || mapArgs.count("-help") || mapArgs.count("-version")) {
        HelpMessageDialog help(NULL, mapArgs.count("-version"));
        help.showOrPrint();
        return 1;
    }

    /// 5. Now that settings and translations are available, ask user for data directory
    // User language is set up: pick a data directory
    if (!Intro::pickDataDirectory())
        return 0;

    /// 6. Determine availability of data directory and parse digiwage.conf
    /// - Do not call GetDataDir(true) before this step finishes
    if (!boost::filesystem::is_directory(GetDataDir(false))) {
        QMessageBox::critical(0, QObject::tr("DIGIWAGE Core"),
            QObject::tr("Error: Specified data directory \"%1\" does not exist.").arg(QString::fromStdString(mapArgs["-datadir"])));
        return 1;
    }
    try {
        ReadConfigFile(mapArgs, mapMultiArgs);
    } catch (const std::exception& e) {
        QMessageBox::critical(0, QObject::tr("DIGIWAGE Core"),
            QObject::tr("Error: Cannot parse configuration file: %1. Only use key=value syntax.").arg(e.what()));
        return 0;
    }

    /// 7. Determine network (and switch to network specific options)
    // - Do not call Params() before this step
    // - Do this after parsing the configuration file, as the network can be switched there
    // - QSettings() will use the new application name after this, resulting in network-specific settings
    // - Needs to be done before createOptionsModel

    // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
    if (!SelectParamsFromCommandLine()) {
        QMessageBox::critical(0, QObject::tr("DIGIWAGE Core"), QObject::tr("Error: Invalid combination of -regtest and -testnet."));
        return 1;
    }
#ifdef ENABLE_WALLET
    // Parse URIs on command line -- this can affect Params()
    PaymentServer::ipcParseCommandLine(argc, argv);
#endif

    QScopedPointer<const NetworkStyle> networkStyle(NetworkStyle::instantiate(QString::fromStdString(Params().NetworkIDString())));
    assert(!networkStyle.isNull());
    // Allow for separate UI settings for testnets
    QApplication::setApplicationName(networkStyle->getAppName());
    // Re-initialize translations after changing application name (language in network-specific settings can be different)
    app.updateTranslation();

#ifdef ENABLE_WALLET
    /// 7a. parse masternode.conf and forge.conf
    std::string strErr;
    if (!masternodeConfig.read(strErr)) {
        QMessageBox::critical(0, QObject::tr("DIGIWAGE Core"),
            QObject::tr("Error reading masternode configuration file: %1").arg(strErr.c_str()));
        return 0;
    }

    if (!forgeMain.readForgeConfig(strErr)) {    
        QMessageBox::critical(0, QObject::tr("DIGIWAGE Core"),
            QObject::tr("Error reading Forge configuration file: %1").arg(strErr.c_str()));
        return 0;
    }

    /// 8. URI IPC sending
    // - Do this early as we don't want to bother initializing if we are just calling IPC
    // - Do this *after* setting up the data directory, as the data directory hash is used in the name
    // of the server.
    // - Do this after creating app and setting up translations, so errors are
    // translated properly.
    if (PaymentServer::ipcSendCommandLine())
        exit(0);

    // Start up the payment server early, too, so impatient users that click on
    // digiwage: links repeatedly have their payment requests routed to this process:
    app.createPaymentServer();
#endif

    /// 9. Main GUI initialization
    // Install global event filter that makes sure that long tooltips can be word-wrapped
    app.installEventFilter(new GUIUtil::ToolTipToRichTextFilter(TOOLTIP_WRAP_THRESHOLD, &app));
#if defined(Q_OS_WIN)
    // Install global event filter for processing Windows session related Windows messages (WM_QUERYENDSESSION and WM_ENDSESSION)
    qApp->installNativeEventFilter(new WinShutdownMonitor());
#endif
    // Install qDebug() message handler to route to debug.log
    qInstallMessageHandler(DebugMessageHandler);
    // Allow parameter interaction before we create the options model
    app.parameterSetup();
    // Load GUI settings from QSettings
    app.createOptionsModel();

    // Subscribe to global signals from core
    uiInterface.InitMessage.connect(InitMessage);

    bool ret = true;
#ifdef ENABLE_WALLET
    // Check if the wallet exists or need to be created
    std::string strWalletFile = GetArg("-wallet", "wallet.dat");
    std::string strDataDir = GetDataDir().string();
    // Wallet file must be a plain filename without a directory
    if (strWalletFile != boost::filesystem::basename(strWalletFile) + boost::filesystem::extension(strWalletFile)){
        throw std::runtime_error(strprintf(_("Wallet %s resides outside data directory %s"), strWalletFile, strDataDir));
    }

    boost::filesystem::path pathBootstrap = GetDataDir() / strWalletFile;
    if (!boost::filesystem::exists(pathBootstrap)) {
        // wallet doesn't exist, popup tutorial screen.
        ret = app.createTutorialScreen();
    }
#endif
    if(!ret){
        // wallet not loaded.
        return 0;
    }

    if (GetBoolArg("-splash", true) && !GetBoolArg("-min", false))
        app.createSplashScreen(networkStyle.data());

    try {
        if (!app.createWindow(networkStyle.data())) {
            return EXIT_FAILURE;
        }
        app.requestInitialize();
#if defined(Q_OS_WIN)
        WinShutdownMonitor::registerShutdownBlockReason(QObject::tr("DIGIWAGE Core didn't yet exit safely..."), (HWND)app.getMainWinId());
#endif
        app.exec();
        app.requestShutdown();
        app.exec();
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "Runaway exception");
        app.handleRunawayException(QString::fromStdString(strMiscWarning));
    } catch (...) {
        PrintExceptionContinue(NULL, "Runaway exception");
        app.handleRunawayException(QString::fromStdString(strMiscWarning));
    }
    return app.getReturnValue();
}
#endif // BITCOIN_QT_TEST
