// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/digiwage-config.h"
#endif

#include "util.h"

#include "allocators.h"
#include "chainparamsbase.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "rpc/protocol.h" // Needed for JSONRPCError
#include "uint256.h"      // Needed for uint256
#include "univalue.h"     // Needed for UniValue
#include <stdarg.h>

#include <boost/date_time/posix_time/posix_time.hpp>


#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable : 4786)
#pragma warning(disable : 4804)
#pragma warning(disable : 4805)
#pragma warning(disable : 4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>


// DIGIWAGE only features
// Masternode
bool fMasterNode = false;
std::string strMasterNodePrivKey = "";
std::string strMasterNodeAddr = "";
bool fLiteMode = false;
// SwiftX
bool fEnableSwiftTX = true;
int nSwiftTXDepth = 5;

/** Spork enforcement enabled time */
int64_t enforceMasternodePaymentsTime = 4085657524;
bool fSucessfullyLoaded = false;
/** All denominations used by obfuscation */
std::vector<int64_t> obfuScationDenominations;
std::string strBudgetMode = "";

std::map<std::string, std::string> mapArgs;
std::map<std::string, std::vector<std::string> > mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fDaemon = false;
std::string strMiscWarning;
bool fLogTimestamps = false;
bool fLogIPs = false;
volatile bool fReopenDebugLog = false;

/** Init OpenSSL library multithreading support */
static RecursiveMutex** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line) NO_THREAD_SAFETY_ANALYSIS
{
    if (mode & CRYPTO_LOCK) {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    } else {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    }
}

// Init
class CInit
{
public:
    CInit()
    {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (RecursiveMutex**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(RecursiveMutex*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new RecursiveMutex();
        CRYPTO_set_locking_callback(locking_callback);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        OPENSSL_no_config();

#ifdef WIN32
        // Seed OpenSSL PRNG with current contents of the screen
        RAND_screen();
#endif

        // Seed OpenSSL PRNG with performance counter
        RandAddSeed();
    }
    ~CInit()
    {
        // Securely erase the memory used by the PRNG
        RAND_cleanup();
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
} instance_of_cinit;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;
/**
 * We use boost::call_once() to make sure these are initialized
 * in a thread-safe manner the first time called:
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;

static void DebugPrintInit()
{
    assert(fileout == NULL);
    assert(mutexDebugLog == NULL);

    boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout) setbuf(fileout, NULL); // unbuffered

    mutexDebugLog = new boost::mutex();
}

bool LogAcceptCategory(const char* category)
{
    if (category != NULL) {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        static boost::thread_specific_ptr<std::set<std::string> > ptrCategory;
        if (ptrCategory.get() == NULL) {
            const std::vector<std::string>& categories = mapMultiArgs["-debug"];
            ptrCategory.reset(new std::set<std::string>(categories.begin(), categories.end()));
            // thread_specific_ptr automatically deletes the set when the thread ends.
            // "digiwage" is a composite category enabling all DIGIWAGE-related debug output
            if (ptrCategory->count(std::string("digiwage"))) {
                ptrCategory->insert(std::string("obfuscation"));
                ptrCategory->insert(std::string("swiftx"));
                ptrCategory->insert(std::string("masternode"));
                ptrCategory->insert(std::string("mnpayments"));
                ptrCategory->insert(std::string("zero"));
                ptrCategory->insert(std::string("mnbudget"));
                ptrCategory->insert(std::string("staking"));
            }
        }
        const std::set<std::string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count(std::string("")) == 0 &&
            setCategories.count(std::string(category)) == 0)
            return false;
    }
    return true;
}

int LogPrintStr(const std::string& str)
{
    int ret = 0; // Returns total number of characters written
    if (fPrintToConsole) {
        // print to console
        ret = fwrite(str.data(), 1, str.size(), stdout);
        fflush(stdout);
    } else if (fPrintToDebugLog && AreBaseParamsConfigured()) {
        static bool fStartedNewLine = true;
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);

        if (fileout == NULL)
            return ret;

        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // reopen the log file, if requested
        if (fReopenDebugLog) {
            fReopenDebugLog = false;
            boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
            if (freopen(pathDebug.string().c_str(), "a", fileout) != NULL)
                setbuf(fileout, NULL); // unbuffered
        }

        // Debug print useful for profiling
        if (fLogTimestamps && fStartedNewLine)
            ret += fprintf(fileout, "%s ", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()).c_str());
        if (!str.empty() && str[str.size() - 1] == '\n')
            fStartedNewLine = true;
        else
            fStartedNewLine = false;

        ret = fwrite(str.data(), 1, str.size(), fileout);
    }

    return ret;
}

/** Interpret string as boolean, for argument parsing */
static bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

/** Turn -noX into -X=0 */
static void InterpretNegativeSetting(std::string& strKey, std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o') {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    mapArgs.clear();
    mapMultiArgs.clear();

    for (int i = 1; i < argc; i++) {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos) {
            strValue = str.substr(is_index + 1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);
        InterpretNegativeSetting(str, strValue);

        mapArgs[str] = strValue;
        mapMultiArgs[str].push_back(strValue);
    }
}

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    if (mapArgs.count(strArg))
        return InterpretBool(mapArgs[strArg]);
    return fDefault;
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    if (mapArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    return true;
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

std::string HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}

static std::string FormatException(const std::exception* pex, const char* pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "DIGIWAGE";
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void PrintExceptionContinue(const std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
    strMiscWarning = message;
}

boost::filesystem::path GetDefaultDataDir()
{
    namespace fs = boost::filesystem;
// Windows < Vista: C:\Documents and Settings\Username\Application Data\Digiwage
// Windows >= Vista: C:\Users\Username\AppData\Roaming\Digiwage
// Mac: ~/Library/Application Support/Digiwage
// Unix: ~/.digiwage
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / "Digiwage";
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    TryCreateDirectory(pathRet);
    return pathRet / "Digiwage";
#else
    // Unix
    return pathRet / ".digiwage";
#endif
#endif
}

static boost::filesystem::path pathCached;
static boost::filesystem::path pathCachedNetSpecific;
static RecursiveMutex csPathCached;

bool CheckIfWalletDatExists(bool fNetSpecific) {

    namespace fs = boost::filesystem;

    std::string walletFile = GetArg("-wallet", "wallet.dat");
    boost::filesystem::path path(walletFile);
    if (!path.is_complete())
        path = GetDataDir(fNetSpecific) / path;

    return fs::exists(path);
}

const boost::filesystem::path& GetDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path& path = fNetSpecific ? pathCachedNetSpecific : pathCached;
    
    if (!path.empty())
        return path;

    if (mapArgs.count("-datadir")) {
        path = fs::system_complete(mapArgs["-datadir"]);
        if (!fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }

    if (fNetSpecific)
        path /= BaseParams().DataDir();

    fs::create_directories(path);

    return path;
}

void ClearDatadirCache()
{
    pathCached = boost::filesystem::path();
    pathCachedNetSpecific = boost::filesystem::path();
}

boost::filesystem::path GetConfigFile()
{
    boost::filesystem::path pathConfigFile(GetArg("-conf", "digiwage.conf"));
    if (!pathConfigFile.is_complete())
        pathConfigFile = GetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

boost::filesystem::path GetMasternodeConfigFile()
{
    boost::filesystem::path pathConfigFile(GetArg("-mnconf", "masternode.conf"));
    if (!pathConfigFile.is_complete()) pathConfigFile = GetDataDir() / pathConfigFile;
    return pathConfigFile;
}

boost::filesystem::path GetForgeConfigFile()
{
    boost::filesystem::path pathConfigFile(GetArg("-forgeconf", "forge.conf"));
    if (!pathConfigFile.is_complete()) pathConfigFile = GetDataDir() / pathConfigFile;
    return pathConfigFile;
}

void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet,
    std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good()) {
        // Create empty digiwage.conf if it does not exist
        FILE* configFile = fopen(GetConfigFile().string().c_str(), "a");
        if (configFile != NULL)
            fclose(configFile);
        return; // Nothing to read, so just return
    }

    std::set<std::string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
        // Don't overwrite existing settings so command line settings override digiwage.conf
        std::string strKey = std::string("-") + it->string_key;
        std::string strValue = it->value[0];
        InterpretNegativeSetting(strKey, strValue);
        if (mapSettingsRet.count(strKey) == 0)
            mapSettingsRet[strKey] = strValue;
        mapMultiSettingsRet[strKey].push_back(strValue);
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
}

#ifndef WIN32
boost::filesystem::path GetPidFile()
{
    boost::filesystem::path pathPidFile(GetArg("-pid", "digiwaged.pid"));
    if (!pathPidFile.is_complete()) pathPidFile = GetDataDir() / pathPidFile;
    return pathPidFile;
}

void CreatePidFile(const boost::filesystem::path& path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w");
    if (file) {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}
#endif

bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
               MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const boost::filesystem::path& p)
{
    try {
        return boost::filesystem::create_directory(p);
    } catch (const boost::filesystem::filesystem_error&) {
        if (!boost::filesystem::exists(p) || !boost::filesystem::is_directory(p))
            throw;
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void FileCommit(FILE* fileout)
{
    fflush(fileout); // harmless if redundantly called
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(fileout));
    FlushFileBuffers(hFile);
#else
#if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(fileout));
#elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(fileout), F_FULLFSYNC, 0);
#else
    fsync(fileno(fileout));
#endif
#endif
}

bool TruncateFile(FILE* file, unsigned int length)
{
#if defined(WIN32)
    return _chsize(_fileno(file), length) == 0;
#else
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD)
{
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE* file, unsigned int offset, unsigned int length)
{
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), fst.fst_length);
#elif defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    posix_fallocate(fileno(file), 0, nEndPos);
#else
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    fseek(file, offset, SEEK_SET);
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

void ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = GetDataDir() / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");
    if (file && boost::filesystem::file_size(pathLog) > 10 * 1000000) {
        // Restart the file with some of the end
        std::vector<char> vch(200000, 0);
        fseek(file, -((long)vch.size()), SEEK_END);
        int nBytes = fread(vch.data(), 1, vch.size(), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file) {
            fwrite(vch.data(), 1, nBytes, file);
            fclose(file);
        }
    } else if (file != NULL)
        fclose(file);
}

#ifdef WIN32
boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = boost::filesystem;

    char pszPath[MAX_PATH] = "";

    if (SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate)) {
        return fs::path(pszPath);
    }

    LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

boost::filesystem::path GetTempPath()
{
#if BOOST_FILESYSTEM_VERSION == 3
    return boost::filesystem::temp_directory_path();
#else
    // TODO: remove when we don't support filesystem v2 anymore
    boost::filesystem::path path;
#ifdef WIN32
    char pszPath[MAX_PATH] = "";

    if (GetTempPathA(MAX_PATH, pszPath))
        path = boost::filesystem::path(pszPath);
#else
    path = boost::filesystem::path("/tmp");
#endif
    if (path.empty() || !boost::filesystem::is_directory(path)) {
        LogPrintf("GetTempPath(): failed to find temp path\n");
        return boost::filesystem::path("");
    }
    return path;
#endif
}

double double_safe_addition(double fValue, double fIncrement)
{
    double fLimit = std::numeric_limits<double>::max() - fValue;

    if (fLimit > fIncrement)
        return fValue + fIncrement;
    else
        return std::numeric_limits<double>::max();
}

double double_safe_multiplication(double fValue, double fmultiplicator)
{
    double fLimit = std::numeric_limits<double>::max() / fmultiplicator;

    if (fLimit > fmultiplicator)
        return fValue * fmultiplicator;
    else
        return std::numeric_limits<double>::max();
}

void runCommand(std::string strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}



// Definition for ParseHashV
uint256 ParseHashV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    else
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be a string");

    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    if (64 != strHex.length())
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be of length %d (not %d)", strName, 64, strHex.length()));

    uint256 result;
    result.SetHex(strHex);
    return result;
}

// Definition for ParseHexV
std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
     else
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be a string");

    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName + " must be hexadecimal string (not '" + strHex + "')");
    return ParseHex(strHex);
}

// Definition for HelpExampleCli
std::string HelpExampleCli(const std::string& methodname, const std::string& args)
{
    return "> digiwage-cli " + methodname + " " + args + "\n";
}

// Definition for HelpExampleRpc
std::string HelpExampleRpc(const std::string& methodname, const std::string& args)
{
    // TODO: Consider getting the default RPC port dynamically from args or chainparams
    return "$ curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
           "\"method\": \"" + methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:31114/\n";
}


void SetThreadPriority(int nPriority)
{
#ifdef WIN32
    SetThreadPriority(GetCurrentThread(), nPriority);
#else // WIN32
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else  // PRIO_THREAD
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif // PRIO_THREAD
#endif // WIN32
}