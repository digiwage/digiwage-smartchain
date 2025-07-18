// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * logging, thread wrappers
 */
 #ifndef BITCOIN_UTIL_H
 #define BITCOIN_UTIL_H
 
 #if defined(HAVE_CONFIG_H)
 #include "config/digiwage-config.h"
 #endif
 
 #include "compat.h"
 #include "tinyformat.h"
 #include "utiltime.h"
 #include "util/threadnames.h"
 
 #include <exception>
 #include <map>
 #include <stdint.h>
 #include <string>
 #include <vector>
 #include "uint256.h" // For uint256
 #include <univalue.h>

 #include <boost/filesystem/path.hpp>
 #include <boost/thread/exceptions.hpp>
 #include <boost/thread/condition_variable.hpp> // for boost::thread_interrupted
 
 // Debugging macros
 // Uncomment the following line to enable debugging messages
 // or enable on a per file basis prior to inclusion of util.h
 //#define ENABLE_DIGIWAGE_DEBUG
 #ifdef ENABLE_DIGIWAGE_DEBUG
 #define DBG( x ) x
 #else
 #define DBG( x )
 #endif
 
 // DIGIWAGE only features
 
 // Declarations for RPC helpers moved to util library
uint256 ParseHashV(const UniValue& v, std::string strName);
std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName);
std::string HelpExampleCli(const std::string& methodname, const std::string& args);
std::string HelpExampleRpc(const std::string& methodname, const std::string& args);


 extern bool fMasterNode;
 extern bool fLiteMode;
 extern bool fEnableSwiftTX;
 extern int nSwiftTXDepth;
 extern int64_t enforceMasternodePaymentsTime;
 extern std::string strMasterNodeAddr;
 extern int keysLoaded;
 extern bool fSucessfullyLoaded;
 extern std::vector<int64_t> obfuScationDenominations;
 extern std::string strBudgetMode;
 
 extern std::map<std::string, std::string> mapArgs;
 extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
 extern bool fDebug;
 extern bool fPrintToConsole;
 extern bool fPrintToDebugLog;
 extern std::string strMiscWarning;
 extern bool fLogTimestamps;
 extern bool fLogIPs;
 extern volatile bool fReopenDebugLog;
 
 void SetupEnvironment();
 bool SetupNetworking();
 
 /** Return true if log accepts specified category */
 bool LogAcceptCategory(const char* category);
 /** Send a string to the log output */
 int LogPrintStr(const std::string& str);
 
 /** Get format string from VA_ARGS for error reporting */
 template<typename... Args> std::string FormatStringFromLogArgs(const char *fmt, const Args&... args) { return fmt; }
 
 #define LogPrintf(...) do {                                                         \
     std::string _log_msg_; /* Unlikely name to avoid shadowing variables */         \
     try {                                                                           \
         _log_msg_ = tfm::format(__VA_ARGS__);                                       \
     } catch (tinyformat::format_error &e) {                                               \
         /* Original format string will have newline so don't add one here */        \
         _log_msg_ = "Error \"" + std::string(e.what()) + "\" while formatting log message: " + FormatStringFromLogArgs(__VA_ARGS__); \
     }                                                                               \
     LogPrintStr(_log_msg_);                                                         \
 } while(0)
 
 #define LogPrint(category, ...) do {                                                \
     if (LogAcceptCategory((category))) {                                            \
         LogPrintf(__VA_ARGS__);                                                     \
     }                                                                               \
 } while(0)
 
 template<typename... Args>
 bool error(const char* fmt, const Args&... args)
 {
     LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
     return false;
 }
 
 double double_safe_addition(double fValue, double fIncrement);
 double double_safe_multiplication(double fValue, double fmultiplicator);
 void PrintExceptionContinue(const std::exception* pex, const char* pszThread);
 void ParseParameters(int argc, const char* const argv[]);
 void FileCommit(FILE* fileout);
 bool TruncateFile(FILE* file, unsigned int length);
 int RaiseFileDescriptorLimit(int nMinFD);
 void AllocateFileRange(FILE* file, unsigned int offset, unsigned int length);
 bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest);
 bool TryCreateDirectory(const boost::filesystem::path& p);
 boost::filesystem::path GetDefaultDataDir();
 bool CheckIfWalletDatExists(bool fNetSpecific = true);
 const boost::filesystem::path &GetDataDir(bool fNetSpecific = true);
 void ClearDatadirCache();
 boost::filesystem::path GetConfigFile();
 boost::filesystem::path GetMasternodeConfigFile();
 boost::filesystem::path GetForgeConfigFile();
 #ifndef WIN32
 boost::filesystem::path GetPidFile();
 void CreatePidFile(const boost::filesystem::path& path, pid_t pid);
 #endif
 void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet, std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);
 #ifdef WIN32
 boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
 #endif
 boost::filesystem::path GetTempPath();
 void ShrinkDebugFile();
 void runCommand(std::string strCommand);
 
 inline bool IsSwitchChar(char c)
 {
 #ifdef WIN32
     return c == '-' || c == '/';
 #else
     return c == '-';
 #endif
 }
 
 /**
  * Return string argument or default value
  *
  * @param strArg Argument to get (e.g. "-foo")
  * @param default (e.g. "1")
  * @return command-line argument or default value
  */
 std::string GetArg(const std::string& strArg, const std::string& strDefault);
 
 /**
  * Return integer argument or default value
  *
  * @param strArg Argument to get (e.g. "-foo")
  * @param default (e.g. 1)
  * @return command-line argument (0 if invalid number) or default value
  */
 int64_t GetArg(const std::string& strArg, int64_t nDefault);
 
 /**
  * Return boolean argument or default value
  *
  * @param strArg Argument to get (e.g. "-foo")
  * @param default (true or false)
  * @return command-line argument or default value
  */
 bool GetBoolArg(const std::string& strArg, bool fDefault);
 
 /**
  * Set an argument if it doesn't already have a value
  *
  * @param strArg Argument to set (e.g. "-foo")
  * @param strValue Value (e.g. "1")
  * @return true if argument gets set, false if it already had a value
  */
 bool SoftSetArg(const std::string& strArg, const std::string& strValue);
 
 /**
  * Set a boolean argument if it doesn't already have a value
  *
  * @param strArg Argument to set (e.g. "-foo")
  * @param fValue Value (e.g. false)
  * @return true if argument gets set, false if it already had a value
  */
 bool SoftSetBoolArg(const std::string& strArg, bool fValue);
 
 /**
  * Format a string to be used as group of options in help messages
  *
  * @param message Group name (e.g. "RPC server options:")
  * @return the formatted string
  */
 std::string HelpMessageGroup(const std::string& message);
 
 /**
  * Format a string to be used as option description in help messages
  *
  * @param option Option message (e.g. "-rpcuser=<user>")
  * @param message Option description (e.g. "Username for JSON-RPC connections")
  * @return the formatted string
  */
 std::string HelpMessageOpt(const std::string& option, const std::string& message);
 
 void SetThreadPriority(int nPriority);
 
 /**
  * .. and a wrapper that just calls func once
  */
 template <typename Callable>
 void TraceThread(const char* name, Callable func)
 {
     std::string s = strprintf("digiwage-%s", name);
     util::ThreadRename(s.c_str());
     try {
         LogPrintf("%s thread start\n", name);
         func();
         LogPrintf("%s thread exit\n", name);
     } catch (boost::thread_interrupted) {
         LogPrintf("%s thread interrupt\n", name);
         throw;
     } catch (std::exception& e) {
         PrintExceptionContinue(&e, name);
         throw;
     } catch (...) {
         PrintExceptionContinue(NULL, name);
         throw;
     }
 }
 
 #endif // BITCOIN_UTIL_H