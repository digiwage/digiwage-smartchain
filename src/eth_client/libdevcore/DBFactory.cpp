// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2018-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.
#include "DBFactory.h"
#include "FileSystem.h"
#include "LevelDB.h"
#include "libethcore/Exceptions.h"


namespace dev
{
namespace db
{
namespace fs = boost::filesystem;
namespace po = boost::program_options;

auto g_kind = DatabaseKind::LevelDB;
fs::path g_dbPath;

/// A helper type to build the table of DB implementations.
///
/// More readable than std::tuple.
/// Fields are not initialized to allow usage of construction with initializer lists {}.
struct DBKindTableEntry
{
    DatabaseKind kind;
    char const* name;
};

/// The table of available DB implementations.
///
/// We don't use a map to avoid complex dynamic initialization. This list will never be long,
/// so linear search only to parse command line arguments is not a problem.
DBKindTableEntry dbKindsTable[] = {
    {DatabaseKind::LevelDB, "leveldb"},
};

void setDatabaseKindByName(std::string const& _name)
{
    for (auto& entry : dbKindsTable)
    {
        if (_name == entry.name)
        {
            g_kind = entry.kind;
            return;
        }
    }

    BOOST_THROW_EXCEPTION(
        eth::InvalidDatabaseKind() << errinfo_comment("invalid database name supplied: " + _name));
}

void setDatabaseKind(DatabaseKind _kind)
{
    g_kind = _kind;
}

void setDatabasePath(std::string const& _path)
{
    g_dbPath = fs::path(_path);
}

bool isDiskDatabase()
{
    switch (g_kind)
    {
        case DatabaseKind::LevelDB:
            return true;
        default:
            return false;
    }
}

DatabaseKind databaseKind()
{
    return g_kind;
}

fs::path databasePath()
{
    return g_dbPath.empty() ? getDataDir() : g_dbPath;
}

po::options_description databaseProgramOptions(unsigned _lineLength)
{
    // It must be a static object because boost expects const char*.
    static std::string const description = [] {
        std::string names;
        for (auto const& entry : dbKindsTable)
        {
            if (!names.empty())
                names += ", ";
            names += entry.name;
        }

        return "Select database implementation. Available options are: " + names + ".";
    }();

    po::options_description opts("DATABASE OPTIONS", _lineLength);
    auto add = opts.add_options();

    add("db",
        po::value<std::string>()->value_name("<name>")->default_value("leveldb")->notifier(
            setDatabaseKindByName),
        description.data());

    add("db-path",
        po::value<std::string>()
            ->value_name("<path>")
            ->default_value(getDataDir().string())
            ->notifier(setDatabasePath),
        "Database path (for non-memory database options)\n");

    return opts;
}

std::unique_ptr<DatabaseFace> DBFactory::create()
{
    return create(databasePath());
}

std::unique_ptr<DatabaseFace> DBFactory::create(fs::path const& _path)
{
    return create(g_kind, _path);
}

std::unique_ptr<DatabaseFace> DBFactory::create(DatabaseKind _kind)
{
    return create(_kind, databasePath());
}

std::unique_ptr<DatabaseFace> DBFactory::create(DatabaseKind _kind, fs::path const& _path)
{
    switch (_kind)
    {
    case DatabaseKind::LevelDB:
        return std::unique_ptr<DatabaseFace>(new LevelDB(_path));
        break;
    default:
        assert(false);
        return {};
    }
}


}  // namespace db
}  // namespace dev
