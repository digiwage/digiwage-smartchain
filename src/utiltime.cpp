// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/digiwage-config.h"
#endif

#include "tinyformat.h"
#include "utiltime.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread.hpp>


static int64_t nMockTime = 0; //! For unit testing

int64_t GetTime()
{
    if (nMockTime) return nMockTime;

    return time(NULL);
}

void SetMockTime(int64_t nMockTimeIn)
{
    nMockTime = nMockTimeIn;
}

int64_t GetTimeMillis()
{
    return (boost::posix_time::ptime(boost::posix_time::microsec_clock::universal_time()) -
            boost::posix_time::ptime(boost::gregorian::date(1970, 1, 1)))
        .total_milliseconds();
}

int64_t GetTimeMicros()
{
    return (boost::posix_time::ptime(boost::posix_time::microsec_clock::universal_time()) -
            boost::posix_time::ptime(boost::gregorian::date(1970, 1, 1)))
        .total_microseconds();
}

void MilliSleep(int64_t n)
{
/**
 * Boost's sleep_for was uninterruptable when backed by nanosleep from 1.50
 * until fixed in 1.52. Use the deprecated sleep method for the broken case.
 * See: https://svn.boost.org/trac/boost/ticket/7238
 */
#if defined(HAVE_WORKING_BOOST_SLEEP_FOR)
    boost::this_thread::sleep_for(boost::chrono::milliseconds(n));
#elif defined(HAVE_WORKING_BOOST_SLEEP)
    boost::this_thread::sleep(boost::posix_time::milliseconds(n));
#else
//should never get here
#error missing boost sleep implementation
#endif
}

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime)
{
    // std::locale takes ownership of the pointer
    std::locale loc(std::locale::classic(), new boost::posix_time::time_facet(pszFormat));
    std::stringstream ss;
    ss.imbue(loc);
    ss << boost::posix_time::from_time_t(nTime);
    return ss.str();
}

std::string DurationToDHMS(int64_t nDurationTime)
{
    int seconds = nDurationTime % 60;
    nDurationTime /= 60;
    int minutes = nDurationTime % 60;
    nDurationTime /= 60;
    int hours = nDurationTime % 24;
    int days = nDurationTime / 24;
    if (days)
        return strprintf("%dd %02dh:%02dm:%02ds", days, hours, minutes, seconds);
    if (hours)
        return strprintf("%02dh:%02dm:%02ds", hours, minutes, seconds);
    return strprintf("%02dm:%02ds", minutes, seconds);
}
