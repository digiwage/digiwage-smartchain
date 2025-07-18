// Copyright (c) 2012-2014 The Bitcoin Core developers
// Copyright (c) 2014-2015 The Dash Core developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netbase.h"
#include "test/test_digiwage.h"

#include <string>

#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(netbase_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(netbase_networks)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").GetNetwork()                              == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("::1").GetNetwork()                                    == NET_UNROUTABLE);
    BOOST_CHECK(CNetAddr("8.8.8.8").GetNetwork()                                == NET_IPV4);
    BOOST_CHECK(CNetAddr("2001::8888").GetNetwork()                             == NET_IPV6);
    BOOST_CHECK(CNetAddr("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").GetNetwork() == NET_TOR);
}

BOOST_AUTO_TEST_CASE(netbase_properties)
{
    BOOST_CHECK(CNetAddr("127.0.0.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::FFFF:192.168.1.1").IsIPv4());
    BOOST_CHECK(CNetAddr("::1").IsIPv6());
    BOOST_CHECK(CNetAddr("10.0.0.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("192.168.1.1").IsRFC1918());
    BOOST_CHECK(CNetAddr("172.31.255.255").IsRFC1918());
    BOOST_CHECK(CNetAddr("2001:0DB8::").IsRFC3849());
    BOOST_CHECK(CNetAddr("169.254.1.1").IsRFC3927());
    BOOST_CHECK(CNetAddr("2002::1").IsRFC3964());
    BOOST_CHECK(CNetAddr("FC00::").IsRFC4193());
    BOOST_CHECK(CNetAddr("2001::2").IsRFC4380());
    BOOST_CHECK(CNetAddr("2001:10::").IsRFC4843());
    BOOST_CHECK(CNetAddr("FE80::").IsRFC4862());
    BOOST_CHECK(CNetAddr("64:FF9B::").IsRFC6052());
    BOOST_CHECK(CNetAddr("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").IsTor());
    BOOST_CHECK(CNetAddr("127.0.0.1").IsLocal());
    BOOST_CHECK(CNetAddr("::1").IsLocal());
    BOOST_CHECK(CNetAddr("8.8.8.8").IsRoutable());
    BOOST_CHECK(CNetAddr("2001::1").IsRoutable());
    BOOST_CHECK(CNetAddr("127.0.0.1").IsValid());
}

bool static TestSplitHost(std::string test, std::string host, int port)
{
    std::string hostOut;
    int portOut = -1;
    SplitHostPort(test, portOut, hostOut);
    return hostOut == host && port == portOut;
}

BOOST_AUTO_TEST_CASE(netbase_splithost)
{
    BOOST_CHECK(TestSplitHost("www.bitcoin.org", "www.bitcoin.org", -1));
    BOOST_CHECK(TestSplitHost("[www.bitcoin.org]", "www.bitcoin.org", -1));
    BOOST_CHECK(TestSplitHost("www.bitcoin.org:80", "www.bitcoin.org", 80));
    BOOST_CHECK(TestSplitHost("[www.bitcoin.org]:80", "www.bitcoin.org", 80));
    BOOST_CHECK(TestSplitHost("127.0.0.1", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("127.0.0.1:46003", "127.0.0.1", 46003));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]", "127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[127.0.0.1]:46003", "127.0.0.1", 46003));
    BOOST_CHECK(TestSplitHost("::ffff:127.0.0.1", "::ffff:127.0.0.1", -1));
    BOOST_CHECK(TestSplitHost("[::ffff:127.0.0.1]:46003", "::ffff:127.0.0.1", 46003));
    BOOST_CHECK(TestSplitHost("[::]:46003", "::", 46003));
    BOOST_CHECK(TestSplitHost("::46003", "::46003", -1));
    BOOST_CHECK(TestSplitHost(":46003", "", 46003));
    BOOST_CHECK(TestSplitHost("[]:46003", "", 46003));
    BOOST_CHECK(TestSplitHost("", "", -1));
}

bool static TestParse(std::string src, std::string canon)
{
    CService addr;
    if (!LookupNumeric(src.c_str(), addr, 65535))
        return canon == "";
    return canon == addr.ToString();
}

BOOST_AUTO_TEST_CASE(netbase_lookupnumeric)
{
    BOOST_CHECK(TestParse("127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("127.0.0.1:46003", "127.0.0.1:46003"));
    BOOST_CHECK(TestParse("::ffff:127.0.0.1", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse("::", "[::]:65535"));
    BOOST_CHECK(TestParse("[::]:46003", "[::]:46003"));
    BOOST_CHECK(TestParse("[127.0.0.1]", "127.0.0.1:65535"));
    BOOST_CHECK(TestParse(":::", ""));
}

BOOST_AUTO_TEST_CASE(onioncat_test)
{
    // values from https://web.archive.org/web/20121122003543/http://www.cypherpunk.at/onioncat/wiki/OnionCat
    CNetAddr addr1("5wyqrzbvrdsumnok.onion");
    CNetAddr addr2("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca");
    BOOST_CHECK(addr1 == addr2);
    BOOST_CHECK(addr1.IsTor());
    BOOST_CHECK(addr1.ToStringIP() == "5wyqrzbvrdsumnok.onion");
    BOOST_CHECK(addr1.IsRoutable());
}

BOOST_AUTO_TEST_CASE(subnet_test)
{
    BOOST_CHECK(CSubNet("1.2.3.0/24") == CSubNet("1.2.3.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24") != CSubNet("1.2.4.0/255.255.255.0"));
    BOOST_CHECK(CSubNet("1.2.3.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.2.0/24").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(CSubNet("1.2.3.4/32").Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("1.2.3.4").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(!CSubNet("1.2.3.4/32").Match(CNetAddr("5.6.7.8")));
    BOOST_CHECK(CSubNet("::ffff:127.0.0.1").Match(CNetAddr("127.0.0.1")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:8")));
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8").Match(CNetAddr("1:2:3:4:5:6:7:9")));
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:0/112").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    BOOST_CHECK(CSubNet("192.168.0.1/24").Match(CNetAddr("192.168.0.2")));
    BOOST_CHECK(CSubNet("192.168.0.20/29").Match(CNetAddr("192.168.0.18")));
    BOOST_CHECK(CSubNet("1.2.2.1/24").Match(CNetAddr("1.2.2.4")));
    BOOST_CHECK(CSubNet("1.2.2.110/31").Match(CNetAddr("1.2.2.111")));
    BOOST_CHECK(CSubNet("1.2.2.20/26").Match(CNetAddr("1.2.2.63")));
    // All-Matching IPv6 Matches arbitrary IPv4 and IPv6
    BOOST_CHECK(CSubNet("::/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    BOOST_CHECK(CSubNet("::/0").Match(CNetAddr("1.2.3.4")));
    // All-Matching IPv4 does not Match IPv6
    BOOST_CHECK(!CSubNet("0.0.0.0/0").Match(CNetAddr("1:2:3:4:5:6:7:1234")));
    // Invalid subnets Match nothing (not even invalid addresses)
    BOOST_CHECK(!CSubNet().Match(CNetAddr("1.2.3.4")));
    BOOST_CHECK(!CSubNet("").Match(CNetAddr("4.5.6.7")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("0.0.0.0")));
    BOOST_CHECK(!CSubNet("bloop").Match(CNetAddr("hab")));
    // Check valid/invalid
    BOOST_CHECK(CSubNet("1.2.3.0/0").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/-1").IsValid());
    BOOST_CHECK(CSubNet("1.2.3.0/32").IsValid());
    BOOST_CHECK(!CSubNet("1.2.3.0/33").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/0").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/33").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/-1").IsValid());
    BOOST_CHECK(CSubNet("1:2:3:4:5:6:7:8/128").IsValid());
    BOOST_CHECK(!CSubNet("1:2:3:4:5:6:7:8/129").IsValid());
    BOOST_CHECK(!CSubNet("fuzzy").IsValid());

    //CNetAddr constructor test
    BOOST_CHECK(CSubNet(CNetAddr("127.0.0.1")).IsValid());
    BOOST_CHECK(CSubNet(CNetAddr("127.0.0.1")).Match(CNetAddr("127.0.0.1")));
    BOOST_CHECK(!CSubNet(CNetAddr("127.0.0.1")).Match(CNetAddr("127.0.0.2")));
    BOOST_CHECK(CSubNet(CNetAddr("127.0.0.1")).ToString() == "127.0.0.1/32");

    BOOST_CHECK(CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).IsValid());
    BOOST_CHECK(CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).Match(CNetAddr("1:2:3:4:5:6:7:8")));
    BOOST_CHECK(!CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).Match(CNetAddr("1:2:3:4:5:6:7:9")));
    BOOST_CHECK(CSubNet(CNetAddr("1:2:3:4:5:6:7:8")).ToString() == "1:2:3:4:5:6:7:8/128");

    CSubNet subnet = CSubNet("1.2.3.4/255.255.255.255");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.4/32");
    subnet = CSubNet("1.2.3.4/255.255.255.254");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.4/31");
    subnet = CSubNet("1.2.3.4/255.255.255.252");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.4/30");
    subnet = CSubNet("1.2.3.4/255.255.255.248");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/29");
    subnet = CSubNet("1.2.3.4/255.255.255.240");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/28");
    subnet = CSubNet("1.2.3.4/255.255.255.224");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/27");
    subnet = CSubNet("1.2.3.4/255.255.255.192");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/26");
    subnet = CSubNet("1.2.3.4/255.255.255.128");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/25");
    subnet = CSubNet("1.2.3.4/255.255.255.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.3.0/24");
    subnet = CSubNet("1.2.3.4/255.255.254.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.2.0/23");
    subnet = CSubNet("1.2.3.4/255.255.252.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/22");
    subnet = CSubNet("1.2.3.4/255.255.248.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/21");
    subnet = CSubNet("1.2.3.4/255.255.240.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/20");
    subnet = CSubNet("1.2.3.4/255.255.224.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/19");
    subnet = CSubNet("1.2.3.4/255.255.192.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/18");
    subnet = CSubNet("1.2.3.4/255.255.128.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/17");
    subnet = CSubNet("1.2.3.4/255.255.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/16");
    subnet = CSubNet("1.2.3.4/255.254.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/15");
    subnet = CSubNet("1.2.3.4/255.252.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/14");
    subnet = CSubNet("1.2.3.4/255.248.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/13");
    subnet = CSubNet("1.2.3.4/255.240.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/12");
    subnet = CSubNet("1.2.3.4/255.224.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/11");
    subnet = CSubNet("1.2.3.4/255.192.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/10");
    subnet = CSubNet("1.2.3.4/255.128.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/9");
    subnet = CSubNet("1.2.3.4/255.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.0.0.0/8");
    subnet = CSubNet("1.2.3.4/254.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/7");
    subnet = CSubNet("1.2.3.4/252.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/6");
    subnet = CSubNet("1.2.3.4/248.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/5");
    subnet = CSubNet("1.2.3.4/240.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/4");
    subnet = CSubNet("1.2.3.4/224.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/3");
    subnet = CSubNet("1.2.3.4/192.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/2");
    subnet = CSubNet("1.2.3.4/128.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/1");
    subnet = CSubNet("1.2.3.4/0.0.0.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "0.0.0.0/0");

    subnet = CSubNet("1:2:3:4:5:6:7:8/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1:2:3:4:5:6:7:8/128");
    subnet = CSubNet("1:2:3:4:5:6:7:8/ffff:0000:0000:0000:0000:0000:0000:0000");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1::/16");
    subnet = CSubNet("1:2:3:4:5:6:7:8/0000:0000:0000:0000:0000:0000:0000:0000");
    BOOST_CHECK_EQUAL(subnet.ToString(), "::/0");
    subnet = CSubNet("1.2.3.4/255.255.232.0");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1.2.0.0/255.255.232.0");
    subnet = CSubNet("1:2:3:4:5:6:7:8/ffff:ffff:ffff:fffe:ffff:ffff:ffff:ff0f");
    BOOST_CHECK_EQUAL(subnet.ToString(), "1:2:3:4:5:6:7:8/ffff:ffff:ffff:fffe:ffff:ffff:ffff:ff0f");
}

BOOST_AUTO_TEST_CASE(validate_test)
{
    std::list<std::string> validIPv4 = {"11.12.13.14", "50.168.168.150", "72.31.250.250"};
    std::list<std::string> validIPv6 = {"1111:2222:3333:4444:5555:6666::8888", "2001:0002:6c::430", "2002:cb0a:3cdd:1::1"};
    std::list<std::string> validTor = {"5wyqrzbvrdsumnok.onion", "FD87:D87E:EB43:edb1:8e4:3588:e546:35ca"};

    for (const std::string& ipStr : validIPv4)
        BOOST_CHECK_MESSAGE(validateMasternodeIP(ipStr), ipStr);
    for (const std::string& ipStr : validIPv6)
        BOOST_CHECK_MESSAGE(validateMasternodeIP(ipStr), ipStr);
    for (const std::string& ipStr : validTor)
        BOOST_CHECK_MESSAGE(validateMasternodeIP(ipStr), ipStr);

    std::list<std::string> invalidIPv4 = {"11.12.13.14.15", "11.12.13.330", "30.168.1.255.1", "192.168.1.1", "255.255.255.255"};
    std::list<std::string> invalidIPv6 = {"1111:2222:3333:4444:5555:6666:7777:8888:9999", "2002:cb0a:3cdd::1::1", "1111:2222:3333:::5555:6666:7777:8888"};
    std::list<std::string> invalidTor = {"5wyqrzbvrdsumnok.noonion"};

    for (const std::string& ipStr : invalidIPv4)
        BOOST_CHECK_MESSAGE(!validateMasternodeIP(ipStr), ipStr);
    for (const std::string& ipStr : invalidIPv6)
        BOOST_CHECK_MESSAGE(!validateMasternodeIP(ipStr), ipStr);
    for (const std::string& ipStr : invalidTor)
        BOOST_CHECK_MESSAGE(!validateMasternodeIP(ipStr), ipStr);
}

BOOST_AUTO_TEST_SUITE_END()
