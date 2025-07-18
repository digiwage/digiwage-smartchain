// Copyright (c) 2012-2013 The Bitcoin Core developers
// Copyright (c) 2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "addrman.h"
#include "test/test_digiwage.h"
#include <string>
#include <boost/test/unit_test.hpp>
#include <crypto/common.h> // for ReadLE64

#include "hash.h"
#include "random.h"

class CAddrManTest : public CAddrMan
{
    uint64_t state;

public:
    CAddrManTest()
    {
        state = 1;
    }

    //! Ensure that bucket placement is always the same for testing purposes.
    void MakeDeterministic()
    {
        nKey.SetNull();
        insecure_rand = FastRandomContext(true);
    }

    int RandomInt(int nMax)
    {
        state = ReadLE64((CHashWriter(SER_GETHASH, 0) << state).GetHash().begin());
        return (unsigned int)(state % nMax);
    }

    CAddrInfo* Find(const CNetAddr& addr, int* pnId = NULL)
    {
        return CAddrMan::Find(addr, pnId);
    }

    CAddrInfo* Create(const CAddress& addr, const CNetAddr& addrSource, int* pnId = NULL)
    {
        return CAddrMan::Create(addr, addrSource, pnId);
    }

    void Delete(int nId)
    {
        CAddrMan::Delete(nId);
    }
};

BOOST_FIXTURE_TEST_SUITE(addrman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(addrman_simple)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    // Test 1: Does Addrman respond correctly when empty.
    BOOST_CHECK(addrman.size() == 0);
    CAddrInfo addr_null = addrman.Select();
    BOOST_CHECK(addr_null.ToString() == "[::]:0");

    // Test 2: Does Addrman::Add work as expected.
    CService addr1 = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 1);
    CAddrInfo addr_ret1 = addrman.Select();
    BOOST_CHECK(addr_ret1.ToString() == "250.1.1.1:8333");

    // Test 3: Does IP address deduplication work correctly.
    //  Expected dup IP should not be added.
    CService addr1_dup = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1_dup), source);
    BOOST_CHECK(addrman.size() == 1);


    // Test 5: New table has one addr and we add a diff addr we should
    //  have two addrs.
    CService addr2 = CService("250.1.1.2", 8333);
    addrman.Add(CAddress(addr2), source);
    BOOST_CHECK(addrman.size() == 2);

    // Test 6: AddrMan::Clear() should empty the new table.
    addrman.Clear();
    BOOST_CHECK(addrman.size() == 0);
    CAddrInfo addr_null2 = addrman.Select();
    BOOST_CHECK(addr_null2.ToString() == "[::]:0");
}

BOOST_AUTO_TEST_CASE(addrman_ports)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    BOOST_CHECK(addrman.size() == 0);

    // Test 7; Addr with same IP but diff port does not replace existing addr.
    CService addr1 = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 1);

    CService addr1_port = CService("250.1.1.1", 8334);
    addrman.Add(CAddress(addr1_port), source);
    BOOST_CHECK(addrman.size() == 1);
    CAddrInfo addr_ret2 = addrman.Select();
    BOOST_CHECK(addr_ret2.ToString() == "250.1.1.1:8333");

    // Test 8: Add same IP but diff port to tried table, it doesn't get added.
    //  Perhaps this is not ideal behavior but it is the current behavior.
    addrman.Good(CAddress(addr1_port));
    BOOST_CHECK(addrman.size() == 1);
    bool newOnly = true;
    CAddrInfo addr_ret3 = addrman.Select(newOnly);
    BOOST_CHECK(addr_ret3.ToString() == "250.1.1.1:8333");
}


BOOST_AUTO_TEST_CASE(addrman_select)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    // Test 9: Select from new with 1 addr in new.
    CService addr1 = CService("250.1.1.1", 8333);
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 1);

    bool newOnly = true;
    CAddrInfo addr_ret1 = addrman.Select(newOnly);
    BOOST_CHECK(addr_ret1.ToString() == "250.1.1.1:8333");

    // Test 10: move addr to tried, select from new expected nothing returned.
    addrman.Good(CAddress(addr1));
    BOOST_CHECK(addrman.size() == 1);
    CAddrInfo addr_ret2 = addrman.Select(newOnly);
    BOOST_CHECK(addr_ret2.ToString() == "[::]:0");

    CAddrInfo addr_ret3 = addrman.Select();
    BOOST_CHECK(addr_ret3.ToString() == "250.1.1.1:8333");

    BOOST_CHECK(addrman.size() == 1);


    // Add three addresses to new table.
    CService addr2 = CService("250.3.1.1", 8333);
    CService addr3 = CService("250.3.2.2", 9999);
    CService addr4 = CService("250.3.3.3", 9999);

    addrman.Add(CAddress(addr2), CService("250.3.1.1", 8333));
    addrman.Add(CAddress(addr3), CService("250.3.1.1", 8333));
    addrman.Add(CAddress(addr4), CService("250.4.1.1", 8333));

    // Add three addresses to tried table.
    CService addr5 = CService("250.4.4.4", 8333);
    CService addr6 = CService("250.4.5.5", 7777);
    CService addr7 = CService("250.4.6.6", 8333);

    addrman.Add(CAddress(addr5), CService("250.3.1.1", 8333));
    addrman.Good(CAddress(addr5));
    addrman.Add(CAddress(addr6), CService("250.3.1.1", 8333));
    addrman.Good(CAddress(addr6));
    addrman.Add(CAddress(addr7), CService("250.1.1.3", 8333));
    addrman.Good(CAddress(addr7));

    // Test 11: 6 addrs + 1 addr from last test = 7.
    BOOST_CHECK(addrman.size() == 7);

    // Test 12: Select pulls from new and tried regardless of port number.
    std::set<uint16_t> ports;
    for (int i = 0; i < 20; ++i) {
        ports.insert(addrman.Select().GetPort());
    }
    BOOST_CHECK_EQUAL(ports.size(), 3);
}

BOOST_AUTO_TEST_CASE(addrman_new_collisions)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    BOOST_CHECK(addrman.size() == 0);

    for (int i = 1; i < 18; i++) {
        CService addr = CService("250.1.1." + boost::to_string(i));
        addrman.Add(CAddress(addr), source);

        //Test 13: No collision in new table yet.
        BOOST_CHECK(addrman.size() == i);
    }

    //Test 14: new table collision!
    CService addr1 = CService("250.1.1.18");
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 17);

    CService addr2 = CService("250.1.1.19");
    addrman.Add(CAddress(addr2), source);
    BOOST_CHECK(addrman.size() == 18);
}

BOOST_AUTO_TEST_CASE(addrman_tried_collisions)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CNetAddr source = CNetAddr("252.2.2.2");

    BOOST_CHECK(addrman.size() == 0);

    for (int i = 1; i < 80; i++) {
        CService addr = CService("250.1.1." + boost::to_string(i));
        addrman.Add(CAddress(addr), source);
        addrman.Good(CAddress(addr));

        //Test 15: No collision in tried table yet.
        BOOST_TEST_MESSAGE(addrman.size());
        BOOST_CHECK(addrman.size() == i);
    }

    //Test 16: tried table collision!
    CService addr1 = CService("250.1.1.80");
    addrman.Add(CAddress(addr1), source);
    BOOST_CHECK(addrman.size() == 79);

    CService addr2 = CService("250.1.1.81");
    addrman.Add(CAddress(addr2), source);
    BOOST_CHECK(addrman.size() == 80);
}

BOOST_AUTO_TEST_CASE(addrman_find)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    BOOST_CHECK(addrman.size() == 0);

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CAddress addr2 = CAddress(CService("250.1.2.1", 9999));
    CAddress addr3 = CAddress(CService("251.255.2.1", 8333));

    CNetAddr source1 = CNetAddr("250.1.2.1");
    CNetAddr source2 = CNetAddr("250.1.2.2");

    addrman.Add(addr1, source1);
    addrman.Add(addr2, source2);
    addrman.Add(addr3, source1);

    // Test 17: ensure Find returns an IP matching what we searched on.
    CAddrInfo* info1 = addrman.Find(addr1);
    BOOST_CHECK(info1);
    if (info1)
        BOOST_CHECK(info1->ToString() == "250.1.2.1:8333");

    // Test 18; Find does not discriminate by port number.
    CAddrInfo* info2 = addrman.Find(addr2);
    BOOST_CHECK(info2);
    if (info2)
        BOOST_CHECK(info2->ToString() == info1->ToString());

    // Test 19: Find returns another IP matching what we searched on.
    CAddrInfo* info3 = addrman.Find(addr3);
    BOOST_CHECK(info3);
    if (info3)
        BOOST_CHECK(info3->ToString() == "251.255.2.1:8333");
}

BOOST_AUTO_TEST_CASE(addrman_create)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    BOOST_CHECK(addrman.size() == 0);

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CNetAddr source1 = CNetAddr("250.1.2.1");

    int nId;
    CAddrInfo* pinfo = addrman.Create(addr1, source1, &nId);

    // Test 20: The result should be the same as the input addr.
    BOOST_CHECK(pinfo->ToString() == "250.1.2.1:8333");

    CAddrInfo* info2 = addrman.Find(addr1);
    BOOST_CHECK(info2->ToString() == "250.1.2.1:8333");
}


BOOST_AUTO_TEST_CASE(addrman_delete)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    BOOST_CHECK(addrman.size() == 0);

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CNetAddr source1 = CNetAddr("250.1.2.1");

    int nId;
    addrman.Create(addr1, source1, &nId);

    // Test 21: Delete should actually delete the addr.
    BOOST_CHECK(addrman.size() == 1);
    addrman.Delete(nId);
    BOOST_CHECK(addrman.size() == 0);
    CAddrInfo* info2 = addrman.Find(addr1);
    BOOST_CHECK(info2 == NULL);
}

BOOST_AUTO_TEST_CASE(addrman_getaddr)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    // Test 22: Sanity check, GetAddr should never return anything if addrman
    //  is empty.
    BOOST_CHECK(addrman.size() == 0);
    std::vector<CAddress> vAddr1 = addrman.GetAddr();
    BOOST_CHECK(vAddr1.size() == 0);

    CAddress addr1 = CAddress(CService("250.250.2.1", 8333));
    addr1.nTime = GetAdjustedTime(); // Set time so isTerrible = false
    CAddress addr2 = CAddress(CService("250.251.2.2", 9999));
    addr2.nTime = GetAdjustedTime();
    CAddress addr3 = CAddress(CService("251.252.2.3", 8333));
    addr3.nTime = GetAdjustedTime();
    CAddress addr4 = CAddress(CService("252.253.3.4", 8333));
    addr4.nTime = GetAdjustedTime();
    CAddress addr5 = CAddress(CService("252.254.4.5", 8333));
    addr5.nTime = GetAdjustedTime();
    CNetAddr source1 = CNetAddr("250.1.2.1");
    CNetAddr source2 = CNetAddr("250.2.3.3");

    // Test 23: Ensure GetAddr works with new addresses.
    addrman.Add(addr1, source1);
    addrman.Add(addr2, source2);
    addrman.Add(addr3, source1);
    addrman.Add(addr4, source2);
    addrman.Add(addr5, source1);

    // GetAddr returns 23% of addresses, 23% of 5 is 1 rounded down.
    BOOST_CHECK(addrman.GetAddr().size() == 1);

    // Test 24: Ensure GetAddr works with new and tried addresses.
    addrman.Good(CAddress(addr1));
    addrman.Good(CAddress(addr2));
    BOOST_CHECK(addrman.GetAddr().size() == 1);

    // Test 25: Ensure GetAddr still returns 23% when addrman has many addrs.
    for (unsigned int i = 1; i < (8 * 256); i++) {
        int octet1 = i % 256;
        int octet2 = (i / 256) % 256;
        int octet3 = (i / (256 * 2)) % 256;
        std::string strAddr = boost::to_string(octet1) + "." + boost::to_string(octet2) + "." + boost::to_string(octet3) + ".23";
        CAddress addr = CAddress(CService(strAddr));

        // Ensure that for all addrs in addrman, isTerrible == false.
        addr.nTime = GetAdjustedTime();
        addrman.Add(addr, CNetAddr(strAddr));
        if (i % 8 == 0)
            addrman.Good(addr);
    }
    std::vector<CAddress> vAddr = addrman.GetAddr();

    size_t percent23 = (addrman.size() * 23) / 100;
    BOOST_CHECK(vAddr.size() == percent23);
    BOOST_CHECK(vAddr.size() == 461);
    // (Addrman.size() < number of addresses added) due to address collisons.
    BOOST_CHECK(addrman.size() == 2007);
}


BOOST_AUTO_TEST_CASE(caddrinfo_get_tried_bucket)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CAddress addr1 = CAddress(CService("250.1.1.1", 8333));
    CAddress addr2 = CAddress(CService("250.1.1.1", 9999));

    CNetAddr source1 = CNetAddr("250.1.1.1");


    CAddrInfo info1 = CAddrInfo(addr1, source1);

    uint256 nKey1 = (uint256)(CHashWriter(SER_GETHASH, 0) << 1).GetHash();
    uint256 nKey2 = (uint256)(CHashWriter(SER_GETHASH, 0) << 2).GetHash();


    BOOST_CHECK(info1.GetTriedBucket(nKey1) == 40);

    // Test 26: Make sure key actually randomizes bucket placement. A fail on
    //  this test could be a security issue.
    BOOST_CHECK(info1.GetTriedBucket(nKey1) != info1.GetTriedBucket(nKey2));

    // Test 27: Two addresses with same IP but different ports can map to
    //  different buckets because they have different keys.
    CAddrInfo info2 = CAddrInfo(addr2, source1);

    BOOST_CHECK(info1.GetKey() != info2.GetKey());
    BOOST_CHECK(info1.GetTriedBucket(nKey1) != info2.GetTriedBucket(nKey1));

    std::set<int> buckets;
    for (int i = 0; i < 255; i++) {
        CAddrInfo infoi = CAddrInfo(
            CAddress(CService("250.1.1." + boost::to_string(i))),
            CNetAddr("250.1.1." + boost::to_string(i)));
        int bucket = infoi.GetTriedBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 28: IP addresses in the same group (\16 prefix for IPv4) should
    //  never get more than 8 buckets
    BOOST_CHECK(buckets.size() == 8);

    buckets.clear();
    for (int j = 0; j < 255; j++) {
        CAddrInfo infoj = CAddrInfo(
            CAddress(CService("250." + boost::to_string(j) + ".1.1")),
            CNetAddr("250." + boost::to_string(j) + ".1.1"));
        int bucket = infoj.GetTriedBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 29: IP addresses in the different groups should map to more than
    //  8 buckets.
    BOOST_CHECK(buckets.size() == 160);
}

BOOST_AUTO_TEST_CASE(caddrinfo_get_new_bucket)
{
    CAddrManTest addrman;

    // Set addrman addr placement to be deterministic.
    addrman.MakeDeterministic();

    CAddress addr1 = CAddress(CService("250.1.2.1", 8333));
    CAddress addr2 = CAddress(CService("250.1.2.1", 9999));

    CNetAddr source1 = CNetAddr("250.1.2.1");

    CAddrInfo info1 = CAddrInfo(addr1, source1);

    uint256 nKey1 = (uint256)(CHashWriter(SER_GETHASH, 0) << 1).GetHash();
    uint256 nKey2 = (uint256)(CHashWriter(SER_GETHASH, 0) << 2).GetHash();

    BOOST_CHECK(info1.GetNewBucket(nKey1) == 786);

    // Test 30: Make sure key actually randomizes bucket placement. A fail on
    //  this test could be a security issue.
    BOOST_CHECK(info1.GetNewBucket(nKey1) != info1.GetNewBucket(nKey2));

    // Test 31: Ports should not effect bucket placement in the addr
    CAddrInfo info2 = CAddrInfo(addr2, source1);
    BOOST_CHECK(info1.GetKey() != info2.GetKey());
    BOOST_CHECK(info1.GetNewBucket(nKey1) == info2.GetNewBucket(nKey1));

    std::set<int> buckets;
    for (int i = 0; i < 255; i++) {
        CAddrInfo infoi = CAddrInfo(
            CAddress(CService("250.1.1." + boost::to_string(i))),
            CNetAddr("250.1.1." + boost::to_string(i)));
        int bucket = infoi.GetNewBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 32: IP addresses in the same group (\16 prefix for IPv4) should
    //  always map to the same bucket.
    BOOST_CHECK(buckets.size() == 1);

    buckets.clear();
    for (int j = 0; j < 4 * 255; j++) {
        CAddrInfo infoj = CAddrInfo(CAddress(
                                        CService(
                                            boost::to_string(250 + (j / 255)) + "." + boost::to_string(j % 256) + ".1.1")),
            CNetAddr("251.4.1.1"));
        int bucket = infoj.GetNewBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 33: IP addresses in the same source groups should map to no more
    //  than 64 buckets.
    BOOST_CHECK(buckets.size() <= 64);

    buckets.clear();
    for (int p = 0; p < 255; p++) {
        CAddrInfo infoj = CAddrInfo(
            CAddress(CService("250.1.1.1")),
            CNetAddr("250." + boost::to_string(p) + ".1.1"));
        int bucket = infoj.GetNewBucket(nKey1);
        buckets.insert(bucket);
    }
    // Test 34: IP addresses in the different source groups should map to more
    //  than 64 buckets.
    BOOST_CHECK(buckets.size() > 64);
}
BOOST_AUTO_TEST_SUITE_END()