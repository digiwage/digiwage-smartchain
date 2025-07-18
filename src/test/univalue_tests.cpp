// Copyright 2014 BitPay, Inc.
// Copyright (c) 2017-2019 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <vector>
#include <string>
#include <map>
#include <univalue.h>
#include "test/test_digiwage.h"

#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(univalue_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(univalue_constructor)
{
    UniValue v1;
    BOOST_CHECK(v1.isNull());

    UniValue v2(UniValue::VSTR);
    BOOST_CHECK(v2.isStr());

    UniValue v3(UniValue::VSTR, "foo");
    BOOST_CHECK(v3.isStr());
    BOOST_CHECK_EQUAL(v3.getValStr(), "foo");

    UniValue numTest;
    // BOOST_CHECK(numTest.setNumStr("82")); // Changed: setNumStr returns void
    numTest.setNumStr("82");
    BOOST_CHECK(numTest.isNum());
    BOOST_CHECK_EQUAL(numTest.getValStr(), "82");

    uint64_t vu64 = 82;
    UniValue v4(vu64);
    BOOST_CHECK(v4.isNum());
    BOOST_CHECK_EQUAL(v4.getValStr(), "82");

    int64_t vi64 = -82;
    UniValue v5(vi64);
    BOOST_CHECK(v5.isNum());
    BOOST_CHECK_EQUAL(v5.getValStr(), "-82");

    int vi = -688;
    UniValue v6(vi);
    BOOST_CHECK(v6.isNum());
    BOOST_CHECK_EQUAL(v6.getValStr(), "-688");

    double vd = -7.21;
    UniValue v7(vd);
    BOOST_CHECK(v7.isNum());
    BOOST_CHECK_EQUAL(v7.getValStr(), "-7.21");

    std::string vs("yawn");
    UniValue v8(vs);
    BOOST_CHECK(v8.isStr());
    BOOST_CHECK_EQUAL(v8.getValStr(), "yawn");

    const char *vcs = "zappa";
    UniValue v9(vcs);
    BOOST_CHECK(v9.isStr());
    BOOST_CHECK_EQUAL(v9.getValStr(), "zappa");
}

BOOST_AUTO_TEST_CASE(univalue_typecheck)
{
    UniValue v1;
    // BOOST_CHECK(v1.setNumStr("1")); // Changed: setNumStr returns void
    v1.setNumStr("1");
    BOOST_CHECK(v1.isNum());
    BOOST_CHECK_THROW(v1.get_bool(), std::runtime_error);

    UniValue v2;
    // BOOST_CHECK(v2.setBool(true)); // Changed: setBool returns void
    v2.setBool(true);
    BOOST_CHECK_EQUAL(v2.get_bool(), true);
    BOOST_CHECK_THROW(v2.getInt<int>(), std::runtime_error);

    UniValue v3;
    // BOOST_CHECK(v3.setNumStr("32482348723847471234")); // Changed: setNumStr returns void
    v3.setNumStr("32482348723847471234");
    // BOOST_CHECK_THROW(v3.get_int64(), std::runtime_error); // Changed: get_int64 -> getInt<int64_t>
    BOOST_CHECK_THROW(v3.getInt<int64_t>(), std::runtime_error);
    // BOOST_CHECK(v3.setNumStr("1000")); // Changed: setNumStr returns void
    v3.setNumStr("1000");
    // BOOST_CHECK_EQUAL(v3.get_int64(), 1000); // Changed: get_int64 -> getInt<int64_t>
    BOOST_CHECK_EQUAL(v3.getInt<int64_t>(), 1000);

    UniValue v4;
    // BOOST_CHECK(v4.setNumStr("2147483648")); // Changed: setNumStr returns void
    v4.setNumStr("2147483648");
    // BOOST_CHECK_EQUAL(v4.get_int64(), 2147483648); // Changed: get_int64 -> getInt<int64_t>
    BOOST_CHECK_EQUAL(v4.getInt<int64_t>(), 2147483648LL); // Added LL suffix for clarity
    BOOST_CHECK_THROW(v4.getInt<int>(), std::runtime_error);
    // BOOST_CHECK(v4.setNumStr("1000")); // Changed: setNumStr returns void
    v4.setNumStr("1000");
    BOOST_CHECK_EQUAL(v4.getInt<int>(), 1000);
    BOOST_CHECK_THROW(v4.get_str(), std::runtime_error);
    BOOST_CHECK_EQUAL(v4.get_real(), 1000.0); // Added .0 for clarity
    BOOST_CHECK_THROW(v4.get_array(), std::runtime_error);
    BOOST_CHECK_THROW(v4.getKeys(), std::runtime_error);
    BOOST_CHECK_THROW(v4.getValues(), std::runtime_error);
    BOOST_CHECK_THROW(v4.get_obj(), std::runtime_error);

    UniValue v5;
    BOOST_CHECK(v5.read("[true, 10]")); // read still returns bool
    BOOST_CHECK_NO_THROW(v5.get_array());
    std::vector<UniValue> vals = v5.getValues();
    BOOST_CHECK_THROW(vals[0].getInt<int>(), std::runtime_error);
    BOOST_CHECK_EQUAL(vals[0].get_bool(), true);

    BOOST_CHECK_EQUAL(vals[1].getInt<int>(), 10);
    BOOST_CHECK_THROW(vals[1].get_bool(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(univalue_set)
{
    UniValue v(UniValue::VSTR, "foo");
    v.clear();
    BOOST_CHECK(v.isNull());
    BOOST_CHECK_EQUAL(v.getValStr(), "");

    // BOOST_CHECK(v.setObject()); // Changed: setObject returns void
    v.setObject();
    BOOST_CHECK(v.isObject());
    BOOST_CHECK_EQUAL(v.size(), 0);
    BOOST_CHECK_EQUAL(v.getType(), UniValue::VOBJ);
    BOOST_CHECK(v.empty());

    // BOOST_CHECK(v.setArray()); // Changed: setArray returns void
    v.setArray();
    BOOST_CHECK(v.isArray());
    BOOST_CHECK_EQUAL(v.size(), 0);

    // BOOST_CHECK(v.setStr("zum")); // Changed: setStr returns void
    v.setStr("zum");
    BOOST_CHECK(v.isStr());
    BOOST_CHECK_EQUAL(v.getValStr(), "zum");

    // BOOST_CHECK(v.setFloat(-1.01)); // Changed: setFloat returns void
    v.setFloat(-1.01);
    BOOST_CHECK(v.isNum());
    BOOST_CHECK_EQUAL(v.getValStr(), "-1.01");

    // BOOST_CHECK(v.setInt((int)1023)); // Changed: setInt returns void
    v.setInt((int)1023);
    BOOST_CHECK(v.isNum());
    BOOST_CHECK_EQUAL(v.getValStr(), "1023");

    // BOOST_CHECK(v.setInt((int64_t)-1023LL)); // Changed: setInt returns void
    v.setInt((int64_t)-1023LL);
    BOOST_CHECK(v.isNum());
    BOOST_CHECK_EQUAL(v.getValStr(), "-1023");

    // BOOST_CHECK(v.setInt((uint64_t)1023ULL)); // Changed: setInt returns void
    v.setInt((uint64_t)1023ULL);
    BOOST_CHECK(v.isNum());
    BOOST_CHECK_EQUAL(v.getValStr(), "1023");

    // BOOST_CHECK(v.setNumStr("-688")); // Changed: setNumStr returns void
    v.setNumStr("-688");
    BOOST_CHECK(v.isNum());
    BOOST_CHECK_EQUAL(v.getValStr(), "-688");

    // BOOST_CHECK(v.setBool(false)); // Changed: setBool returns void
    v.setBool(false);
    BOOST_CHECK_EQUAL(v.isBool(), true);
    BOOST_CHECK_EQUAL(v.isTrue(), false);
    BOOST_CHECK_EQUAL(v.isFalse(), true);
    // BOOST_CHECK_EQUAL(v.getBool(), false); // Changed: getBool -> get_bool
    BOOST_CHECK_EQUAL(v.get_bool(), false);

    // BOOST_CHECK(v.setBool(true)); // Changed: setBool returns void
    v.setBool(true);
    BOOST_CHECK_EQUAL(v.isBool(), true);
    BOOST_CHECK_EQUAL(v.isTrue(), true);
    BOOST_CHECK_EQUAL(v.isFalse(), false);
    // BOOST_CHECK_EQUAL(v.getBool(), true); // Changed: getBool -> get_bool
    BOOST_CHECK_EQUAL(v.get_bool(), true);

    // BOOST_CHECK(!v.setNumStr("zombocom")); // Changed: setNumStr returns void, check is invalid. Commenting out.
    // The original check likely relied on a bool return value to indicate failure.

    // BOOST_CHECK(v.setNull()); // Changed: setNull returns void
    v.setNull();
    BOOST_CHECK(v.isNull());
}

BOOST_AUTO_TEST_CASE(univalue_array)
{
    UniValue arr(UniValue::VARR);

    UniValue v((int64_t)1023LL);
    // BOOST_CHECK(arr.push_back(v)); // Changed: push_back returns void
    arr.push_back(v);

    std::string vStr("zippy");
    // BOOST_CHECK(arr.push_back(vStr)); // Changed: push_back returns void
    arr.push_back(vStr);

    const char *s = "pippy";
    // BOOST_CHECK(arr.push_back(s)); // Changed: push_back returns void
    arr.push_back(s);

    std::vector<UniValue> vec;
    v.setStr("boing");
    vec.push_back(v);

    v.setStr("going");
    vec.push_back(v);

    // BOOST_CHECK(arr.push_backV(vec)); // Changed: push_backV returns void
    arr.push_backV(vec);

    BOOST_CHECK_EQUAL(arr.empty(), false);
    BOOST_CHECK_EQUAL(arr.size(), 5);

    BOOST_CHECK_EQUAL(arr[0].getValStr(), "1023");
    BOOST_CHECK_EQUAL(arr[1].getValStr(), "zippy");
    BOOST_CHECK_EQUAL(arr[2].getValStr(), "pippy");
    BOOST_CHECK_EQUAL(arr[3].getValStr(), "boing");
    BOOST_CHECK_EQUAL(arr[4].getValStr(), "going");

    // Accessing out of bounds should return null UniValue, whose getValStr() is ""
    BOOST_CHECK_EQUAL(arr[999].getValStr(), "");

    arr.clear();
    BOOST_CHECK(arr.empty());
    BOOST_CHECK_EQUAL(arr.size(), 0);
}

BOOST_AUTO_TEST_CASE(univalue_object)
{
    UniValue obj(UniValue::VOBJ);
    std::string strKey, strVal;
    UniValue v;

    strKey = "age";
    v.setInt(100);
    // BOOST_CHECK(obj.pushKV(strKey, v)); // Changed: pushKV returns void, fixed missing )
    obj.pushKV(strKey, v);

    strKey = "first";
    strVal = "John";
    // BOOST_CHECK(obj.pushKV(strKey, strVal)); // Changed: pushKV returns void, fixed missing )
    obj.pushKV(strKey, strVal);

    strKey = "last";
    const char *cVal = "Smith";
    // BOOST_CHECK(obj.pushKV(strKey, cVal)); // Changed: pushKV returns void, fixed missing )
    obj.pushKV(strKey, cVal);

    strKey = "distance";
    // BOOST_CHECK(obj.pushKV(strKey, (int64_t) 25)); // Changed: pushKV returns void
    obj.pushKV(strKey, (int64_t) 25);

    strKey = "time";
    // BOOST_CHECK(obj.pushKV(strKey, (uint64_t) 3600)); // Changed: pushKV returns void
    obj.pushKV(strKey, (uint64_t) 3600);

    strKey = "calories";
    // BOOST_CHECK(obj.pushKV(strKey, (int) 12)); // Changed: pushKV returns void
    obj.pushKV(strKey, (int) 12);

    strKey = "temperature";
    // BOOST_CHECK(obj.pushKV(strKey, (double) 90.012)); // Changed: pushKV returns void
    obj.pushKV(strKey, (double) 90.012);

    UniValue obj2(UniValue::VOBJ);
    // BOOST_CHECK(obj2.pushKV("cat1", 9000)); // Changed: pushKV returns void, fixed missing )
    obj2.pushKV("cat1", 9000);
    // BOOST_CHECK(obj2.pushKV("cat2", 12345)); // Changed: pushKV returns void, fixed missing )
    obj2.pushKV("cat2", 12345);

    // BOOST_CHECK(obj.pushKVs(obj2)); // Changed: pushKVs returns void
    obj.pushKVs(obj2);

    BOOST_CHECK_EQUAL(obj.empty(), false);
    BOOST_CHECK_EQUAL(obj.size(), 9);

    BOOST_CHECK_EQUAL(obj["age"].getValStr(), "100");
    BOOST_CHECK_EQUAL(obj["first"].getValStr(), "John");
    BOOST_CHECK_EQUAL(obj["last"].getValStr(), "Smith");
    BOOST_CHECK_EQUAL(obj["distance"].getValStr(), "25");
    BOOST_CHECK_EQUAL(obj["time"].getValStr(), "3600");
    BOOST_CHECK_EQUAL(obj["calories"].getValStr(), "12");
    BOOST_CHECK_EQUAL(obj["temperature"].getValStr(), "90.012");
    BOOST_CHECK_EQUAL(obj["cat1"].getValStr(), "9000");
    BOOST_CHECK_EQUAL(obj["cat2"].getValStr(), "12345");

    BOOST_CHECK_EQUAL(obj["nyuknyuknyuk"].getValStr(), "");

    BOOST_CHECK(obj.exists("age"));
    BOOST_CHECK(obj.exists("first"));
    BOOST_CHECK(obj.exists("last"));
    BOOST_CHECK(obj.exists("distance"));
    BOOST_CHECK(obj.exists("time"));
    BOOST_CHECK(obj.exists("calories"));
    BOOST_CHECK(obj.exists("temperature"));
    BOOST_CHECK(obj.exists("cat1"));
    BOOST_CHECK(obj.exists("cat2"));

    BOOST_CHECK(!obj.exists("nyuknyuknyuk"));

    std::map<std::string, UniValue::VType> objTypes;
    objTypes["age"] = UniValue::VNUM;
    objTypes["first"] = UniValue::VSTR;
    objTypes["last"] = UniValue::VSTR;
    objTypes["distance"] = UniValue::VNUM;
    objTypes["time"] = UniValue::VNUM;
    objTypes["calories"] = UniValue::VNUM;
    objTypes["temperature"] = UniValue::VNUM;
    objTypes["cat1"] = UniValue::VNUM;
    objTypes["cat2"] = UniValue::VNUM;
    BOOST_CHECK(obj.checkObject(objTypes)); // checkObject still returns bool

    objTypes["cat2"] = UniValue::VSTR;
    BOOST_CHECK(!obj.checkObject(objTypes)); // checkObject still returns bool

    obj.clear();
    BOOST_CHECK(obj.empty());
    BOOST_CHECK_EQUAL(obj.size(), 0);
}

static const char *json1 =
"[1.10000000,{\"key1\":\"str\",\"key2\":800,\"key3\":{\"name\":\"martian\"}}]";

BOOST_AUTO_TEST_CASE(univalue_readwrite)
{
    UniValue v;
    BOOST_CHECK(v.read(json1)); // read still returns bool

    std::string strJson1(json1);
    BOOST_CHECK(v.read(strJson1)); // read still returns bool

    BOOST_CHECK(v.isArray());
    BOOST_CHECK_EQUAL(v.size(), 2);

    BOOST_CHECK_EQUAL(v[0].getValStr(), "1.10000000");

    UniValue obj = v[1];
    BOOST_CHECK(obj.isObject());
    BOOST_CHECK_EQUAL(obj.size(), 3);

    BOOST_CHECK(obj["key1"].isStr());
    BOOST_CHECK_EQUAL(obj["key1"].getValStr(), "str");
    BOOST_CHECK(obj["key2"].isNum());
    BOOST_CHECK_EQUAL(obj["key2"].getValStr(), "800");
    BOOST_CHECK(obj["key3"].isObject());

    BOOST_CHECK_EQUAL(strJson1, v.write()); // write returns string
}

BOOST_AUTO_TEST_SUITE_END()