// Copyright (c) 2018 The DIGIWAGE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode-budget.h"
#include "tinyformat.h"
#include "utilmoneystr.h"
#include "test_digiwage.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(budget_tests, TestingSetup)

void CheckBudgetValue(int nHeight, std::string strNetwork, CAmount nExpectedValue)
{
    CBudgetManager budget;
    CAmount nBudget = budget.GetTotalBudget(nHeight);
    std::string strError = strprintf("Budget is not as expected for %s. Result: %s, Expected: %s", strNetwork, FormatMoney(nBudget), FormatMoney(nExpectedValue));
    BOOST_CHECK_MESSAGE(nBudget == nExpectedValue, strError);
}

BOOST_AUTO_TEST_CASE(budget_value)
{
    SelectParams(CBaseChainParams::TESTNET);
    int nHeightTest = Params().GetConsensus().height_start_ZC_SerialsV2 + 1;
    CheckBudgetValue(nHeightTest, "testnet", 7300*COIN);

    SelectParams(CBaseChainParams::MAIN);
    nHeightTest = Params().GetConsensus().height_start_ZC_SerialsV2 + 1;
    CheckBudgetValue(nHeightTest, "mainnet", 43200*COIN);
}

BOOST_AUTO_TEST_SUITE_END()
