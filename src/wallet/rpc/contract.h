// Copyright (c) 2023 The DigiWage developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIGIWAGE_WALLET_RPC_CONTRACT_H
#define DIGIWAGE_WALLET_RPC_CONTRACT_H

class CRPCTable;

void RegisterContractRPCCommands(CRPCTable &t); //!< Register RPC commands for contracts

#endif // DIGIWAGE_WALLET_RPC_CONTRACT_H