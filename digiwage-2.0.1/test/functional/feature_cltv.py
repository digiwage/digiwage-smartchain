#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP65 (CHECKLOCKTIMEVERIFY).

Test that the CHECKLOCKTIMEVERIFY soft-fork activates at (regtest) block height
1351.
"""

from test_framework.test_framework import DigiwageTestFramework
from test_framework.util import *
from test_framework.mininode import *
from test_framework.blocktools import create_coinbase, create_block
from test_framework.script import CScript, OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY, OP_DROP, CScriptNum
from io import BytesIO

CLTV_HEIGHT = 750

# Reject codes that we might receive in this test
REJECT_INVALID = 16
REJECT_OBSOLETE = 17
REJECT_NONSTANDARD = 64

def cltv_invalidate(tx):
    '''Modify the signature in vin 0 of the tx to fail CLTV

    Prepends -1 CLTV DROP in the scriptSig itself.

    TODO: test more ways that transactions using CLTV could be invalid (eg
    locktime requirements fail, sequence time requirements fail, etc).
    '''
    tx.vin[0].scriptSig = CScript([OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY, OP_DROP] +
                                  list(CScript(tx.vin[0].scriptSig)))

def cltv_validate(node, tx, height):
    '''Modify the signature in vin 0 of the tx to pass CLTV
    Prepends <height> CLTV DROP in the scriptSig, and sets
    the locktime to height'''
    tx.vin[0].nSequence = 0
    tx.nLockTime = height

    # Need to re-sign, since nSequence and nLockTime changed
    signed_result = node.signrawtransaction(ToHex(tx))
    new_tx = CTransaction()
    new_tx.deserialize(BytesIO(hex_str_to_bytes(signed_result['hex'])))

    new_tx.vin[0].scriptSig = CScript([CScriptNum(height), OP_CHECKLOCKTIMEVERIFY, OP_DROP] +
                                  list(CScript(new_tx.vin[0].scriptSig)))
    return new_tx

def create_transaction(node, coinbase, to_address, amount):
    from_txid = node.getblock(coinbase)['tx'][0]
    inputs = [{ "txid" : from_txid, "vout" : 0}]
    outputs = { to_address : amount }
    rawtx = node.createrawtransaction(inputs, outputs)
    signresult = node.signrawtransaction(rawtx)
    tx = CTransaction()
    tx.deserialize(BytesIO(hex_str_to_bytes(signresult['hex'])))
    return tx

class BIP65Test(DigiwageTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-promiscuousmempoolflags=1', '-whitelist=127.0.0.1']]
        self.setup_clean_chain = True

    def run_test(self):
        self.nodes[0].add_p2p_connection(P2PInterface())

        network_thread_start()

        # wait_for_verack ensures that the P2P connection is fully up.
        self.nodes[0].p2p.wait_for_verack()

        self.log.info("Mining %d blocks", CLTV_HEIGHT - 2)
        self.coinbase_blocks = self.nodes[0].generate(CLTV_HEIGHT - 2)
        self.nodeaddress = self.nodes[0].getnewaddress()

        self.log.info("Test that an invalid-according-to-CLTV transaction can still appear in a block")

        spendtx = create_transaction(self.nodes[0], self.coinbase_blocks[0],
                self.nodeaddress, 1.0)
        cltv_invalidate(spendtx)
        spendtx.rehash()

        tip = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblockheader(tip)['mediantime'] + 1
        block = create_block(int(tip, 16), create_coinbase(CLTV_HEIGHT - 1), block_time)
        block.nVersion = 4
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        self.nodes[0].p2p.send_and_ping(msg_block(block))
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)

        self.nodes[0].generate(205)

        self.log.info("Test that blocks must now be at least version 5")
        tip = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblockheader(tip)['mediantime'] + 1
        block = create_block(int(tip, 16), create_coinbase(CLTV_HEIGHT + 205), block_time)
        block.nVersion = 4
        block.solve()
        self.nodes[0].p2p.send_and_ping(msg_block(block))

        wait_until(lambda: "reject" in self.nodes[0].p2p.last_message.keys(), lock=mininode_lock)
        with mininode_lock:
            assert_equal(self.nodes[0].p2p.last_message["reject"].code, REJECT_OBSOLETE)
            assert_equal(self.nodes[0].p2p.last_message["reject"].reason, b'bad-version')
            assert_equal(self.nodes[0].p2p.last_message["reject"].data, block.sha256)
            del self.nodes[0].p2p.last_message["reject"]

        self.log.info("Test that invalid-according-to-cltv transactions cannot appear in a block")
        block.nVersion = 5

        spendtx = create_transaction(self.nodes[0], self.coinbase_blocks[1],
                self.nodeaddress, 1.0)
        cltv_invalidate(spendtx)
        spendtx.rehash()

        # Verify that a block with this transaction is invalid.
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        self.nodes[0].p2p.send_and_ping(msg_block(block))

        wait_until(lambda: "reject" in self.nodes[0].p2p.last_message.keys(), lock=mininode_lock)
        with mininode_lock:
            assert self.nodes[0].p2p.last_message["reject"].code in [REJECT_INVALID, REJECT_NONSTANDARD]
            assert_equal(self.nodes[0].p2p.last_message["reject"].data, block.sha256)
            if self.nodes[0].p2p.last_message["reject"].code == REJECT_INVALID:
                # Generic rejection when a block is invalid
                assert_equal(self.nodes[0].p2p.last_message["reject"].reason, b'block-validation-failed')
            else:
                assert b'Negative locktime' in self.nodes[0].p2p.last_message["reject"].reason

        self.log.info("Test that a version 5 block with a valid-according-to-CLTV transaction is accepted")
        spendtx = cltv_validate(self.nodes[0], spendtx, CLTV_HEIGHT - 1)
        spendtx.rehash()

        block.vtx.pop(1)
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        self.nodes[0].p2p.send_and_ping(msg_block(block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)


if __name__ == '__main__':
    BIP65Test().main()
