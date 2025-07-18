#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compare two or more digiwageds to each other.

To use, create a class that implements get_tests(), and pass it in
as the test generator to TestManager.  get_tests() should be a python
generator that returns TestInstance objects.  See below for definition.

TestNode behaves as follows:
    Configure with a BlockStore and TxStore
    on_inv: log the message but don't request
    on_headers: log the chain tip
    on_pong: update ping response map (for synchronization)
    on_getheaders: provide headers via BlockStore
    on_getdata: provide blocks via BlockStore
"""

from .mininode import *
from .blockstore import BlockStore, TxStore
from .util import p2p_port, wait_until

import logging

logger=logging.getLogger("TestFramework.comptool")

global mininode_lock

class RejectResult():
    """Outcome that expects rejection of a transaction or block."""
    def __init__(self, code, reason=b''):
        self.code = code
        self.reason = reason
    def match(self, other):
        if self.code != other.code:
            return False
        return other.reason.startswith(self.reason)
    def __repr__(self):
        return '%i:%s' % (self.code,self.reason or '*')

class TestNode(P2PInterface):

    def __init__(self, block_store, tx_store):
        super().__init__()
        self.bestblockhash = None
        self.block_store = block_store
        self.block_request_map = {}
        self.tx_store = tx_store
        self.tx_request_map = {}
        self.block_reject_map = {}
        self.tx_reject_map = {}

        # When the pingmap is non-empty we're waiting for
        # a response
        self.pingMap = {}
        self.lastInv = []
        self.closed = False

    def on_close(self):
        self.closed = True

    def on_headers(self, message):
        if len(message.headers) > 0:
            best_header = message.headers[-1]
            best_header.calc_sha256()
            self.bestblockhash = best_header.sha256

    def on_getheaders(self, message):
        response = self.block_store.headers_for(message.locator, message.hashstop)
        if response is not None:
            self.send_message(response)

    def on_getdata(self, message):
        [self.send_message(r) for r in self.block_store.get_blocks(message.inv)]
        [self.send_message(r) for r in self.tx_store.get_transactions(message.inv)]

        for i in message.inv:
            if i.type == 1 or i.type == 1 | (1 << 30): # MSG_TX or MSG_WITNESS_TX
                self.tx_request_map[i.hash] = True
            elif i.type == 2 or i.type == 2 | (1 << 30): # MSG_BLOCK or MSG_WITNESS_BLOCK
                self.block_request_map[i.hash] = True

    def on_inv(self, message):
        self.lastInv = [x.hash for x in message.inv]

    def on_pong(self, message):
        try:
            del self.pingMap[message.nonce]
        except KeyError:
            raise AssertionError("Got pong for unknown ping [%s]" % repr(message))

    def on_reject(self, message):
        if message.message == b'tx':
            self.tx_reject_map[message.data] = RejectResult(message.code, message.reason)
        if message.message == b'block':
            self.block_reject_map[message.data] = RejectResult(message.code, message.reason)

    def send_inv(self, obj):
        mtype = 2 if isinstance(obj, CBlock) else 1
        self.send_message(msg_inv([CInv(mtype, obj.sha256)]))

    def send_getheaders(self):
        # We ask for headers from their last tip.
        m = msg_getheaders()
        m.locator = self.block_store.get_locator(self.bestblockhash)
        self.send_message(m)

    def send_header(self, header):
        m = msg_headers()
        m.headers.append(header)
        self.send_message(m)

    # This assumes BIP31
    def send_ping(self, nonce):
        self.pingMap[nonce] = True
        self.send_message(msg_ping(nonce))

    def received_ping_response(self, nonce):
        return nonce not in self.pingMap

    def send_mempool(self):
        self.lastInv = []
        self.send_message(msg_mempool())

# TestInstance:
#
# Instances of these are generated by the test generator, and fed into the
# comptool.
#
# "blocks_and_transactions" should be an array of
#    [obj, True/False/None, hash/None]:
#  - obj is either a CBlock, CBlockHeader, or a CTransaction, and
#  - the second value indicates whether the object should be accepted
#    into the blockchain or mempool (for tests where we expect a certain
#    answer), or "None" if we don't expect a certain answer and are just
#    comparing the behavior of the nodes being tested.
#  - the third value is the hash to test the tip against (if None or omitted,
#    use the hash of the block)
#  - NOTE: if a block header, no test is performed; instead the header is
#    just added to the block_store.  This is to facilitate block delivery
#    when communicating with headers-first clients (when withholding an
#    intermediate block).
# sync_every_block: if True, then each block will be inv'ed, synced, and
#    nodes will be tested based on the outcome for the block.  If False,
#    then inv's accumulate until all blocks are processed (or max inv size
#    is reached) and then sent out in one inv message.  Then the final block
#    will be synced across all connections, and the outcome of the final
#    block will be tested.
# sync_every_tx: analogous to behavior for sync_every_block, except if outcome
#    on the final tx is None, then contents of entire mempool are compared
#    across all connections.  (If outcome of final tx is specified as true
#    or false, then only the last tx is tested against outcome.)

class TestInstance():
    def __init__(self, objects=None, sync_every_block=True, sync_every_tx=False):
        self.blocks_and_transactions = objects if objects else []
        self.sync_every_block = sync_every_block
        self.sync_every_tx = sync_every_tx

class TestManager():

    def __init__(self, testgen, datadir):
        self.test_generator = testgen
        self.p2p_connections= []
        self.block_store    = BlockStore(datadir)
        self.tx_store       = TxStore(datadir)
        self.ping_counter   = 1

    def add_all_connections(self, nodes):
        for i in range(len(nodes)):
            # Create a p2p connection to each node
            node = TestNode(self.block_store, self.tx_store)
            node.peer_connect('127.0.0.1', p2p_port(i))
            self.p2p_connections.append(node)

    def clear_all_connections(self):
        self.p2p_connections = []

    def wait_for_disconnections(self):
        def disconnected():
            return all(node.closed for node in self.p2p_connections)
        wait_until(disconnected, timeout=10, lock=mininode_lock)

    def wait_for_verack(self):
        return all(node.wait_for_verack() for node in self.p2p_connections)

    def wait_for_pings(self, counter):
        def received_pongs():
            return all(node.received_ping_response(counter) for node in self.p2p_connections)
        wait_until(received_pongs, lock=mininode_lock)

    # sync_blocks: Wait for all connections to request the blockhash given
    # then send get_headers to find out the tip of each node, and synchronize
    # the response by using a ping (and waiting for pong with same nonce).
    def sync_blocks(self, blockhash, num_blocks):
        def blocks_requested():
            return all(
                blockhash in node.block_request_map and node.block_request_map[blockhash]
                for node in self.p2p_connections
            )

        # --> error if not requested
        wait_until(blocks_requested, attempts=20*num_blocks, lock=mininode_lock)

        # Send getheaders message
        [ c.send_getheaders() for c in self.p2p_connections ]

        # Send ping and wait for response -- synchronization hack
        [ c.send_ping(self.ping_counter) for c in self.p2p_connections ]
        self.wait_for_pings(self.ping_counter)
        self.ping_counter += 1

    # Analogous to sync_block (see above)
    def sync_transaction(self, txhash, num_events):
        # Wait for nodes to request transaction (50ms sleep * 20 tries * num_events)
        def transaction_requested():
            return all(
                txhash in node.tx_request_map and node.tx_request_map[txhash]
                for node in self.p2p_connections
            )

        # --> error if not requested
        wait_until(transaction_requested, attempts=20*num_events, lock=mininode_lock)

        # Get the mempool
        [ c.send_mempool() for c in self.p2p_connections ]

        # Send ping and wait for response -- synchronization hack
        [ c.send_ping(self.ping_counter) for c in self.p2p_connections ]
        self.wait_for_pings(self.ping_counter)
        self.ping_counter += 1

        # Sort inv responses from each node
        with mininode_lock:
            [ c.lastInv.sort() for c in self.p2p_connections ]

    # Verify that the tip of each connection all agree with each other, and
    # with the expected outcome (if given)
    def check_results(self, blockhash, outcome):
        with mininode_lock:
            for c in self.p2p_connections:
                if outcome is None:
                    if c.bestblockhash != self.p2p_connections[0].bestblockhash:
                        return False
                elif isinstance(outcome, RejectResult): # Check that block was rejected w/ code
                    if c.bestblockhash == blockhash:
                        return False
                    if blockhash not in c.block_reject_map:
                        logger.error('Block not in reject map: %064x' % (blockhash))
                        return False
                    if not outcome.match(c.block_reject_map[blockhash]):
                        logger.error('Block rejected with %s instead of expected %s: %064x' % (c.block_reject_map[blockhash], outcome, blockhash))
                        return False
                elif ((c.bestblockhash == blockhash) != outcome):
                    return False
            return True

    # Either check that the mempools all agree with each other, or that
    # txhash's presence in the mempool matches the outcome specified.
    # This is somewhat of a strange comparison, in that we're either comparing
    # a particular tx to an outcome, or the entire mempools altogether;
    # perhaps it would be useful to add the ability to check explicitly that
    # a particular tx's existence in the mempool is the same across all nodes.
    def check_mempool(self, txhash, outcome):
        with mininode_lock:
            for c in self.p2p_connections:
                if outcome is None:
                    # Make sure the mempools agree with each other
                    if c.lastInv != self.p2p_connections[0].lastInv:
                        return False
                elif isinstance(outcome, RejectResult): # Check that tx was rejected w/ code
                    if txhash in c.lastInv:
                        return False
                    if txhash not in c.tx_reject_map:
                        logger.error('Tx not in reject map: %064x' % (txhash))
                        return False
                    if not outcome.match(c.tx_reject_map[txhash]):
                        logger.error('Tx rejected with %s instead of expected %s: %064x' % (c.tx_reject_map[txhash], outcome, txhash))
                        return False
                elif ((txhash in c.lastInv) != outcome):
                    return False
            return True

    def run(self):
        # Wait until verack is received
        self.wait_for_verack()

        test_number = 0
        tests = self.test_generator.get_tests()
        for test_instance in tests:
            test_number += 1
            logger.info("Running test %d: %s line %s" % (test_number, tests.gi_code.co_filename, tests.gi_frame.f_lineno))
            # We use these variables to keep track of the last block
            # and last transaction in the tests, which are used
            # if we're not syncing on every block or every tx.
            [ block, block_outcome, tip ] = [ None, None, None ]
            [ tx, tx_outcome ] = [ None, None ]
            invqueue = []

            for test_obj in test_instance.blocks_and_transactions:
                b_or_t = test_obj[0]
                outcome = test_obj[1]
                # Determine if we're dealing with a block or tx
                if isinstance(b_or_t, CBlock):  # Block test runner
                    block = b_or_t
                    block_outcome = outcome
                    tip = block.sha256
                    # each test_obj can have an optional third argument
                    # to specify the tip we should compare with
                    # (default is to use the block being tested)
                    if len(test_obj) >= 3:
                        tip = test_obj[2]

                    # Add to shared block_store, set as current block
                    # If there was an open getdata request for the block
                    # previously, and we didn't have an entry in the
                    # block_store, then immediately deliver, because the
                    # node wouldn't send another getdata request while
                    # the earlier one is outstanding.
                    first_block_with_hash = True
                    if self.block_store.get(block.sha256) is not None:
                        first_block_with_hash = False
                    with mininode_lock:
                        self.block_store.add_block(block)
                        for c in self.p2p_connections:
                            if first_block_with_hash and block.sha256 in c.block_request_map and c.block_request_map[block.sha256] == True:
                                # There was a previous request for this block hash
                                # Most likely, we delivered a header for this block
                                # but never had the block to respond to the getdata
                                c.send_message(msg_block(block))
                            else:
                                c.block_request_map[block.sha256] = False
                    # Either send inv's to each node and sync, or add
                    # to invqueue for later inv'ing.
                    if (test_instance.sync_every_block):
                        # if we expect success, send inv and sync every block
                        # if we expect failure, just push the block and see what happens.
                        if outcome == True:
                            [ c.send_inv(block) for c in self.p2p_connections ]
                            self.sync_blocks(block.sha256, 1)
                        else:
                            [ c.send_message(msg_block(block)) for c in self.p2p_connections ]
                            [ c.send_ping(self.ping_counter) for c in self.p2p_connections ]
                            self.wait_for_pings(self.ping_counter)
                            self.ping_counter += 1
                        if (not self.check_results(tip, outcome)):
                            raise AssertionError("Test failed at test %d" % test_number)
                    else:
                        invqueue.append(CInv(2, block.sha256))
                elif isinstance(b_or_t, CBlockHeader):
                    block_header = b_or_t
                    self.block_store.add_header(block_header)
                    [ c.send_header(block_header) for c in self.p2p_connections ]

                else:  # Tx test runner
                    assert(isinstance(b_or_t, CTransaction))
                    tx = b_or_t
                    tx_outcome = outcome
                    # Add to shared tx store and clear map entry
                    with mininode_lock:
                        self.tx_store.add_transaction(tx)
                        for c in self.p2p_connections:
                            c.tx_request_map[tx.sha256] = False
                    # Again, either inv to all nodes or save for later
                    if (test_instance.sync_every_tx):
                        [ c.send_inv(tx) for c in self.p2p_connections ]
                        self.sync_transaction(tx.sha256, 1)
                        if (not self.check_mempool(tx.sha256, outcome)):
                            raise AssertionError("Test failed at test %d" % test_number)
                    else:
                        invqueue.append(CInv(1, tx.sha256))
                # Ensure we're not overflowing the inv queue
                if len(invqueue) == MAX_INV_SZ:
                    [ c.send_message(msg_inv(invqueue)) for c in self.p2p_connections ]
                    invqueue = []

            # Do final sync if we weren't syncing on every block or every tx.
            if (not test_instance.sync_every_block and block is not None):
                if len(invqueue) > 0:
                    [ c.send_message(msg_inv(invqueue)) for c in self.p2p_connections ]
                    invqueue = []
                self.sync_blocks(block.sha256, len(test_instance.blocks_and_transactions))
                if (not self.check_results(tip, block_outcome)):
                    raise AssertionError("Block test failed at test %d" % test_number)
            if (not test_instance.sync_every_tx and tx is not None):
                if len(invqueue) > 0:
                    [ c.send_message(msg_inv(invqueue)) for c in self.p2p_connections ]
                    invqueue = []
                self.sync_transaction(tx.sha256, len(test_instance.blocks_and_transactions))
                if (not self.check_mempool(tx.sha256, tx_outcome)):
                    raise AssertionError("Mempool test failed at test %d" % test_number)

        [ c.disconnect_node() for c in self.p2p_connections ]
        self.wait_for_disconnections()
        self.block_store.close()
        self.tx_store.close()
