// Copyright (c) 2012-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 80810;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 70077;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION_BEFORE_ENFORCEMENT = 70810;
static const int MIN_PEER_PROTO_VERSION_AFTER_ENFORCEMENT = 80810;

//! masternodes older than this proto version use old strMessage format for mnannounce
static const int MIN_PEER_MNANNOUNCE = 80810;

//! nTime field added to CAddress, starting with this version;
//! if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "mempool" command, enhanced "getdata" behavior starts with this version
static const int MEMPOOL_GD_VERSION = 60002;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 70005;


#endif // BITCOIN_VERSION_H
