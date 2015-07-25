// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x03;
        pchMessageStart[1] = 0x3f;
        pchMessageStart[2] = 0x1a;
        pchMessageStart[3] = 0x0c;
        vAlertPubKey = ParseHex("04f828a532f5df028c41cc1e04eab69c8a34371d39ef8440679857ed7707ed8bf8a9acaaf12fcf3721b1e4cf409614e6ced7da9a5ed8788886671dc0a90860c67a");
        nDefaultPort = 15760;
        nRPCPort = 15770;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        //CBlock(hash=000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1393221600, nBits=1e0fffff, nNonce=164482, vtx=1, vchBlockSig=)
        //  Coinbase(hash=12630d16a9, nTime=1393221600, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
        //    CTxOut(empty)
        //  vMerkleTree: 12630d16a9
        const char* pszTimestamp = "19 Jul 2015 coindesk.com 10 VC Firms Betting Big on Bitcoin and the Blockchain";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1437456154, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1437456154;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 43454;

        hashGenesisBlock = genesis.GetHash();
/*
if (true && (genesis.GetHash() != hashGenesisBlock)) {
	// This will figure out a valid hash and Nonce if you're
	// creating a different genesis block:
	    uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
	    while (genesis.GetHash() > hashTarget)
	    {
	        ++genesis.nNonce;
	        if (genesis.nNonce == 0)
		{
		    printf("NONCE WRAPPED, incrementing time");
		    ++genesis.nTime;
		}
	    }
	}
	//// debug print
	printf("block.GetHash() == %s\n", genesis.GetHash().ToString().c_str());
	printf("block.hashMerkleRoot == %s\n", genesis.hashMerkleRoot.ToString().c_str());
	printf("block.nTime = %u \n", genesis.nTime);
	printf("block.nNonce = %u \n", genesis.nNonce);
*/
        assert(hashGenesisBlock == uint256("0x75687e926dd7611f320a99144869f1e281e275b306c634e285e780f1440a0064"));
        assert(genesis.hashMerkleRoot == uint256("0x9d35af1a8dadf0ebe7369bd5f472ed899b1b84222259ea0a1a1853b093148135"));

        vSeeds.push_back(CDNSSeedData("seed.axiomcoin.xyz", "seed.axiomcoin.xyz"));
        
        base58Prefixes[PUBKEY_ADDRESS] = list_of(23); // A
        base58Prefixes[SCRIPT_ADDRESS] = list_of(85);
        base58Prefixes[SECRET_KEY] =     list_of(153);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x3f;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0x1c;
        pchMessageStart[3] = 0x05;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        vAlertPubKey = ParseHex("04f828a532f5df028c41cc1e04eab69c8a34371d39ef8440679857ed7707ed8bf8a9acaaf12fcf3721b1e4cf409614e6ced7da9a5ed8788886671dc0a90860c67a");
        nDefaultPort = 25760;
        nRPCPort = 25770;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 43454;
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x75687e926dd7611f320a99144869f1e281e275b306c634e285e780f1440a0064"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(83);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
