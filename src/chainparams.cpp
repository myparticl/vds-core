// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"
#include "crypto/equihash.h"
//#include "equi_miner.h"
#include <pow.h>

#include "util.h"
#include "utilstrencodings.h"
#include <key_io.h>
#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

using namespace std;

#include "chainparamsseeds.h"
///////////////////////////////////////////// // qtum
#include <libdevcore/SHA3.h>
#include <libdevcore/RLP.h>
#include "arith_uint256.h"
/////////////////////////////////////////////

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, int64_t nVibPool,
                                 uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward,
                                 const std::vector<unsigned char> vSolution)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << vector<unsigned char>((const unsigned char*) pszTimestamp, (const unsigned char*) pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].nFlag = 0;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    genesis.hashFinalSaplingRoot = SaplingMerkleTree::empty_root();
    genesis.nVersion = nVersion;
    genesis.nVibPool = nVibPool;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.hashStateRoot = uint256(h256Touint(dev::h256("e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec91410771495"))); // qtum
    genesis.hashUTXORoot = uint256(h256Touint(dev::sha3(dev::rlp("")))); // qtum
    genesis.nSolution = vSolution;
    return genesis;
}

static CBlock CreateGenesisBlock(int64_t nVibPool, uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, const std::vector<unsigned char> vSolution)
{
    const char* pszTimestamp = "Bitcoin000000000000000000001d07114997c2fbd5e277ae19d85b6adbb1e00d3d92b2";
    // "address": "Vchf78qDRpnF2nJipiFaXVL5b8hdLUPC2F5",
    // "btcaddr": "1HoaX1yHkoFi6ojZn5xBgFbBYP7CW2FZpZ",
    // "hash160": "b16a7e3a2b2f58e561b929997b5484ee342051b8",
    // "scriptPubKey": "76a914b8512034ee84547b9929b961e5582f2b3a7e6ab188ac",

    //std::vector<unsigned char> script = ParseHex("76a914b8512034ee84547b9929b961e5582f2b3a7e6ab188ac");
    //std::vector<unsigned char> script = ParseHex("76a914da85409224a452078a62ecec9f41232c9b54d10088ac");
	std::vector<unsigned char> script = ParseHex("76a914ebfb107ecfc7cbffa8ec0d5baa18689871e2585388ac"); //VcnNHBA8gzR6cgj6Sv87Zb2PTRnKog9QiC4
    const CScript genesisOutputScript = CScript(script.begin(), script.end());

    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nVibPool, nTime, nNonce, nBits, nVersion, genesisReward, vSolution);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams
{
public:

    CMainParams()
    {
        strNetworkID = "main";
        strCurrencyUnits = "VC";
        bip44CoinType = 133;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nMasternodePaymentsStartBlock = 100000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // actual historical value
        consensus.nMasternodePaymentsIncreasePeriod = 576 * 30; // 17280 - actual historical value
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nSuperblockStartBlock = 0;
        consensus.nSuperblockCycle = 40;
        consensus.nBidPeriod = 60;
        consensus.nBidLimit = 100 * COIN;

        consensus.nSubsidyHalvingInterval = 211680;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint / UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nBitcoinUTXOHeight = 297; // TODO: here change to candy end block
        consensus.nBitcoinRootEndHeight = 231839;

        consensus.nBlockCountPerDay = 1440;
        consensus.nWeekCount1stSeason = 3;
        consensus.nWeekCountOfSeason = 1;
        consensus.nBlockCountOfWeek = consensus.nBlockCountPerDay * 7;
        consensus.nBlockCountOf1stSeason = consensus.nBlockCountOfWeek * consensus.nWeekCount1stSeason;
        consensus.nBlockCountOfSeason = consensus.nBlockCountOfWeek * consensus.nWeekCountOfSeason;

        consensus.nClueChildrenDepth = 12;
        consensus.nClueChildrenWidth = 12;
        consensus.nClueMaturity = consensus.nBlockCountOfWeek;

        consensus.nVibStartHeight = 563012;
        consensus.nVibClue = 10;
        consensus.nVibLucky = 20;

        consensus.nTandiaPayPeriod = 144;
        consensus.nTandiaBallotPeriod = 10080;
        consensus.nTandiaBallotStart = 110500;

        consensus.nFounderPayHeight = consensus.nBlockCountOf1stSeason;
        consensus.nFounderAmount = 12000000 * COIN;
        //consensus.nFounderScript = ParseHex("76a9146974d7944e5475c4982a4c0912efb17172b0598788ac"); //VcaU8YHjzGvWL8xTNn9weq7YGACV1Kx93F8
        //consensus.nFounderScript = ParseHex("76a9145cde40fd9782b4ab4e8cbef9f4b4e1dc21631e2288ac");  //VcZKa2w61gyZgmRcuynWrp7Aj1EgrJyzqZR
		consensus.nFounderScript = ParseHex("76a9147fbfd314876ab386833e02503150a5f75977b8cf88ac");  //VccW1ENzUPLocBWjoHrGfMv1oVCyatLwd71

        //strPubkeyVibPreIco = "VcRM27JjdzyxvyFtXewtJHrk6NQGyo9TN7U"; //"1VVVVVVvzycHkuGinFxUnFgn5kqwFuV9P"
        //strPubkeyVibPreIco = "VcW6ZF4Ja6B9o1QxK2coHrf9NFFNgmQkwCn"; //"16F2dF4S2CAUKuy46TAx3aexevrYudLsSN"
		strPubkeyVibPreIco = "VcjoS9dF6DwTNuATr7dUEtiiA5AWHnLZWha"; //"1KwuXozx9xU4DfUbBTqu5eDkUqz9p41cM1"
        const size_t N = 96, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        /**
         * The message start string should be awesome! ⓥ❤ (ASCII)
         */
        //pchMessageStart[0] = 0x24;
		pchMessageStart[0] = 0x25;
        pchMessageStart[1] = 0xe5;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04b7ecf0baa90495ceb4e4090f6b2fd37eec1e9c85fac68a487f3ce11589692e4a317479316ee814e066638e1db54e37a10689b70286e6315b1087b6615d179264");
        nDefaultPort = 6533;
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;


        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60 * 60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";
        strMasternodePaymentsPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";
        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database (and is in any case of zero value).
         *
         */

        genesis = CreateGenesisBlock(

                      7052517017282037,
                      //1547165612, // nTime
                      //1565596800,//1558764000, // nTime
					  1569045600,//1558764000, // nTime
                      //uint256S("00000000000000000000000000000000000000000000000000000000000000b9"), // nNonce
					  uint256S("00000000000000000000000000000000000000000000000000000000000000dc"), // nNonce
                      0x2007ffff, // nBits
                      4, // nVersion
                      1747482982717963, // genesisReward
                      //ParseHex("08bc9767284a389bf0db4ff042d3c18c7d398b9dede5781b75f4a5deec7d51ad92301ae2c96f9e7f3671f3d4cf1b519f88eeab1d31d1c98c82f09fab020e0cdf4ffbb305"));
                      //ParseHex("009389e0b5d30f45a81720ea9da21b33a501b4d27c2675716ae9271898fb8d24bd1480c1e3ddda540be3370d4aefaed7b0719721a09f93d600c31e981bf7d670941a8b2d5"));
					  ParseHex("108cdca34521b544627aaf3a051afc983b262d69918d53c802634291a1b27b7d7087278c62d99b08937e7ce26e716753a5c86b2cac703fdf16507db702d5afc9f74fcd2f"));
                      

        printf("Searching for genesis block...\n");
        // This will figure out a valid hash and Nonce if you're
        // creating a different genesis block:
        arith_uint256 hashTarget = hashTarget.SetCompact(genesis.nBits);
        printf("hashTarget = %s\n", hashTarget.ToString().c_str());
        arith_uint256 thash;

        while(true)
        {
            crypto_generichash_blake2b_state state;
            std::mutex m_cs;
            bool cancelSolver = false;
            std::string solver = GetArg("-equihashsolver", "default");
            EhInitialiseState(nEquihashN, nEquihashK, state);

            // I = the block header minus nonce and solution.
            CEquihashInput I{genesis};
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << I;

            // H(I||...
            crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

            // H(I||V||...
            crypto_generichash_blake2b_state curr_state;
            curr_state = state;
            crypto_generichash_blake2b_update(&curr_state,
                                        genesis.nNonce.begin(),
                                        genesis.nNonce.size());
            std::function<bool(std::vector<unsigned char>)> validBlock =
                [&hashTarget, &m_cs, &cancelSolver, this]
                    (std::vector<unsigned char> soln) {
                        // Write the solution to the hash and compute the result.
                        // printf("- Checking solution against target\n");
                        genesis.nSolution = soln;

                        if (UintToArith256(genesis.GetPoWHash()) > hashTarget) {
                            return false;
                        }

                        if (!CheckEquihashSolution(&genesis, *this)) {
                            return false;
                        }

                        // Found a solution
                        // Ignore chain updates caused by us
                        std::lock_guard<std::mutex> lock{m_cs};
                        cancelSolver = false;
                        return true;
            };
            std::function<bool(EhSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](EhSolverCancelCheck pos) {
                std::lock_guard<std::mutex> lock{m_cs};
                return cancelSolver;
            };
			
            if (solver == "tromp") {
                // Create solver and initialize it.
                /*
                equi eq(1);
                eq.setstate(&curr_state);

                // Intialization done, start algo driver.
                eq.digit0(0);
                eq.xfull = eq.bfull = eq.hfull = 0;
                eq.showbsizes(0);
                for (u32 r = 1; r < WK; r++) {
                    (r&1) ? eq.digitodd(r, 0) : eq.digiteven(r, 0);
                    eq.xfull = eq.bfull = eq.hfull = 0;
                    eq.showbsizes(r);
                }
                eq.digitK(0);

                // Convert solution indices to byte array (decompress) and pass it to validBlock method.
                bool ready = false;
                for (size_t s = 0; s < eq.nsols; s++) {
                    // printf("\rChecking solution %d", int(s+1));
                    std::vector<eh_index> index_vector(PROOFSIZE);
                    for (size_t i = 0; i < PROOFSIZE; i++) {
                        index_vector[i] = eq.sols[s][i];
                    }
                    std::vector<unsigned char> sol_char = GetMinimalFromIndices(index_vector, DIGITBITS);

                    if (validBlock(sol_char)) {
                        // If we find a POW solution, do not try other solutions
                        // because they become invalid as we created a new block in blockchain.
                        ready = true;
                        break;
                    }
                }
                if (ready) break;*/
                
            } else {
                try {
                    // If we find a valid block, we rebuild
                    bool found = EhOptimisedSolve(nEquihashN, nEquihashK, curr_state, validBlock, cancelled);
                    if (found) {
                        break;
                    }
                } catch (EhSolverCancelledException&) {
                    printf("Equihash solver cancelled\n");
                    std::lock_guard<std::mutex> lock{m_cs};
                    cancelSolver = false;
                }
            }
             
            genesis.nNonce = ArithToUint256(UintToArith256(genesis.nNonce) + 1);
        }

        printf("block.nTime = %u \n", genesis.nTime);
        printf("block.nNonce = %s \n", genesis.nNonce.ToString().c_str());
        printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        printf("block.GetPoWHash = %s\n", genesis.GetPoWHash().ToString().c_str());
        printf("block.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("block.nSolution = %s\n", HexStr(genesis.nSolution.begin(), genesis.nSolution.end()).c_str());//
        
        
        consensus.hashGenesisBlock = genesis.GetHash();
//        std::cout <<  consensus.hashGenesisBlock.GetHex() << std::endl;
        //assert(consensus.hashGenesisBlock == uint256S("0804fd488d9f5787d025d8b1e9e199301b5b42bcbe779a4e875983103c6036a8"));
        //assert(genesis.hashMerkleRoot == uint256S("1888f3aa0ce450cbd75b44ffeec790a510b7e3164ba9ae8ca33caf3475485d18"));
		//assert(consensus.hashGenesisBlock == uint256S("e75ffb8dd67f55e7df217dbecc660b673c1e1001a458df964453966b2eef757a"));
        //assert(genesis.hashMerkleRoot == uint256S("461956d5de2787730eb6363622c5758c9647793de63fec2115b1082ac8ec3241"));
		assert(consensus.hashGenesisBlock == uint256S("cf33371615c7e2dbe82dc5ec6c3f8c8e14ab577361b247fd3994d0dd6a0d8779"));
        assert(genesis.hashMerkleRoot == uint256S("4a5edd4f338f3bec6e21cd5145880ca1f8b8df140c55833b1664b4541b54611f"));

        vFixedSeeds.clear();
        vSeeds.clear();


        // guarantees the first 2 characters, when base58 encoded, are "Vc"
        base58Prefixes[PUBKEY_ADDRESS] = {0x10, 0x1C};
        // guarantees the first 2 characters, when base58 encoded, are "Vs"
        base58Prefixes[SCRIPT_ADDRESS] = {0x10, 0x41};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY] = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x0B, 0x36};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8, 0xAB, 0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY] = {0x0F, 0xDB};

        base58BTCPrefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 0);
        base58BTCPrefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);
        base58BTCPrefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 128);

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "vs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "vviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "vivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";
        bech32HRPs[WITNESS_KEY]                  = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
                {300, uint256S("963eb04b69717938075e48c55559e8bc382ba8abc19a4b8212421d630d5fd864")},
                {52683, uint256S("33080b760439352ba9d6c9915fd777011a8f594791f149c3743c7d4736c7efa0")}
            }
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            //"13hYCAMdStpxWCBTKoHHZ2fq6FgcuDQ3kv",
            "1NtXXn6YRsMVkx5QFEPGpqpJMizgUR7hgo",
            "1DQCvRtZfHq3evHcYkesxD2rSpxwdVtKDp",
            "18VZr89iySRMEsjYUWqMKHDtGo3UQKA5zw",
            "1LcR8ThDBWxHZ5nsxG1v5DMNwjEY8EwrBV",
            "1EZNevYjCC3MBZfaw1x7oQBurxfgS2QXow",
            "14GXWN52ug4Qf415KmQoJJqAheVGLTMZ9K",
            "13hbWQCdLhMfxo6D8UKAP4nkTRLLKkaknm",
            "1EorQXRjmEpk1DLCrfGZdFnJr44xfnsVK4",
            "1D4yBDqhDHgrMnXPMNwPuM1xrA4bGiXexP",
            "17r2zDa3mu76Zv3uJxxGbJhWvDSZsf4sA9",
            "13cRmUxxnzhM56qNNTD3NH1r82fAeavD3E",
            "1NCadHZKiVKEyQN5HhgjmDHezmtpHc9bfK",
            "12TwL1hx86tckNqCvaEAyW97B2AYe2vYEs",
            "1c7KpgeHZzMjYHR6Wc6qtWi5ik88bk2td",
            "14wsT94txeZBeTKg1yiqne36f5JT23b8KX",
            "19GpC3te4uNoYUgjpD1s1zhmYReerwsYDa",
            "1MfcY9P81ET1dgcC12WMwtbShvwzq8kRUb",
            "1AdrLmdaj29dHgos53hFZeXXtLkH6Py2aV",
            "1ETZ5DWGqdxff5NP3Q96YcQ88DyAARmyHr",
            "14voVz9QVGMMynrJGLSTyF8o6C2YTv3Uww",
            "14oG5aEHuL9SDkLakuqzEsbrQTHk7jXZed",
            "18nmT6GLDz3ExS7cU69FGL2khNwfM6pHyS",
            "19po8Zkx8zW4FdQpu4r8LKyfWStkHcCgFK",
            "1LkDjZEKmws6TyKjLNALemAd6TUiVvarmF",
            "1D1qDSNsfHSonMnVn67FqWDQ9oFkvMk8ha",
            "1ArS7rcZhBYaBjbmsC7nafEoYGhNwo9mFJ",
            "1Pw8tXrLacgry7Q65XUpt1cAJKuqPVFipW",
            "17KPvKQQWjus7mCrZQtNk6QRABHDPqNwqM",
            "1MaFTbGzy1tQPHYQJUWsRFkTxEa4NYMqSf",
            "1jYFZA5uyqvNAxt2cqUprEpomdbCG16CJ",
            "1JQHg2fGHK35d8Wk7ACawUx7bFZoHaL2jo",
            "17GvNhcAVpEV2gdryj8pJQFQHNjcBLCJsv",
            "1MbXWjRkBJ1Fgp6GEdPsexJzdq2sM3wNcw"

        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams
{
public:

    CTestNetParams()
    {
        strNetworkID = "test";
        strCurrencyUnits = "vc";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nMasternodePaymentsStartBlock = 10000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 46000;
        consensus.nMasternodePaymentsIncreasePeriod = 576;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nSuperblockStartBlock = 0;
        consensus.nSuperblockCycle = 40;
        consensus.nBidPeriod = 60;
        consensus.nBidLimit = 100 * COIN;

        consensus.nSubsidyHalvingInterval = 211680;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;

        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 32; //
        consensus.nPowMaxAdjustUp = 16; //
        consensus.nPowTargetSpacing = 10;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;


        assert(maxUint / UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nBitcoinUTXOHeight = 297; // TODO: here change to candy end block
        consensus.nBitcoinRootEndHeight = 231839;

        consensus.nBlockCountPerDay = 1440;
        consensus.nWeekCount1stSeason = 3;
        consensus.nWeekCountOfSeason = 1;
        consensus.nBlockCountOfWeek = consensus.nBlockCountPerDay * 7;
        consensus.nBlockCountOf1stSeason = consensus.nBlockCountOfWeek * consensus.nWeekCount1stSeason;
        consensus.nBlockCountOfSeason = consensus.nBlockCountOfWeek * consensus.nWeekCountOfSeason;

        consensus.nClueMaturity = consensus.nBlockCountOfWeek;

        consensus.nClueChildrenDepth = 12;
        consensus.nClueChildrenWidth = 12;

        consensus.nVibStartHeight = 300;
        consensus.nVibClue = 10;
        consensus.nVibLucky = 20;

        consensus.nTandiaPayPeriod = 144;
        consensus.nTandiaBallotPeriod = 10080;
        consensus.nTandiaBallotStart = 110500;

        consensus.nFounderPayHeight = consensus.nBlockCountOf1stSeason;
        consensus.nFounderAmount = 12000000 * COIN;
        consensus.nFounderScript = ParseHex("76a9146974d7944e5475c4982a4c0912efb17172b0598788ac");

        strPubkeyVibPreIco = "vag5Xvo2pikduEKL6i5UbKbrESSQNvTqgDL";
        const size_t N = 96, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 26533;
        nMinerThreads = 0;
        nMaxTipAge = 12 * 60 * 60;
        nPruneAfterHeight = 1000;

        nFulfilledRequestExpireTime = 60 * 60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";
        strMasternodePaymentsPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis = CreateGenesisBlock(

                      7052517017282037,
                      //1547165612, // nTime
					  //1565596800,
					  1569045600,
                      uint256S("0000000000000000000000000000000000000000000000000000000000000011"), // nNonce
                      0x2007ffff, // nBits
                      4, // nVersion
                      1747482982717963, // genesisReward
                      //ParseHex("0c12ac1006b7febbb2d90b909f1565c99e16a1f5544ecab24512662c0604aba4e33819d928b1a38b59f986a835ad764231c31724c6961b19993c3c65ea740e95c87f36b9"));
                      //ParseHex("0c37df4b6d5c174485048fe49e574551ef0f1e5fa9da17bc5e91ba875bc98c2be50418db97798a15343c488e7e7edad969a27822044ae817fb949636a17593961f83a4e3"));
					  ParseHex("01ee920005c426df60d2b0c71c8ebc66971019a431e5b5fd7293f25721055fdb5f111d075b704b7570c593649af8cad869c2b23763d763a840372fa4cd5f2c36637334fe"));
		
		printf("Searching for testnet genesis block...\n");
        // This will figure out a valid hash and Nonce if you're
        // creating a different genesis block:
        arith_uint256 hashTarget = hashTarget.SetCompact(genesis.nBits);
        printf("hashTarget = %s\n", hashTarget.ToString().c_str());
        arith_uint256 thash;

        while(true)
        {
            crypto_generichash_blake2b_state state;
            std::mutex m_cs;
            bool cancelSolver = false;
            std::string solver = GetArg("-equihashsolver", "default");
            EhInitialiseState(nEquihashN, nEquihashK, state);

            // I = the block header minus nonce and solution.
            CEquihashInput I{genesis};
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << I;

            // H(I||...
            crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

            // H(I||V||...
            crypto_generichash_blake2b_state curr_state;
            curr_state = state;
            crypto_generichash_blake2b_update(&curr_state,
                                        genesis.nNonce.begin(),
                                        genesis.nNonce.size());
            std::function<bool(std::vector<unsigned char>)> validBlock =
                [&hashTarget, &m_cs, &cancelSolver, this]
                    (std::vector<unsigned char> soln) {
                        // Write the solution to the hash and compute the result.
                        // printf("- Checking solution against target\n");
                        genesis.nSolution = soln;

                        if (UintToArith256(genesis.GetPoWHash()) > hashTarget) {
                            return false;
                        }

                        if (!CheckEquihashSolution(&genesis, *this)) {
                            return false;
                        }

                        // Found a solution
                        // Ignore chain updates caused by us
                        std::lock_guard<std::mutex> lock{m_cs};
                        cancelSolver = false;
                        return true;
            };
            std::function<bool(EhSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](EhSolverCancelCheck pos) {
                std::lock_guard<std::mutex> lock{m_cs};
                return cancelSolver;
            };
			
            if (solver == "tromp") {
                // Create solver and initialize it.
                /*
                equi eq(1);
                eq.setstate(&curr_state);

                // Intialization done, start algo driver.
                eq.digit0(0);
                eq.xfull = eq.bfull = eq.hfull = 0;
                eq.showbsizes(0);
                for (u32 r = 1; r < WK; r++) {
                    (r&1) ? eq.digitodd(r, 0) : eq.digiteven(r, 0);
                    eq.xfull = eq.bfull = eq.hfull = 0;
                    eq.showbsizes(r);
                }
                eq.digitK(0);

                // Convert solution indices to byte array (decompress) and pass it to validBlock method.
                bool ready = false;
                for (size_t s = 0; s < eq.nsols; s++) {
                    // printf("\rChecking solution %d", int(s+1));
                    std::vector<eh_index> index_vector(PROOFSIZE);
                    for (size_t i = 0; i < PROOFSIZE; i++) {
                        index_vector[i] = eq.sols[s][i];
                    }
                    std::vector<unsigned char> sol_char = GetMinimalFromIndices(index_vector, DIGITBITS);

                    if (validBlock(sol_char)) {
                        // If we find a POW solution, do not try other solutions
                        // because they become invalid as we created a new block in blockchain.
                        ready = true;
                        break;
                    }
                }
                if (ready) break;*/
                
            } else {
                try {
                    // If we find a valid block, we rebuild
                    bool found = EhOptimisedSolve(nEquihashN, nEquihashK, curr_state, validBlock, cancelled);
                    if (found) {
                        break;
                    }
                } catch (EhSolverCancelledException&) {
                    printf("Equihash solver cancelled\n");
                    std::lock_guard<std::mutex> lock{m_cs};
                    cancelSolver = false;
                }
            }
             
            genesis.nNonce = ArithToUint256(UintToArith256(genesis.nNonce) + 1);
        }

        printf("block.nTime = %u \n", genesis.nTime);
        printf("block.nNonce = %s \n", genesis.nNonce.ToString().c_str());
        printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        printf("block.GetPoWHash = %s\n", genesis.GetPoWHash().ToString().c_str());
        printf("block.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("block.nSolution = %s\n", HexStr(genesis.nSolution.begin(), genesis.nSolution.end()).c_str());//
        
		
		
		
		consensus.hashGenesisBlock = genesis.GetHash();

        //assert(consensus.hashGenesisBlock == uint256S("bd94031d0ba5bbb72b50eecd5f5444056e5f0f788538e24261878178cdab6a62"));
        //assert(genesis.hashMerkleRoot == uint256S("898ea66248eba5b44db100123c4f09c4e9fe670142268674684752a92461d133"));
        //assert(consensus.hashGenesisBlock == uint256S("ffc49ff57b50825d365871222ad3d623811cc94b5e6a80be2b19f442c24eb5ec"));
        //assert(genesis.hashMerkleRoot == uint256S("461956d5de2787730eb6363622c5758c9647793de63fec2115b1082ac8ec3241"));
		assert(consensus.hashGenesisBlock == uint256S("e5cc89a48d70cd1fb5764dc0b568dbb0071b7ac5a28124a44db0784790cc1636"));
        assert(genesis.hashMerkleRoot == uint256S("4a5edd4f338f3bec6e21cd5145880ca1f8b8df140c55833b1664b4541b54611f"));

        vFixedSeeds.clear();
        vSeeds.clear();

        // guarantees the first 2 characters, when base58 encoded, are "vc"
        base58Prefixes[PUBKEY_ADDRESS] = {0x1E, 0x2B};
        // guarantees the first 2 characters, when base58 encoded, are "vs"
        base58Prefixes[SCRIPT_ADDRESS] = {0x1E, 0x55};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY] = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x6B, 0x99};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8, 0xAC, 0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY] = {0x6A, 0xC2};

        base58BTCPrefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58BTCPrefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58BTCPrefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "vtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "vviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "vivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";
        bech32HRPs[WITNESS_KEY]                  = "tb";
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,
            0,
            0
        };
        // Founders reward script expects a vector of 2-of-3 multisig addresses
        // PrivKey: cVPR1vvU7RU296c8jonmK1DnL8A7htMTRXTpoFWkwBu3fWJBzddo
        // Founders reward script expects an address
        vFoundersRewardAddress = {
            "vasfGCr5uNmv154DAY6C5fZy21AeDmyuKBx",
            "vaaWu99k1Tsftzxp6RLVHyj2HEWKzuKNAb3",
            "vaaXsJAA9b877L3v38nvGbmakqyA7SxvwwQ",
            "vaarfKRkuaviG5N5tw7C3SZq1bg3dCaopw6",
            "vab5FEtXgFgcW64C8ACUjcZWobHwqMbe36y",
            "vabdmLtCsxdWFdtkBFjHKKJsZTTL38M5NZ4",
            "vabqx4cuzNq71GHxtiFKcHyW8t6YLbZ978E",
            "vabveUN98NNAjiaGEcnQgLpfXh217b8eWkb",
            "vac13xRGmHikbFqxEfVMEi1KyFaA7diKUfd",
            "vacWRJy1jGjFWCUyo8bsDL3rEh5hKEJpRVd",
            "vacZ7yGTMEjch4NxYePB1cCErTwMTUSHyhB",
            "vacvPphjryM1eodDqTbAtiGhQnafbtGNL4Z",
            "vad8mQVmt6VBcmJ9wmNHNkhLvM6otq2FMGt",
            "vadEnYbzPNQocxt8ioqimnKvSm5qqv6Ls7x",
            "vadG99GUkg47JXSYpTPkxUormiM6VSrJPVS",
            "vadKNgXTZb1sopBGVJPEecTxsrWx4kAnDZm",
            "vaePj5FyNsegoQTwY3pyi3fgFEopu6CYnfn",
            "vaeiNwxLCtpmHq4tVmLTR9YmVGDfdhJSyyr",
            "vaejPFakG2ZygmrhY6VsmqrBoKXgKbFRSUV",
            "vafHTGvxM2E4yL9QgN6eJD9vvTFeuyMUy1e",
            "vafMTpvZXypNsUp2Stn4BEXp2JRSqgvwMC7",
            "vafkEidPmqw8NYSApsZijtRku7LMy6vNY9s",
            "vafmNWBiBHxjmPG2L4PK7DeZPrqG3h7QFPD",
            "vag8Vw8iYsAMLTmmAtwKvGPmcDxc7qrvQzm",
            "vag9yAynXYt8h6n8KyfSmZApzaH9AAtY2Na",
            "vagTBnPPYZi8ABVXaZTpvnvL3rmWc91gU11",
            "vagTxWLzpPUH15HJ7di8pYqQbyaVnYhRRzA",
            "vaghy3FvjSRo7tQxNfbiGBHfm2oY2NLnXkm",
            "vahAaGEGZniuyj3LfTsvCTMo439z3P667bT",
            "vahLosF5YhYsSZLUVDfN5Yk7WkYnAQ8d8fr",
            "vahfJx5MXUoNvGpy8cFsLKUuj2mSrJedRGN",
            "vahpQZsrsJCXhTo7cnsXkjxcNtU3hX1N35F",
            "vahwBQ9akxHGYCMhCbfqTFMtFA8MyeunMy3",
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams
{
public:

    CRegTestParams()
    {
        strNetworkID = "regtest";
        strCurrencyUnits = "vc";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nMasternodePaymentsStartBlock = 240;
        consensus.nMasternodePaymentsIncreaseBlock = 350;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nSuperblockStartBlock = 0;
        consensus.nSuperblockCycle = 40;
        consensus.nBidPeriod = 10;
        consensus.nBidLimit = 1 * COIN;

        consensus.nSubsidyHalvingInterval = 210;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 1;
        assert(maxUint / UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 1;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nMinerConfirmationWindow = 144; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nBitcoinUTXOHeight = 120;
        consensus.nBitcoinRootEndHeight = 360;
        consensus.fPowNoRetargeting = false;

        consensus.nBlockCountPerDay = 100;
        consensus.nWeekCount1stSeason = 3;
        consensus.nWeekCountOfSeason = 1;
        consensus.nBlockCountOfWeek = consensus.nBlockCountPerDay * 7;
        consensus.nBlockCountOf1stSeason = consensus.nBlockCountOfWeek * consensus.nWeekCount1stSeason;
        consensus.nBlockCountOfSeason = consensus.nBlockCountOfWeek * consensus.nWeekCountOfSeason;

        consensus.nClueMaturity = consensus.nBlockCountOfWeek;
        consensus.nClueChildrenDepth = 12;
        consensus.nClueChildrenWidth = 12;

        consensus.nVibStartHeight = 140;
        consensus.nVibClue = 3;
        consensus.nVibLucky = 3;

        consensus.nTandiaPayPeriod = 10;
        consensus.nTandiaBallotPeriod = 70;
        consensus.nTandiaBallotStart = 105;

        consensus.nFounderPayHeight = consensus.nBlockCountOf1stSeason;
        consensus.nFounderAmount = 12000000 * COIN;
        consensus.nFounderScript = ParseHex("76a9146974d7944e5475c4982a4c0912efb17172b0598788ac");

        strPubkeyVibPreIco = "vag5Xvo2pikduEKL6i5UbKbrESSQNvTqgDL";
        const size_t N = 96, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;

        genesis = CreateGenesisBlock(
                      7052517017282037,
                      //1547165612,
					  //1565596800,
					  1569045600,
                      uint256S("0000000000000000000000000000000000000000000000000000000000000000"),
                      0x207fffff,
                      4,
                      1747482982717963,
                      //ParseHex("05301f3bc8725d28e321b3959ae31572a21c06e9535dd8b0b665950d8949b10d3ee60ed2e2fca3ec7630e20fa5e1d6feabf89d1c185dc6157cb9d0029c0f05f50ac3f439"));
					  //ParseHex("01c238f14861a9b1eaef86a22ac53dadb01ac98e6d8ed18785434b7f916d70d1733a0e41f3ae937c9dcb84c4f60f3e2e019ab90f0fd93f10437ee3d80b6605f7ec67fe76"));
					  ParseHex("049e78409f7abb69c966470023523dfd640a03a71e8396160502d3760b1ac6c3790514620f738af5197c65e88bb2d9f99fa5831fff45fae0a6b240769a9e861aa94fd0d3"));
        
		printf("Searching for regnet genesis block...\n");
        // This will figure out a valid hash and Nonce if you're
        // creating a different genesis block:
        arith_uint256 hashTarget = hashTarget.SetCompact(genesis.nBits);
        printf("hashTarget = %s\n", hashTarget.ToString().c_str());
        arith_uint256 thash;

        while(true)
        {
            crypto_generichash_blake2b_state state;
            std::mutex m_cs;
            bool cancelSolver = false;
            std::string solver = GetArg("-equihashsolver", "default");
            EhInitialiseState(nEquihashN, nEquihashK, state);

            // I = the block header minus nonce and solution.
            CEquihashInput I{genesis};
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << I;

            // H(I||...
            crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

            // H(I||V||...
            crypto_generichash_blake2b_state curr_state;
            curr_state = state;
            crypto_generichash_blake2b_update(&curr_state,
                                        genesis.nNonce.begin(),
                                        genesis.nNonce.size());
            std::function<bool(std::vector<unsigned char>)> validBlock =
                [&hashTarget, &m_cs, &cancelSolver, this]
                    (std::vector<unsigned char> soln) {
                        // Write the solution to the hash and compute the result.
                        // printf("- Checking solution against target\n");
                        genesis.nSolution = soln;

                        if (UintToArith256(genesis.GetPoWHash()) > hashTarget) {
                            return false;
                        }

                        if (!CheckEquihashSolution(&genesis, *this)) {
                            return false;
                        }

                        // Found a solution
                        // Ignore chain updates caused by us
                        std::lock_guard<std::mutex> lock{m_cs};
                        cancelSolver = false;
                        return true;
            };
            std::function<bool(EhSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](EhSolverCancelCheck pos) {
                std::lock_guard<std::mutex> lock{m_cs};
                return cancelSolver;
            };
			
            if (solver == "tromp") {
                // Create solver and initialize it.
                /*
                equi eq(1);
                eq.setstate(&curr_state);

                // Intialization done, start algo driver.
                eq.digit0(0);
                eq.xfull = eq.bfull = eq.hfull = 0;
                eq.showbsizes(0);
                for (u32 r = 1; r < WK; r++) {
                    (r&1) ? eq.digitodd(r, 0) : eq.digiteven(r, 0);
                    eq.xfull = eq.bfull = eq.hfull = 0;
                    eq.showbsizes(r);
                }
                eq.digitK(0);

                // Convert solution indices to byte array (decompress) and pass it to validBlock method.
                bool ready = false;
                for (size_t s = 0; s < eq.nsols; s++) {
                    // printf("\rChecking solution %d", int(s+1));
                    std::vector<eh_index> index_vector(PROOFSIZE);
                    for (size_t i = 0; i < PROOFSIZE; i++) {
                        index_vector[i] = eq.sols[s][i];
                    }
                    std::vector<unsigned char> sol_char = GetMinimalFromIndices(index_vector, DIGITBITS);

                    if (validBlock(sol_char)) {
                        // If we find a POW solution, do not try other solutions
                        // because they become invalid as we created a new block in blockchain.
                        ready = true;
                        break;
                    }
                }
                if (ready) break;*/
                
            } else {
                try {
                    // If we find a valid block, we rebuild
                    bool found = EhOptimisedSolve(nEquihashN, nEquihashK, curr_state, validBlock, cancelled);
                    if (found) {
                        break;
                    }
                } catch (EhSolverCancelledException&) {
                    printf("Equihash solver cancelled\n");
                    std::lock_guard<std::mutex> lock{m_cs};
                    cancelSolver = false;
                }
            }
             
            genesis.nNonce = ArithToUint256(UintToArith256(genesis.nNonce) + 1);
        }

        printf("block.nTime = %u \n", genesis.nTime);
        printf("block.nNonce = %s \n", genesis.nNonce.ToString().c_str());
        printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        printf("block.GetPoWHash = %s\n", genesis.GetPoWHash().ToString().c_str());
        printf("block.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("block.nSolution = %s\n", HexStr(genesis.nSolution.begin(), genesis.nSolution.end()).c_str());//
        
		
		
		
		
		
		
		
		
		
		
		consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 16533;
//        std::cout << "GenesisBlockHash: " << consensus.hashGenesisBlock.GetHex() << std::endl;
        //assert(consensus.hashGenesisBlock == uint256S("61a8f1d40cac7b7b611e4bedf8d821f98c4b1d4dbef895237e1209e50c75f5e2"));
        //assert(genesis.hashMerkleRoot == uint256S("898ea66248eba5b44db100123c4f09c4e9fe670142268674684752a92461d133"));
		//assert(consensus.hashGenesisBlock == uint256S("f9fc4412df0da219e7a0c28ea06ed1e80e0b49439ba156e351c97b108a02bc82"));
        //assert(genesis.hashMerkleRoot == uint256S("461956d5de2787730eb6363622c5758c9647793de63fec2115b1082ac8ec3241"));
		assert(consensus.hashGenesisBlock == uint256S("7ed1eabc3ec2a8c37730f2f2ea794362884af5f974298783a7095caf1e13a9f6"));
        assert(genesis.hashMerkleRoot == uint256S("4a5edd4f338f3bec6e21cd5145880ca1f8b8df140c55833b1664b4541b54611f"));		
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear(); //! Regtest mode doesn't have any DNS seeds.

        // guarantees the first 2 characters, when base58 encoded, are "vc"
        base58Prefixes[PUBKEY_ADDRESS] = {0x1E, 0x2B};
        // guarantees the first 2 characters, when base58 encoded, are "vs"
        base58Prefixes[SCRIPT_ADDRESS] = {0x1E, 0x55};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY] = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x6B, 0x99};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8, 0xAC, 0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY] = {0x6A, 0xC2};

        base58BTCPrefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58BTCPrefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58BTCPrefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "vregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "vviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "vivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
        bech32HRPs[WITNESS_KEY]                  = "bcrt";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,
            0,
            0
        };

        // PrivKey: cVPR1vvU7RU296c8jonmK1DnL8A7htMTRXTpoFWkwBu3fWJBzddo
        // Founders reward script expects an address
        vFoundersRewardAddress = {
            "vasfGCr5uNmv154DAY6C5fZy21AeDmyuKBx",
            "vaaWu99k1Tsftzxp6RLVHyj2HEWKzuKNAb3",
            "vaaXsJAA9b877L3v38nvGbmakqyA7SxvwwQ",
            "vaarfKRkuaviG5N5tw7C3SZq1bg3dCaopw6",
            "vab5FEtXgFgcW64C8ACUjcZWobHwqMbe36y",
            "vabdmLtCsxdWFdtkBFjHKKJsZTTL38M5NZ4",
            "vabqx4cuzNq71GHxtiFKcHyW8t6YLbZ978E",
            "vabveUN98NNAjiaGEcnQgLpfXh217b8eWkb",
            "vac13xRGmHikbFqxEfVMEi1KyFaA7diKUfd",
            "vacWRJy1jGjFWCUyo8bsDL3rEh5hKEJpRVd",
            "vacZ7yGTMEjch4NxYePB1cCErTwMTUSHyhB",
            "vacvPphjryM1eodDqTbAtiGhQnafbtGNL4Z",
            "vad8mQVmt6VBcmJ9wmNHNkhLvM6otq2FMGt",
            "vadEnYbzPNQocxt8ioqimnKvSm5qqv6Ls7x",
            "vadG99GUkg47JXSYpTPkxUormiM6VSrJPVS",
            "vadKNgXTZb1sopBGVJPEecTxsrWx4kAnDZm",
            "vaePj5FyNsegoQTwY3pyi3fgFEopu6CYnfn",
            "vaeiNwxLCtpmHq4tVmLTR9YmVGDfdhJSyyr",
            "vaejPFakG2ZygmrhY6VsmqrBoKXgKbFRSUV",
            "vafHTGvxM2E4yL9QgN6eJD9vvTFeuyMUy1e",
            "vafMTpvZXypNsUp2Stn4BEXp2JRSqgvwMC7",
            "vafkEidPmqw8NYSApsZijtRku7LMy6vNY9s",
            "vafmNWBiBHxjmPG2L4PK7DeZPrqG3h7QFPD",
            "vag8Vw8iYsAMLTmmAtwKvGPmcDxc7qrvQzm",
            "vag9yAynXYt8h6n8KyfSmZApzaH9AAtY2Na",
            "vagTBnPPYZi8ABVXaZTpvnvL3rmWc91gU11",
            "vagTxWLzpPUH15HJ7di8pYqQbyaVnYhRRzA",
            "vaghy3FvjSRo7tQxNfbiGBHfm2oY2NLnXkm",
            "vahAaGEGZniuyj3LfTsvCTMo439z3P667bT",
            "vahLosF5YhYsSZLUVDfN5Yk7WkYnAQ8d8fr",
            "vahfJx5MXUoNvGpy8cFsLKUuj2mSrJedRGN",
            "vahpQZsrsJCXhTo7cnsXkjxcNtU3hX1N35F",
            "vahwBQ9akxHGYCMhCbfqTFMtFA8MyeunMy3",
        };
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)

std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const
{
    assert(nHeight > 0);

    size_t addressChangeInterval = vFoundersRewardAddress.size();
    size_t i = nHeight % addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address for mainnet but regtest

CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const
{
    assert(nHeight > 0);

    CTxDestination destination = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(destination));
    return GetScriptForDestination(destination);
}

CScript CChainParams::GetFoundersRewardScriptAtIndex(int nIndex) const
{
    assert(nIndex >= 0);

    CTxDestination destination = DecodeDestination(GetFoundersRewardAddressAtIndex(nIndex).c_str());
    assert(IsValidDestination(destination));
    return GetScriptForDestination(destination);
}


std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const
{
    i = i % vFoundersRewardAddress.size();
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
