// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "uint256.h"
#include "serialize.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>

#include "sph_shabal.h"


#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_shabal256_context z_shabal;

#define fillz() do { \
sph_shabal256_init(&z_shabal); \
} while (0) 

#define ZSHABAL (memcpy(&ctx_shabal, &z_shabal, sizeof(z_shabal)))

template<typename T1>
inline uint256 AxiomHash(const T1 pbegin, const T1 pend)
{
    // Axiom Proof of Work Hash
    // based on RandMemoHash https://bitslog.files.wordpress.com/2013/12/memohash-v0-3.pdf
   /* RandMemoHash(s, R, N)
	(1) Set M[0] := s
	(2) For i := 1 to N − 1 do set M[i] := H(M[i − 1])
	(3) For r := 1 to R do
	    (a) For b := 0 to N − 1 do
	        (i) p := (b − 1 + N) mod N
	        (ii) q :=AsInteger(M[p]) mod (N − 1)
	        (iii) j := (b + q) mod N
	        (iv) M[b] :=H(M[p] || M[j])
*/
    int R = 2;
    int N = 65536;

    std::vector<uint256> M(N);
    sph_shabal256_context ctx_shabal;
    static unsigned char pblank[1];
    uint256 hash1;
    sph_shabal256_init(&ctx_shabal);
    sph_shabal256 (&ctx_shabal, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_shabal256_close(&ctx_shabal, static_cast<void*>(&hash1));
    M[0] = hash1;

    for(int i = 1; i < N; i++)
    {
        //HashShabal((unsigned char*)&M[i - 1], sizeof(M[i - 1]), (unsigned char*)&M[i]);
	sph_shabal256_init(&ctx_shabal);
        sph_shabal256 (&ctx_shabal, (unsigned char*)&M[i - 1], sizeof(M[i - 1]));
        sph_shabal256_close(&ctx_shabal, static_cast<void*>((unsigned char*)&M[i]));
    }

    for(int r = 1; r < R; r ++)
    {
	for(int b = 0; b < N; b++)
	{	    
	    int p = (b - 1 + N) % N;
	    int q = M[p].GetInt() % (N - 1);
	    int j = (b + q) % N;
	    std::vector<uint256> pj(2);
	    
	    pj[0] = M[p];
	    pj[1] = M[j];
	    //HashShabal((unsigned char*)&pj[0], 2 * sizeof(pj[0]), (unsigned char*)&M[b]);
	    sph_shabal256_init(&ctx_shabal);
            sph_shabal256 (&ctx_shabal, (unsigned char*)&pj[0], 2 * sizeof(pj[0]));
            sph_shabal256_close(&ctx_shabal, static_cast<void*>((unsigned char*)&M[b]));
	}
    }

    return M[N - 1];
}

template<typename T1>
inline uint256 HashShabal(const T1 pbegin, const T1 pend)
{    
    sph_shabal256_context ctx_shabal;
    static unsigned char pblank[1];
    uint256 hash[1];
    sph_shabal256_init(&ctx_shabal);
    // ZSHABAL;
    sph_shabal256 (&ctx_shabal, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_shabal256_close(&ctx_shabal, static_cast<void*>(&hash[0]));

    return hash[0];
}


template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

class CHashWriter
{
private:
    SHA256_CTX ctx;

public:
    int nType;
    int nVersion;

    void Init() {
        SHA256_Init(&ctx);
    }

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    CHashWriter& write(const char *pch, size_t size) {
        SHA256_Update(&ctx, pch, size);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 hash1;
        SHA256_Final((unsigned char*)&hash1, &ctx);
        uint256 hash2;
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
        return hash2;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};


template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

typedef struct
{
    SHA512_CTX ctxInner;
    SHA512_CTX ctxOuter;
} HMAC_SHA512_CTX;

int HMAC_SHA512_Init(HMAC_SHA512_CTX *pctx, const void *pkey, size_t len);
int HMAC_SHA512_Update(HMAC_SHA512_CTX *pctx, const void *pdata, size_t len);
int HMAC_SHA512_Final(unsigned char *pmd, HMAC_SHA512_CTX *pctx);

#endif
