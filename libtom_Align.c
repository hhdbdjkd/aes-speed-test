
/************** 对齐函数 ****************/
#define ALIGN(buf, n) ((void*)((ltc_uintptr)&((unsigned char*)(buf))[n - 1] & (~(CONSTPTR(n) - CONSTPTR(1)))))

int SETUP(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    int i;
    ulong32 temp, *rk, *K;
#ifndef ENCRYPT_ONLY
    ulong32 *rrk;
#endif
    LTC_ARGCHK(key  != NULL);  
    LTC_ARGCHK(skey != NULL);  
    if (keylen != 16 && keylen != 24 && keylen != 32) {
       return CRYPT_INVALID_KEYSIZE;
    }
    if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2)) {
       return CRYPT_INVALID_ROUNDS;
    }
    skey->rijndael.Nr = 10 + ((keylen/8)-2)*2; 

    /********************** 对齐缓冲区 **********************/
    K = ALIGN(skey->rijndael.K, 16); 
    skey->rijndael.eK = K;
    K += 60;
    skey->rijndael.dK = K;
    /*******************************************************/

    i                 = 0;
    rk                = skey->rijndael.eK;
    LOAD32H(rk[0], key     );
    LOAD32H(rk[1], key +  4);
    LOAD32H(rk[2], key +  8);
    LOAD32H(rk[3], key + 12);

    if (keylen == 16) {
        for (;;) {
            temp  = rk[3];
            rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
               break;
            }
            rk += 4;
        }
    } else if (keylen == 24) {
        LOAD32H(rk[4], key + 16);
        LOAD32H(rk[5], key + 20);
        for (;;) {
        #ifdef _MSC_VER
            temp = skey->rijndael.eK[rk - skey->rijndael.eK + 5];
        #else
            temp = rk[5];
        #endif
            rk[ 6] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                break;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    } else if (keylen == 32) {
        LOAD32H(rk[4], key + 16);
        LOAD32H(rk[5], key + 20);
        LOAD32H(rk[6], key + 24);
        LOAD32H(rk[7], key + 28);
        for (;;) {
        #ifdef _MSC_VER
            temp = skey->rijndael.eK[rk - skey->rijndael.eK + 7];
        #else
            temp = rk[7];
        #endif
            rk[ 8] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                break;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^ setup_mix(RORc(temp, 8));
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];
            rk += 8;
        }
    } else {
       return CRYPT_ERROR;
    }

#ifndef ENCRYPT_ONLY
    rk   = skey->rijndael.dK;
    rrk  = skey->rijndael.eK + (28 + keylen) - 4;



    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
    rk -= 3; rrk -= 3;

    for (i = 1; i < skey->rijndael.Nr; i++) {
        rrk -= 4;
        rk  += 4;
    #ifdef LTC_SMALL_CODE
        temp = rrk[0];
        rk[0] = setup_mix2(temp);
        temp = rrk[1];
        rk[1] = setup_mix2(temp);
        temp = rrk[2];
        rk[2] = setup_mix2(temp);
        temp = rrk[3];
        rk[3] = setup_mix2(temp);
     #else
        temp = rrk[0];
        rk[0] =
            Tks0[LTC_BYTE(temp, 3)] ^
            Tks1[LTC_BYTE(temp, 2)] ^
            Tks2[LTC_BYTE(temp, 1)] ^
            Tks3[LTC_BYTE(temp, 0)];
        temp = rrk[1];
        rk[1] =
            Tks0[LTC_BYTE(temp, 3)] ^
            Tks1[LTC_BYTE(temp, 2)] ^
            Tks2[LTC_BYTE(temp, 1)] ^
            Tks3[LTC_BYTE(temp, 0)];
        temp = rrk[2];
        rk[2] =
            Tks0[LTC_BYTE(temp, 3)] ^
            Tks1[LTC_BYTE(temp, 2)] ^
            Tks2[LTC_BYTE(temp, 1)] ^
            Tks3[LTC_BYTE(temp, 0)];
        temp = rrk[3];
        rk[3] =
            Tks0[LTC_BYTE(temp, 3)] ^
            Tks1[LTC_BYTE(temp, 2)] ^
            Tks2[LTC_BYTE(temp, 1)] ^
            Tks3[LTC_BYTE(temp, 0)];
      #endif

    }
    rrk -= 4;
    rk  += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
#endif 

    return CRYPT_OK;
}
