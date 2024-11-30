

int aes_detect(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
#endif
{
    ulong32 s0, s1, s2, s3, t0, t1, t2, t3;
    const ulong32 *rk;  
    int Nr, r;          

    // 检查输入是否为空
    //LTC_ARGCHK(pt != NULL);
    //LTC_ARGCHK(ct != NULL);
    //LTC_ARGCHK(skey != NULL);

    Nr = skey->rijndael.Nr;  

    // 检查轮数是否合法
    //if (Nr < 2 || Nr > 16)
    //    return CRYPT_INVALID_ROUNDS;

    rk = skey->rijndael.eK;  


    LOAD32H(s0, pt      ); s0 ^= rk[0];
    LOAD32H(s1, pt  +  4); s1 ^= rk[1];
    LOAD32H(s2, pt  +  8); s2 ^= rk[2];
    LOAD32H(s3, pt  + 12); s3 ^= rk[3];

#ifdef LTC_SMALL_CODE

    for (r = 0; ; r++) {
        rk += 4;
        t0 =
            Te0(LTC_BYTE(s0, 3)) ^
            Te1(LTC_BYTE(s1, 2)) ^
            Te2(LTC_BYTE(s2, 1)) ^
            Te3(LTC_BYTE(s3, 0)) ^
            rk[0];
        t1 =
            Te0(LTC_BYTE(s1, 3)) ^
            Te1(LTC_BYTE(s2, 2)) ^
            Te2(LTC_BYTE(s3, 1)) ^
            Te3(LTC_BYTE(s0, 0)) ^
            rk[1];
        t2 =
            Te0(LTC_BYTE(s2, 3)) ^
            Te1(LTC_BYTE(s3, 2)) ^
            Te2(LTC_BYTE(s0, 1)) ^
            Te3(LTC_BYTE(s1, 0)) ^
            rk[2];
        t3 =
            Te0(LTC_BYTE(s3, 3)) ^
            Te1(LTC_BYTE(s0, 2)) ^
            Te2(LTC_BYTE(s1, 1)) ^
            Te3(LTC_BYTE(s2, 0)) ^
            rk[3];
        if (r == Nr-2) {
           break;
        }
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;

#else//使用完整的循环结构，执行Nr - 1轮的加密


    r = Nr >> 1;
    for (;;) {
        // 当前状态与轮密钥进行运算，并生成临时状态
        t0 =
            Te0(LTC_BYTE(s0, 3)) ^
            Te1(LTC_BYTE(s1, 2)) ^
            Te2(LTC_BYTE(s2, 1)) ^
            Te3(LTC_BYTE(s3, 0)) ^
            rk[4];
        t1 =
            Te0(LTC_BYTE(s1, 3)) ^
            Te1(LTC_BYTE(s2, 2)) ^
            Te2(LTC_BYTE(s3, 1)) ^
            Te3(LTC_BYTE(s0, 0)) ^
            rk[5];
        t2 =
            Te0(LTC_BYTE(s2, 3)) ^
            Te1(LTC_BYTE(s3, 2)) ^
            Te2(LTC_BYTE(s0, 1)) ^
            Te3(LTC_BYTE(s1, 0)) ^
            rk[6];
        t3 =
            Te0(LTC_BYTE(s3, 3)) ^
            Te1(LTC_BYTE(s0, 2)) ^
            Te2(LTC_BYTE(s1, 1)) ^
            Te3(LTC_BYTE(s2, 0)) ^
            rk[7];

        rk += 8;  // 每次轮密钥向后移动8个字节
        if (--r == 0) {  // 达到轮数，退出循环
            break;
        }

        // 用临时状态生成下一个状态值
        s0 =
            Te0(LTC_BYTE(t0, 3)) ^
            Te1(LTC_BYTE(t1, 2)) ^
            Te2(LTC_BYTE(t2, 1)) ^
            Te3(LTC_BYTE(t3, 0)) ^
            rk[0];
        s1 =
            Te0(LTC_BYTE(t1, 3)) ^
            Te1(LTC_BYTE(t2, 2)) ^
            Te2(LTC_BYTE(t3, 1)) ^
            Te3(LTC_BYTE(t0, 0)) ^
            rk[1];
        s2 =
            Te0(LTC_BYTE(t2, 3)) ^
            Te1(LTC_BYTE(t3, 2)) ^
            Te2(LTC_BYTE(t0, 1)) ^
            Te3(LTC_BYTE(t1, 0)) ^
            rk[2];
        s3 =
            Te0(LTC_BYTE(t3, 3)) ^
            Te1(LTC_BYTE(t0, 2)) ^
            Te2(LTC_BYTE(t1, 1)) ^
            Te3(LTC_BYTE(t2, 0)) ^
            rk[3];
    }

#endif

    // 最后一轮加密，并将加密状态存储到输出字节数组
    s0 =
        (Te4_3[LTC_BYTE(t0, 3)]) ^
        (Te4_2[LTC_BYTE(t1, 2)]) ^
        (Te4_1[LTC_BYTE(t2, 1)]) ^
        (Te4_0[LTC_BYTE(t3, 0)]) ^
        rk[0];
    STORE32H(s0, ct);
    s1 =
        (Te4_3[LTC_BYTE(t1, 3)]) ^
        (Te4_2[LTC_BYTE(t2, 2)]) ^
        (Te4_1[LTC_BYTE(t3, 1)]) ^
        (Te4_0[LTC_BYTE(t0, 0)]) ^
        rk[1];
    STORE32H(s1, ct+4);
    s2 =
        (Te4_3[LTC_BYTE(t2, 3)]) ^
        (Te4_2[LTC_BYTE(t3, 2)]) ^
        (Te4_1[LTC_BYTE(t0, 1)]) ^
        (Te4_0[LTC_BYTE(t1, 0)]) ^
        rk[2];
    STORE32H(s2, ct+8);
    s3 =
        (Te4_3[LTC_BYTE(t3, 3)]) ^
        (Te4_2[LTC_BYTE(t0, 2)]) ^
        (Te4_1[LTC_BYTE(t1, 1)]) ^
        (Te4_0[LTC_BYTE(t2, 0)]) ^
        rk[3];
    STORE32H(s3, ct+12);

    return CRYPT_OK;
}


