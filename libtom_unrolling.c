
/* 
 * AES加密函数
 * 
 * 参数：
 * - pt：输入的明文（16字节）
 * - ct：输出的密文（16字节）
 * - skey：已调度的密钥
 */

int aes_unrolling(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
#endif
{
    ulong32 s0, s1, s2, s3, t0, t1, t2, t3;
    const ulong32 *rk;  
    int Nr, r;         

    LTC_ARGCHK(pt != NULL);
    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(skey != NULL);

    Nr = skey->rijndael.Nr; 


    if (Nr < 2 || Nr > 16)
        return CRYPT_INVALID_ROUNDS;

    rk = skey->rijndael.eK;  

    LOAD32H(s0, pt      ); s0 ^= rk[0];
    LOAD32H(s1, pt  +  4); s1 ^= rk[1];
    LOAD32H(s2, pt  +  8); s2 ^= rk[2];
    LOAD32H(s3, pt  + 12); s3 ^= rk[3];

#ifdef LTC_SMALL_CODE// 小代码模式，会选择一种更节省空间但会降低性能的实现方式。

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


    // 第一轮展开
    t0 = Te0(LTC_BYTE(s0, 3)) ^ Te1(LTC_BYTE(s1, 2)) ^ Te2(LTC_BYTE(s2, 1)) ^ Te3(LTC_BYTE(s3, 0)) ^ rk[4];
    t1 = Te0(LTC_BYTE(s1, 3)) ^ Te1(LTC_BYTE(s2, 2)) ^ Te2(LTC_BYTE(s3, 1)) ^ Te3(LTC_BYTE(s0, 0)) ^ rk[5];
    t2 = Te0(LTC_BYTE(s2, 3)) ^ Te1(LTC_BYTE(s3, 2)) ^ Te2(LTC_BYTE(s0, 1)) ^ Te3(LTC_BYTE(s1, 0)) ^ rk[6];
    t3 = Te0(LTC_BYTE(s3, 3)) ^ Te1(LTC_BYTE(s0, 2)) ^ Te2(LTC_BYTE(s1, 1)) ^ Te3(LTC_BYTE(s2, 0)) ^ rk[7];

    // 第二轮展开
    s0 = Te0(LTC_BYTE(t0, 3)) ^ Te1(LTC_BYTE(t1, 2)) ^ Te2(LTC_BYTE(t2, 1)) ^ Te3(LTC_BYTE(t3, 0)) ^ rk[8];
    s1 = Te0(LTC_BYTE(t1, 3)) ^ Te1(LTC_BYTE(t2, 2)) ^ Te2(LTC_BYTE(t3, 1)) ^ Te3(LTC_BYTE(t0, 0)) ^ rk[9];
    s2 = Te0(LTC_BYTE(t2, 3)) ^ Te1(LTC_BYTE(t3, 2)) ^ Te2(LTC_BYTE(t0, 1)) ^ Te3(LTC_BYTE(t1, 0)) ^ rk[10];
    s3 = Te0(LTC_BYTE(t3, 3)) ^ Te1(LTC_BYTE(t0, 2)) ^ Te2(LTC_BYTE(t1, 1)) ^ Te3(LTC_BYTE(t2, 0)) ^ rk[11];

    // 第三轮展开
    t0 = Te0(LTC_BYTE(s0, 3)) ^ Te1(LTC_BYTE(s1, 2)) ^ Te2(LTC_BYTE(s2, 1)) ^ Te3(LTC_BYTE(s3, 0)) ^ rk[12];
    t1 = Te0(LTC_BYTE(s1, 3)) ^ Te1(LTC_BYTE(s2, 2)) ^ Te2(LTC_BYTE(s3, 1)) ^ Te3(LTC_BYTE(s0, 0)) ^ rk[13];
    t2 = Te0(LTC_BYTE(s2, 3)) ^ Te1(LTC_BYTE(s3, 2)) ^ Te2(LTC_BYTE(s0, 1)) ^ Te3(LTC_BYTE(s1, 0)) ^ rk[14];
    t3 = Te0(LTC_BYTE(s3, 3)) ^ Te1(LTC_BYTE(s0, 2)) ^ Te2(LTC_BYTE(s1, 1)) ^ Te3(LTC_BYTE(s2, 0)) ^ rk[15];

    // 第四轮展开
    s0 = Te0(LTC_BYTE(t0, 3)) ^ Te1(LTC_BYTE(t1, 2)) ^ Te2(LTC_BYTE(t2, 1)) ^ Te3(LTC_BYTE(t3, 0)) ^ rk[16];
    s1 = Te0(LTC_BYTE(t1, 3)) ^ Te1(LTC_BYTE(t2, 2)) ^ Te2(LTC_BYTE(t3, 1)) ^ Te3(LTC_BYTE(t0, 0)) ^ rk[17];
    s2 = Te0(LTC_BYTE(t2, 3)) ^ Te1(LTC_BYTE(t3, 2)) ^ Te2(LTC_BYTE(t0, 1)) ^ Te3(LTC_BYTE(t1, 0)) ^ rk[18];
    s3 = Te0(LTC_BYTE(t3, 3)) ^ Te1(LTC_BYTE(t0, 2)) ^ Te2(LTC_BYTE(t1, 1)) ^ Te3(LTC_BYTE(t2, 0)) ^ rk[19];
    // 第五轮展开
    t0 = Te0(LTC_BYTE(s0, 3)) ^ Te1(LTC_BYTE(s1, 2)) ^ Te2(LTC_BYTE(s2, 1)) ^ Te3(LTC_BYTE(s3, 0)) ^ rk[20];
    t1 = Te0(LTC_BYTE(s1, 3)) ^ Te1(LTC_BYTE(s2, 2)) ^ Te2(LTC_BYTE(s3, 1)) ^ Te3(LTC_BYTE(s0, 0)) ^ rk[21];
    t2 = Te0(LTC_BYTE(s2, 3)) ^ Te1(LTC_BYTE(s3, 2)) ^ Te2(LTC_BYTE(s0, 1)) ^ Te3(LTC_BYTE(s1, 0)) ^ rk[22];
    t3 = Te0(LTC_BYTE(s3, 3)) ^ Te1(LTC_BYTE(s0, 2)) ^ Te2(LTC_BYTE(s1, 1)) ^ Te3(LTC_BYTE(s2, 0)) ^ rk[23];

    // 第六轮展开
    s0 = Te0(LTC_BYTE(t0, 3)) ^ Te1(LTC_BYTE(t1, 2)) ^ Te2(LTC_BYTE(t2, 1)) ^ Te3(LTC_BYTE(t3, 0)) ^ rk[24];
    s1 = Te0(LTC_BYTE(t1, 3)) ^ Te1(LTC_BYTE(t2, 2)) ^ Te2(LTC_BYTE(t3, 1)) ^ Te3(LTC_BYTE(t0, 0)) ^ rk[25];
    s2 = Te0(LTC_BYTE(t2, 3)) ^ Te1(LTC_BYTE(t3, 2)) ^ Te2(LTC_BYTE(t0, 1)) ^ Te3(LTC_BYTE(t1, 0)) ^ rk[26];
    s3 = Te0(LTC_BYTE(t3, 3)) ^ Te1(LTC_BYTE(t0, 2)) ^ Te2(LTC_BYTE(t1, 1)) ^ Te3(LTC_BYTE(t2, 0)) ^ rk[27];

    // 第七轮展开
    t0 = Te0(LTC_BYTE(s0, 3)) ^ Te1(LTC_BYTE(s1, 2)) ^ Te2(LTC_BYTE(s2, 1)) ^ Te3(LTC_BYTE(s3, 0)) ^ rk[28];
    t1 = Te0(LTC_BYTE(s1, 3)) ^ Te1(LTC_BYTE(s2, 2)) ^ Te2(LTC_BYTE(s3, 1)) ^ Te3(LTC_BYTE(s0, 0)) ^ rk[29];
    t2 = Te0(LTC_BYTE(s2, 3)) ^ Te1(LTC_BYTE(s3, 2)) ^ Te2(LTC_BYTE(s0, 1)) ^ Te3(LTC_BYTE(s1, 0)) ^ rk[30];
    t3 = Te0(LTC_BYTE(s3, 3)) ^ Te1(LTC_BYTE(s0, 2)) ^ Te2(LTC_BYTE(s1, 1)) ^ Te3(LTC_BYTE(s2, 0)) ^ rk[31];

    // 第八轮展开
    s0 = Te0(LTC_BYTE(t0, 3)) ^ Te1(LTC_BYTE(t1, 2)) ^ Te2(LTC_BYTE(t2, 1)) ^ Te3(LTC_BYTE(t3, 0)) ^ rk[32];
    s1 = Te0(LTC_BYTE(t1, 3)) ^ Te1(LTC_BYTE(t2, 2)) ^ Te2(LTC_BYTE(t3, 1)) ^ Te3(LTC_BYTE(t0, 0)) ^ rk[33];
    s2 = Te0(LTC_BYTE(t2, 3)) ^ Te1(LTC_BYTE(t3, 2)) ^ Te2(LTC_BYTE(t0, 1)) ^ Te3(LTC_BYTE(t1, 0)) ^ rk[34];
    s3 = Te0(LTC_BYTE(t3, 3)) ^ Te1(LTC_BYTE(t0, 2)) ^ Te2(LTC_BYTE(t1, 1)) ^ Te3(LTC_BYTE(t2, 0)) ^ rk[35];

    // 第九轮展开
    t0 = Te0(LTC_BYTE(s0, 3)) ^ Te1(LTC_BYTE(s1, 2)) ^ Te2(LTC_BYTE(s2, 1)) ^ Te3(LTC_BYTE(s3, 0)) ^ rk[36];
    t1 = Te0(LTC_BYTE(s1, 3)) ^ Te1(LTC_BYTE(s2, 2)) ^ Te2(LTC_BYTE(s3, 1)) ^ Te3(LTC_BYTE(s0, 0)) ^ rk[37];
    t2 = Te0(LTC_BYTE(s2, 3)) ^ Te1(LTC_BYTE(s3, 2)) ^ Te2(LTC_BYTE(s0, 1)) ^ Te3(LTC_BYTE(s1, 0)) ^ rk[38];
    t3 = Te0(LTC_BYTE(s3, 3)) ^ Te1(LTC_BYTE(s0, 2)) ^ Te2(LTC_BYTE(s1, 1)) ^ Te3(LTC_BYTE(s2, 0)) ^ rk[39];
    rk += 40;
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




