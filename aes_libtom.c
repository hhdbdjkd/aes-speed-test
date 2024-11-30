#include "tomcrypt_private.h"

#ifdef LTC_RIJNDAEL

#ifndef ENCRYPT_ONLY

#define SETUP    rijndael_setup
#define ECB_ENC  rijndael_ecb_encrypt
#define ECB_DEC  rijndael_ecb_decrypt
#define ECB_DONE rijndael_done
#define ECB_TEST rijndael_test
#define ECB_KS   rijndael_keysize

// 描述Rijndael密码算法的结构体及函数映射
const struct ltc_cipher_descriptor rijndael_desc =
{
    "rijndael",
    6,
    16, 32, 16, 10,// 最小/最大密钥大小，块大小，默认轮数
    SETUP, ECB_ENC, ECB_DEC, ECB_TEST, ECB_DONE, ECB_KS,// AES相关操作函数
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#else

#define SETUP    rijndael_enc_setup
#define ECB_ENC  rijndael_enc_ecb_encrypt
#define ECB_KS   rijndael_enc_keysize
#define ECB_DONE rijndael_enc_done

const struct ltc_cipher_descriptor rijndael_enc_desc =
{
    "rijndael",
    6,
    16, 32, 16, 10,
    SETUP, ECB_ENC, NULL, NULL, ECB_DONE, ECB_KS,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif

#define LTC_AES_TAB_C
#include "aes_tab.c"

static ulong32 setup_mix(ulong32 temp)
{
   return (Te4_3[LTC_BYTE(temp, 2)]) ^
          (Te4_2[LTC_BYTE(temp, 1)]) ^
          (Te4_1[LTC_BYTE(temp, 0)]) ^
          (Te4_0[LTC_BYTE(temp, 3)]);
}

#ifndef ENCRYPT_ONLY
#ifdef LTC_SMALL_CODE
static ulong32 setup_mix2(ulong32 temp)
{
   return Td0(255 & Te4[LTC_BYTE(temp, 3)]) ^
          Td1(255 & Te4[LTC_BYTE(temp, 2)]) ^
          Td2(255 & Te4[LTC_BYTE(temp, 1)]) ^
          Td3(255 & Te4[LTC_BYTE(temp, 0)]);
}
#endif
#endif

/* 初始化密钥
 * 
 * 该函数根据提供的密钥、密钥长度和轮数初始化AES密钥调度表。
 * 密钥调度预先计算了每一轮加密和解密的密钥转换，
 * 以加速后续的加解密操作。
 * 
 * 参数：
 * - key：密钥
 * - keylen：密钥长度
 * - num_rounds：轮数
 * - skey：存储密钥调度的结构体
 */
int SETUP(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    int i;
    ulong32 temp, *rk, *K;
#ifndef ENCRYPT_ONLY
    ulong32 *rrk;
#endif
    LTC_ARGCHK(key  != NULL);  // 检查密钥是否为NULL
    LTC_ARGCHK(skey != NULL);  // 检查skey结构是否为NULL
        // 检查密钥长度
    if (keylen != 16 && keylen != 24 && keylen != 32) {
       return CRYPT_INVALID_KEYSIZE;
    }
    // 检查轮数
    if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2)) {
       return CRYPT_INVALID_ROUNDS;
    }
    // 根据密钥长度确定轮数，并初始化密钥调度表
    skey->rijndael.Nr = 10 + ((keylen/8)-2)*2; // 默认轮数

    // 设置正向密钥调度 
    i                 = 0;
    rk                = skey->rijndael.eK;
    LOAD32H(rk[0], key     );
    LOAD32H(rk[1], key +  4);
    LOAD32H(rk[2], key +  8);
    LOAD32H(rk[3], key + 12);

    // 根据密钥长度（16、24、32字节）执行不同的密钥扩展
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
       return CRYPT_ERROR;// 错误：不支持的密钥长度
    }

#ifndef ENCRYPT_ONLY
    // 设置逆向密钥调度 
    rk   = skey->rijndael.dK;
    rrk  = skey->rijndael.eK + (28 + keylen) - 4;


    // 应用逆MixColumn变换到所有轮密钥，除了第一个和最后一个
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
    // 复制最后一轮的密钥
    rrk -= 4;
    rk  += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
#endif 

    return CRYPT_OK;
}

/* 
 * AES加密函数
 * 
 * 参数：
 * - pt：输入的明文（16字节）
 * - ct：输出的密文（16字节）
 * - skey：已调度的密钥
 */
#ifdef LTC_CLEAN_STACK
static int s_rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
#else
int ECB_ENC(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
#endif
{
    ulong32 s0, s1, s2, s3, t0, t1, t2, t3; // 中间值
    const ulong32 *rk;  // 指向轮密钥的指针
    int Nr, r;          // AES轮数和循环计数器

    // 检查输入是否为空
    LTC_ARGCHK(pt != NULL);
    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(skey != NULL);

    Nr = skey->rijndael.Nr;  // 获取轮数

    // 检查轮数是否合法
    if (Nr < 2 || Nr > 16)
        return CRYPT_INVALID_ROUNDS;

    rk = skey->rijndael.eK;  // 将轮密钥初始化为正向加密密钥

    // 将字节数组块映射到加密状态，并添加初始轮密钥：
    // 初始轮密钥通过异或运算直接应用于输入的明文块。
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

#ifdef LTC_CLEAN_STACK
// 该函数首先调用实际的AES加密函数 `s_rijndael_ecb_encrypt`，并在返回前
// 调用 `burn_stack` 函数清理堆栈，以提高安全性？？？？
int ECB_ENC(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
   int err = s_rijndael_ecb_encrypt(pt, ct, skey);
   burn_stack(sizeof(unsigned long)*8 + sizeof(unsigned long*) + sizeof(int)*2);
   return err;
}
#endif

#ifndef ENCRYPT_ONLY

// AES解密函数
#ifdef LTC_CLEAN_STACK
static int s_rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
#else
int ECB_DEC(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
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

    rk = skey->rijndael.dK;

    LOAD32H(s0, ct      ); s0 ^= rk[0];
    LOAD32H(s1, ct  +  4); s1 ^= rk[1];
    LOAD32H(s2, ct  +  8); s2 ^= rk[2];
    LOAD32H(s3, ct  + 12); s3 ^= rk[3];

#ifdef LTC_SMALL_CODE
    // 小代码模式下的解密循环
    for (r = 0; ; r++) {
        rk += 4;
        t0 =
            Td0(LTC_BYTE(s0, 3)) ^
            Td1(LTC_BYTE(s3, 2)) ^
            Td2(LTC_BYTE(s2, 1)) ^
            Td3(LTC_BYTE(s1, 0)) ^
            rk[0];
        t1 =
            Td0(LTC_BYTE(s1, 3)) ^
            Td1(LTC_BYTE(s0, 2)) ^
            Td2(LTC_BYTE(s3, 1)) ^
            Td3(LTC_BYTE(s2, 0)) ^
            rk[1];
        t2 =
            Td0(LTC_BYTE(s2, 3)) ^
            Td1(LTC_BYTE(s1, 2)) ^
            Td2(LTC_BYTE(s0, 1)) ^
            Td3(LTC_BYTE(s3, 0)) ^
            rk[2];
        t3 =
            Td0(LTC_BYTE(s3, 3)) ^
            Td1(LTC_BYTE(s2, 2)) ^
            Td2(LTC_BYTE(s1, 1)) ^
            Td3(LTC_BYTE(s0, 0)) ^
            rk[3];
        if (r == Nr-2) {
           break;
        }
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;

#else

    // 标准解密轮次循环，执行Nr-1轮解密
    r = Nr >> 1;
    for (;;) {

        t0 =
            Td0(LTC_BYTE(s0, 3)) ^
            Td1(LTC_BYTE(s3, 2)) ^
            Td2(LTC_BYTE(s2, 1)) ^
            Td3(LTC_BYTE(s1, 0)) ^
            rk[4];
        t1 =
            Td0(LTC_BYTE(s1, 3)) ^
            Td1(LTC_BYTE(s0, 2)) ^
            Td2(LTC_BYTE(s3, 1)) ^
            Td3(LTC_BYTE(s2, 0)) ^
            rk[5];
        t2 =
            Td0(LTC_BYTE(s2, 3)) ^
            Td1(LTC_BYTE(s1, 2)) ^
            Td2(LTC_BYTE(s0, 1)) ^
            Td3(LTC_BYTE(s3, 0)) ^
            rk[6];
        t3 =
            Td0(LTC_BYTE(s3, 3)) ^
            Td1(LTC_BYTE(s2, 2)) ^
            Td2(LTC_BYTE(s1, 1)) ^
            Td3(LTC_BYTE(s0, 0)) ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }


        s0 =
            Td0(LTC_BYTE(t0, 3)) ^
            Td1(LTC_BYTE(t3, 2)) ^
            Td2(LTC_BYTE(t2, 1)) ^
            Td3(LTC_BYTE(t1, 0)) ^
            rk[0];
        s1 =
            Td0(LTC_BYTE(t1, 3)) ^
            Td1(LTC_BYTE(t0, 2)) ^
            Td2(LTC_BYTE(t3, 1)) ^
            Td3(LTC_BYTE(t2, 0)) ^
            rk[1];
        s2 =
            Td0(LTC_BYTE(t2, 3)) ^
            Td1(LTC_BYTE(t1, 2)) ^
            Td2(LTC_BYTE(t0, 1)) ^
            Td3(LTC_BYTE(t3, 0)) ^
            rk[2];
        s3 =
            Td0(LTC_BYTE(t3, 3)) ^
            Td1(LTC_BYTE(t2, 2)) ^
            Td2(LTC_BYTE(t1, 1)) ^
            Td3(LTC_BYTE(t0, 0)) ^
            rk[3];
    }
#endif
    // 最后一轮解密
    s0 =
        (Td4[LTC_BYTE(t0, 3)] & 0xff000000) ^
        (Td4[LTC_BYTE(t3, 2)] & 0x00ff0000) ^
        (Td4[LTC_BYTE(t2, 1)] & 0x0000ff00) ^
        (Td4[LTC_BYTE(t1, 0)] & 0x000000ff) ^
        rk[0];
    STORE32H(s0, pt);
    s1 =
        (Td4[LTC_BYTE(t1, 3)] & 0xff000000) ^
        (Td4[LTC_BYTE(t0, 2)] & 0x00ff0000) ^
        (Td4[LTC_BYTE(t3, 1)] & 0x0000ff00) ^
        (Td4[LTC_BYTE(t2, 0)] & 0x000000ff) ^
        rk[1];
    STORE32H(s1, pt+4);
    s2 =
        (Td4[LTC_BYTE(t2, 3)] & 0xff000000) ^
        (Td4[LTC_BYTE(t1, 2)] & 0x00ff0000) ^
        (Td4[LTC_BYTE(t0, 1)] & 0x0000ff00) ^
        (Td4[LTC_BYTE(t3, 0)] & 0x000000ff) ^
        rk[2];
    STORE32H(s2, pt+8);
    s3 =
        (Td4[LTC_BYTE(t3, 3)] & 0xff000000) ^
        (Td4[LTC_BYTE(t2, 2)] & 0x00ff0000) ^
        (Td4[LTC_BYTE(t1, 1)] & 0x0000ff00) ^
        (Td4[LTC_BYTE(t0, 0)] & 0x000000ff) ^
        rk[3];
    STORE32H(s3, pt+12);

    return CRYPT_OK;
}


#ifdef LTC_CLEAN_STACK
int ECB_DEC(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
   int err = s_rijndael_ecb_decrypt(ct, pt, skey);
   burn_stack(sizeof(unsigned long)*8 + sizeof(unsigned long*) + sizeof(int)*2);
   return err;
}
#endif


// 执行AES块密码的自我测试，使用一组已知的测试来验证AES加密和解密的正确性
int ECB_TEST(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
 int err;
 static const struct {
     int keylen;
     unsigned char key[32], pt[16], ct[16];
 } tests[] = {
    { 16,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }
    }, {
      24,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }
    }, {
      32,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }
    }
 };

  symmetric_key key;
  unsigned char tmp[2][16];
  int i, y;

  for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
    zeromem(&key, sizeof(key));  
    // 设置密钥并执行加密操作
    if ((err = rijndael_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) {
       return err;  // 密钥设置失败，返回错误
    }

    // 执行加密和解密，比较结果
    rijndael_ecb_encrypt(tests[i].pt, tmp[0], &key);
    rijndael_ecb_decrypt(tmp[0], tmp[1], &key);

    // 比较加密后的密文和预期密文，解密后的明文和原始明文
    if (compare_testvector(tmp[0], 16, tests[i].ct, 16, "AES Encrypt", i) ||
          compare_testvector(tmp[1], 16, tests[i].pt, 16, "AES Decrypt", i)) {
        return CRYPT_FAIL_TESTVECTOR;  // 不匹配，返回失败
    }

    for (y = 0; y < 16; y++) tmp[0][y] = 0;  
    for (y = 0; y < 1000; y++) rijndael_ecb_encrypt(tmp[0], tmp[0], &key);  // 1000次加密测试
    for (y = 0; y < 1000; y++) rijndael_ecb_decrypt(tmp[0], tmp[0], &key);  // 1000次解密测试
    for (y = 0; y < 16; y++) if (tmp[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;  
  }
  return CRYPT_OK;  
 #endif
}

#endif 

// 结束AES上下文
void ECB_DONE(symmetric_key *skey)
{
  LTC_UNUSED_PARAM(skey);
}


//该函数用于检查并调整输入的密钥大小，以确保符合AES的标准密钥长度（16、24或32字节）。
int ECB_KS(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);

   if (*keysize < 16) {
      return CRYPT_INVALID_KEYSIZE;
   }
   if (*keysize < 24) {
      *keysize = 16;
      return CRYPT_OK;
   }
   if (*keysize < 32) {
      *keysize = 24;
      return CRYPT_OK;
   }
   *keysize = 32;
   return CRYPT_OK;
}

#endif

