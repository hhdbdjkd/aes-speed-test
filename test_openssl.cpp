#include "speedtest.h"

#include <assert.h>

#include "deprecated.h"

#include <openssl/aes.h>
#include "aes_local.h"
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#define BLOCK_SIZE 16

void AES_ecb_encrypt(const unsigned char* in, unsigned char* out,
    const AES_KEY* key, const int enc)
{

    assert(in && out && key);
    assert((AES_ENCRYPT == enc) || (AES_DECRYPT == enc));

    if (AES_ENCRYPT == enc)
        AES_encrypt(in, out, key);
    else
        AES_decrypt(in, out, key);
}

bool test_openssl(const unsigned char* data, double av1, double sig1) {
    uint64_t cl = 0xffffffffffffffff;
    uint64_t loops_good = 0;
    long double av = 0;
    long double sig = 0;
    unsigned char key[17] = "0123456789abcdef"; // 128 位密钥
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];

    // 初始化 AES_KEY 结构
    AES_KEY encryptKey, decryptKey;
    AES_set_encrypt_key(key, 128, &encryptKey); // 设置加密密钥

    // 加密

    for (size_t i = 0; i < loops; i++) {
        uint64_t cy = __rdtsc();
        for (size_t j = 0; j < 20; j++) {
            for (size_t k = 0; k < 1024; k += BLOCK_SIZE) {
                AES_ecb_encrypt(&data[k], ciphertext, &encryptKey, AES_ENCRYPT);
            }
        }
        cy = __rdtsc() - cy;
        if (cy > (av1 - sig1) && cy < (av1 + sig1)) {
            av += cy;
            sig += cy * cy;
            loops_good++;
            cl = (cl < cy ? cl : cy);
        }
    }
    if (loops_good > 0.9 * loops) {
        av /= loops_good;
        sig = sqrt((sig - av * av * loops_good) / loops_good);
        if (sig > 0.1 * av) {
            return 0;
        }
    }
    else {
        return 0;
    }
    uint64_t t0 = __rdtsc();
    t0 = __rdtsc() - t0;
    double v = (double)(cl - t0) / (20 * len);
    sig /= av;
    av = (av - t0) / (20 * len);
    std::cout << "openssl:  " << v-1 << "   " << av-1 << "   " << sig * 100 << "%" << std::endl;
    return 1;
}

void speed_openssl(const unsigned char* data) {
    while (1) {
        uint64_t av = 0;
        uint64_t sig = 0;
        unsigned char key[17] = "0123456789abcdef"; // 128 位密钥
        unsigned char ciphertext[16];
        unsigned char decryptedtext[16];

        // 初始化 AES_KEY 结构
        AES_KEY encryptKey, decryptKey;
        AES_set_encrypt_key(key, 128, &encryptKey); // 设置加密密钥
        AES_set_decrypt_key(key, 128, &decryptKey); // 设置解密密钥

        // 加密
        
        for (size_t i = 0; i < loops; i++) {
            uint64_t cy = __rdtsc();
            for (size_t j = 0; j < 20; j++) {
                for (size_t k = 0; k < 1024; k += BLOCK_SIZE) {
                    AES_ecb_encrypt(&data[k], ciphertext, &encryptKey, AES_ENCRYPT);
                }
            }
            cy = __rdtsc() - cy;
            av += cy;
            sig += cy * cy;
        }
        sig = sqrtl((sig - av * av / loops) / loops);
        av /= loops;
        sig = (sig < 0.05 * av ? 0.05 * av : sig);
        if (test_openssl(data, av, sig)) {
            break;
       }
    }
}


