#include <stdio.h>
#include <tchar.h>
#include <tomcrypt.h>
#include <math.h>
#include "speedtest.h"
#define BLOCK_SIZE 16

using namespace std;

bool test_unrolling(char* data, double av1, double sig1) {
    uint64_t cl = 0xffffffffffffffff;
    uint64_t loops_good = 0;
    long double av = 0;
    long double sig = 0;

    symmetric_key key;
    unsigned char tmp[16];
    int keylen = 16;
    unsigned char inkey[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    zeromem(&key, sizeof(key));
    rijndael_setup(inkey, keylen, 0, &key);

    // º”√‹

    for (size_t i = 0; i < loops; i++) {
        uint64_t cy = __rdtsc();
        for (size_t j = 0; j < 20; j++) {
            for (size_t k = 0; k < 1024; k += BLOCK_SIZE) {
                aes_unrolling((const unsigned char*)&data[k], tmp, &key);
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
    std::cout << "unrolling:" << v << "   " << av << "   " << sig * 100 << "%" << std::endl;
    return 1;
}

void speed_unrolling(char* data) {
    while (1) {
        uint64_t av = 0;
        uint64_t sig = 0;

        symmetric_key key;
        unsigned char tmp[16];
        int keylen = 16;
        unsigned char inkey[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        zeromem(&key, sizeof(key));
        rijndael_setup(inkey, keylen, 0, &key);


        // º”√‹

        for (size_t i = 0; i < loops; i++) {
            uint64_t cy = __rdtsc();
            for (size_t j = 0; j < 20; j++) {
                for (size_t k = 0; k < 1024; k += BLOCK_SIZE) {
                    aes_unrolling((const unsigned char*)&data[k], tmp, &key);
                }
            }
            cy = __rdtsc() - cy;
            av += cy;
            sig += cy * cy;
        }
        sig = sqrtl((sig - av * av / loops) / loops);
        av /= loops;
        sig = (sig < 0.05 * av ? 0.05 * av : sig);
        if (test_unrolling(data, av, sig)) {
            break;
        }
    }
}

