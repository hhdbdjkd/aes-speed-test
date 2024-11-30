#include "speedtest.h"
#include "present.h"


#define BLOCK_SIZE 8  // 64-bit block size

bool test_present(const std::vector<uint8_t>& data, double av1, double sig1) {
    uint64_t cl = 0xffffffffffffffff;
    uint64_t loops_good = 0;
    long double av = 0;
    long double sig = 0;
    // 定义主密钥和轮密钥
    uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    uint8_t roundKeys[(PRESENT_ROUNDS + 1) * 8] = { 0 }; // 32 * 8 = 256 字节
    present_64_128_key_schedule(key, roundKeys);

    for (size_t i = 0; i < loops; i++) {
        std::vector<uint8_t> buffer(data);
        uint64_t cy = __rdtsc();
        for (size_t j = 0; j < 20; j++) {
            for (size_t k = 0; k < buffer.size(); k += BLOCK_SIZE) {
                present_encrypt(&buffer[k], roundKeys);
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
    std::cout << "present:   " << v << "   " << av << "   " << sig * 100 << "%" << std::endl;
    return 1;
}

void speed_present(const std::vector<uint8_t>& data) {
    while (1) {
        uint64_t av = 0;
        uint64_t sig = 0;
        // 定义主密钥和轮密钥
        uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
        uint8_t roundKeys[(PRESENT_ROUNDS + 1) * 8] = { 0 }; // 32 * 8 = 256 字节
        present_64_128_key_schedule(key, roundKeys);

        for (size_t i = 0; i < loops; i++) {
            std::vector<uint8_t> buffer(data);
            uint64_t cy = __rdtsc();
            for (size_t j = 0; j < 20; j++) {
                for (size_t k = 0; k < buffer.size(); k += BLOCK_SIZE) {
                    present_encrypt(&buffer[k], roundKeys);
                }
            }
            cy = __rdtsc() - cy;
            av += cy;
            sig += cy * cy;
        }
        sig = sqrtl((sig - av * av / loops) / loops);
        av /= loops;
        sig = (sig < 0.05 * av ? 0.05 * av : sig);
        if (test_present(data, av, sig)) {
            break;
        }
    }
}


