#include "speedtest.h"
#include "present.h"

void sbox_verify(const std::vector<uint8_t>& data) {
        uint64_t av = 0;
        uint64_t sig = 0;
        // 定义主密钥和轮密钥
        uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
        uint8_t roundKeys[(PRESENT_ROUNDS + 1) * 8] = { 0 }; // 32 * 8 = 256 字节
        present_64_128_key_schedule(key, roundKeys);


        std::vector<uint8_t> buffer(data);

        printf("present:   \n");
        for (size_t k = 0; k < buffer.size()/4; k += 8) {
            present_encrypt(&buffer[k], roundKeys);
            for (int i = 0; i < 8; i++) {
                printf("%x", buffer[k+i]);
            }
        }
        printf("\n\n");

        printf("present_SP:\n");
        std::vector<uint8_t> buffer2(data);
        for (size_t k = 0; k < buffer2.size()/4; k += 8) {
            present_encrypt_sp_I(&buffer2[k], roundKeys);
            for (int i = 0; i < 8; i++) {
                printf("%x", buffer2[k+i]);
            }
        }
}
