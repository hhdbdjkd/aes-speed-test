#include "present.h"

// SBox����SBox�����ڷ����Ա任
static u8 sbox[] = { 0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2 };
static u8 invsbox[] = { 0x5, 0xe, 0xf, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA };

// �޸ĺ�sbox
static const uint8_t Sbox256[256] = {
    0xcc, 0xc5, 0xc6, 0xcb, 0xc9, 0xc0, 0xca, 0xcd, 0xc3, 0xce, 0xcf, 0xc8, 0xc4, 0xc7, 0xc1, 0xc2,
    0x5c, 0x55, 0x56, 0x5b, 0x59, 0x50, 0x5a, 0x5d, 0x53, 0x5e, 0x5f, 0x58, 0x54, 0x57, 0x51, 0x52,
    0x6c, 0x65, 0x66, 0x6b, 0x69, 0x60, 0x6a, 0x6d, 0x63, 0x6e, 0x6f, 0x68, 0x64, 0x67, 0x61, 0x62,
    0xbc, 0xb5, 0xb6, 0xbb, 0xb9, 0xb0, 0xba, 0xbd, 0xb3, 0xbe, 0xbf, 0xb8, 0xb4, 0xb7, 0xb1, 0xb2,
    0x9c, 0x95, 0x96, 0x9b, 0x99, 0x90, 0x9a, 0x9d, 0x93, 0x9e, 0x9f, 0x98, 0x94, 0x97, 0x91, 0x92,
    0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d, 0x03, 0x0e, 0x0f, 0x08, 0x04, 0x07, 0x01, 0x02,
    0xac, 0xa5, 0xa6, 0xab, 0xa9, 0xa0, 0xaa, 0xad, 0xa3, 0xae, 0xaf, 0xa8, 0xa4, 0xa7, 0xa1, 0xa2,
    0xdc, 0xd5, 0xd6, 0xdb, 0xd9, 0xd0, 0xda, 0xdd, 0xd3, 0xde, 0xdf, 0xd8, 0xd4, 0xd7, 0xd1, 0xd2,
    0x3c, 0x35, 0x36, 0x3b, 0x39, 0x30, 0x3a, 0x3d, 0x33, 0x3e, 0x3f, 0x38, 0x34, 0x37, 0x31, 0x32,
    0xec, 0xe5, 0xe6, 0xeb, 0xe9, 0xe0, 0xea, 0xed, 0xe3, 0xee, 0xef, 0xe8, 0xe4, 0xe7, 0xe1, 0xe2,
    0xfc, 0xf5, 0xf6, 0xfb, 0xf9, 0xf0, 0xfa, 0xfd, 0xf3, 0xfe, 0xff, 0xf8, 0xf4, 0xf7, 0xf1, 0xf2,
    0x8c, 0x85, 0x86, 0x8b, 0x89, 0x80, 0x8a, 0x8d, 0x83, 0x8e, 0x8f, 0x88, 0x84, 0x87, 0x81, 0x82,
    0x4c, 0x45, 0x46, 0x4b, 0x49, 0x40, 0x4a, 0x4d, 0x43, 0x4e, 0x4f, 0x48, 0x44, 0x47, 0x41, 0x42,
    0x7c, 0x75, 0x76, 0x7b, 0x79, 0x70, 0x7a, 0x7d, 0x73, 0x7e, 0x7f, 0x78, 0x74, 0x77, 0x71, 0x72,
    0x1c, 0x15, 0x16, 0x1b, 0x19, 0x10, 0x1a, 0x1d, 0x13, 0x1e, 0x1f, 0x18, 0x14, 0x17, 0x11, 0x12,
    0x2c, 0x25, 0x26, 0x2b, 0x29, 0x20, 0x2a, 0x2d, 0x23, 0x2e, 0x2f, 0x28, 0x24, 0x27, 0x21, 0x22
};
// 64λ��ѭ����λ
static inline uint64_t ror64(uint64_t x, int n) { return x >> n | x << (64 - n); }

// 32λ��ѭ����λ
static inline uint32_t rol32(uint32_t x, int n) { return x << n | x >> (32 - n); }

// 32λ��ѭ����λ
static inline uint32_t ror32(uint32_t x, int n) { return x >> n | x << (32 - n); }


void present_64_80_key_schedule(const u8* key, u8* roundKeys) {
    // ������Կ����ȡ��64λ�͸�16λ
    u64 keylow = *(const u64*)key;
    u16 highBytes = *(const u16*)(key + 8);
    u64 keyhigh = ((u64)(highBytes) << 48) | (keylow >> 16);
    u64* rk = (u64*)roundKeys;
    rk[0] = keyhigh; // ���õ�һ����Կ

    u64 temp;
    u8 i;

    for (i = 0; i < PRESENT_ROUNDS; i++) {
        // 61λ���� 
        temp = keyhigh;
        keyhigh <<= 61;
        keyhigh |= (keylow << 45);
        keyhigh |= (temp >> 19);
        keylow = (temp >> 3) & 0xFFFF;

        // SBox�����������4λ����SBox�任
        temp = sbox[keyhigh >> 60];
        keyhigh &= 0x0FFFFFFFFFFFFFFF;
        keyhigh |= temp << 60;

        // �����ִμ��� 
        keylow ^= (((u64)(i + 1) & 0x01) << 15);
        keyhigh ^= ((u64)(i + 1) >> 1);

        // ���õ�ǰ�ֵ�����Կ
        rk[i + 1] = keyhigh;
    }
}

// 128λ����Կ
void present_64_128_key_schedule(const u8* key, u8* roundKeys) {
    // ������Կ����ȡ��64λ�͸�64λ
    u64 keylow = *(const u64*)key;
    u64 keyhigh = *((const u64*)key + 1);
    u64* rk = (u64*)roundKeys;
    rk[0] = keyhigh; 

    u64 temp;
    u8 i;

    for (i = 0; i < PRESENT_ROUNDS; i++) {
        temp = ((keyhigh << 61) | (keylow >> 3));
        keylow = ((keylow << 61) | (keyhigh >> 3));
        keyhigh = temp;
        temp = (sbox[keyhigh >> 60] << 4) ^ (sbox[(keyhigh >> 56) & 0xf]);
        keyhigh &= 0x00FFFFFFFFFFFFFF;
        keyhigh |= temp << 56;
        temp = ((keyhigh << 2) | (keylow >> 62)) ^ (u64)(i + 1);
        keyhigh = (keyhigh & 0xFFFFFFFFFFFFFFF8) ^ (temp & 0x7);
        keylow = (keylow & 0x3FFFFFFFFFFFFFFF) ^ (temp << 62);
        rk[i + 1] = keyhigh;
    }
}


// ����������
void present_encrypt(u8* plainText, const u8* roundKeys) {
    u64 state = *(u64*)plainText; // �����������ݵ�state
    const u64* rk = (const u64*)roundKeys;
    u64 result;
    u8 sInput; // SBox����
    u8 pLayerIndex;
    u64 stateBit; 
    u8 i; //�ִ�
    u16 k;

    for (i = 0; i < PRESENT_ROUNDS; i++) {
        // ����Կ��
        state ^= rk[i];//                               ^:32

        // SBox�� 

        for (k = 0; k < PRESENT_BLOCK_SIZE / 4; k++) {
            sInput = state & 0xF; // ��ȡ���4λ,      &:16*32
            state &= 0xFFFFFFFFFFFFFFF0;//              &:16*32
            state |= sbox[sInput]; // SBox�滻,        |:16*32
            state = ror64(state, 4); // ѭ������4λ    -:16*32 |:16*32 >>:16*32*2
        }
        // pLaye �� 
        result = 0;
        for (k = 0; k < PRESENT_BLOCK_SIZE; k++) {
            stateBit = state & 0x1;//                   &:32*64
            state >>=  1;//                             >>:32*64
            if (0 !=stateBit) {//                       cmp:32*64
                pLayerIndex = (16 * k) % 63;//          *:32*64/2  %:32*64/2
                if (63 == k) {//                        cmp:32*64/2
                    pLayerIndex = 63;                   
                }
                result |= stateBit << pLayerIndex;//        |:32*64/2  >>32*64/2
            }
        }
        state = result;
    }

    // ���һ����Կ�ӷ�
    state ^= rk[i];
    *(u64*)plainText = state; // �����ܽ��д��        // ��32*32*30=30720
}

// ����������,�Ľ�sbox��
void present_encrypt_s_I(u8* plainText, const u8* roundKeys) {
    u64 state = *(u64*)plainText; // �����������ݵ�state
    const u64* rk = (const u64*)roundKeys;
    u64 result;
    u8 sInput; // SBox����
    u8 pLayerIndex; 
    u64 stateBit;
    u8 i; // �ִ�
    u16 k;
    u8* plain = (u8*)(&state);
    for (i = 0; i < PRESENT_ROUNDS; i++) {
        // ����Կ��
        state ^= rk[i];

        // SBox�� 

        /*
        for (k = 0; k < PRESENT_BLOCK_SIZE / 4; k++) {
            sInput = state & 0xF; // ��ȡ���4λ,   
            state &= 0xFFFFFFFFFFFFFFF0;//              
            state |= sbox[sInput]; // SBox�滻,       
            state = ror64(state, 4); // ѭ������4λ   
        }*/
        for (int k = 0; k < 8; k++) {
            plain[k] = Sbox256[plain[k]];
        }

        // pLayer�� 
        result = 0;
        for (k = 0; k < PRESENT_BLOCK_SIZE; k++) {
            stateBit = state & 0x1;              
            state >>= 1;                          
            if (stateBit) {                       
                pLayerIndex = (16 * k) % 63;
                if (63 == k) {                     
                    pLayerIndex = 63;
                }
                result |= stateBit << pLayerIndex;
            }
        }
        state = result;
    }

    // ���һ����Կ�ӷ�
    state ^= rk[i];
    *(u64*)plainText = state;
}



// pLayer��Ľ�
int pLayerIndices[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,
     2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,
     6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};

void present_encrypt_p_I(u8* plainText, const u8* roundKeys) {
    u64 state = *(u64*)plainText; // �����������ݵ�state
    const u64* rk = (const u64*)roundKeys;
    u64 result;
    u8 sInput; // SBox����
    u8 i; // �ִ�
    u16 k;

    for (i = 0; i < PRESENT_ROUNDS; i++) {
        // ����Կ�ӷ�(AddRoundKey)
        state ^= rk[i];//                             

        // SBox�� 

        for (k = 0; k < PRESENT_BLOCK_SIZE / 4; k++) {
            sInput = state & 0xF; // ��ȡ��� 4 λ,    
            state &= 0xFFFFFFFFFFFFFFF0;//             
            state |= sbox[sInput]; // S-Box�滻,       
            state = ror64(state, 4); // ѭ������ 4 λ    
        }

        // pLayer�� 
        result = 0;
        for (int k = 0; k < PRESENT_BLOCK_SIZE; k++) {
            if (state & 0x1) {
                int pLayerIndex = pLayerIndices[k];
                result |= (1ULL << pLayerIndex);
            }
            state >>= 1;
        }
        state = result;
    }

    // ���һ����Կ�ӷ�
    state ^= rk[i];
    *(u64*)plainText = state;       
}

//ͬʱ�޸�sbox��player��
void present_encrypt_sp_I(u8* plainText, const u8* roundKeys) {
    u64 state = *(u64*)plainText; // �����������ݵ�state
    const u64* rk = (const u64*)roundKeys;
    u64 result;
    u8 i; // �ִ�
    u16 k;
    u8* plain = (u8*)(&state);
    for (i = 0; i < PRESENT_ROUNDS; i++) {
        // ����Կ�ӷ�(AddRoundKey)
        state ^= rk[i];//                             

        // SBox�� 
        for (int k = 0; k < 8; k++) {
            plain[k] = Sbox256[plain[k]];    
        }
        // pLayer�� 
        result = 0;
        for (int k = 0; k < PRESENT_BLOCK_SIZE; k++) {
            if (state & 0x1) {
                int pLayerIndex = pLayerIndices[k];
                result |= (1ULL << pLayerIndex);
            }
            state >>= 1;
        }
        state = result;
    }

    // ���һ����Կ�ӷ�
    state ^= rk[i];
    *(u64*)plainText = state;     
}

// ���ܺ���
void present_decrypt(u8* cipherText, const u8* roundKeys) {
    u64 state = *(u64*)cipherText; // �����������ݵ�state
    const u64* rk = (const u64*)roundKeys;
    u64 result;
    u8 sInput; // SBox����
    u8 pLayerIndex; 
    u64 stateBit; 
    u8 i; // �ִ�
    u16 k;

    for (i = PRESENT_ROUNDS; i > 0; i--) {
        // ����Կ�ӷ�
        state ^= rk[i];

        result = 0;
        for (k = 0; k < PRESENT_BLOCK_SIZE; k++) {
            stateBit = state & 0x1;
            state = state >> 1;
            if (0 != stateBit) {
                pLayerIndex = (4 * k) % 63;
                if (63 == k) {
                    pLayerIndex = 63;
                }
                result |= stateBit << pLayerIndex;
            }
        }
        state = result;

        for (k = 0; k < PRESENT_BLOCK_SIZE / 4; k++) {
            sInput = state & 0xF; // ��ȡ���4λ
            state &= 0xFFFFFFFFFFFFFFF0;
            state |= invsbox[sInput]; // SBox�滻
            state = ror64(state, 4); // ѭ������4λ
        }
    }

    // ���һ����Կ�ӷ�
    state ^= rk[i];
    *(uint64_t*)cipherText = state;
}
