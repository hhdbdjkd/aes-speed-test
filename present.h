
/*
 *
 * The input is from right to left. 
 * The rightmost byte is the least significant byte.
 * The leftmost byte is the most significant byte.
 */

#ifndef PRESENT_H
#define PRESENT_H

#define PRESENT_BLOCK_SIZE   (64)  /* block size in bits */
#define PRESENT_KEY_SIZE_80  (80)  /* key size in bits */
#define PRESENT_KEY_SIZE_128 (128) /* key size in bits */
#define PRESENT_ROUNDS       (31)  /* rounds */

#include <stdint.h>

typedef  uint8_t  u8;
typedef  uint16_t u16;
typedef  uint32_t u32;
typedef  uint64_t u64;

/*
 * key schedule
 * inputKey: the original keys
 * keys: round keys
 */
void present_64_80_key_schedule(const u8 * inputKey, u8 * keys );

void present_64_128_key_schedule(const u8 * inputKey, u8 * keys );

/*
 * encrypt
 * plainText: plainText has just one block.
 * keys: round keys
 */
void present_encrypt(u8 * plainText, const u8 * keys );
void present_encrypt_s_I(u8* plainText, const u8* roundKeys);
void present_encrypt_p_I(u8* plainText, const u8* roundKeys);
void present_encrypt_sp_I(u8* plainText, const u8* roundKeys);
/*
 * decrypt
 * cipherText: cipherText has just one block.
 * keys: round keys
 */
void present_decrypt(u8 * cipherText, const u8 * keys );

#endif