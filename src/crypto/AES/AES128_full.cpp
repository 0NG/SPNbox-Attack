#include "AES128_full.h"

AESKey::AESKey(byte key[16])
{
    AESKeySchedule(key, 10);
    return;
}

#include <iostream>
#include <iomanip>
void AESKey::print()
{
    unsigned char kchar[16];
    std::cout << std::hex;
    for (int i = 0; i < 10; ++i) {
        std::cout << i << " : ";

        _mm_storeu_si128((__m128i *)kchar, this->rk[i]);
        for (int j = 0; j < 16; ++j)
            std::cout << " " << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(kchar[j]);

        std::cout << std::endl;
    }
    std::cout << std::dec;
    return;
}

/****************************    AES key schedule     ****************************************/
#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
__m128i AESKey::aes_128_key_expansion(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

void AESKey::AESKeySchedule(byte key[16], const int round)
{
    this->rk[0] = _mm_loadu_si128((const __m128i*)key);
    this->rk[1]  = AES_128_key_exp(this->rk[0], 0x01);
    this->rk[2]  = AES_128_key_exp(this->rk[1], 0x02);
    this->rk[3]  = AES_128_key_exp(this->rk[2], 0x04);
    this->rk[4]  = AES_128_key_exp(this->rk[3], 0x08);
    this->rk[5]  = AES_128_key_exp(this->rk[4], 0x10);
    this->rk[6]  = AES_128_key_exp(this->rk[5], 0x20);
    this->rk[7]  = AES_128_key_exp(this->rk[6], 0x40);
    this->rk[8]  = AES_128_key_exp(this->rk[7], 0x80);
    this->rk[9]  = AES_128_key_exp(this->rk[8], 0x1B);
    this->rk[10] = AES_128_key_exp(this->rk[9], 0x36);

    this->rk[11] = _mm_aesimc_si128(this->rk[10]);
    this->rk[12] = _mm_aesimc_si128(this->rk[9]);
    this->rk[13] = _mm_aesimc_si128(this->rk[8]);
    this->rk[14] = _mm_aesimc_si128(this->rk[7]);
    this->rk[15] = _mm_aesimc_si128(this->rk[6]);
    this->rk[16] = _mm_aesimc_si128(this->rk[5]);
    this->rk[17] = _mm_aesimc_si128(this->rk[4]);
    this->rk[18] = _mm_aesimc_si128(this->rk[3]);
    this->rk[19] = _mm_aesimc_si128(this->rk[2]);
    this->rk[20] = _mm_aesimc_si128(this->rk[1]);

    return;
}

/**************       AES  ***************************/

AES& AES::instance()
{
    static AES AESINSTANCE;
    return AESINSTANCE;
}

void AES::AESEncrypt(byte ciphertext[16], const byte plaintext[16], const AESKey key, const int round)
{
    auto c = _mm_loadu_si128((__m128i *)plaintext);

    c = _mm_xor_si128(c, key.rk[0]);

    for (int i = 1; i <= round; ++i)
        c = _mm_aesenc_si128(c, key.rk[i]);

    _mm_storeu_si128((__m128i *)ciphertext, c);

    return;
}

void AES::AESDecrypt(byte plaintext[16], const byte ciphertext[16], const AESKey key, const int round)
{
    auto p = _mm_loadu_si128((__m128i *)ciphertext);

    auto tmpK = p;
    p = _mm_aesenclast_si128(p, tmpK);
    p = _mm_xor_si128   (p, tmpK);

    for (int i = 21 - round; i < 21; ++i)
        p = _mm_aesdec_si128(p, key.rk[i]);

    p = _mm_aesdeclast_si128(p, key.rk[ 0]);

    _mm_storeu_si128((__m128i *)plaintext, p);

    return;
}

