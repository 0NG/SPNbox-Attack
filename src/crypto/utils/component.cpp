#include "component.h"

#include "../AES/AES128_ni.h"
#include "../GF/GF28.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <wmmintrin.h>
#include <array>

/*
auto _ct_genAESSbox()
{
    std::array<unsigned char, 256> _ct_sbox = { 0x00 };

    for (int i = 0; i < 256; ++i)
        _ct_sbox[i] = GF28::inv(i);

    return _ct_sbox;
}
*/

constexpr std::array<unsigned char, 256> aesSbox =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

constexpr auto _ct_genAESInvSbox()
{
    std::array<unsigned char, 256> _ct_sbox = { 0x00 };

    for (int i = 0; i < 256; ++i)
        _ct_sbox[aesSbox[i]] = i & 0xff;

    return _ct_sbox;
}

constexpr auto aesInvSbox = _ct_genAESInvSbox();

void component::printx(const unsigned char s[16])
{
    std::cout << std::hex;
    for (int i = 0; i < 16; ++i) {
        if (i % 4 == 0) std::cout << "| ";
        std::cout << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(s[i]) << ' ';
    }
    std::cout << std::dec;
    std::cout << "| ";
    return;
}

void component::invSB(unsigned char text[16])
{
    unsigned char tmp[16];
    for (int i = 0; i < 16; ++i)
        tmp[i] = aesInvSbox[text[i]];
    memcpy(text, tmp, 16);
    return;
}

void component::SB(unsigned char text[16])
{
    unsigned char tmp[16];
    for (int i = 0; i < 16; ++i)
        tmp[i] = aesSbox[text[i]];
    memcpy(text, tmp, 16);
    return;
}

void component::SB(unsigned char text[16], const unsigned char sbox[256])
{
    unsigned char tmp[16];
    for (int i = 0; i < 16; ++i)
        tmp[i] = sbox[text[i]];
    memcpy(text, tmp, 16);
    return;
}

void component::SB(unsigned char text[16], const std::array<unsigned char, 256>& sbox)
{
    unsigned char tmp[16];
    for (int i = 0; i < 16; ++i)
        tmp[i] = sbox[text[i]];
    memcpy(text, tmp, 16);
    return;
}

void component::SR(unsigned char text[16])
{
    int index[16] = {0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};  
    unsigned char tmp[16];

    for (int i = 0; i < 16; ++i)
        tmp[i] = text[index[i]];

    memcpy(text, tmp, 16);
    return;
}

void component::MC(unsigned char text[16])
{
    unsigned char state[16];
    memcpy(state, text, 16);
    for (int i = 0; i < 4; ++i) {
        unsigned char tmpState = state[4 * i + 0] ^ state[4 * i + 1] ^ state[4 * i + 2] ^ state[4 * i + 3];

        text[4 * i + 0] = tmpState ^ state[4 * i + 0] ^ GF28::mul(0x02, state[4 * i + 0] ^ state[4 * i + 1]);
        text[4 * i + 1] = tmpState ^ state[4 * i + 1] ^ GF28::mul(0x02, state[4 * i + 1] ^ state[4 * i + 2]);
        text[4 * i + 2] = tmpState ^ state[4 * i + 2] ^ GF28::mul(0x02, state[4 * i + 2] ^ state[4 * i + 3]);
        text[4 * i + 3] = tmpState ^ state[4 * i + 3] ^ GF28::mul(0x02, state[4 * i + 3] ^ state[4 * i + 0]);
    }

    return;
}

void component::ARK(unsigned char text[16], const unsigned char roundKey[16])
{
    unsigned char tmp[16];
    for (int i = 0; i < 16; ++i)
        tmp[i] = text[i] ^ roundKey[i];
    memcpy(text, tmp, 16);
    return;
}

void component::invMC(unsigned char text[16])
{
    unsigned char state[16];
    memcpy(state, text, 16);

    for (int i = 0; i < 4; ++i) {
        const unsigned char tmpState = state[4 * i + 0] ^ state[4 * i + 1] ^ state[4 * i + 2] ^ state[4 * i + 3];

        text[4 * i + 0] = state[4 * i + 0] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[4 * i + 0] ^ state[4 * i + 2]) ^ GF28::mul(0x02, state[4 * i + 0] ^ state[4 * i + 1]);
        text[4 * i + 1] = state[4 * i + 1] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[4 * i + 1] ^ state[4 * i + 3]) ^ GF28::mul(0x02, state[4 * i + 1] ^ state[4 * i + 2]);
        text[4 * i + 2] = state[4 * i + 2] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[4 * i + 0] ^ state[4 * i + 2]) ^ GF28::mul(0x02, state[4 * i + 2] ^ state[4 * i + 3]);
        text[4 * i + 3] = state[4 * i + 3] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[4 * i + 1] ^ state[4 * i + 3]) ^ GF28::mul(0x02, state[4 * i + 3] ^ state[4 * i + 0]);
    }

    return;
}

void component::invSR(unsigned char text[16])
{
    int index[16] = { 0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3 };
    unsigned char tmp[16];

    for (int i = 0; i < 16; ++i)
        tmp[i] = text[index[i]];

    memcpy(text, tmp, 16);
    return;
}

inline void generateRndStream(unsigned char rndStream[256 * 16 * 3], unsigned char key[16], int rndIndex = 0)
{
    AESKey aesKey(key);
    AES& aesHandler = AES::instance();
    unsigned char counter[16];
    memset(counter, 0x00, 16);
    for (int i = rndIndex; i < 256 * 3; ++i) {
        counter[14] = (i >> 8) & 0xff;
        counter[15] = i & 0xff;

        aesHandler.AESEncrypt(rndStream, counter, aesKey, 10);

        rndStream += 16;
    }
    return;
}
int component::generateBox(unsigned char sbox[256], unsigned char invsbox[256], unsigned char key[16], int rndIndex)
{
    unsigned char rndStream[256 * 16 * 3];
    generateRndStream(rndStream, key);

    for (int i = 0; i < 256; ++i) sbox[i] = i;
    for (int i = 256 - 1; i >= 0; --i) {
        int j = rndStream[rndIndex++] % (i + 1);
        int tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }

    for (int i = 0; i < 256; ++i)
        invsbox[sbox[i]] = i;

    return rndIndex;
}

int component::generateBox16(unsigned short sbox[1 << 16], unsigned short invsbox[1 << 16], unsigned char key[16], int rndIndex)
{
    unsigned char _rndStream[256 * 16 * 3];
    generateRndStream(_rndStream, key);
    auto rndStream = reinterpret_cast<unsigned short*>(_rndStream);

    for (int i = 0; i < (1 << 16); ++i) sbox[i] = i;
    for (int i = (1 << 16) - 1; i >= 0; --i) {
        int j = rndStream[rndIndex++] % (i + 1);
        int tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;

        if (rndIndex % 256 == 0) {
            generateRndStream(_rndStream, key, i);
            rndIndex = 0;
        }
    }

    for (int i = 0; i < (1 << 16); ++i)
        invsbox[sbox[i]] = i;

    return rndIndex;
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
inline __m128i aes_128_key_expansion(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}
void component::generateAESRoundKey(unsigned char roundkey[11][16], unsigned char key[16])
{
    __m128i rk[11];

    rk[0] = _mm_loadu_si128((const __m128i*)key);

    rk[1]  = AES_128_key_exp(rk[0], 0x01);
    rk[2]  = AES_128_key_exp(rk[1], 0x02);
    rk[3]  = AES_128_key_exp(rk[2], 0x04);
    rk[4]  = AES_128_key_exp(rk[3], 0x08);
    rk[5]  = AES_128_key_exp(rk[4], 0x10);
    rk[6]  = AES_128_key_exp(rk[5], 0x20);
    rk[7]  = AES_128_key_exp(rk[6], 0x40);
    rk[8]  = AES_128_key_exp(rk[7], 0x80);
    rk[9]  = AES_128_key_exp(rk[8], 0x1B);
    rk[10] = AES_128_key_exp(rk[9], 0x36);

    for (int i = 0; i < 11; ++i)
        _mm_storeu_si128((__m128i *)roundkey[i], rk[i]);
    return;
}

const std::array<unsigned char, 256>& component::getAESSbox()
{
    return aesSbox;
}

const std::array<unsigned char, 256>& component::getAESInvSbox()
{
    return aesInvSbox;
}

