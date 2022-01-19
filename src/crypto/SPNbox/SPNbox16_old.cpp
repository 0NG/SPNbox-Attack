#include "SPNbox16.h"
#include "../AES/AES128_ni.h"

#include <givaro/gfq.h>

#include <cstring>

static int modulus16[] = { 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }; // x^16 + x^5 + x^3 + x + 1  (0x2b)
static Givaro::GFqDom<int> GF216(2, 16, modulus16);

static unsigned short GF16_mul(const unsigned short a, const unsigned short b)
{
    Givaro::GFqDom<int>::Element ga, gb, gc;
    GF216.init(ga, a);   // initialize
    GF216.init(gb, b);
    GF216.mul(gc, ga, gb);   // field multiplication
    unsigned int c;
    GF216.convert(c, gc);
    return c;
}

SPNboxKey::SPNboxKey(unsigned char key[16]) { generateBox(key); }

void SPNboxKey::generateRndStream(unsigned short rndStream[(1 << 16)], unsigned char key[16])
{
    AESKey aesKey(key);
    AES& aesHandler = AES::instance();
    unsigned char counter[16];
    memset(counter, 0x00, 16);
    for (int i = 0; i < (1 << 16) / 8; ++i) {
        counter[14] = (i >> 8) & 0xff;
        counter[15] = i & 0xff;

        aesHandler.AESEncrypt(reinterpret_cast<unsigned char*>(rndStream), counter, aesKey, 10);

        rndStream += 8;
    }
    return;
}

void SPNboxKey::generateBox(unsigned char key[16])
{
    unsigned short rndStream[(1 << 16)];
    generateRndStream(rndStream, key);

    int rndIndex = 0;
    for (int i = 0; i < (1 << 16); ++i) sbox[i] = i;

    for (int i = (1 << 16) - 1; i >= 0; --i) {
        const int j = rndStream[rndIndex++] % (i + 1);
        const unsigned short tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }

    for (int i = 0; i < (1 << 16); ++i)
        invsbox[sbox[i]] = i;
    return;
}

SPNbox& SPNbox::instance()
{
    static SPNbox SPNboxINSTANCE;
    return SPNboxINSTANCE;
}

void SPNbox::SLayer(unsigned char text[16], const unsigned short sbox[256])
{
    auto text_Uint16 = reinterpret_cast<unsigned short*>(text);
    for (int i = 0; i < 8; ++i)
        text_Uint16[i] = sbox[text_Uint16[i]];
    return;
}

void SPNbox::invSLayer(unsigned char text[16], const unsigned short invsbox[256])
{
    auto text_Uint16 = reinterpret_cast<unsigned short*>(text);
    for (int i = 0; i < 8; ++i)
        text_Uint16[i] = invsbox[text_Uint16[i]];
    return;
}

static void MC(unsigned char text[16])
{
    constexpr unsigned char M16[8][8] =  {
        { 0x01, 0x03, 0x04, 0x05, 0x06, 0x08, 0x0b, 0x07 },
        { 0x03, 0x01, 0x05, 0x04, 0x08, 0x06, 0x07, 0x0b },
        { 0x04, 0x05, 0x01, 0x03, 0x0b, 0x07, 0x06, 0x08 },
        { 0x05, 0x04, 0x03, 0x01, 0x07, 0x0b, 0x08, 0x06 },
        { 0x06, 0x08, 0x0b, 0x07, 0x01, 0x03, 0x04, 0x05 },
        { 0x08, 0x06, 0x07, 0x0b, 0x03, 0x01, 0x05, 0x04 },
        { 0x0b, 0x07, 0x06, 0x08, 0x04, 0x05, 0x01, 0x03 },
        { 0x07, 0x0b, 0x08, 0x06, 0x05, 0x04, 0x03, 0x01 }
    };
    auto text_Uint16 = reinterpret_cast<unsigned short*>(text);
    unsigned short tmp[8];
    for (int i = 0; i < 8; ++i) {
        tmp[i] = 0x00;
        for (int j = 0; j < 8; ++j)
            tmp[i] ^= GF16_mul(M16[i][j], text_Uint16[j]);
    }

    memcpy(text, tmp, 16);
    return;
}

void SPNbox::PLayer(unsigned char text[16], unsigned short c)
{
    MC(text);
    auto text_Uint16 = reinterpret_cast<unsigned short*>(text);

    for (int i = 0; i < 8; ++i) {
        text_Uint16[i] ^= c;
        ++c;
    }
    return;
}

void SPNbox::invPLayer(unsigned char text[16], unsigned short c)
{
    auto text_Uint16 = reinterpret_cast<unsigned short*>(text);
    for (int i = 0; i < 8; ++i) {
        text_Uint16[i] ^= c;
        ++c;
    }
    MC(text);
    return;
}

void SPNbox::SPNboxEncrypt(unsigned char ciphertext[16], const unsigned char plaintext[16], const SPNboxKey key)
{
    memcpy(ciphertext, plaintext, 16);
    SPNbox::SLayer(ciphertext, key.sbox);
    SPNbox::PLayer(ciphertext, 0);
    SPNbox::SLayer(ciphertext, key.sbox);
    SPNbox::PLayer(ciphertext, 8);
    SPNbox::SLayer(ciphertext, key.sbox);
    return;
}

void SPNbox::SPNboxDecrypt(unsigned char plaintext[16], const unsigned char ciphertext[16], const SPNboxKey key)
{
    memcpy(plaintext, ciphertext, 16);
    SPNbox::invSLayer(plaintext, key.invsbox);
    SPNbox::invPLayer(plaintext, 8);
    SPNbox::invSLayer(plaintext, key.invsbox);
    SPNbox::invPLayer(plaintext, 0);
    SPNbox::invSLayer(plaintext, key.invsbox);
    return;
}
