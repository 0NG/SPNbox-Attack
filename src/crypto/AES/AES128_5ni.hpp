#include <array>
#include <wmmintrin.h>

namespace AES {

    template<int round>
    std::array<__m128i, 2 * round> AESKey(const unsigned char key[16]);

    template<int round>
    void AESEncrypt(unsigned char ciphertext[16], const unsigned char plaintext[16], const std::array<__m128i, 2 * round> key);

    template<int round>
    void AESDecrypt(unsigned char plaintext[16], const unsigned char ciphertext[16], const std::array<__m128i, 2 * round> key);

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

template <int round>
std::array<__m128i, 2 * round> AES::AESKey(const unsigned char key[16])
{
    std::array<__m128i, 2 * round> rk;
    constexpr unsigned char rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

    rk[0] = _mm_loadu_si128((const __m128i*)key);

    for (int i = 1; i < round; ++i)
        rk[i] = AES_128_key_exp(rk[i - 1], rcon[i]);

    rk[round] = AES_128_key_exp(rk[round - 1], rcon[round]);

    for (int i = round + 1; i < rk.size(); ++i)
        rk[i] = _mm_aesimc_si128(rk[2 * round - i]);

    return rk;
}

template<int round>
void AES::AESEncrypt(unsigned char ciphertext[16], const unsigned char plaintext[16], const std::array<__m128i, 2 * round> key)
{
    auto c = _mm_loadu_si128((__m128i *)plaintext);

    c = _mm_xor_si128(c, key[ 0]);

    for (int i = 1; i < round; ++i)
        c = _mm_aesenc_si128(c, key[i]);

    c = _mm_aesenclast_si128(c, key[round]);

    _mm_storeu_si128((__m128i *)ciphertext, c);

    return;
}

template<int round>
void AES::AESDecrypt(unsigned char plaintext[16], const unsigned char ciphertext[16], const std::array<__m128i, 2 * round> key)
{
    auto p = _mm_loadu_si128((__m128i *)ciphertext);

    p = _mm_xor_si128(p, key[round]);

    for (int i = 21 - round; i < 20; ++i)
        p = _mm_aesdec_si128(p, key[i]);

    p = _mm_aesdeclast_si128(p, key[ 0]);

    _mm_storeu_si128((__m128i *)plaintext, p);

    return;
}

