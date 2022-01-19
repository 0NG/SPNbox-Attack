#pragma once

#include <immintrin.h>

class AESKey {
    using byte = unsigned char;

    private:
        __m128i aes_128_key_expansion(__m128i key, __m128i keygened);
        void AESKeySchedule(byte key[], int round);

    public:
        __m128i rk[21];

        void print();

        AESKey() = default;
        ~AESKey() = default;
        AESKey(byte key[]); // for default aes128, 10 rounds
};

class AES {
    using byte = unsigned char;

    public:
        AES() = default;
        ~AES() = default;
        AES(const AES&) = delete;
        AES(AES&&) = delete;
        AES& operator=(const AES&) = delete;
        AES operator=(const AES&&) = delete;

        static AES& instance();

        void AESEncrypt(byte ciphertext[], const byte plaintext[], const AESKey key, const int round);
        void AESDecrypt(byte plaintext[], const byte ciphertext[], const AESKey key, const int round);
};

