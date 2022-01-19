#pragma once

#include <wmmintrin.h>

class AESKey {
    using byte = unsigned char;

    private:
        void AESKeySchedule(byte key[], int round);

    public:
        __m128i rk[20];

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

