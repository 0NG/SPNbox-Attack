#pragma once

class AESKey {
    using byte = unsigned char;
 
    private:
        void AESKeySchedule(byte key[], int round);

    public:
        byte rk[11][16];

        AESKey() = default;
        ~AESKey() = default;
        AESKey(byte key[]); // for default aes128, 10 rounds
};

class AES {
    using byte = unsigned char;

    private:
        void AESRoundfunc(byte state[], const byte rk[]);
        void AESRoundfunclast(byte state[], const byte rk[]);
        void AESinvRoundfunc(byte state[], const byte rk[]);
        void AESinvRoundfunclast(byte state[], const byte rk[]);
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

