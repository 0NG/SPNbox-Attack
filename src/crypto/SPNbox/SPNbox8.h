#pragma once

class SPNboxKey {
    private:
        void generateRndStream(unsigned char rndStream[], unsigned char key[]);
        void generateBox(unsigned char key[]);

    public:
        unsigned char sbox[256];
        unsigned char invsbox[256];

        SPNboxKey() = default;
        ~SPNboxKey() = default;
        SPNboxKey(unsigned char key[]);
};

class SPNbox {
    private:
        void SLayer(unsigned char text[], const unsigned char sbox[256]);
        void invSLayer(unsigned char text[], const unsigned char invsbox[256]);

    public:
        void PLayer(unsigned char text[], unsigned char c = 0);
        void invPLayer(unsigned char text[], unsigned char c = 0);

        SPNbox() = default;
        ~SPNbox() = default;
        SPNbox(const SPNbox&) = delete;
        SPNbox(SPNbox&&) = delete;
        SPNbox& operator=(const SPNbox&) = delete;
        SPNbox operator=(const SPNbox&&) = delete;

        static SPNbox& instance();

        void SPNboxEncrypt(unsigned char ciphertext[], const unsigned char plaintext[], const SPNboxKey key);
        void SPNboxDecrypt(unsigned char plaintext[], const unsigned char ciphertext[], const SPNboxKey key);
};

