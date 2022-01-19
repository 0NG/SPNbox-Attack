#pragma once

class SPNboxKey {
    private:
        void generateRndStream(unsigned short rndStream[], unsigned char key[]);
        void generateBox(unsigned char key[]);

    public:
        unsigned short sbox[1 << 16];
        unsigned short invsbox[1 << 16];

        SPNboxKey() = default;
        ~SPNboxKey() = default;
        SPNboxKey(unsigned char key[]);
};

class SPNbox {
    private:
        void SLayer(unsigned char text[], const unsigned short sbox[1 << 16]);
        void invSLayer(unsigned char text[], const unsigned short invsbox[1 << 16]);

    public:
        void PLayer(unsigned char text[], unsigned short c = 0);
        void invPLayer(unsigned char text[], unsigned short c = 0);

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
