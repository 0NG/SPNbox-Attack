#include <array>

namespace component {
    void SB(unsigned char text[16], const std::array<unsigned char, 256>& sbox);
    void SB(unsigned char text[16], const unsigned char sbox[256]);
    void SB(unsigned char text[16]);
    void invSB(unsigned char text[16]);

    void SR(unsigned char text[16]);

    void MC(unsigned char text[16]);

    void ARK(unsigned char text[16], const unsigned char roundKey[16]);

    void invMC(unsigned char text[16]);

    void invSR(unsigned char text[16]);

    int generateBox(unsigned char sbox[256], unsigned char invsbox[256], unsigned char key[16], int rndIndex = 0);
    int generateBox16(unsigned short sbox[1 << 16], unsigned short invsbox[1 << 16], unsigned char key[16], int rndIndex = 0);

    void generateAESRoundKey(unsigned char roundKey[11][16], unsigned char key[16]);

    void printx(const unsigned char s[16]);

//    const std::array<unsigned char, 256> aesSbox = { 0x00 };
//    const std::array<unsigned char, 256> aesInvSbox = { 0x00 };

    const std::array<unsigned char, 256>& getAESSbox();
    const std::array<unsigned char, 256>& getAESInvSbox();
}

