#include "crypto/GF/GF216.h"
#include "crypto/SPNbox/SPNbox16.h"
#include "crypto/utils/component.h"

#include <iostream>
#include <cstring>
#include <string>
#include <functional>
#include <random>
#include <cassert>
#include <iomanip>

using std::cout;
using std::endl;
using component::printx;

constexpr int eqSetNum = 1;
//constexpr int eqNum = 1 + eqSetNum * 255; // 1 for the special equation
constexpr int eqNum = 1 << 16;

static void info(std::string s)
{
    static int steps;
    cout << "[" << steps << "] " << s << endl;
    ++steps;
    return;
}

constexpr int eqSize = 1 << 16;
static inline void swapEq(unsigned short *eq1, unsigned short *eq2)
{
    unsigned short tmp[eqSize];
    memcpy(tmp, eq1, eqSize * 2);
    memcpy(eq1, eq2, eqSize * 2);
    memcpy(eq2, tmp, eqSize * 2);
    return;
}
static inline void xorEq(unsigned short *eq, unsigned short *eq1, unsigned short *eq2)
{
    unsigned short tmp[eqSize];
    for (int i = 0; i < eqSize; ++i)
        tmp[i] = eq1[i] ^ eq2[i];
    memcpy(eq, tmp, eqSize * 2);
    return;
}
static inline void mulEq(unsigned short *eq, unsigned short *eq1, const unsigned short c)
{
    unsigned short tmp[eqSize];
    for (int i = 0; i < eqSize; ++i) {
        if (eq1[i] == 0)
            tmp[i] = 0;
        else
            tmp[i] = GF216::mul(eq1[i], c);
    }
    memcpy(eq, tmp, eqSize * 2);
    return;
}
static inline void mulEq2(unsigned short *eq, unsigned short *eq1)
{
    unsigned short tmp[eqSize];
    for (int i = 0; i < eqSize; ++i) {
        const unsigned short msb = (eq1[i] >> 15) & 0x01;
        tmp[i] = (eq1[i] << 1) ^ (0x2b * msb);
    }
    memcpy(eq, tmp, eqSize);
    return;
}
// number of zeros
static inline unsigned short ntz(unsigned short x)
{
    if (x == 0) return 0;
    unsigned short n = 0;
    if ((x >> 8) != 0) { n += 8; x >>= 8; }
    if ((x >> 4) != 0) { n += 4; x >>= 4; }
    if ((x >> 2) != 0) { n += 2; x >>= 2; }
    n = n + (x >> 1);
    return n;
}
static inline int g(int n)
{
    return n ^ (n >> 1);
}
static inline int g_inv(int g)
{
    int n = 0;
    while (g) {
        n ^= g;
        g >>= 1;
    }
    return n;
}
static inline void genMulTableRow(unsigned short *mulTable[(1 << 16)], unsigned short *eq)
{
    unsigned short bitRow[16][eqSize];
    memcpy(bitRow[0], eq, eqSize);
    for (int i = 1; i < 16; ++i) {
        mulEq2(bitRow[i], bitRow[i - 1]);
    }

    memset(mulTable[0], 0x0000, eqSize);
    for (int i = 1; i < (1 << 16); ++i) {
        const unsigned short g1 = g(i - 1);
        const unsigned short g2 = g(i);
        const unsigned short addBit = g1 ^ g2;
        const unsigned short rowi = ntz(addBit);
        xorEq(mulTable[i], mulTable[i - 1], bitRow[rowi]);
    }
    return;
}
/*
 * improved with gray code and precomputation
 */
static int solveLinear(unsigned short linearEqs[eqNum][eqSize])
{
    auto mulTable = new unsigned short*[(1 << 16)];
    for (int i = 0; i < (1 << 16); ++i) mulTable[i] = new unsigned short[eqSize];

    int rank = 0;
    for (int col = 0, firstRow = 0; col < eqSize; ++col) {
        bool hasOne = false;

        for (int row = firstRow; row < eqNum; ++row)
            if (linearEqs[row][col]) {
                swapEq(linearEqs[firstRow], linearEqs[row]);
                hasOne = true;
                break;
            }

        if (!hasOne) continue;

        ++rank;
        const unsigned short pivot = linearEqs[firstRow][col];
        const unsigned short invPivot = GF216::inv(pivot);
        mulEq(linearEqs[firstRow], linearEqs[firstRow], invPivot);
        genMulTableRow(mulTable, linearEqs[firstRow]);

        for (int row = 0; row < eqNum; ++row)
            if (linearEqs[row][col] && row != firstRow) {
                const unsigned char preRowi = g_inv(linearEqs[row][col]);
                xorEq(linearEqs[row], linearEqs[row], mulTable[preRowi]);
            }

        ++firstRow;
    }

    // Triangle form
    int oneRow;
    for (oneRow = eqSize - 1; oneRow >= 0; --oneRow) {
        bool isAny = false;
        for (int col = 0; col < eqSize; ++col)
            if (linearEqs[oneRow][col]) {
                isAny = true;
                break;
            }
        if (isAny) break;
    }
    while (!linearEqs[oneRow][oneRow]) {
        for (int i = oneRow - 1; i < eqSize; ++i)
            if (linearEqs[oneRow][i]) {
                swapEq(linearEqs[i], linearEqs[oneRow]);
                break;
            }

        --oneRow;
    }

    for (int i = 0; i < (1 << 16); ++i) delete[] mulTable[i];
    delete[] mulTable;
    return rank;
}
static int solveLinear_cache(unsigned short linearEqs[eqNum][eqSize])
{
    bool isCached[(1 << 16)];
    auto mulTable = new unsigned short*[(1 << 16)];
    for (int i = 0; i < (1 << 16); ++i) mulTable[i] = new unsigned short[eqSize];

    int rank = 0;
    for (int col = 0, firstRow = 0; col < eqSize; ++col) {
        bool hasOne = false;

        for (int row = firstRow; row < eqNum; ++row)
            if (linearEqs[row][col]) {
                swapEq(linearEqs[firstRow], linearEqs[row]);
                hasOne = true;
                break;
            }

        if (!hasOne) continue;

        ++rank;
        const unsigned short pivot = linearEqs[firstRow][col];
        const unsigned short invPivot = GF216::inv(pivot);
        mulEq(linearEqs[firstRow], linearEqs[firstRow], invPivot);

        for (int row = 0; row < eqNum; ++row)
            if (linearEqs[row][col] && row != firstRow) {
                //unsigned short tmp[eqSize];
                //mulEq(tmp, linearEqs[firstRow], linearEqs[row][col]);
                //xorEq(linearEqs[row], linearEqs[row], tmp);
                const unsigned short cachei = linearEqs[row][col];
                if (!isCached[cachei]) {
                    isCached[cachei] = 1;
                    mulEq(mulTable[cachei], linearEqs[firstRow], cachei);
                }
                xorEq(linearEqs[row], linearEqs[row], mulTable[cachei]);
            }

        ++firstRow;
    }

    // Triangle form
    int oneRow;
    for (oneRow = eqSize - 1; oneRow >= 0; --oneRow) {
        bool isAny = false;
        for (int col = 0; col < eqSize; ++col)
            if (linearEqs[oneRow][col]) {
                isAny = true;
                break;
            }
        if (isAny) break;
    }
    while (!linearEqs[oneRow][oneRow]) {
        for (int i = oneRow - 1; i < eqSize; ++i)
            if (linearEqs[oneRow][i]) {
                swapEq(linearEqs[i], linearEqs[oneRow]);
                break;
            }

        --oneRow;
    }

    for (int i = 0; i < (1 << 16); ++i) delete[] mulTable[i];
    delete[] mulTable;
    return rank;
}

int main()
{
    //unsigned short eqs[eqNum < (1 << 16) ? (1 << 16) : eqNum][(1 << 16)];
    auto eqs = new unsigned short[eqNum < (1 << 16) ? (1 << 16) : eqNum][(1 << 16)];

    info("Setup oracle");
    std::random_device rd;
    std::default_random_engine randomGen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    unsigned char secretKey[16];
    for (int i = 0; i < 16; ++i) secretKey[i] = static_cast<unsigned char>(dist(randomGen));

    SPNboxKey spnKey(secretKey);
    auto& spnHandler = SPNbox::instance();
    auto oracle = std::bind(&SPNbox::SPNboxEncrypt, std::ref(spnHandler), std::placeholders::_1, std::placeholders::_2, spnKey);
    auto pOracle  = std::bind(&SPNbox::PLayer, std::ref(spnHandler), std::placeholders::_1, std::placeholders::_2);

    //unsigned char p1[] = { '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' };
    //spnHandler.SPNboxEncrypt(p1, p1, spnKey);
    //printx(p1); cout << endl;
    //unsigned char p2[] = { '+', '+', '+', '-', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+' };
    //spnHandler.SPNboxEncrypt(p2, p2, spnKey);
    //printx(p2); cout << endl;

    cout << endl << "===== test vector =====" << endl;
    unsigned char testvector[] = { '-', '#', '-', ' ', 'c', 'o', 'r', 'r', 'e', 'c', 't', '!', ' ', '-', '#', '-' };
    spnHandler.SPNboxEncrypt(testvector, testvector, spnKey);
    printx(testvector); cout << endl;
    spnHandler.SPNboxDecrypt(testvector, testvector, spnKey);
    for (int _vi = 0; _vi < 16; ++_vi) { cout << testvector[_vi]; } cout << endl;
    cout << "====== end  test ======" << endl << endl;

    info("Start Attack");

    info("Query oracle");
    for (int i = 0; i < (1 << 16); ++i)
        for (int j = 0; j < (1 << 16); ++j)
            eqs[i][j] = 0x0000;

    for (int j = 0; j < (1 << 16); ++j) eqs[0][j] = 0x01;
    for (int eqSetCnt = 0; eqSetCnt < eqSetNum; ++eqSetCnt) {
        unsigned char plaintext[16];
        auto plaintext_Uint16 = reinterpret_cast<unsigned short*>(plaintext);
        auto cByte = static_cast<unsigned char>(dist(randomGen));
        const int firstEq = 1 + (1 << 16) * eqSetCnt;
        if (firstEq >= eqNum) break;
        {
            memset(plaintext, 0x00, 16);
            plaintext[0] = cByte;

            unsigned char ciphertext[16];
            auto ciphertext_Uint16 = reinterpret_cast<unsigned short*>(ciphertext);
            oracle(ciphertext, plaintext);

            eqs[firstEq + 0][ciphertext_Uint16[ 0]] ^= 0x01;
            eqs[firstEq + 0][ciphertext_Uint16[ 1]] ^= 0x03;
            eqs[firstEq + 0][ciphertext_Uint16[ 2]] ^= 0x04;
            eqs[firstEq + 0][ciphertext_Uint16[ 3]] ^= 0x05;
            eqs[firstEq + 0][ciphertext_Uint16[ 4]] ^= 0x06;
            eqs[firstEq + 0][ciphertext_Uint16[ 5]] ^= 0x08;
            eqs[firstEq + 0][ciphertext_Uint16[ 6]] ^= 0x0b;
            eqs[firstEq + 0][ciphertext_Uint16[ 7]] ^= 0x07;
        }
        for (int i = 0; i < (1 << 16); ++i) {
            if (firstEq + i >= eqNum) break;
            plaintext[0] = cByte;
            plaintext_Uint16[1] = i & 0xffff;
            plaintext_Uint16[2] = i & 0xffff;
            plaintext_Uint16[3] = i & 0xffff;
            plaintext_Uint16[4] = i & 0xffff;
            plaintext_Uint16[5] = i & 0xffff;
            plaintext_Uint16[6] = i & 0xffff;
            plaintext_Uint16[7] = i & 0xffff;

            unsigned char ciphertext[16];
            auto ciphertext_Uint16 = reinterpret_cast<unsigned short*>(ciphertext);
            oracle(ciphertext, plaintext);

            eqs[firstEq + i][ciphertext_Uint16[ 0]] ^= 0x01;
            eqs[firstEq + i][ciphertext_Uint16[ 1]] ^= 0x03;
            eqs[firstEq + i][ciphertext_Uint16[ 2]] ^= 0x04;
            eqs[firstEq + i][ciphertext_Uint16[ 3]] ^= 0x05;
            eqs[firstEq + i][ciphertext_Uint16[ 4]] ^= 0x06;
            eqs[firstEq + i][ciphertext_Uint16[ 5]] ^= 0x08;
            eqs[firstEq + i][ciphertext_Uint16[ 6]] ^= 0x0b;
            eqs[firstEq + i][ciphertext_Uint16[ 7]] ^= 0x07;

            if (i + 1 < 0xffff && firstEq + i + 1 < eqNum) {
                eqs[firstEq + i + 1][ciphertext_Uint16[ 0]] ^= 0x01;
                eqs[firstEq + i + 1][ciphertext_Uint16[ 1]] ^= 0x03;
                eqs[firstEq + i + 1][ciphertext_Uint16[ 2]] ^= 0x04;
                eqs[firstEq + i + 1][ciphertext_Uint16[ 3]] ^= 0x05;
                eqs[firstEq + i + 1][ciphertext_Uint16[ 4]] ^= 0x06;
                eqs[firstEq + i + 1][ciphertext_Uint16[ 5]] ^= 0x08;
                eqs[firstEq + i + 1][ciphertext_Uint16[ 6]] ^= 0x0b;
                eqs[firstEq + i + 1][ciphertext_Uint16[ 7]] ^= 0x07;
            }
        }
    }

    for (int row = 0; row < (1 << 16); ++row) {
        unsigned short res = 0x0000;
        for (int col = 0; col < (1 << 16); ++col) {
            if (eqs[row][col])
                res ^= GF216::mul(eqs[row][col], spnKey.invsbox[col]);
        }
        assert(res == 0x00);
        if (res != 0x00) {
            cout << "wrong" << endl;
            return 0;
        }
    }

    info("Gauss Elimination");
    int rank = solveLinear(eqs);
    cout << "rank: " << rank << endl;

    for (int row = 0; row < eqNum; ++row) {
        unsigned short res = 0x0000;
        for (int col = 0; col < (1 << 16); ++col) {
            if (eqs[row][col])
                res ^= GF216::mul(eqs[row][col], spnKey.invsbox[col]);
        }
        assert(res == 0x00);
        if (res != 0x00) {
            cout << "wrong" << endl;
            return 0;
        }
    }

    delete[] eqs;
    return 0;
}

