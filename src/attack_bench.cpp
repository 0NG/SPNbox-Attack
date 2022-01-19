#include "crypto/SPNbox/SPNbox8.h"
#include "crypto/GF/GF28.h"
#include "crypto/utils/component.h"

#include <iostream>
#include <cstring>
#include <string>
#include <functional>
#include <random>
#include <cassert>
#include <iomanip>
#include <chrono>

using std::cout;
using std::endl;

using component::printx;

constexpr int eqSetNum = 1; // 1 for the special equation
//constexpr int eqNum = 1 + eqSetNum * 255; // 1 for the special equation
constexpr int eqNum = 1 << 8; // 1 for the special equation

static void info(std::string s)
{
    return;
    static int steps;
    cout << "[" << steps << "] " << s << endl;
    ++steps;
    return;
}

constexpr int eqSize = 256;
static inline void swapEq(unsigned char *eq1, unsigned char *eq2)
{
    unsigned char tmp[eqSize];
    memcpy(tmp, eq1, eqSize);
    memcpy(eq1, eq2, eqSize);
    memcpy(eq2, tmp, eqSize);
    return;
}
static inline void xorEq(unsigned char *eq, unsigned char *eq1, unsigned char *eq2)
{
    unsigned char tmp[eqSize];
    for (int i = 0; i < eqSize; ++i)
        tmp[i] = eq1[i] ^ eq2[i];
    memcpy(eq, tmp, eqSize);
    return;
}
static inline void mulEq(unsigned char *eq, unsigned char *eq1, unsigned char c)
{
    unsigned char tmp[eqSize];
    for (int i = 0; i < eqSize; ++i)
        tmp[i] = GF28::mul(eq1[i], c);
    memcpy(eq, tmp, eqSize);
    return;
}
static inline void mulEq2(unsigned char *eq, unsigned char *eq1)
{
    unsigned char tmp[eqSize];
    for (int i = 0; i < eqSize; ++i) {
        const unsigned char msb = (eq1[i] >> 7) & 0x01;
        tmp[i] = (eq1[i] << 1) ^ (0x1b * msb);
    }
    memcpy(eq, tmp, eqSize);
    return;
}
// number of zeros
static inline unsigned char ntz(unsigned char x)
{
    if (x == 0) return 0;
    unsigned char n = 0;
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
static inline void genMulTableRow(unsigned char *mulTable[256], unsigned char *eq)
{
    unsigned char bitRow[8][eqSize];
    memcpy(bitRow[0], eq, eqSize);
    for (int i = 1; i < 8; ++i) {
        mulEq2(bitRow[i], bitRow[i - 1]);
    }

    memset(mulTable[0], 0x00, eqSize);
    for (int i = 1; i < 256; ++i) {
        const unsigned char g1 = g(i - 1);
        const unsigned char g2 = g(i);
        const unsigned char addBit = g1 ^ g2;
        const unsigned char rowi = ntz(addBit);
        xorEq(mulTable[i], mulTable[i - 1], bitRow[rowi]);
    }
    return;
}
static int solveLinear(unsigned char linearEqs[eqNum][eqSize])
{
    auto mulTable = new unsigned char*[256];
    for (int i = 0; i < 256; ++i) mulTable[i] = new unsigned char[eqSize];

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
        const auto pivot = linearEqs[firstRow][col];
        const auto invPivot = GF28::inv(pivot);
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
    for (oneRow = eqNum - 1; oneRow >= 0; --oneRow) {
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

    for (int i = 0; i < 256; ++i) delete[] mulTable[i];
    delete[] mulTable;
    return rank;
}
static int solveLinear_old(unsigned char linearEqs[eqNum][eqSize])
{
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
        auto pivot = linearEqs[firstRow][col];
        auto invPivot = GF28::inv(pivot);
        mulEq(linearEqs[firstRow], linearEqs[firstRow], invPivot);

        for (int row = 0; row < eqNum; ++row)
            if (linearEqs[row][col] && row != firstRow) {
                unsigned char tmp[eqSize];
                mulEq(tmp, linearEqs[firstRow], linearEqs[row][col]);
                xorEq(linearEqs[row], linearEqs[row], tmp);
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

    return rank;
}

static int bench()
{
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

    //cout << endl << "===== test vector =====" << endl;
    //unsigned char testvector[] = { '-', '#', '-', ' ', 'c', 'o', 'r', 'r', 'e', 'c', 't', '!', ' ', '-', '#', '-' };
    //spnHandler.SPNboxEncrypt(testvector, testvector, spnKey);
    //printx(testvector); cout << endl;
    //spnHandler.SPNboxDecrypt(testvector, testvector, spnKey);
    //for (int _vi = 0; _vi < 16; ++_vi) { cout << testvector[_vi]; } cout << endl;
    //cout << "====== end  test ======" << endl << endl;

    info("Start Attack");

    info("Query oracle");
    unsigned char eqs[eqNum < 256 ? 256 : eqNum][256];
    memset(eqs, 0x00, sizeof(eqs));

    auto start = std::chrono::high_resolution_clock::now();

    for (int j = 0; j < 256; ++j) eqs[0][j] = 0x01;
    for (int eqSetCnt = 0; eqSetCnt < eqSetNum; ++eqSetCnt) {
        unsigned char plaintext[16];
        auto cByte = static_cast<unsigned char>(dist(randomGen));
        const int firstEq = 1 + 255 * eqSetCnt;
        if (firstEq >= eqNum) break;
        {
            memset(plaintext, 0x00, 16);
            plaintext[0] = cByte;

            unsigned char ciphertext[16];
            oracle(ciphertext, plaintext);

            eqs[firstEq + 0][ciphertext[ 0]] ^= 0x01;
            eqs[firstEq + 0][ciphertext[ 1]] ^= 0x8a;
            eqs[firstEq + 0][ciphertext[ 2]] ^= 0x16;
            eqs[firstEq + 0][ciphertext[ 3]] ^= 0x08;
            eqs[firstEq + 0][ciphertext[ 4]] ^= 0x76;
            eqs[firstEq + 0][ciphertext[ 5]] ^= 0x24;
            eqs[firstEq + 0][ciphertext[ 6]] ^= 0x8d;
            eqs[firstEq + 0][ciphertext[ 7]] ^= 0x70;
            eqs[firstEq + 0][ciphertext[ 8]] ^= 0x48;
            eqs[firstEq + 0][ciphertext[ 9]] ^= 0xad;
            eqs[firstEq + 0][ciphertext[10]] ^= 0x91;
            eqs[firstEq + 0][ciphertext[11]] ^= 0xa8;
            eqs[firstEq + 0][ciphertext[12]] ^= 0xf8;
            eqs[firstEq + 0][ciphertext[13]] ^= 0xaf;
            eqs[firstEq + 0][ciphertext[14]] ^= 0xb5;
            eqs[firstEq + 0][ciphertext[15]] ^= 0x05;
        }
        for (int i = 0; i < 0xff; ++i) {
            if (firstEq + i >= eqNum) break;
            memset(plaintext, (i + 1) & 0xff, 16);
            plaintext[0] = cByte;

            unsigned char ciphertext[16];
            oracle(ciphertext, plaintext);

            eqs[firstEq + i][ciphertext[ 0]] ^= 0x01;
            eqs[firstEq + i][ciphertext[ 1]] ^= 0x8a;
            eqs[firstEq + i][ciphertext[ 2]] ^= 0x16;
            eqs[firstEq + i][ciphertext[ 3]] ^= 0x08;
            eqs[firstEq + i][ciphertext[ 4]] ^= 0x76;
            eqs[firstEq + i][ciphertext[ 5]] ^= 0x24;
            eqs[firstEq + i][ciphertext[ 6]] ^= 0x8d;
            eqs[firstEq + i][ciphertext[ 7]] ^= 0x70;
            eqs[firstEq + i][ciphertext[ 8]] ^= 0x48;
            eqs[firstEq + i][ciphertext[ 9]] ^= 0xad;
            eqs[firstEq + i][ciphertext[10]] ^= 0x91;
            eqs[firstEq + i][ciphertext[11]] ^= 0xa8;
            eqs[firstEq + i][ciphertext[12]] ^= 0xf8;
            eqs[firstEq + i][ciphertext[13]] ^= 0xaf;
            eqs[firstEq + i][ciphertext[14]] ^= 0xb5;
            eqs[firstEq + i][ciphertext[15]] ^= 0x05;

            if (i + 1 < 0xff && firstEq + i + 1 < eqNum) {
                eqs[firstEq + i + 1][ciphertext[ 0]] ^= 0x01;
                eqs[firstEq + i + 1][ciphertext[ 1]] ^= 0x8a;
                eqs[firstEq + i + 1][ciphertext[ 2]] ^= 0x16;
                eqs[firstEq + i + 1][ciphertext[ 3]] ^= 0x08;
                eqs[firstEq + i + 1][ciphertext[ 4]] ^= 0x76;
                eqs[firstEq + i + 1][ciphertext[ 5]] ^= 0x24;
                eqs[firstEq + i + 1][ciphertext[ 6]] ^= 0x8d;
                eqs[firstEq + i + 1][ciphertext[ 7]] ^= 0x70;
                eqs[firstEq + i + 1][ciphertext[ 8]] ^= 0x48;
                eqs[firstEq + i + 1][ciphertext[ 9]] ^= 0xad;
                eqs[firstEq + i + 1][ciphertext[10]] ^= 0x91;
                eqs[firstEq + i + 1][ciphertext[11]] ^= 0xa8;
                eqs[firstEq + i + 1][ciphertext[12]] ^= 0xf8;
                eqs[firstEq + i + 1][ciphertext[13]] ^= 0xaf;
                eqs[firstEq + i + 1][ciphertext[14]] ^= 0xb5;
                eqs[firstEq + i + 1][ciphertext[15]] ^= 0x05;
            }
        }
    }
    
    //for (int i = 0; i < eqNum; ++i) {
    //    for (int j = 0; j < 256; ++j) {
    //        cout << std::hex << std::setfill('0') << std::setw(2)
    //             << static_cast<unsigned int>(eqs[i][j]) << ':';
    //    }
    //    cout << endl;
    //}

    info("Gauss Elimination");
    const int rank = solveLinear(eqs);
    //const int rank = solveLinear_old(eqs);
    //cout << "rank: " << rank << endl;

    /*
    for (int row = 0; row < 256; ++row) {
        unsigned char res = 0x00;
        for (int col = 0; col < 256; ++col) {
            if (eqs[row][col])
                res ^= GF28::mul(eqs[row][col], spnKey.invsbox[col]);
        }
        assert(res == 0x00);
        if (res != 0x00) cout << "wrong" << endl;
    }
    */

    info("Recovering Sbox");
    int pos0 = -1;
    int pos1 = -1;
    for (int row = 0; row < 256; ++row) {
        if (eqs[row][row] == 0) {
            if (pos0 == -1) pos0 = row;
            else {
                pos1 = row;
                break;
            }
        }

        if (pos0 != -1 && pos1 != -1) break;
    }

    unsigned char zeroText[16] = { 0x00 };
    unsigned char filter[16];
    oracle(filter, zeroText);

    unsigned char recovered[256];
    recovered[pos0] = 0x00;
    recovered[pos1] = 0x01;
    for (int row = 0; row < 256; ++row) {
        if (eqs[row][row] == 0) continue;

        unsigned char z = eqs[row][pos1]; // GF28::mul(eqs[row][pos0], 0x00) ^ GF28::mul(eqs[row][pos1], 0x01);
        recovered[row] = z;
    }

    int cnt = 0;
    for (int c0 = 0x00; c0 <= 0xff; ++c0) {
        for (int c1 = 0x00; c1 <= 0xff; ++c1) {
            if (c0 == c1) continue;

            bool isTaken[256];
            memset(isTaken, 0, sizeof(isTaken));
            isTaken[c0] = 1;
            isTaken[c1] = 1;

            recovered[pos0] = c0;
            recovered[pos1] = c1;

            bool isFound = true;
            for (int row = 0; row < 256; ++row) {
                if (eqs[row][row] == 0) continue;

                unsigned char z = GF28::mul(eqs[row][pos0], c0) ^ GF28::mul(eqs[row][pos1], c1);
                if (isTaken[z]) {
                    isFound = false;
                    break;
                }
                isTaken[z] = 1;

                recovered[row] = z;
            }
            if (!isFound) continue;

            unsigned char rec[256];
            for (int i = 0x00; i <= 0xff; ++i)
                rec[recovered[i]] = i & 0xff;
            memcpy(recovered, rec, 256);

            for (int ti = 0; ti < 16; ++ti) zeroText[ti] = recovered[0x00];
            pOracle(zeroText, 0);
            component::SB(zeroText, recovered);
            pOracle(zeroText, 16);
            component::SB(zeroText, recovered);

            for (int ti = 0; ti < 16; ++ti)
                if (zeroText[ti] != filter[ti]) {
                    isFound = false;
                    break;
                }
            if (!isFound) continue;

            ++cnt;
            for (int sbi = 0; sbi < 256; ++sbi) {
                assert(recovered[sbi] == spnKey.sbox[sbi]);
                if (recovered[sbi] != spnKey.sbox[sbi]) {
                    cout << "wrong" << endl;
                }
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return duration;
}

int main()
{
    constexpr int btime = 500;
    int total = 0;

    for (int i = 0; i < 20; ++i)
        total += bench();
    total = 0;

    for (int i = 0; i < btime; ++i)
        total += bench();

    cout << "run " << btime << " times" << endl;
    cout << "total cost: " << total << " milliseconds" << endl;
    cout << "average cost: " << total * 1.0 / btime << " milliseconds" << endl;
    return 0;
}

