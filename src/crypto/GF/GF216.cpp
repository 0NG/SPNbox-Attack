#include "GF216.h"

#include <array>

static unsigned short _ct_mul3(unsigned short a) 
{
    unsigned short ret = a;
    const unsigned short msb = (a & 0x8000) >> 15;
    a <<= 1;
    a ^= 0x2b * msb;
    return ret ^ a;
}

static unsigned short _internal_mul(unsigned short a, unsigned short b) 
{
    unsigned short ret = 0;
    for (int i = 0; i < 16; ++i) {
        const auto lowBit = b & 0x01;
        if (lowBit)    ret ^= a;
        const unsigned short msb = (a & 0x8000) >> 15;
        a <<= 1;
        a ^= 0x2b * msb;
        b >>= 1;

        if (!b) break;
    }
    return ret;
}

static auto _ct_genExpTable()
{
    std::array<unsigned short, 1<<16> expTable = { 0x00 };
    expTable[0] = 0x01;

    unsigned short cur = 0x01;
    for (int exp = 1; exp < (1<<16); ++exp) {
        cur = _ct_mul3(cur);
        expTable[exp] = cur;
    }

    return expTable;
}
static auto expTable = _ct_genExpTable();

static auto _ct_genDlogTable() 
{
    std::array<unsigned short, 1<<16> _ct_table = { 0x00 };
    unsigned int exp = 0;
    unsigned short cur = 0x01;

    _ct_table[0x01] = 0;
    while (exp < (1<<16)) {
        ++exp;
        cur = _ct_mul3(cur);
        _ct_table[cur] = exp;
    }

    return _ct_table;
}

static auto _ct_genInvTable(const std::array<unsigned short, 1<<16> logTable) 
{
    std::array<unsigned short, 1<<16> _ct_table = { 0x00 };

    _ct_table[0x00] = 0x0000;
    for (int a = 0x0001; a <= 0xffff; ++a) {
        auto loga = logTable[a];
        _ct_table[a] = expTable[(1<<16) - loga];
    }

    return _ct_table;
}

// DLog respective to 0x03
static auto dlogTable = _ct_genDlogTable();
unsigned short GF216::log03(const unsigned short a) 
{
    return dlogTable[a];
}

// inverse of a in GF(2^8)
static auto invTable = _ct_genInvTable(dlogTable);
unsigned short GF216::inv(const unsigned short a) 
{
    return invTable[a];
}

// a * b in GF(2^16)
unsigned short GF216::mul(const unsigned short a, const unsigned short b) 
{
    return _internal_mul(a, b);
}

