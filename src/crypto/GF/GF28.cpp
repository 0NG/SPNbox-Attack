#include "GF28.h"

#include <array>

template<int i>
constexpr auto _ct_mul_helper(unsigned char a, unsigned char b) 
{
    unsigned char ret = 0;

    const auto lowBit = b & 0x01;
    if (lowBit)    ret ^= a;

    const unsigned char msb = (a & 0x80) >> 7;
    a <<= 1;
    a ^= 0x1b * msb;

    return ret ^ _ct_mul_helper<i + 1>(a, b >> 1);
}
template <>
constexpr auto _ct_mul_helper<8>(unsigned char a, unsigned char b) { return 0x00; }

constexpr auto _ct_mul(unsigned char a, unsigned char b) 
{
    /*
    unsigned char ret = 0;
    for (int i = 0; i < 8; ++i) {
        const auto lowBit = b & 0x01;
        if (lowBit)    ret ^= a;
        //if (a & 0x80) {
        //    a <<= 1;
        //    a ^= 0x1b;
        //} else a <<= 1;
        const unsigned char msb = (a & 0x80) >> 7;
        a <<= 1;
        a ^= 0x1b * msb;
        b >>= 1;
    }
    return ret;
    */
    return _ct_mul_helper<0>(a, b);
}

constexpr auto _ct_genExpTable()
{
    std::array<unsigned char, 256> expTable = { 0x00 };
    expTable[0] = 0x01;

    unsigned char cur = 0x01;
    for (int exp = 1; exp < 256; ++exp) {
        cur = _ct_mul(cur, 0x03);
        expTable[exp] = cur;
    }

    return expTable;
}
constexpr auto expTable = _ct_genExpTable();

constexpr auto _ct_genDlogTable() 
{
    std::array<unsigned char, 256> _ct_table = { 0x00 };
    unsigned char exp = 0;
    unsigned char cur = 0x01;

    _ct_table[0x01] = 0;
    while (exp < 255) {
        ++exp;
        cur = _ct_mul(cur, 0x03);
        _ct_table[cur] = exp;
    }

    return _ct_table;
}

constexpr auto _ct_genInvTable(const std::array<unsigned char, 256> logTable) 
{
    std::array<unsigned char, 256> _ct_table = { 0x00 };

    _ct_table[0x00] = 0x00;
    for (int a = 0x01; a <= 0xff; ++a) {
        auto loga = logTable[a];
        _ct_table[a] = expTable[255 - loga];
    }

    return _ct_table;
}

template<int b>
constexpr void _ct_genMulTable_helper_helper(std::array< std::array<unsigned char, 256>, 256 > &_ct_table, unsigned char a)
{
    _ct_table[a][b] = _ct_mul(a, b);

    _ct_genMulTable_helper_helper<b + 1>(_ct_table, a);
    return;
}
template<>
constexpr void _ct_genMulTable_helper_helper<0xff + 1>(std::array< std::array<unsigned char, 256>, 256 > &_ct_table, unsigned char a) { return; }

template<int a>
constexpr void _ct_genMulTable_helper(std::array< std::array<unsigned char, 256>, 256 > &_ct_table)
{
    for (int b = 0x00; b <= 0xff; ++b)
        _ct_table[a][b] = _ct_mul(a, b);
    //_ct_genMulTable_helper_helper<0>(_ct_table, a);

    _ct_genMulTable_helper<a + 1>(_ct_table);
    return;
}
template<>
constexpr void _ct_genMulTable_helper<0xff + 1>(std::array< std::array<unsigned char, 256>, 256 > &_ct_table) { return; }
constexpr auto _ct_genMulTable() 
{
    std::array< std::array<unsigned char, 256>, 256 > _ct_table = {{ {{ 0x00 }} }};

    //for (int a = 0x00; a <= 0xff; ++a)
    //    for (int b = 0x00; b <= 0xff; ++b)
    //        _ct_table[a][b] = _ct_mul(a, b);
    _ct_genMulTable_helper<0>(_ct_table);

    return _ct_table;
}

// DLog respective to 0x03
constexpr auto dlogTable = _ct_genDlogTable();
unsigned char GF28::log03(const unsigned char a) 
{
    return dlogTable[a];
}

// inverse of a in GF(2^8)
constexpr auto invTable = _ct_genInvTable(dlogTable);
unsigned char GF28::inv(const unsigned char a) 
{
    return invTable[a];
}

// a * b in GF(2^8)
constexpr auto mulTable = _ct_genMulTable();
unsigned char GF28::mul(const unsigned char a, const unsigned char b) 
{
    return mulTable[a][b];
}

